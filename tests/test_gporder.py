"""The processing order doctor recomputes ([MS-GPOL] 3.2.5.1.5), on synthetic layouts."""
from __future__ import annotations

from conftest import BASE, DDP, SCHOOL_NAMES, SCHOOLS_OU, gplink_value, school_guid
from lmn_gpo import gporder
from lmn_gpo.gporder import GpoInfo, SchoolLayout, Som

OURS = "{D21E0000-0000-0000-0000-000000000020}"
LOCKDOWN_STUDENT = "{15150000-0000-0000-0000-000000000001}"   # LMN-U-GLOBAL-15-lockdown-student
LOCKDOWN_BASE = "{15150000-0000-0000-0000-000000000002}"      # machine only
PROXY_STUDENT = "{12120000-0000-0000-0000-000000000001}"      # LMN-U-<school>-12-proxy-...
LMNT_USER = "{53D9208E-3A92-4509-A352-6F0E39133512}"          # lab control GPO at OU=Students
OTHER = "{0BAD0000-0000-0000-0000-000000000001}"


def sdn(school):
    return f"OU={school},{SCHOOLS_OU}"


def layout(schools=SCHOOL_NAMES):
    return [SchoolLayout(s, [f"OU=Teachers,{sdn(s)}", f"OU=5a,OU=Students,{sdn(s)}"],
                         [f"OU=Devices,{sdn(s)}", f"OU=r101,OU=Devices,{sdn(s)}"])
            for s in schools]


def soms(ours_opts=2, extra=None):
    out = {BASE.lower(): Som(BASE, [(DDP, 0)]),
           SCHOOLS_OU.lower(): Som(SCHOOLS_OU, [(OURS, ours_opts), (LOCKDOWN_STUDENT, 0)])}
    for s in SCHOOL_NAMES:
        out[sdn(s).lower()] = Som(sdn(s), [(school_guid(s), 0)])
    for dn, links in (extra or {}).items():
        som = out.setdefault(dn.lower(), Som(dn))
        som.links = links
    return out


def gpos(**extra):
    out = {DDP: GpoInfo(DDP, "Default Domain Policy"),
           OURS: GpoInfo(OURS, "LMN-U-GLOBAL-20-drives", True),
           LOCKDOWN_STUDENT: GpoInfo(LOCKDOWN_STUDENT, "LMN-U-GLOBAL-15-lockdown-student"),
           OTHER: GpoInfo(OTHER, "other-drives", True)}
    for s in SCHOOL_NAMES:
        g = school_guid(s)
        out[g] = GpoInfo(g, f"sophomorix:school:{s}", True)
    out.update(extra)
    return out


def check(s=None, g=None, schools=SCHOOL_NAMES, sites=None):
    return gporder.check(s or soms(), g or gpos(), OURS, layout(schools), BASE, sites)


# --------------------------------------------------------------------------- #
# the list builder itself
# --------------------------------------------------------------------------- #
def test_first_gplink_entry_of_a_som_is_processed_last():
    assert gporder.gpo_list([Som("OU=x", [("X", 0), ("Y", 0)])]) == ["Y", "X"]


def test_parents_first_children_last_enforced_at_the_end():
    chain = [Som("OU=child", [("C", 0), ("CE", 2)]), Som("OU=parent", [("P", 0), ("PE", 2)]),
             Som("DC=dom", [("D", 0)])]
    assert gporder.gpo_list(chain) == ["D", "P", "C", "CE", "PE"]


def test_enforced_entries_of_one_som_keep_string_order():
    assert gporder.gpo_list([Som("OU=x", [("E1", 2), ("E2", 2)])]) == ["E1", "E2"]


def test_disabled_links_are_ignored_even_when_enforced():
    assert gporder.gpo_list([Som("OU=x", [("A", 1), ("B", 3), ("C", 0)])]) == ["C"]


def test_block_inheritance_drops_only_non_enforced_parent_links():
    chain = [Som("OU=school", [("S", 0)], block_inheritance=True),
             Som("OU=SCHOOLS", [("G", 0), ("E", 2)]), Som("DC=dom", [("D", 0)])]
    assert gporder.gpo_list(chain) == ["S", "E"]


def test_som_chain_skips_containers_and_stops_at_the_domain():
    s = soms()
    chain = gporder.som_chain(f"OU=5a,OU=Students,{sdn('gsg')}", s, BASE)
    assert [c.dn for c in chain] == [f"OU=5a,OU=Students,{sdn('gsg')}",
                                     f"OU=Students,{sdn('gsg')}", sdn("gsg"), SCHOOLS_OU, BASE]
    chain = gporder.som_chain(f"CN=Users,{BASE}", s, BASE, site=Som("CN=Default"))
    assert [c.dn for c in chain] == [BASE, "CN=Default"]


def test_split_dn_honours_escaped_commas():
    assert gporder.split_dn(r"OU=a\,b,OU=c,DC=x") == [r"OU=a\,b", "OU=c", "DC=x"]


def test_lab_measurement_5312_merge_list_is_reproduced():
    """gpo-user-scope-verification.md §7: event 5312 in Merge listed (user settings only)
    LMN-U-GLOBAL-15-lockdown-student sophomorix:school:default-school lmnt-gpouser-students
    LMN-U-GLOBAL-15-lockdown-student sophomorix:school:default-school
    LMN-U-default-school-12-proxy-student-schule."""
    d = sdn("default-school")
    s = {BASE.lower(): Som(BASE, [(DDP, 0)]),
         SCHOOLS_OU.lower(): Som(SCHOOLS_OU, [(LOCKDOWN_STUDENT, 0), (LOCKDOWN_BASE, 0)]),
         d.lower(): Som(d, [(school_guid("default-school"), 0)]),
         f"OU=Students,{d}".lower(): Som(f"OU=Students,{d}", [(LMNT_USER, 0)]),
         f"OU=Devices,{d}".lower(): Som(f"OU=Devices,{d}", [(PROXY_STUDENT, 0)])}
    user = gporder.som_chain(f"OU=testklasse,OU=Students,{d}", s, BASE)
    comp = gporder.som_chain(f"OU=server,OU=Devices,{d}", s, BASE)
    has_user = {LOCKDOWN_STUDENT, school_guid("default-school"), LMNT_USER, PROXY_STUDENT}
    got = [g for g in gporder.user_policy_list(user, comp, "merge") if g in has_user]
    assert got == [LOCKDOWN_STUDENT, school_guid("default-school"), LMNT_USER,
                   LOCKDOWN_STUDENT, school_guid("default-school"), PROXY_STUDENT]
    # Replace (7.3.1's value, measured too): only the computer's list
    got = [g for g in gporder.user_policy_list(user, comp, "replace") if g in has_user]
    assert got == [LOCKDOWN_STUDENT, school_guid("default-school"), PROXY_STUDENT]


# --------------------------------------------------------------------------- #
# the 20-drives check: every school, every mode, cross-school merge
# --------------------------------------------------------------------------- #
def test_enforced_at_schools_is_last_everywhere():
    findings, counts = check()
    assert findings == []
    assert set(counts) == set(SCHOOL_NAMES)
    # per school: 2 user OUs (none) + 2 computer OUs (replace) + 2 x 8 user OUs (merge)
    assert all(c == {"checked": 2 + 2 + 2 * 8, "bad": 0} for c in counts.values()), counts


def test_cross_school_merge_teacher_of_msg_on_a_gsg_computer():
    s, g = soms(), gpos()
    user = gporder.som_chain(f"OU=Teachers,{sdn('msg')}", s, BASE)
    comp = gporder.som_chain(f"OU=r101,OU=Devices,{sdn('gsg')}", s, BASE)
    order = gporder.user_policy_list(user, comp, "merge")
    drive_gpos = [x for x in order if g[x].user_drive_maps]
    assert drive_gpos == [school_guid("msg"), OURS, school_guid("gsg"), OURS]
    assert gporder.after_ours(order, OURS, {x for x in g if g[x].user_drive_maps}) == []


def test_not_enforced_loses_against_every_school_gpo_in_every_mode():
    findings, counts = check(soms(ours_opts=0))
    modes = {(f.school, f.mode) for f in findings}
    assert modes == {(s, m) for s in SCHOOL_NAMES for m in ("none", "merge", "replace")}
    f = next(f for f in findings if f.school == "gsg" and f.mode == "merge")
    assert f.kind == "after" and school_guid("gsg") in f.gpos
    assert all(c["bad"] == c["checked"] for c in counts.values())


def test_disabled_link_means_ours_reaches_nobody():
    findings, _ = check(soms(ours_opts=3))
    assert findings and all(f.kind == "missing" for f in findings)


def test_enforced_domain_gpo_with_drive_maps_comes_after_ours():
    s = soms(extra={BASE: [(DDP, 0), (OTHER, 2)]})
    findings, _ = check(s)
    assert findings and all(f.gpos == (OTHER,) for f in findings)


def test_enforced_gpo_deeper_in_the_tree_comes_before_ours():
    s = soms(extra={f"OU=Devices,{sdn('gsg')}": [(OTHER, 2)]})
    assert check(s)[0] == []


def test_second_enforced_link_at_schools_after_ours_is_reported():
    s = soms()
    s[SCHOOLS_OU.lower()].links = [(OURS, 2), (OTHER, 2)]
    assert {f.gpos for f in check(s)[0]} == {(OTHER,)}
    s[SCHOOLS_OU.lower()].links = [(OTHER, 2), (OURS, 2)]
    assert check(s)[0] == []


def test_gpo_without_drive_maps_or_with_user_half_disabled_does_not_count():
    s = soms(extra={BASE: [(DDP, 0), (OTHER, 2)]})
    g = gpos()
    g[OTHER] = GpoInfo(OTHER, "other", user_drive_maps=False)
    assert check(s, g)[0] == []
    g[OTHER] = GpoInfo(OTHER, "other", user_drive_maps=True, user_disabled=True)
    assert check(s, g)[0] == []


def test_block_inheritance_at_a_school_does_not_stop_the_enforced_link():
    s = soms()
    s[sdn("gym").lower()].block_inheritance = True
    assert check(s)[0] == []
    findings, _ = check(soms(ours_opts=0) | {sdn("gym").lower(): Som(
        sdn("gym"), [(school_guid("gym"), 0)], True)})
    assert any(f.school == "gym" and f.kind == "missing" for f in findings)


def test_sites_enforced_after_ours_non_enforced_before():
    site = Som("CN=Default-First-Site-Name,CN=Sites,CN=Configuration," + BASE, [(OTHER, 0)])
    assert check(sites=[site])[0] == []
    site.links = [(OTHER, 2)]
    assert check(sites=[site])[0]


def test_with_planned_link_keeps_position_or_inserts_first():
    s = soms(ours_opts=0)
    s[SCHOOLS_OU.lower()].links = [(LOCKDOWN_STUDENT, 0), (OURS, 1)]
    planned = gporder.with_planned_link(s, SCHOOLS_OU, OURS)
    assert planned[SCHOOLS_OU.lower()].links == [(LOCKDOWN_STUDENT, 0), (OURS, 2)]
    assert s[SCHOOLS_OU.lower()].links == [(LOCKDOWN_STUDENT, 0), (OURS, 1)], "copy, not edit"
    s[SCHOOLS_OU.lower()].links = [(LOCKDOWN_STUDENT, 0)]
    planned = gporder.with_planned_link(s, SCHOOLS_OU, OURS)
    assert planned[SCHOOLS_OU.lower()].links == [(OURS, 2), (LOCKDOWN_STUDENT, 0)]


def test_report_names_the_gpo_the_link_and_its_letters():
    s, g = soms(ours_opts=0), gpos()
    findings, counts = check(s, g, schools=("gsg",))
    ok, warn = gporder.report(findings, counts, g, s, "LMN-U-GLOBAL-20-drives",
                              letters_of=lambda guid: {"K", "T"})
    assert not ok
    text = "\n".join(warn)
    assert "sophomorix:school:gsg runs AFTER LMN-U-GLOBAL-20-drives" in text
    assert f"linked at {sdn('gsg')} (not enforced)" in text
    assert "it maps K: T:" in text
    assert "loopback Merge" in text and "without loopback" in text and "Replace" in text
    ok, warn = gporder.report(*check(schools=("gsg",)), g, soms(), "LMN-U-GLOBAL-20-drives")
    assert warn == [] and ok and ok[0].startswith("gsg: LMN-U-GLOBAL-20-drives is the last")


# --------------------------------------------------------------------------- #
# loading from the (fake) directory
# --------------------------------------------------------------------------- #
def test_load_from_directory_and_check(domain):
    fake, env, _ = domain
    s, g, layouts, sites = gporder.load(env, fake)
    assert sites == []
    assert {x.name for x in layouts} == set(SCHOOL_NAMES)
    gsg = next(x for x in layouts if x.name == "gsg")
    assert f"OU=r101,OU=Devices,{sdn('gsg')}" in gsg.computer_ous
    assert f"OU=5a,OU=Students,{sdn('gsg')}" in gsg.user_ous
    assert all("Devices" not in u for u in gsg.user_ous)
    assert g[school_guid("gsg")].user_drive_maps and not g[DDP].user_drive_maps
    # before the first apply: simulate the planned link
    g[OURS] = GpoInfo(OURS, "LMN-U-GLOBAL-20-drives", True)
    planned = gporder.with_planned_link(s, SCHOOLS_OU, OURS)
    assert gporder.check(planned, g, OURS, layouts, BASE, sites)[0] == []
    # the same GPO linked without enforcement: every school reports
    fake.get(SCHOOLS_OU).set("gPLink", gplink_value((OURS, 0)))
    s, g, layouts, sites = gporder.load(env, fake)
    g[OURS] = GpoInfo(OURS, "LMN-U-GLOBAL-20-drives", True)
    findings, _ = gporder.check(s, g, OURS, layouts, BASE, sites)
    assert {f.school for f in findings} == set(SCHOOL_NAMES)
