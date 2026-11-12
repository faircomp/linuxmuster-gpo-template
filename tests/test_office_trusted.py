"""Pack 21-office-trusted-schule: the drives as Office trusted locations.

Unit level (lmn_gpo/officetrust.py, no AD) and end to end on the fake domain (fake
samba-tool with Samba's merge/replace semantics, fake sam.ldb): which locations, merging,
the 20-per-application limit, the application list, on/off, and the exact registry values
against a golden file. The value names are Microsoft's (docs/RESEARCH.md section 9).
"""
from __future__ import annotations

import json
import os

import pytest

from conftest import BASE, GROUP_SIDS, POLICIES, SCHOOLS_OU, school_drives_xml
from fakesamba import FakeSamba
from lmn_gpo import apply, catalog, drivesconf, officetrust, sophodrives
from lmn_gpo.gpo import GpoEngine

PACK = "21-office-trusted-schule"
GOLDEN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden",
                      "21-office-trusted-default-school.json")
ACCESS = r"software\policies\microsoft\office\16.0\access\security\trusted locations"
COMMON = r"software\policies\microsoft\office\16.0\common\security\trusted locations"

# The shipped example's layout (Kevin's site): drives for the other schools and the
# administration's own file server.
KEVIN = """\
version: 1
linuxmuster_defaults:
  remove: all
  for_groups: [role-teacher, role-staff]
drives:
  - {letter: H, label: Home, home: true}
  - {letter: M, label: MSG Shares, path: '\\\\@server\\msg', groups: [msg-teachers]}
  - {letter: G, label: GSG Shares, path: '\\\\@server\\gsg', groups: [gsg-teachers]}
  - {letter: Y, label: GYM Shares, path: '\\\\@server\\gym', groups: [gym-teachers]}
  - {letter: V, label: Verwaltung, path: '\\\\verwaltung\\verwaltung', groups: [verwaltung]}
"""


def name(school):
    return f"LMN-U-{school}-{PACK}"


def sopho_items(school="default-school"):
    return sophodrives.parse_drives_xml(school_drives_xml(school))


def sources(school="default-school", yaml_text=None):
    src = officetrust.home_sources([rf"\\server\{school}\students\5a\max",
                                    rf"\\server\{school}\teachers\lehrer1"])
    src += officetrust.sophomorix_sources(sopho_items(school), f"sophomorix:school:{school}")
    if yaml_text:
        import yaml
        cfg = drivesconf.parse(yaml.safe_load(yaml_text))
        src += officetrust.drives_yaml_sources(cfg, "server", "server.dev.lmschule.de")
    return src


# --------------------------------------------------------------------------- #
# paths and sources
# --------------------------------------------------------------------------- #
def test_share_root_and_static_path():
    assert officetrust.share_root(r"\\server\default-school\students\5a\max") == \
        "\\\\server\\default-school\\"
    assert officetrust.share_root(r"H:\x") == "" and officetrust.share_root(r"\\server") == ""
    assert officetrust.static_path(r"\\server\share\folder") == "\\\\server\\share\\folder\\"
    assert officetrust.static_path("\\\\server\\share\\folder\\") == "\\\\server\\share\\folder\\"
    # a Group Policy Preferences variable is not expanded by Office: cut before it
    assert officetrust.static_path(r"\\server\share\%LogonUser%\x") == "\\\\server\\share\\"
    assert officetrust.static_path(r"\\server\%LogonDomain%") == ""
    assert officetrust.static_path(r"\\@@SERVER@@\@@SCHOOL@@\program") == ""
    assert officetrust.static_path(r"C:\Program Files") == ""


def test_home_is_the_share_root_once_not_one_path_per_user():
    src = officetrust.home_sources([r"\\server\default-school\students\5a\a",
                                    r"\\SERVER\default-school\students\6b\b",
                                    r"\\server\default-school\teachers\t", "", None])
    assert [(s.letter, s.path) for s in src] == [("H", "\\\\server\\default-school\\")]
    # another host spelling is another string to Office: two roots
    src = officetrust.home_sources([r"\\server\x\a", r"\\server.dev.lmschule.de\x\b"])
    assert len(src) == 2


def test_sophomorix_default_drives_skip_disabled_and_delete_items():
    items = sopho_items()
    assert [i.letter for i in items] == ["K", "P", "S", "T", "R"]
    items[0].disabled = True                      # the WebUI switched K: off
    items[1].action = "D"
    src = officetrust.sophomorix_sources(items, "sophomorix:school:default-school")
    assert [s.letter for s in src] == ["S", "T", "R"]


def test_drives_yaml_entries_use_the_substituted_path_and_skip_home():
    import yaml
    cfg = drivesconf.parse(yaml.safe_load(KEVIN))
    src = officetrust.drives_yaml_sources(cfg, "server", "server.dev.lmschule.de")
    assert [(s.letter, s.path) for s in src] == [
        ("M", r"\\server\msg"), ("G", r"\\server\gsg"), ("Y", r"\\server\gym"),
        ("V", r"\\verwaltung\verwaltung")]
    assert src[3].origin == "drives.yaml entry 5 (V:)"


# --------------------------------------------------------------------------- #
# plan: merging, forms, the limit
# --------------------------------------------------------------------------- #
def test_h_and_the_default_drives_merge_into_one_school_root():
    p = officetrust.plan(sources())
    assert [(loc.kind, loc.path, loc.letters) for loc in p.locations] == [
        ("unc", "\\\\server\\default-school\\", ["H", "K", "P", "R", "S", "T"]),
        ("letter", "H:\\", ["H"]), ("letter", "K:\\", ["K"]), ("letter", "P:\\", ["P"]),
        ("letter", "R:\\", ["R"]), ("letter", "S:\\", ["S"]), ("letter", "T:\\", ["T"])]
    assert p.locations[0].description == "lmn-gpo H: K: P: R: S: T:"
    assert p.locations[1].description == "lmn-gpo H:"
    assert not officetrust.problems(p)


def test_merging_is_by_path_component_case_insensitive_and_never_across_hosts():
    S = officetrust.DriveSource
    p = officetrust.plan([S("T", r"\\server\school\share", "a"),
                          S("P", r"\\SERVER\School\Share\projects", "b"),
                          S("Q", r"\\server\school\shareX", "c"),          # not below share
                          S("F", r"\\server.dev.lmschule.de\school\share", "d")],
                         forms=("unc",))
    assert [(loc.path, loc.letters) for loc in p.locations] == [
        ("\\\\server.dev.lmschule.de\\school\\share\\", ["F"]),
        ("\\\\server\\school\\share\\", ["P", "T"]),
        ("\\\\server\\school\\shareX\\", ["Q"])]
    assert p.locations[1].origins == ["a", "b"]


def test_forms_unc_only_and_letter_only():
    assert [loc.kind for loc in officetrust.plan(sources(), ("unc",)).locations] == ["unc"]
    assert {loc.kind for loc in officetrust.plan(sources(), ("letter",)).locations} == \
        {"letter"}


def test_a_path_that_is_not_unc_is_reported_not_trusted():
    p = officetrust.plan([officetrust.DriveSource("X", r"C:\temp", "drives.yaml entry 9")])
    assert p.locations == [] and "not a UNC path" in p.notes[0]
    assert "nothing to trust" in officetrust.problems(p)[0]


def test_twenty_locations_fit_twenty_one_are_refused_not_cut():
    S = officetrust.DriveSource
    letters = "DEFGHIJKLM"
    twenty = [S(x, rf"\\srv{i}\share", "t") for i, x in enumerate(letters)]
    p = officetrust.plan(twenty)
    assert len(p.locations) == 20 and not officetrust.problems(p)
    # a second path for D: is one more UNC location and no new letter
    p = officetrust.plan(twenty + [S("D", r"\\srv99\share", "t")])
    assert len(p.locations) == 21
    why = officetrust.problems(p)
    assert why and "21 trusted locations" in why[0] and "at most 20" in why[0]


# --------------------------------------------------------------------------- #
# registry values
# --------------------------------------------------------------------------- #
def test_entries_use_microsofts_value_names_and_types():
    p = officetrust.plan(sources())
    ents = officetrust.entries(p, ["access"])
    by = {(e["keyname"], e["valuename"]): e for e in ents}
    assert by[(ACCESS, "allownetworklocations")]["data"] == 1
    loc1 = ACCESS + r"\location1"
    assert by[(loc1, "path")] == {"keyname": loc1, "valuename": "path", "class": "USER",
                                  "type": "REG_EXPAND_SZ", "data": "\\\\server\\default-school\\"}
    assert by[(loc1, "allowsubfolders")]["type"] == "REG_DWORD"
    assert by[(loc1, "allowsubfolders")]["data"] == 1
    assert by[(loc1, "description")]["type"] == "REG_SZ"
    assert by[(COMMON, "allow user locations")]["data"] == 1
    assert {e["class"] for e in ents} == {"USER"}
    assert not [e for e in ents if e["valuename"] == "date"]
    assert ACCESS + r"\location8" not in {e["keyname"] for e in ents}
    assert len(ents) == 1 + 7 * 3 + 1
    assert not [e for e in ents if e["valuename"].startswith("**")]


def test_application_list():
    p = officetrust.plan(sources())
    ents = officetrust.entries(p, ["word", "access", "excel", "powerpoint"])
    apps = [e["keyname"].split("\\")[5] for e in ents if e["valuename"] == "allownetworklocations"]
    assert apps == ["access", "excel", "word", "powerpoint"]
    assert officetrust.parse_apps(None) == (["access"], "")
    assert officetrust.parse_apps(["Excel", "access"]) == (["access", "excel"], "")
    assert officetrust.parse_apps("access, word") == (["access", "word"], "")
    assert "unknown application" in officetrust.parse_apps(["access", "outlook"])[1]
    assert "office_trusted_enabled: false" in officetrust.parse_apps([])[1]
    assert officetrust.parse_roles(None) == ([], "") == officetrust.parse_roles("all")
    assert officetrust.parse_roles(["student", "teacher"]) == \
        (["@role-teacher", "@role-student"], "")
    assert "unknown role" in officetrust.parse_roles(["teachers"])[1]
    assert officetrust.parse_forms(None) == (("unc", "letter"), "") == \
        (officetrust.DEFAULT_FORMS, "")
    assert officetrust.parse_forms(["dfs", "unc", "letter"]) == (("unc", "letter", "dfs"), "")
    assert officetrust.parse_forms(["letter"]) == (("letter",), "")
    assert "unknown form" in officetrust.parse_forms(["drive"])[1]


def test_golden_registry_values_for_a_sample_site():
    """H: + the sophomorix default drives + Kevin's drives.yaml, Access: pinned value by value.
    Regenerate deliberately: python3 -c 'import tests.test_office_trusted as t; t.write_golden()'"""
    assert golden_entries() == json.load(open(GOLDEN, encoding="utf-8"))


def golden_entries():
    return officetrust.entries(officetrust.plan(sources(yaml_text=KEVIN)), ["access"])


def write_golden():                      # pragma: no cover - a helper, not a test
    with open(GOLDEN, "w", encoding="utf-8") as fh:
        json.dump(golden_entries(), fh, indent=1, ensure_ascii=True)
        fh.write("\n")


# --------------------------------------------------------------------------- #
# apply, end to end on the fake domain
# --------------------------------------------------------------------------- #
@pytest.fixture
def dc(domain, tmp_path, monkeypatch):
    fake, env, sysvol = domain
    samba = FakeSamba(fake, sysvol).install(monkeypatch)
    monkeypatch.setattr(apply, "RETIRE_BACKUP_DIR", str(tmp_path / "backups"))
    # no smb.conf here: no share is a DFS proxy unless a test says so
    monkeypatch.setattr(apply.Applier, "_msdfs_proxy", lambda self, share: "")
    for school in ("default-school", "msg", "gsg", "gym"):
        sdn = f"OU={school},{SCHOOLS_OU}"
        fake.add(f"CN=max,OU=5a,OU=Students,{sdn}", objectClass=["top", "person", "user"],
                 homeDirectory=rf"\\server\{school}\students\5a\max")
        fake.add(f"CN=lehrer1,OU=Teachers,{sdn}", objectClass=["top", "person", "user"],
                 homeDirectory=rf"\\server\{school}\teachers\lehrer1")
        # a computer object is objectClass=user too, and carries no home
        fake.add(f"CN=pc01,OU=r101,OU=Devices,{sdn}",
                 objectClass=["top", "person", "user", "computer"])
    path = tmp_path / "drives.yaml"
    path.write_text(KEVIN, encoding="utf-8")
    return fake, env, sysvol, samba, str(path)


def run(env, answers, dry_run=False):
    ap = apply.Applier(env, {"packs": [PACK], "schools": ["default-school"], **answers},
                       dry_run=dry_run)
    rc = ap.run(catalog.load_packs())
    return ap, rc


def gpo(fake, display):
    for m in fake.search(base=POLICIES, scope="one", expr="(objectClass=groupPolicyContainer)"):
        if fake.val(m, "displayName") == display:
            return fake.val(m, "cn"), m
    return None, None


def locations(samba, guid, app="access"):
    pol = samba.pol(guid)
    key = rf"software\policies\microsoft\office\16.0\{app}\security\trusted locations"
    out, i = [], 1
    while (f"{key}\\location{i}", "path") in pol:
        out.append(pol[(f"{key}\\location{i}", "path")][1])
        i += 1
    return out


def test_pack_shape_and_defaults():
    pack = {p.id: p for p in catalog.load_packs()}[PACK]
    assert pack.scope == "school" and pack.requires == "office_trusted"
    assert pack.registry_source == "office-trusted" and not pack.registry
    assert pack.has_user and not pack.has_machine and pack.type_letter == "U"
    assert apply.Applier.needs_loopback(pack)
    d = apply.DEFAULT_ANSWERS
    assert d["office_trusted_enabled"] is True and d["office_trusted_apps"] == ["access"]
    assert d["office_trusted_roles"] == "all"
    # measured (lab 2026-11-12): letter and mapped UNC cover each other, DFS only on request
    assert d["office_trusted_forms"] == ["unc", "letter"]


def test_default_on_writes_one_user_gpo_per_school_with_replace(dc, capsys):
    fake, env, _sysvol, samba, _path = dc
    ap, rc = run(env, {})                     # an upgraded site.yaml without any office key
    out = capsys.readouterr().out
    assert rc == 0, out
    guid, msg = gpo(fake, name("default-school"))
    assert guid and ap.results[0]["gpo"] == name("default-school")
    devices = f"OU=Devices,OU=default-school,{SCHOOLS_OU}"
    assert guid.upper() in fake.val(fake.get(devices), "gPLink").upper()
    load = samba.loads[-1]
    assert load["guid"] == guid and load["replace"] is True
    assert {e["class"] for e in load["entries"]} == {"USER"}
    assert locations(samba, guid) == ["\\\\server\\default-school\\", "H:\\", "K:\\", "P:\\",
                                      "R:\\", "S:\\", "T:\\"]
    assert not samba.pol(guid, "Machine")
    assert int(fake.val(msg, "versionNumber")) == 1 << 16
    assert "Office trusted locations for access: 7 of 20" in out
    assert "\\\\server\\default-school\\" in out and "H: K: P: R: S: T:" in out
    # no exclusive filter: every user of every role
    assert not samba.ran("dsacl")


def test_second_apply_changes_nothing(dc, capsys):
    fake, env, _sysvol, samba, _path = dc
    run(env, {})
    guid, msg = gpo(fake, name("default-school"))
    version = fake.val(msg, "versionNumber")
    loads = len(samba.loads)
    capsys.readouterr()
    _ap, rc = run(env, {})
    assert rc == 0 and len(samba.loads) == loads
    assert "Registry unchanged — skipped" in capsys.readouterr().out
    assert fake.val(gpo(fake, name("default-school"))[1], "versionNumber") == version


def test_drives_yaml_adds_its_drives_and_a_removed_drive_loses_its_location(dc, tmp_path):
    fake, env, _sysvol, samba, path = dc
    on = {"drives_enabled": True, "drives_file": path}
    _ap, rc = run(env, on)
    guid, _msg = gpo(fake, name("default-school"))
    assert rc == 0
    locs = locations(samba, guid)
    assert "\\\\verwaltung\\verwaltung\\" in locs and "V:\\" in locs and "M:\\" in locs
    assert len(locs) == 15
    # V: is taken out of drives.yaml: the location must go, not linger as location15
    text = "\n".join(line for line in KEVIN.splitlines() if "verwaltung" not in line) + "\n"
    open(path, "w", encoding="utf-8").write(text)
    _ap, rc = run(env, on)
    assert rc == 0 and samba.loads[-1]["replace"] is True
    locs = locations(samba, guid)
    assert len(locs) == 13 and "V:\\" not in locs
    assert not [k for k in samba.pol(guid) if k[0].endswith("location14")]


def test_drives_enabled_with_a_broken_file_holds_the_pack_back(dc, capsys, tmp_path):
    fake, env, _sysvol, samba, path = dc
    run(env, {})
    guid, msg = gpo(fake, name("default-school"))
    version, loads = fake.val(msg, "versionNumber"), len(samba.loads)
    bad = tmp_path / "missing.yaml"
    capsys.readouterr()
    ap, rc = run(env, {"drives_enabled": True, "drives_file": str(bad)})
    out = capsys.readouterr().out
    assert rc == 1 and ap.held_back == [name("default-school")]
    assert "existing GPO left untouched" in out and "drives.yaml drives cannot be listed" in out
    assert len(samba.loads) == loads
    assert fake.val(gpo(fake, name("default-school"))[1], "versionNumber") == version


def test_overflow_holds_back_and_writes_nothing(dc, capsys, tmp_path):
    fake, env, _sysvol, samba, _path = dc
    lines = ["version: 1", "drives:"]
    for i, x in enumerate("DEFGIJLMNOQU"):
        lines.append(f"  - {{letter: {x}, path: '\\\\srv{i}\\share'}}")
    big = tmp_path / "big.yaml"
    big.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ap, rc = run(env, {"drives_enabled": True, "drives_file": str(big)})
    out = capsys.readouterr().out
    assert rc == 1 and ap.held_back == [name("default-school")], out
    assert "31 trusted locations needed" in out and "at most 20" in out
    assert "GPO not created" in out and gpo(fake, name("default-school"))[0] is None
    assert not samba.loads
    # one form alone fits: 13 UNC paths
    ap, rc = run(env, {"drives_enabled": True, "drives_file": str(big),
                       "office_trusted_forms": ["unc"]})
    assert rc == 0 and len(locations(samba, gpo(fake, name("default-school"))[0])) == 13


def test_more_applications_and_an_unknown_one(dc, capsys):
    fake, env, _sysvol, samba, _path = dc
    _ap, rc = run(env, {"office_trusted_apps": ["access", "excel"]})
    guid, _msg = gpo(fake, name("default-school"))
    assert rc == 0 and len(locations(samba, guid, "excel")) == 7
    assert not locations(samba, guid, "word")
    capsys.readouterr()
    ap, rc = run(env, {"office_trusted_apps": ["access", "outlook"]})
    out = capsys.readouterr().out
    assert rc == 1 and ap.held_back and "unknown application(s) outlook" in out
    # the earlier values stay on the GPO (held back, not rewritten)
    assert len(locations(samba, guid, "excel")) == 7


def test_roles_filter_to_role_groups_and_a_typo_never_widens(dc, capsys, monkeypatch):
    fake, env, _sysvol, _samba, _path = dc
    # the real one edits the DACL through samba.sd_utils on sam.ldb; record the call instead
    filtered = []
    monkeypatch.setattr(GpoEngine, "set_exclusive_filter",
                        lambda eng, guid, sids: filtered.append((guid, list(sids))))
    ap, rc = run(env, {"office_trusted_roles": ["teacher"]})
    assert rc == 0
    assert filtered == [(gpo(fake, name("default-school"))[0], [GROUP_SIDS["role-teacher"]])]
    filtered.clear()
    run(env, {"office_trusted_roles": "all", "schools": ["gsg"]})
    assert filtered == []
    ap, rc = run(env, {"office_trusted_roles": ["teachers"], "schools": ["msg"]})
    out = capsys.readouterr().out
    assert rc == 1 and ap.held_back == [name("msg")] and "unknown role(s) teachers" in out
    assert gpo(fake, name("msg"))[0] is None


def test_switching_off_retires_the_gpo(dc, capsys):
    fake, env, _sysvol, samba, _path = dc
    run(env, {})
    guid, _msg = gpo(fake, name("default-school"))
    capsys.readouterr()
    ap, rc = run(env, {"office_trusted_enabled": False})
    out = capsys.readouterr().out
    assert rc == 0 and ap.retired == [name("default-school")]
    assert samba.ran("gpo", "backup") and samba.ran("gpo", "del")
    assert gpo(fake, name("default-school"))[0] is None
    assert guid.upper() not in (fake.val(fake.get(f"OU=Devices,OU=default-school,{SCHOOLS_OU}"),
                                         "gPLink", "") or "").upper()
    assert "KMS registry values" not in out
    # and off with no GPO: one line, nothing written
    ap, rc = run(env, {"office_trusted_enabled": False})
    assert rc == 0 and "skipped: office_trusted_enabled is not true" in capsys.readouterr().out


def test_dry_run_shows_the_plan_and_writes_nothing(dc, capsys):
    fake, env, _sysvol, samba, _path = dc
    _ap, rc = run(env, {}, dry_run=True)
    out = capsys.readouterr().out
    assert rc == 0 and not samba.loads and gpo(fake, name("default-school"))[0] is None
    assert "location1   \\\\server\\default-school\\" in out
    assert "path = '\\\\\\\\server\\\\default-school\\\\'" in out     # the dry-run load line


def test_loopback_is_needed_and_reported(dc, capsys):
    _fake, env, _sysvol, _samba, _path = dc
    ap = apply.Applier(env, {"packs": [PACK], "schools": ["default-school"]}, dry_run=True)
    rows = ap.loopback_gap(catalog.load_packs())
    assert rows and rows[0][0] == PACK and "15-lockdown-base" in rows[0][2]
    ap = apply.Applier(env, {"packs": [PACK, "15-lockdown-base"], "schools": ["default-school"]},
                       dry_run=True)
    assert ap.loopback_gap(catalog.load_packs()) == []


def test_no_catalog_pack_deletes_registry_values():
    """'**del.' / '**delvals.' in a Registry.pol make the client delete values another GPO
    set (the Site to Zone Assignment List is additive in Microsoft's ADMX for that reason)."""
    for p in catalog.load_packs():
        for e in p.registry:
            assert not str(e["name"]).startswith("**"), (p.id, e)
    assert POLICIES and BASE      # fixtures imported for the fake domain


def test_setup_assistant_defaults_and_re_asks_on_a_typo(monkeypatch, capsys):
    from lmn_gpo import setup
    answers = dict(apply.DEFAULT_ANSWERS)
    replies = iter(["", "access, wordd", "access,word", "teacher", ""])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(replies))
    setup._ask_office_trusted(answers)
    assert answers["office_trusted_enabled"] is True          # Enter = on (the default)
    assert answers["office_trusted_apps"] == ["access", "word"]
    assert answers["office_trusted_roles"] == ["teacher"]
    assert answers["office_trusted_forms"] == ["unc", "letter"]   # Enter = the default
    assert "unknown application(s) wordd" in capsys.readouterr().out
    replies = iter(["", "", "", "unc, drive", "dfs,unc"])
    setup._ask_office_trusted(answers)
    assert answers["office_trusted_forms"] == ["unc", "dfs"]
    assert "unknown form(s) drive" in capsys.readouterr().out
    replies = iter(["n"])
    setup._ask_office_trusted(answers)
    assert answers["office_trusted_enabled"] is False


@pytest.mark.parametrize("have,roles,held", [
    ({"AU"}, "all", False),                                     # unchanged
    ({"AU"}, ["teacher"], False),                               # narrowing: apply removes AU
    ({GROUP_SIDS["role-teacher"]}, ["teacher", "student"], False),   # widening as configured
    ({GROUP_SIDS["role-teacher"]}, ["student"], True),          # teachers would stay in
    ({GROUP_SIDS["role-teacher"]}, "all", True),                # would stay teacher-only
])
def test_a_changed_role_filter_on_an_existing_gpo_is_held_back(dc, capsys, monkeypatch,
                                                                 have, roles, held):
    from lmn_gpo import ad
    fake, env, _sysvol, samba, _path = dc
    monkeypatch.setattr(GpoEngine, "set_exclusive_filter", lambda eng, guid, sids: None)
    run(env, {})
    loads = len(samba.loads)
    monkeypatch.setattr(GpoEngine, "apply_trustees", lambda eng, guid: set(have))
    monkeypatch.setattr(ad, "sddl_trustee", lambda sid: sid)
    capsys.readouterr()
    ap, rc = run(env, {"office_trusted_roles": roles, "office_trusted_apps": ["access", "word"]})
    out = capsys.readouterr().out
    if held:
        assert rc == 1 and ap.held_back == [name("default-school")], out
        assert "does not match office_trusted_roles" in out and "lmn-gpo remove --school " \
            "default-school --pack 21-office-trusted-schule --yes" in out
        assert len(samba.loads) == loads
    else:
        assert rc == 0 and not ap.held_back, out
        assert len(samba.loads) == loads + 1          # word added: written



# --------------------------------------------------------------------------- #
# the DFS target (linuxmuster-fileserver: msdfs proxy on the DC's school share)
# --------------------------------------------------------------------------- #
def test_proxy_root_and_dfs_twins():
    assert officetrust.proxy_root("//fs.dev.lmschule.de/default-school") == \
        "\\\\fs.dev.lmschule.de\\default-school\\"
    assert officetrust.proxy_root(r"\fs\share") == "\\\\fs\\share\\"
    assert officetrust.proxy_root("") == officetrust.proxy_root("//fs") == ""
    proxies = {"default-school": "//fs.dev.lmschule.de/default-school"}
    src = sources() + [officetrust.DriveSource("V", r"\\verwaltung\verwaltung", "drives.yaml")]
    twins = officetrust.dfs_sources(src, ["SERVER", "server.dev.lmschule.de", "server"],
                                    lambda share: proxies.get(share, ""))
    assert [(t.letter, t.path, t.form) for t in twins] == [
        ("H", "\\\\fs.dev.lmschule.de\\default-school\\", "dfs"),
        ("K", "\\\\fs.dev.lmschule.de\\default-school\\program", "dfs"),
        ("P", "\\\\fs.dev.lmschule.de\\default-school\\share\\projects", "dfs"),
        ("S", "\\\\fs.dev.lmschule.de\\default-school\\students", "dfs"),
        ("T", "\\\\fs.dev.lmschule.de\\default-school\\share", "dfs"),
        ("R", "\\\\fs.dev.lmschule.de\\default-school\\iso", "dfs")]
    assert twins[0].origin == "homeDirectory (msdfs proxy)"


def test_dfs_twins_merge_and_the_forms_pick_them():
    proxies = {"default-school": "//fs.dev.lmschule.de/default-school"}
    src = sources()
    src += officetrust.dfs_sources(src, ["server"], lambda share: proxies.get(share, ""))
    p = officetrust.plan(src, officetrust.FORMS)
    assert [(loc.kind, loc.path) for loc in p.locations][:2] == [
        ("unc", "\\\\server\\default-school\\"),
        ("dfs", "\\\\fs.dev.lmschule.de\\default-school\\")]
    assert len(p.locations) == 8 and p.locations[1].letters == ["H", "K", "P", "R", "S", "T"]
    assert [loc.kind for loc in officetrust.plan(src, ("unc", "letter")).locations].count("dfs") == 0
    assert [loc.kind for loc in officetrust.plan(src).locations].count("dfs") == 0   # default
    assert [loc.kind for loc in officetrust.plan(src, ("dfs",)).locations] == ["dfs"]
    # a form that is not written never swallows a path of a written one
    S = officetrust.DriveSource
    mixed = [S("T", r"\\fs\school\share", "drives.yaml", "unc"), S("H", r"\\fs\school", "h", "dfs")]
    assert [loc.path for loc in officetrust.plan(mixed, ("unc",)).locations] == \
        ["\\\\fs\\school\\share\\"]


def test_apply_reads_the_msdfs_proxy_of_the_school_share(dc, monkeypatch):
    fake, env, _sysvol, samba, _path = dc
    asked = []

    def proxy(self, share):
        asked.append(share)
        return "//fs.dev.lmschule.de/default-school" if share == "default-school" else ""
    monkeypatch.setattr(apply.Applier, "_msdfs_proxy", proxy)
    _ap, rc = run(env, {"office_trusted_forms": ["unc", "letter", "dfs"]})
    locs = locations(samba, gpo(fake, name("default-school"))[0])
    assert rc == 0 and locs[:2] == ["\\\\server\\default-school\\",
                                    "\\\\fs.dev.lmschule.de\\default-school\\"]
    assert len(locs) == 8 and set(asked) == {"default-school"}
    # without the dfs form (the default since the lab measurement) nothing is asked and
    # nothing is written for it - an upgraded site.yaml without the key included
    asked.clear()
    _ap, rc = run(env, {})
    assert rc == 0 and not asked
    assert "\\\\fs.dev.lmschule.de\\default-school\\" not in \
        locations(samba, gpo(fake, name("default-school"))[0])
