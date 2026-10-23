"""Group name -> SID resolution and the apply plan (held back, never widened)."""
from __future__ import annotations

from conftest import BASE, GROUP_SIDS, sid
from lmn_gpo import drivesconf


class DictResolver:
    """Resolver over a dict name -> sid; anything else is missing."""

    def __init__(self, sids=None):
        self.sids = dict(GROUP_SIDS if sids is None else sids)
        self.calls = []

    def group(self, token, computer=False):
        self.calls.append((token, computer))
        name = token.lstrip("@") if token.startswith("@role-") else token
        if name in self.sids:
            return drivesconf.Resolved(token, "ok", name, self.sids[name])
        return drivesconf.Resolved(token, "missing", note="group not found")


def cfg(drives=(), remove=(), for_groups=()):
    return drivesconf.parse({"version": 1, "drives": list(drives),
                             "linuxmuster_defaults": {"remove": remove if remove == "all"
                                                      else list(remove),
                                                      "for_groups": list(for_groups)}})


def plan(c, resolver=None, **kw):
    kw.setdefault("netbios", "DEV")
    kw.setdefault("server", "server")
    return drivesconf.plan(c, resolver or DictResolver(), **kw)


# --------------------------------------------------------------------------- #
# AdResolver against the fake directory
# --------------------------------------------------------------------------- #
def test_ad_resolver_by_samaccountname(domain):
    fake, _env, _ = domain
    r = drivesconf.AdResolver(fake)
    res = r.group("gsg-teachers")
    assert (res.status, res.name, res.sid) == ("ok", "gsg-teachers", GROUP_SIDS["gsg-teachers"])
    # case-insensitive like AD, canonical name comes back from the directory
    assert r.group("GSG-Teachers").name == "gsg-teachers"


def test_ad_resolver_missing_suggests_close_names(domain):
    fake, _env, _ = domain
    res = drivesconf.AdResolver(fake).group("gym-teacher")
    assert res.status == "missing" and "did you mean gym-teachers" in res.note, res


def test_ad_resolver_role_tokens_and_unknown_tokens(domain):
    fake, _env, _ = domain
    r = drivesconf.AdResolver(fake)
    assert r.group("@role-teacher").sid == GROUP_SIDS["role-teacher"]
    res = r.group("@teachernb")
    assert res.status == "missing" and "not a known token" in res.note


def test_ad_resolver_sids(domain):
    fake, _env, _ = domain
    r = drivesconf.AdResolver(fake)
    res = r.group(GROUP_SIDS["verwaltung"])
    assert res.ok and res.name == "verwaltung"
    assert r.group("*" + GROUP_SIDS["verwaltung"].lower()).sid == GROUP_SIDS["verwaltung"]
    # the sophomorix template's S: SID comes from another domain
    assert not r.group("S-1-5-21-453622583-2410402998-3896360232-1110").ok
    wk = r.group("S-1-5-11")
    assert wk.ok and wk.name == "" and wk.note == "well-known SID"


def test_ad_resolver_refuses_distribution_groups(domain):
    fake, _env, _ = domain
    res = drivesconf.AdResolver(fake).group("newsletter")
    assert res.status == "missing" and "distribution group" in res.note


def test_ad_resolver_ambiguous_and_escaping(domain):
    fake, _env, _ = domain
    fake.add(f"CN=dup,OU=a,{BASE}", objectClass="group", sAMAccountName="dup",
             objectSid=sid(1700), groupType="-2147483646")
    fake.add(f"CN=dup,OU=b,{BASE}", objectClass="group", sAMAccountName="dup",
             objectSid=sid(1701), groupType="-2147483646")
    r = drivesconf.AdResolver(fake)
    assert r.group("dup").status == "ambiguous"
    # '*' must never become a wildcard search
    assert r.group("*teachers").status == "missing"
    assert r.group("gsg-teachers)(cn=*").status == "missing"


def test_ad_resolver_caches(domain):
    fake, _env, _ = domain
    r = drivesconf.AdResolver(fake)
    calls = []
    orig = fake.search
    fake.search = lambda *a, **k: calls.append(1) or orig(*a, **k)
    r.ad = fake
    r.group("verwaltung")
    r.group("verwaltung")
    assert len(calls) == 1


# --------------------------------------------------------------------------- #
# plan(): order, defaults, holding back
# --------------------------------------------------------------------------- #
def test_plan_order_deletes_then_home_then_maps():
    c = cfg(drives=[{"letter": "V", "path": r"\\verwaltung\verwaltung", "groups": ["verwaltung"]},
                    {"letter": "H", "home": True},
                    {"letter": "M", "path": r"\\@server\msg", "groups": ["msg-teachers"]}],
            remove=["T", "K"])
    p = plan(c)
    assert [(i["kind"], i["letter"]) for i in p.items] == [
        ("del", "K"), ("del", "T"), ("home", "H"), ("map", "V"), ("map", "M")]
    assert p.items[4]["path"] == r"\\server\msg"           # @server substituted
    assert p.items[3]["groups"] == [{"name": "DEV\\verwaltung", "sid": GROUP_SIDS["verwaltung"]}]
    assert p.complete and not p.held
    assert [r.status for r in p.rows] == ["ok"] * 4


def test_plan_remove_all_reads_school_letters_but_never_h():
    p = plan(cfg(remove="all"), sopho_letters={"K", "X", "H"}, sopho_source="read from x")
    assert p.remove_letters == ["K", "P", "R", "S", "T", "X"]
    assert p.remove_source == "read from x"
    assert all(i["action"] == "D" and not i["groups"] for i in p.items)


def test_plan_for_groups_target_the_deletes():
    p = plan(cfg(remove=["K"], for_groups=["@role-teacher", "role-staff"]))
    assert p.items[0]["groups"] == [
        {"name": "DEV\\role-teacher", "sid": GROUP_SIDS["role-teacher"]},
        {"name": "DEV\\role-staff", "sid": GROUP_SIDS["role-staff"]}]
    assert p.rows[0].groups == "role-teacher|role-staff"


def test_plan_unknown_for_group_keeps_every_default_drive():
    p = plan(cfg(remove="all", for_groups=["role-teacher", "lehrer"],
                 drives=[{"letter": "M", "path": r"\\s\m", "groups": ["msg-teachers"]}]))
    assert not [i for i in p.items if i["kind"] == "del"], "would delete for EVERYONE"
    assert [i["letter"] for i in p.items] == ["M"]
    held = p.held
    assert len(held) == 1 and held[0].where == "remove" and "'lehrer'" in held[0].note
    assert "default drives stay" in held[0].note and not p.complete


def test_plan_partial_group_list_holds_the_entry_back():
    p = plan(cfg(drives=[{"letter": "M", "path": r"\\s\m", "groups": ["msg-teachers", "lk-mgs"]},
                         {"letter": "G", "path": r"\\s\g", "groups": ["gsg-teachers"]}]))
    assert [i["letter"] for i in p.items] == ["G"]
    assert [(r.where, r.status) for r in p.rows] == [("entry 1 (M:)", "held"),
                                                    ("entry 2 (G:)", "ok")]
    assert "lk-mgs" in p.rows[0].note


def test_plan_unknown_device_group_holds_back():
    p = plan(cfg(drives=[{"letter": "V", "path": r"\\v\v", "groups": ["verwaltung"],
                          "devices": ["d_nope"]}]))
    assert not p.items and p.held[0].where == "entry 1 (V:)"


def test_plan_devices_are_resolved_in_computer_context():
    r = DictResolver()
    plan(cfg(drives=[{"letter": "V", "path": r"\\v\v", "devices": ["d_verwaltung"]}]), r)
    assert ("d_verwaltung", True) in r.calls


def test_plan_same_letter_excludes_every_earlier_written_entry():
    p = plan(cfg(drives=[
        {"letter": "S", "path": r"\\s\msg", "groups": ["msg-teachers"]},
        {"letter": "S", "path": r"\\s\gsg", "groups": ["gsg-teachers"], "devices": ["d_verwaltung"]},
        {"letter": "S", "path": r"\\s\all"}]))
    s = [i for i in p.items if i["letter"] == "S"]
    assert [i["index"] for i in s] == [0, 1, 2]
    assert s[0]["exclude"] == []
    assert s[1]["exclude"] == [{"groups": s[0]["groups"], "devices": []}]
    assert s[2]["exclude"] == [{"groups": s[0]["groups"], "devices": []},
                               {"groups": s[1]["groups"], "devices": s[1]["devices"]}]
    assert "unless an earlier S: entry matches" in p.rows[1].note


def test_plan_held_entry_keeps_the_uid_index_of_later_entries():
    p = plan(cfg(drives=[{"letter": "S", "path": r"\\s\a", "groups": ["nope"]},
                         {"letter": "S", "path": r"\\s\b", "groups": ["teachers"]}]))
    assert [(i["letter"], i["index"], i["exclude"]) for i in p.items] == [("S", 1, [])]


def test_plan_reconnect_and_update():
    p = plan(cfg(drives=[{"letter": "M", "path": r"\\s\m", "reconnect": True},
                         {"letter": "N", "path": r"\\s\n", "action": "update"}]))
    m, n = p.items
    assert (m["action"], m["persistent"], m["remove_policy"]) == ("R", True, True)
    assert (n["action"], n["persistent"], n["remove_policy"]) == ("U", False, False)


def test_plan_lines_are_readable():
    p = plan(cfg(remove=["K"], for_groups=["role-teacher"],
                 drives=[{"letter": "H", "home": True},
                         {"letter": "Y", "path": r"\\@server\gym", "groups": ["gym-teacher"]}]))
    text = "\n".join(p.lines())
    assert "K:" in text and "delete" in text and "role-teacher" in text
    assert "%homeDirectory%" in text and "all users" in text
    assert "held back (entry 2 (Y:))" in text and "gym-teacher" in text


def test_substitute():
    assert drivesconf.substitute(r"\\@server\x", "server") == r"\\server\x"
    assert drivesconf.substitute(r"\\@serverfqdn\x", "server", "server.dev.lmschule.de") \
        == r"\\server.dev.lmschule.de\x"
