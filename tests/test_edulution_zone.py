"""Pack 22-edulution-trusted-schule: the school's edulution website in the Trusted sites zone.

On by default but only with a host (never guessed), per-school override, https:// only,
teacher notebooks included, and next to 12-proxy-zone-schule in the same ZoneMapKey
without either GPO deleting the other's value (docs/RESEARCH.md section 10).
"""
from __future__ import annotations

import pytest

from conftest import POLICIES, SCHOOLS_OU
from fakesamba import FakeSamba
from lmn_gpo import apply, catalog

PACK = "22-edulution-trusted-schule"
ZONEMAP = r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMapKey"


def name(school, pack=PACK, letter="C"):
    return f"LMN-{letter}-{school}-{pack}"


@pytest.fixture
def dc(domain, tmp_path, monkeypatch):
    fake, env, sysvol = domain
    samba = FakeSamba(fake, sysvol).install(monkeypatch)
    monkeypatch.setattr(apply, "RETIRE_BACKUP_DIR", str(tmp_path / "backups"))
    return fake, env, sysvol, samba


def run(env, answers, packs=(PACK,), schools=("default-school",)):
    ap = apply.Applier(env, {"packs": list(packs), "schools": list(schools), **answers})
    rc = ap.run(catalog.load_packs())
    return ap, rc


def gpo(fake, display):
    for m in fake.search(base=POLICIES, scope="one", expr="(objectClass=groupPolicyContainer)"):
        if fake.val(m, "displayName") == display:
            return fake.val(m, "cn")
    return None


def test_pack_shape_and_defaults():
    pack = {p.id: p for p in catalog.load_packs()}[PACK]
    assert pack.scope == "school" and pack.requires == "edulution_trusted"
    assert pack.type_letter == "C" and not pack.has_user
    # teacher notebooks get it too: no exclusion copied from 12-proxy-zone-schule
    assert not pack.filter_deny and not pack.filter_deny_read and not pack.filter_apply
    assert [(e["key"], e["name"], e["type"], e["data"]) for e in pack.registry] == \
        [(ZONEMAP, "https://@edulution-host", "sz", "2")]
    assert apply.DEFAULT_ANSWERS["edulution_trusted_enabled"] is True
    assert apply.DEFAULT_ANSWERS["edulution_host"] == ""


def test_without_a_host_it_is_skipped_and_nothing_is_guessed(dc, capsys):
    fake, env, _sysvol, samba = dc
    ap, rc = run(env, {})
    out = capsys.readouterr().out
    assert rc == 0 and ap.skipped == [name("default-school")]
    assert "skipped: no edulution_host (or edulution_host_by_school[default-school])" in out
    assert not samba.loads and gpo(fake, name("default-school")) is None


def test_host_is_mapped_https_only_to_zone_2(dc):
    fake, env, _sysvol, samba = dc
    _ap, rc = run(env, {"edulution_host": "https://Edulution.Dev.LMSchule.de/"})
    guid = gpo(fake, name("default-school"))
    assert rc == 0 and guid
    load = samba.loads[-1]
    assert load["replace"] is True            # its own Registry.pol only, see registry_replace
    assert load["entries"] == [{"keyname": ZONEMAP, "valuename": "https://edulution.dev.lmschule.de",
                                "class": "MACHINE", "type": "REG_SZ", "data": "2"}]
    assert samba.pol(guid, "Machine") == {
        (ZONEMAP.lower(), "https://edulution.dev.lmschule.de"): (1, "2")}
    devices = f"OU=Devices,OU=default-school,{SCHOOLS_OU}"
    assert guid.upper() in fake.val(fake.get(devices), "gPLink").upper()
    assert not samba.ran("dsacl")             # no deny ACE: teacher notebooks included


def test_per_school_override(dc):
    fake, env, _sysvol, samba = dc
    _ap, rc = run(env, {"edulution_host": "edu.dev.lmschule.de",
                        "edulution_host_by_school": {"msg": "edu.msg.example.org"}},
                  schools=("default-school", "msg"))
    assert rc == 0
    names = {s: list(samba.pol(gpo(fake, name(s)), "Machine")) for s in ("default-school", "msg")}
    assert names["default-school"] == [(ZONEMAP.lower(), "https://edu.dev.lmschule.de")]
    assert names["msg"] == [(ZONEMAP.lower(), "https://edu.msg.example.org")]


@pytest.mark.parametrize("bad", ["edu.example.org/edulution", "*.example.org",
                                 "edu.example.org:8443", "edu example.org"])
def test_an_invalid_host_holds_the_pack_back(dc, capsys, bad):
    fake, env, _sysvol, samba = dc
    ap, rc = run(env, {"edulution_host": bad})
    out = capsys.readouterr().out
    assert rc == 1 and ap.held_back == [name("default-school")], out
    assert "is not a host name" in out and not samba.loads
    assert apply.site_host(bad) == ("", apply.site_host(bad)[1]) and apply.site_host(bad)[1]


def test_site_host_normalises():
    assert apply.site_host(" https://EDU.example.org/ ") == ("edu.example.org", "")
    assert apply.site_host("http://edu.example.org") == ("edu.example.org", "")
    assert apply.site_host("10.0.0.5") == ("10.0.0.5", "")
    assert apply.site_host("") == ("", "")


def test_switching_off_and_removing_the_host_retire_the_gpo(dc):
    fake, env, _sysvol, _samba = dc
    run(env, {"edulution_host": "edu.dev.lmschule.de"})
    assert gpo(fake, name("default-school"))
    ap, rc = run(env, {"edulution_host": "edu.dev.lmschule.de", "edulution_trusted_enabled": False})
    assert rc == 0 and ap.retired == [name("default-school")]
    run(env, {"edulution_host": "edu.dev.lmschule.de"})
    ap, rc = run(env, {"edulution_host": ""})
    assert rc == 0 and ap.retired == [name("default-school")]


def test_coexists_with_the_proxy_zone_entry_in_the_same_key(dc):
    """12-proxy-zone-schule (proxy host -> 1) and this pack (edulution -> 2) write the same
    ZoneMapKey from two GPOs. On the client the registry extension applies both GPOs'
    values into that key; only a '**delvals.' or '**del.<name>' entry in one Registry.pol
    would delete the other's value - Microsoft's ADMX list is additive="true" for that
    reason. Neither GPO may carry one. This pack loads with --replace, which rewrites ITS
    OWN Registry.pol (Samba replace_s), so a changed host does not linger - the proxy GPO's
    file is never touched."""
    fake, env, _sysvol, samba = dc
    answers = {"edulution_host": "edu.dev.lmschule.de", "proxy_enabled": True,
               "proxy_host": "proxy.dev.lmschule.de", "teachernb": "skip"}
    _ap, rc = run(env, answers, packs=("12-proxy-zone-schule", PACK))
    assert rc == 0
    proxy = gpo(fake, name("default-school", "12-proxy-zone-schule"))
    edu = gpo(fake, name("default-school"))
    assert proxy and edu and proxy != edu
    by_guid = {ld["guid"]: ld for ld in samba.loads}
    assert by_guid[proxy]["replace"] is False and by_guid[edu]["replace"] is True
    for guid in (proxy, edu):
        for e in by_guid[guid]["entries"]:
            assert not e["valuename"].startswith("**"), e
    pols = {g: samba.pol(g, "Machine") for g in (proxy, edu)}
    assert pols[proxy] == {(ZONEMAP.lower(), "proxy.dev.lmschule.de"): (1, "1")}
    assert pols[edu] == {(ZONEMAP.lower(), "https://edu.dev.lmschule.de"): (1, "2")}
    # what the client ends up with: the union of both GPOs' values in one key
    client = {}
    for g in (proxy, edu):
        client.update(pols[g])
    assert client == {(ZONEMAP.lower(), "proxy.dev.lmschule.de"): (1, "1"),
                      (ZONEMAP.lower(), "https://edu.dev.lmschule.de"): (1, "2")}
    # a second run changes neither (idempotent), and re-running one pack leaves the other
    loads = len(samba.loads)
    run(env, answers, packs=("12-proxy-zone-schule", PACK))
    assert len(samba.loads) == loads
    run(env, {**answers, "edulution_host": "edu2.dev.lmschule.de"}, packs=(PACK,))
    assert samba.pol(proxy, "Machine") == pols[proxy]
    assert samba.pol(edu, "Machine") == {(ZONEMAP.lower(), "https://edu2.dev.lmschule.de"): (1, "2")}


def test_setup_assistant_asks_the_host(monkeypatch, capsys):
    from lmn_gpo import setup
    answers = dict(apply.DEFAULT_ANSWERS)
    replies = iter(["", "edu.example.org/x", "https://Edu.example.org/"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(replies))
    setup._ask_edulution(answers)
    assert answers["edulution_trusted_enabled"] is True
    assert answers["edulution_host"] == "edu.example.org"
    assert "is not a host name" in capsys.readouterr().out
    replies = iter(["", ""])                                  # keep on, no host
    answers["edulution_host"] = ""
    setup._ask_edulution(answers)
    assert answers["edulution_host"] == "" and "skipped until one is set" in capsys.readouterr().out
