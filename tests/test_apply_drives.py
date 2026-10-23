"""apply for pack 20-drives, end to end on the fake domain (fake samba-tool, fake sam.ldb):
opt-in, fail closed, enforced link set and restored in place, idempotent, retirement."""
from __future__ import annotations

import hashlib
import os

import pytest

from conftest import BASE, GROUP_SIDS, POLICIES, SCHOOLS_OU, gplink_value, sid
from fakesamba import FakeSamba
from lmn_gpo import apply, catalog, drivesconf, gplink
from lmn_gpo.drives import DRIVES_REL, render_managed

NAME = "LMN-U-GLOBAL-20-drives"
LOCKDOWN = "{15150000-0000-0000-0000-000000000001}"

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


@pytest.fixture
def dc(domain, tmp_path, monkeypatch):
    fake, env, sysvol = domain
    samba = FakeSamba(fake, sysvol).install(monkeypatch)
    monkeypatch.setattr(apply, "RETIRE_BACKUP_DIR", str(tmp_path / "backups"))
    # another global pack is already linked at OU=SCHOOLS (lmn-gpo before this release)
    fake.get(SCHOOLS_OU).set("gPLink", gplink_value((LOCKDOWN, 0)))
    fake.add(f"CN={LOCKDOWN},{POLICIES}", objectClass="groupPolicyContainer", cn=LOCKDOWN,
             displayName="LMN-U-GLOBAL-15-lockdown-student", flags="0", versionNumber="65536",
             gPCUserExtensionNames="")
    path = tmp_path / "drives.yaml"
    path.write_text(KEVIN, encoding="utf-8")
    return fake, env, sysvol, samba, str(path)


def run(env, answers, packs=None, dry_run=False):
    ap = apply.Applier(env, {"packs": ["20-drives"], **answers}, dry_run=dry_run)
    rc = ap.run(packs or catalog.load_packs())
    return ap, rc


def ours(fake):
    msgs = [m for m in fake.search(base=POLICIES, scope="one",
                                   expr="(objectClass=groupPolicyContainer)")
            if fake.val(m, "displayName") == NAME]
    return (fake.val(msgs[0], "cn"), msgs[0]) if msgs else (None, None)


def drives_file(sysvol, guid):
    return os.path.join(sysvol, guid, DRIVES_REL)


def mutations(samba):
    """samba-tool calls that change something (every apply ends with sysvolreset+aclcheck)."""
    return [a for a in samba.log if a[1:3] not in (["ntacl", "sysvolreset"], ["gpo", "aclcheck"])]


def md5(path):
    return hashlib.md5(open(path, "rb").read()).hexdigest()


def test_pack_is_a_user_gpo_linked_enforced_and_opt_in():
    pack = {p.id: p for p in catalog.load_packs()}["20-drives"]
    assert apply.gpo_name(pack, None) == NAME
    assert pack.has_user and not pack.has_machine and pack.type_letter == "U"
    assert pack.link_enforced and pack.drives_source == "drives.yaml"
    assert pack.requires == "drives" and pack.scope == "global"
    assert not apply.Applier.needs_loopback(pack)
    assert apply.DEFAULT_ANSWERS["drives_enabled"] is False
    # no other pack is enforced or reads an admin file
    assert [p.id for p in catalog.load_packs() if p.link_enforced or p.drives_source] == \
        ["20-drives"]


def test_without_drives_enabled_nothing_happens(dc, capsys):
    fake, env, _sysvol, samba, path = dc
    ap, rc = run(env, {"drives_file": path})
    assert rc == 0 and ours(fake)[0] is None
    assert not mutations(samba), samba.log
    out = capsys.readouterr().out
    assert f"▸ {NAME}  skipped: drives_enabled is not true" in out
    # the whole catalog (an upgraded 7.3.5 site, no drives keys at all) - not even a read
    ap = apply.Applier(env, {}, dry_run=True)
    pack = {p.id: p for p in catalog.load_packs()}["20-drives"]
    assert not ap._applicable(pack, None) and ap._drives_loaded is False


def test_first_apply_writes_links_enforced_and_checks_the_order(dc, capsys):
    fake, env, sysvol, samba, path = dc
    ap, rc = run(env, {"drives_enabled": True, "drives_file": path})
    out = capsys.readouterr().out
    assert rc == 0, out
    guid, msg = ours(fake)
    assert guid and ap.results == [{"pack": "20-drives", "gpo": NAME, "guid": guid,
                                    "school": "GLOBAL"}]
    # exactly the rendered plan, user CSE, user version 1
    plan = ap.drives_plan()
    assert open(drives_file(sysvol, guid), encoding="utf-8", newline="").read() == \
        render_managed(plan.items, guid)
    assert "5794DAFD" in fake.val(msg, "gPCUserExtensionNames").upper()
    assert int(fake.val(msg, "versionNumber")) == 1 << 16
    # linked FIRST at OU=SCHOOLS, enforced, the old link untouched behind it
    assert fake.val(fake.get(SCHOOLS_OU), "gPLink") == gplink_value((guid, 2), (LOCKDOWN, 0))
    assert samba.ran("gpo", "setlink") == [["samba-tool", "gpo", "setlink", SCHOOLS_OU, guid,
                                            "--enforce"]]
    assert "linuxmuster default letters removed: K P R S T" in out
    assert "M:" in out and r"\\server\msg" in out and "msg-teachers" in out
    for school in ("default-school", "msg", "gsg", "gym"):
        assert f"order: {school}: {NAME} is the last GPO with drive maps" in out, out
    assert "\u26a0 order" not in out


def test_second_apply_changes_nothing(dc, capsys):
    fake, env, sysvol, samba, path = dc
    run(env, {"drives_enabled": True, "drives_file": path})
    guid, msg = ours(fake)
    before = (md5(drives_file(sysvol, guid)), fake.val(msg, "versionNumber"),
              fake.val(fake.get(SCHOOLS_OU), "gPLink"))
    capsys.readouterr()
    samba.log.clear()
    _ap, rc = run(env, {"drives_enabled": True, "drives_file": path})
    out = capsys.readouterr().out
    assert rc == 0
    assert "Drives.xml unchanged — skipped" in out and "Link present" in out
    assert (md5(drives_file(sysvol, guid)), fake.val(ours(fake)[1], "versionNumber"),
            fake.val(fake.get(SCHOOLS_OU), "gPLink")) == before
    assert not samba.ran("gpo", "create") and not samba.ran("gpo", "setlink")


def test_enforcement_switched_off_in_gpmc_is_restored_in_place(dc, capsys):
    fake, env, sysvol, samba, path = dc
    run(env, {"drives_enabled": True, "drives_file": path})
    guid, _ = ours(fake)
    # GPMC: link order changed AND enforcement off AND link disabled
    fake.get(SCHOOLS_OU).set("gPLink", gplink_value((LOCKDOWN, 0), (guid, 1)))
    _ap, rc = run(env, {"drives_enabled": True, "drives_file": path}, dry_run=True)
    out = capsys.readouterr().out
    assert "[dry-run] link options" in out and "DISABLED -> enforced" in out
    assert fake.val(fake.get(SCHOOLS_OU), "gPLink") == gplink_value((LOCKDOWN, 0), (guid, 1))
    _ap, rc = run(env, {"drives_enabled": True, "drives_file": path})
    assert rc == 0
    assert fake.val(fake.get(SCHOOLS_OU), "gPLink") == gplink_value((LOCKDOWN, 0), (guid, 2))


def test_unknown_group_on_an_existing_gpo_leaves_it_untouched(dc, capsys):
    fake, env, sysvol, samba, path = dc
    run(env, {"drives_enabled": True, "drives_file": path})
    guid, msg = ours(fake)
    before = (md5(drives_file(sysvol, guid)), fake.val(msg, "versionNumber"))
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("  - {letter: W, path: '\\\\s\\w', groups: [gibtsnicht]}\n")
    capsys.readouterr()
    ap, rc = run(env, {"drives_enabled": True, "drives_file": path})
    out = capsys.readouterr().out
    assert rc == 0, "held back is a notice, not a failure (7.3.1 rule)"
    assert ap.held_back == [NAME]
    assert "held back: 1 drives.yaml entry cannot be resolved" in out
    assert "existing GPO left untouched" in out and "lmn-gpo remove --pack 20-drives" in out
    assert "gibtsnicht" in out
    assert (md5(drives_file(sysvol, guid)), fake.val(ours(fake)[1], "versionNumber")) == before


def test_unknown_group_on_a_new_gpo_writes_the_rest(dc, capsys):
    fake, env, sysvol, samba, path = dc
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("  - {letter: W, path: '\\\\s\\w', groups: [gibtsnicht]}\n")
    ap, rc = run(env, {"drives_enabled": True, "drives_file": path})
    out = capsys.readouterr().out
    assert rc == 0 and not ap.held_back
    guid, _ = ours(fake)
    text = open(drives_file(sysvol, guid), encoding="utf-8").read()
    assert 'letter="V"' in text and 'letter="W"' not in text
    assert "held back (entry 6 (W:))" in out and "the GPO is new" in out


def test_nothing_resolvable_creates_no_gpo(dc, capsys):
    fake, env, _sysvol, samba, path = dc
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("version: 1\ndrives:\n  - {letter: W, path: '\\\\s\\w', groups: [nope]}\n")
    ap, rc = run(env, {"drives_enabled": True, "drives_file": path})
    assert rc == 0 and ap.held_back == [NAME] and ours(fake)[0] is None
    assert "GPO not created" in capsys.readouterr().out


@pytest.mark.parametrize("content", [None, "version: 1\ndrives: [{letter: H, path: '\\\\s\\h'}]\n"])
def test_missing_or_invalid_file_keeps_the_gpo_and_fails_the_run(dc, capsys, content):
    fake, env, sysvol, samba, path = dc
    run(env, {"drives_enabled": True, "drives_file": path})
    guid, _ = ours(fake)
    before = md5(drives_file(sysvol, guid))
    if content is None:
        os.remove(path)
    else:
        open(path, "w", encoding="utf-8").write(content)
    capsys.readouterr()
    samba.log.clear()
    ap, rc = run(env, {"drives_enabled": True, "drives_file": path})
    out = capsys.readouterr().out
    assert rc == 1, "the admin must notice"
    assert ours(fake)[0] == guid and md5(drives_file(sysvol, guid)) == before
    assert not samba.ran("gpo", "del") and not samba.ran("gpo", "dellink")
    assert "GPO left untouched (not deleted)" in out
    assert ("file not found" if content is None else "only 'home: true' may use it") in out
    assert any("20-drives" in w for w in ap.warnings)


def test_missing_file_without_gpo_is_skipped_with_the_reason(dc, capsys):
    _fake, env, _sysvol, samba, path = dc
    ap, rc = run(env, {"drives_enabled": True, "drives_file": path + ".nope"})
    out = capsys.readouterr().out
    assert rc == 1 and not mutations(samba)
    assert f"▸ {NAME}  skipped:" in out and "file not found" in out


def test_switching_it_off_retires_the_gpo_after_a_backup(dc, capsys, tmp_path):
    fake, env, sysvol, samba, path = dc
    run(env, {"drives_enabled": True, "drives_file": path})
    guid, _ = ours(fake)
    ap, rc = run(env, {"drives_enabled": False, "drives_file": path})
    assert rc == 0 and ap.retired == [NAME]
    assert ours(fake)[0] is None
    assert fake.val(fake.get(SCHOOLS_OU), "gPLink") == gplink_value((LOCKDOWN, 0))
    assert samba.ran("gpo", "backup") and os.listdir(tmp_path / "backups")


def test_dry_run_on_a_fresh_site_writes_nothing_and_simulates_the_order(dc, capsys):
    fake, env, _sysvol, samba, path = dc
    _ap, rc = run(env, {"drives_enabled": True, "drives_file": path}, dry_run=True)
    out = capsys.readouterr().out
    assert rc == 0 and ours(fake)[0] is None
    assert not mutations(samba)
    assert "[dry-run] samba-tool gpo create LMN-U-GLOBAL-20-drives" in out
    assert "--enforce" in out and "[dry-run] Drives.xml" in out
    assert "order: gsg: LMN-U-GLOBAL-20-drives is the last GPO with drive maps" in out


def test_remove_all_follows_letters_moved_in_the_webui(dc):
    fake, env, sysvol, samba, path = dc
    school = [m for m in fake.search(base=POLICIES, scope="one",
                                     expr="(displayName=sophomorix:school:gym)")][0]
    f = os.path.join(sysvol, fake.val(school, "cn"), DRIVES_REL)
    text = open(f, encoding="utf-8").read().replace('letter="R"/>', 'letter="Q"/>')
    open(f, "w", encoding="utf-8").write(text)
    ap = apply.Applier(env, {"drives_enabled": True, "drives_file": path}, dry_run=True)
    plan = ap.drives_plan()
    assert plan.remove_letters == ["K", "P", "Q", "R", "S", "T"]
    assert "sophomorix:school:gym" in plan.remove_source


def test_group_recreated_with_a_new_sid_is_picked_up_by_the_next_apply(dc):
    fake, env, sysvol, samba, path = dc
    run(env, {"drives_enabled": True, "drives_file": path})
    guid, _ = ours(fake)
    fake.get(f"CN=verwaltung,OU=Groups,OU=GLOBAL,{BASE}").set("objectSid", sid(1999))
    run(env, {"drives_enabled": True, "drives_file": path})
    text = open(drives_file(sysvol, guid), encoding="utf-8").read()
    assert sid(1999) in text and GROUP_SIDS["verwaltung"] not in text


def test_the_example_file_is_refused_until_edited(dc, capsys):
    fake, env, _sysvol, samba, _path = dc
    from conftest import ROOT
    example = os.path.join(ROOT, "examples", "drives.yaml.example")
    ap, rc = run(env, {"drives_enabled": True, "drives_file": example})
    out = capsys.readouterr().out
    assert rc == 1 and ours(fake)[0] is None and not mutations(samba)
    assert "still the shipped EXAMPLE" in out


def test_drives_default_path():
    ap = apply.Applier(None, {})
    assert ap.drives_file() == drivesconf.DEFAULT_FILE == "/etc/linuxmuster/lmn-gpo/drives.yaml"
    assert apply.Applier(None, {"drives_file": " /x.yaml "}).drives_file() == "/x.yaml"


def test_link_order_is_respected_by_the_planned_check(dc):
    """gplink.set_options keeps the position - the order check sees the same layout."""
    fake, env, _sysvol, _samba, path = dc
    run(env, {"drives_enabled": True, "drives_file": path})
    guid, _ = ours(fake)
    value = fake.val(fake.get(SCHOOLS_OU), "gPLink")
    assert [lk.guid for lk in gplink.parse(value)] == [guid, LOCKDOWN]
