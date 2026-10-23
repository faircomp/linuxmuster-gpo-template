"""`lmn-gpo doctor`, section Drive maps, on the fake domain after a real (fake) apply."""
from __future__ import annotations

import pytest

from conftest import BASE, GROUP_SIDS, SCHOOLS_OU, gplink_value, sid
from lmn_gpo import apply, catalog, drivescheck, ui
from test_apply_drives import NAME, dc, ours, run  # noqa: F401  (dc is a fixture)


@pytest.fixture(autouse=True)
def plain(monkeypatch):
    ui.set_color(False)
    monkeypatch.setattr(drivescheck, "_server_shares",
                        lambda: {"default-school", "msg", "gsg", "gym", "netlogon", "sysvol"})


def doctor(env, answers, capsys) -> str:
    capsys.readouterr()
    ap = apply.Applier(env, answers, dry_run=True)
    drivescheck.run(env, ap.answers, ap, catalog.load_packs())
    return capsys.readouterr().out


def lines(out, tag):
    return [x for x in out.splitlines() if x.strip().startswith(tag)]


def test_not_enabled_is_one_ok_line(dc, capsys):
    _fake, env, _sysvol, _samba, path = dc
    out = doctor(env, {"drives_file": path}, capsys)
    assert "[ok] not enabled" in out and "it is not used" in out
    assert not lines(out, "[warn]")


def test_healthy_site(dc, capsys):
    fake, env, _sysvol, _samba, path = dc
    answers = {"drives_enabled": True, "drives_file": path}
    run(env, answers)
    out = doctor(env, answers, capsys)
    assert not lines(out, "[warn]"), out
    for want in ("schema ok, 5 entries", "groups: all 6 resolve", "(enforced)",
                 "deployed Drives.xml matches drives.yaml",
                 "gsg: LMN-U-GLOBAL-20-drives is the last GPO with drive maps",
                 "needs no loopback", "sophomorix:school:gym: K: P: S: T: R:",
                 "share 'msg' exists on this server", r"\\verwaltung\verwaltung: other server",
                 "sets no permissions"):
        assert want in out, (want, out)
    # the sophomorix template's S: SID does not exist in this domain
    assert "S: of default-school, gsg, gym, msg targets S-1-5-21-453622583-2410402998-3896360232-1110" in out


def test_before_the_first_apply_the_order_is_simulated(dc, capsys):
    _fake, env, _sysvol, _samba, path = dc
    out = doctor(env, {"drives_enabled": True, "drives_file": path}, capsys)
    assert "does not exist yet" in out and "simulated" in out
    assert "msg: LMN-U-GLOBAL-20-drives is the last GPO" in out


def test_enforcement_lost_is_reported_with_the_fix(dc, capsys):
    fake, env, _sysvol, _samba, path = dc
    answers = {"drives_enabled": True, "drives_file": path}
    run(env, answers)
    guid, _ = ours(fake)
    fake.get(SCHOOLS_OU).set("gPLink", gplink_value((guid, 0)))
    out = doctor(env, answers, capsys)
    warns = "\n".join(lines(out, "[warn]"))
    assert "link at OU=SCHOOLS" in warns and "not enforced" in warns
    assert "sophomorix:school:gsg runs AFTER LMN-U-GLOBAL-20-drives" in warns
    assert "it maps K: P: R: S: T:" in warns


def test_sid_drift_unknown_group_and_file_drift(dc, capsys):
    fake, env, _sysvol, _samba, path = dc
    answers = {"drives_enabled": True, "drives_file": path}
    run(env, answers)
    fake.get(f"CN=verwaltung,OU=Groups,OU=GLOBAL,{BASE}").set("objectSid", sid(1999))
    out = doctor(env, answers, capsys)
    assert f"group 'verwaltung' now has SID {sid(1999)}" in out
    assert GROUP_SIDS["verwaltung"] in out
    assert "differs from what apply would write now" in out
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("  - {letter: W, path: '\\\\s\\w', groups: [gym-teacher]}\n")
    out = doctor(env, answers, capsys)
    assert "group 'gym-teacher' not found (did you mean gym-teachers?)" in out
    assert "leaves the existing GPO untouched" in out


def test_explicit_pack_list_without_20_drives_and_h_twice(dc, capsys):
    _fake, env, _sysvol, _samba, path = dc
    out = doctor(env, {"drives_enabled": True, "drives_file": path, "home_drive_enabled": True,
                       "packs": ["15-lockdown-base"]}, capsys)
    assert "explicit 'packs:' list without 20-drives" in out
    assert "H: comes twice" in out


def test_invalid_file_is_listed(dc, capsys):
    _fake, env, _sysvol, _samba, path = dc
    open(path, "w", encoding="utf-8").write("version: 1\nlinuxmuster_defaults: {off: all}\n")
    out = doctor(env, {"drives_enabled": True, "drives_file": path}, capsys)
    assert "use 'remove'" in out and "apply skips the pack" in out


def test_gpo_exists_but_disabled(dc, capsys):
    fake, env, _sysvol, _samba, path = dc
    run(env, {"drives_enabled": True, "drives_file": path})
    out = doctor(env, {"drives_file": path}, capsys)
    assert "exists although drives_enabled is not true" in out
