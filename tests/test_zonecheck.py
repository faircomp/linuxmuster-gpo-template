"""`lmn-gpo doctor` and `lmn-gpo selftest`: a GPO with site-to-zone values but without the
Internet Explorer Zonemapping extension is named; the selftest checks the extension against
the real samba-tool (here: its steps against the fakes)."""
from __future__ import annotations

import os

from conftest import POLICIES
from fakesamba import FakeSamba, write_pol
from lmn_gpo import regpol, ui, version, zonecheck
from test_zonemap_cse import ANSWERS, EDU, REG_GPMC, REG_SAMBA, ZONE, dc, gpo, run  # noqa: F401


# --------------------------------------------------------------------------- #
# doctor
# --------------------------------------------------------------------------- #
def test_doctor_names_a_gpo_without_the_extension(dc, capsys):
    ui.set_color(False)
    fake, env, sysvol, samba = dc
    assert zonecheck.run(env) == 0
    assert "[ok] no LMN-* GPO carries site-to-zone values" in capsys.readouterr().out
    run(env, ANSWERS)
    run(env, {}, packs=("21-office-trusted-schule",))       # no zone values: not listed
    capsys.readouterr()
    assert zonecheck.run(env) == 0
    out = capsys.readouterr().out
    assert out.count("[ok] LMN-C-default-school-") == 2 and "[warn]" not in out
    assert "21-office-trusted-schule" not in out
    edu, msg = gpo(fake, EDU)
    msg.set("gPCMachineExtensionNames", REG_SAMBA)          # as 7.3.7 left it
    assert (f"LMN-C-default-school-{EDU}", edu, "gPCMachineExtensionNames", False) in \
        zonecheck.rows(env)
    assert zonecheck.run(env) == 1
    out = capsys.readouterr().out
    assert f"[warn] LMN-C-default-school-{EDU} {edu}: has ZoneMapKey values" in out
    assert version.ZONEMAP_CSE in out and "Run 'lmn-gpo apply'" in out
    # glued into another group by a premature registration: still missing
    msg.set("gPCMachineExtensionNames", "[{35378eac-683f-11d2-a89a-00c04fbbcfa2}"
            "{4CFB60C1-FAA6-47F1-89AA-0B18730C9FD3}]")
    assert zonecheck.run(env) == 1
    capsys.readouterr()
    # apply heals it (an extension on top of the glued one), doctor is quiet again
    run(env, ANSWERS)
    assert zonecheck.run(env) == 0 and "[warn]" not in capsys.readouterr().out


def test_doctor_ignores_gpos_that_are_not_ours(dc):
    fake, env, sysvol, samba = dc
    guid = "{AAAAAAAA-0000-0000-0000-000000000001}"
    fake.add(f"CN={guid},{POLICIES}", objectClass="groupPolicyContainer", cn=guid,
             displayName="Some admin GPO", gPCMachineExtensionNames=REG_GPMC, versionNumber="1")
    write_pol(os.path.join(sysvol, guid, "Machine", "Registry.pol"),
              [(regpol.ZONEMAP_KEY, "intranet.example", 1, "1\x00".encode("utf-16-le"))])
    assert regpol.pol_has_zonemap(os.path.join(sysvol, guid), "Machine")   # zone values: yes
    assert zonecheck.rows(env) == []                                      # but not ours


# --------------------------------------------------------------------------- #
# selftest (runs on a real DC in the lab; here its zone-list steps against the fakes)
# --------------------------------------------------------------------------- #
def test_selftest_zone_list_steps(domain, monkeypatch, capsys):
    from lmn_gpo import ad, selftest
    from lmn_gpo import env as envmod
    ui.set_color(False)
    fake, env, sysvol = domain
    samba = FakeSamba(fake, sysvol).install(monkeypatch)
    monkeypatch.setattr(envmod, "detect", lambda: env)
    # the DACL steps need python3-samba (not on the CI runner) and a real sam.ldb
    monkeypatch.setattr(ad, "descriptor_sddl", lambda dn: "", raising=False)
    monkeypatch.setattr(ad, "sddl_trustee", lambda sid: sid)
    selftest.run()
    out = capsys.readouterr().out
    # (other steps need a real sysvol/DACL and fail on the fakes; not what this test checks)
    for want in ("[ok] IE Zonemapping CSE registered as its own group, Registry CSE kept  — "
                 + REG_SAMBA + ZONE,
                 "[ok] versionNumber bumped for the zone list (load + extension), GPT.INI in "
                 "lockstep  — v1 -> v3",
                 "[ok] same zone values again: extension names and version unchanged",
                 "[ok] GPO + sysvol completely removed"):
        assert want in out, (want, out)
    # the zone value is taken out again before the GPO is ever linked
    subs = [a[1:3] for a in samba.log]
    assert ["gpo", "remove"] in subs
    assert subs.index(["gpo", "remove"]) < subs.index(["gpo", "setlink"])
