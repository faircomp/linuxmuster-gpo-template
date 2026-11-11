"""apply for pack 17-ntp-zeit, end to end on the fake domain (fake samba-tool, fake sam.ldb):
Secure Time Seeding off in the machine Registry.pol, and the upgrade from a 7.3.6 GPO."""
from __future__ import annotations

import dataclasses
import os

import pytest

from conftest import POLICIES
from fakesamba import FakeSamba, _samba_available, read_pol, write_pol
from lmn_gpo import apply, catalog

NAME = "LMN-C-GLOBAL-17-ntp-zeit"
CONFIG = r"Software\Policies\Microsoft\W32Time\Config"
NTPCLIENT = r"Software\Policies\Microsoft\W32Time\TimeProviders\NtpClient"
STS = (CONFIG.lower(), "utilizessltimedata")


def pack17(without_sts=False):
    pack = {p.id: p for p in catalog.load_packs()}["17-ntp-zeit"]
    if without_sts:   # the pack as lmn-gpo 7.3.6 shipped it
        pack = dataclasses.replace(
            pack, registry=[e for e in pack.registry if e["name"] != "UtilizeSslTimeData"])
    return pack


@pytest.fixture
def dc(domain, monkeypatch):
    fake, env, sysvol = domain
    return fake, env, sysvol, FakeSamba(fake, sysvol).install(monkeypatch)


def run(env, pack):
    ap = apply.Applier(env, {"packs": ["17-ntp-zeit"], "ntp_mode": "ntp"})
    return ap.run([pack])


def gpo(fake):
    msgs = [m for m in fake.search(base=POLICIES, scope="one",
                                   expr="(objectClass=groupPolicyContainer)")
            if fake.val(m, "displayName") == NAME]
    assert len(msgs) == 1
    return fake.val(msgs[0], "cn"), msgs[0]


def versions(fake, sysvol, guid):
    """(AD versionNumber, GPT.INI Version); they must always move in lockstep."""
    _, msg = gpo(fake)
    ad = int(fake.val(msg, "versionNumber"))
    gpt = open(os.path.join(sysvol, guid, "GPT.INI")).read()
    ini = int(gpt.split("Version=", 1)[1].split()[0])
    return ad, ini


def machine_pol(sysvol, guid):
    return read_pol(os.path.join(sysvol, guid, "Machine", "Registry.pol"))


def loads(samba):
    return samba.ran("gpo", "load")


def test_catalog_switches_secure_time_seeding_off():
    entries = [e for e in pack17().registry if e["name"] == "UtilizeSslTimeData"]
    assert entries == [{"key": CONFIG, "name": "UtilizeSslTimeData", "class": "machine",
                        "type": "dword", "data": 0}]


def test_apply_writes_it_into_the_machine_registry_pol(dc):
    fake, env, sysvol, samba = dc
    assert run(env, pack17()) == 0
    guid, _ = gpo(fake)
    pol = machine_pol(sysvol, guid)
    assert pol[STS] == (4, 0)                                  # REG_DWORD 0
    # the values that were there before stay, unchanged
    assert pol[(CONFIG.lower(), "maxposphasecorrection")] == (4, 0xFFFFFFFF)
    assert pol[(CONFIG.lower(), "maxnegphasecorrection")] == (4, 0xFFFFFFFF)
    t, data = pol[(NTPCLIENT.lower(), "type")]
    assert (t, str(data).rstrip("\x00")) == (1, "NTP")      # REG_SZ
    assert not os.path.exists(os.path.join(sysvol, guid, "User", "Registry.pol"))
    ad, ini = versions(fake, sysvol, guid)
    assert ad == ini == 1                                      # machine half only


def test_upgrade_from_736_writes_the_value_and_raises_the_machine_version(dc, capsys):
    fake, env, sysvol, samba = dc
    assert run(env, pack17(without_sts=True)) == 0             # the GPO as 7.3.6 left it
    guid, _ = gpo(fake)
    assert STS not in machine_pol(sysvol, guid)
    before = versions(fake, sysvol, guid)
    n = len(loads(samba))

    assert run(env, pack17()) == 0                             # lmn-gpo apply after upgrading
    assert len(loads(samba)) == n + 1
    assert machine_pol(sysvol, guid)[STS] == (4, 0)
    ad, ini = versions(fake, sysvol, guid)
    assert ad == ini
    assert ad & 0xFFFF == (before[0] & 0xFFFF) + 1             # clients see a new version
    assert ad >> 16 == before[0] >> 16                         # user half untouched
    assert gpo(fake)[0] == guid                                # same GPO, not a new one


def test_second_apply_changes_nothing(dc, capsys):
    fake, env, sysvol, samba = dc
    assert run(env, pack17()) == 0
    guid, _ = gpo(fake)
    before, n = versions(fake, sysvol, guid), len(loads(samba))
    capsys.readouterr()
    assert run(env, pack17()) == 0
    assert len(loads(samba)) == n                              # no gpo load at all
    assert versions(fake, sysvol, guid) == before
    assert "Registry unchanged" in capsys.readouterr().out


@pytest.mark.skipif(not _samba_available(), reason="python3-samba not installed")
def test_fake_registry_pol_is_what_samba_reads(tmp_path):
    """The fake's Registry.pol must parse identically with Samba's own NDR parser,
    the one lmn_gpo.regpol uses on a real DC."""
    from lmn_gpo.regpol import _read_pol
    path = str(tmp_path / "Registry.pol")
    write_pol(path, [(CONFIG, "UtilizeSslTimeData", 4, (0).to_bytes(4, "little")),
                     (CONFIG, "MaxPosPhaseCorrection", 4, (0xFFFFFFFF).to_bytes(4, "little")),
                     (NTPCLIENT, "NtpServer", 1, "server,0x9\x00".encode("utf-16-le"))])
    ours, samba = read_pol(path), _read_pol(path)
    assert set(ours) == set(samba)
    for k, (t, data) in ours.items():
        assert samba[k][0] == t
        assert str(samba[k][1]).rstrip("\x00") == str(data).rstrip("\x00")
