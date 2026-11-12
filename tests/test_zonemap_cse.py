"""The Internet Explorer Zonemapping extension on GPOs with Site to Zone Assignment List values.

Lab, Windows 11 (work/gpo-office-trusted/lab-gpo.md section 6): with only the registry
extension the ZoneMapKey values arrive in HKLM and the zone stays 3; with
{4CFB60C1-FAA6-47F1-89AA-0B18730C9FD3}{D02B1F72-...} in gPCMachineExtensionNames and a new
version the site gets its zone. 12-proxy-zone-schule and 22-edulution-trusted-schule both
carry ZoneMapKey values. The fake samba-tool registers the registry extension exactly like
Samba 4.19.5/4.22 (tests/fakesamba.py), so the interplay with `gpo load` is tested too.
"""
from __future__ import annotations

import os

import pytest

from conftest import POLICIES
from fakesamba import FakeSamba, samba_register_extension_name
from lmn_gpo import apply, catalog, regpol, version
from lmn_gpo.gpo import GpoEngine

REG_SAMBA = "[{35378eac-683f-11d2-a89a-00c04fbbcfa2}]"           # what samba-tool writes
REG_GPMC = "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]"
ZONE = "[{4CFB60C1-FAA6-47F1-89AA-0B18730C9FD3}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]"
SECURITY = "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"
GROUPS = "[{17D89FEC-5C44-4972-B12D-241CAEF74509}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}]"
EDU = "22-edulution-trusted-schule"
PROXY = "12-proxy-zone-schule"
ANSWERS = {"edulution_host": "edu.dev.lmschule.de", "proxy_enabled": True,
           "proxy_host": "proxy.dev.lmschule.de", "teachernb": "skip"}


# --------------------------------------------------------------------------- #
# the splice, on strings
# --------------------------------------------------------------------------- #
def test_the_measured_pair_is_the_zone_map_group():
    assert version.ZONEMAP_CSE == "{4CFB60C1-FAA6-47F1-89AA-0B18730C9FD3}"
    assert version.splice_cse("", version.ZONEMAP_CSE) == ZONE
    # the exact value measured in the lab, already there: nothing changes
    measured = REG_GPMC + ZONE
    assert version.splice_cse(measured, version.ZONEMAP_CSE) == measured


def test_samba_lowercase_registry_group_is_kept_byte_for_byte():
    out = version.splice_cse(REG_SAMBA, version.ZONEMAP_CSE)
    assert out == REG_SAMBA + ZONE
    assert version.has_cse(out, version.REGISTRY_CSE) and version.has_cse(out, version.ZONEMAP_CSE)


def test_sorted_by_cse_guid_without_case():
    assert version.splice_cse(SECURITY, version.ZONEMAP_CSE) == ZONE + SECURITY
    mixed = GROUPS + REG_SAMBA + SECURITY
    assert version.splice_cse(mixed, version.ZONEMAP_CSE) == GROUPS + REG_SAMBA + ZONE + SECURITY


def test_idempotent_and_case_insensitive():
    once = version.splice_cse(GROUPS + REG_SAMBA, version.ZONEMAP_CSE)
    assert version.splice_cse(once, version.ZONEMAP_CSE) == once
    lower = REG_SAMBA + ZONE.lower()
    assert version.splice_cse(lower, version.ZONEMAP_CSE) == lower


def test_a_guid_glued_into_another_group_is_no_extension():
    """Samba appends its registry GUID inside the last group; such a GUID is a tool GUID to
    Windows. has_cse() must not count it, and the splice adds the real group."""
    glued = "[{4CFB60C1-FAA6-47F1-89AA-0B18730C9FD3}{D02B1F72-3407-48AE-BA88-E8213C6761F1}" \
            "{35378eac-683f-11d2-a89a-00c04fbbcfa2}]"
    assert version.has_cse(glued, version.ZONEMAP_CSE)
    assert not version.has_cse(glued, version.REGISTRY_CSE)
    glued2 = "[{35378eac-683f-11d2-a89a-00c04fbbcfa2}{4CFB60C1-FAA6-47F1-89AA-0B18730C9FD3}]"
    assert not version.has_cse(glued2, version.ZONEMAP_CSE)
    assert version.splice_cse(glued2, version.ZONEMAP_CSE) == glued2 + ZONE


# --------------------------------------------------------------------------- #
# why the registry group stays lowercase and why the order matters (Samba's own code)
# --------------------------------------------------------------------------- #
def test_samba_load_leaves_our_value_alone():
    ours = REG_SAMBA + ZONE
    assert samba_register_extension_name(ours) == ours


def test_samba_load_would_corrupt_a_normalised_or_premature_value():
    # an upper-case registry group (the GPMC form) is not found by Samba's substring test:
    # the next load glues a second registry GUID into the LAST group
    assert samba_register_extension_name(REG_GPMC + ZONE) == \
        REG_GPMC + ZONE[:-1] + "{35378eac-683f-11d2-a89a-00c04fbbcfa2}]"
    # registered before the first load, the zone-map group swallows the registry extension
    swallowed = samba_register_extension_name(ZONE)
    assert not version.has_cse(swallowed, version.REGISTRY_CSE)


# --------------------------------------------------------------------------- #
# apply, end to end on the fake domain
# --------------------------------------------------------------------------- #
@pytest.fixture
def dc(domain, tmp_path, monkeypatch):
    fake, env, sysvol = domain
    samba = FakeSamba(fake, sysvol).install(monkeypatch)
    monkeypatch.setattr(apply, "RETIRE_BACKUP_DIR", str(tmp_path / "backups"))
    return fake, env, sysvol, samba


def run(env, answers, packs=(PROXY, EDU), dry_run=False):
    ap = apply.Applier(env, {"packs": list(packs), "schools": ["default-school"], **answers},
                       dry_run=dry_run)
    rc = ap.run(catalog.load_packs())
    return ap, rc


def gpo(fake, pack):
    display = f"LMN-C-default-school-{pack}"
    for m in fake.search(base=POLICIES, scope="one", expr="(objectClass=groupPolicyContainer)"):
        if fake.val(m, "displayName") == display:
            return fake.val(m, "cn"), m
    return None, None


def state(fake, sysvol, samba, guid):
    msg = fake.get(f"CN={guid},{POLICIES}")
    gpt = open(os.path.join(sysvol, guid, "GPT.INI"), encoding="latin-1").read()
    return (fake.val(msg, "gPCMachineExtensionNames"), fake.val(msg, "gPCUserExtensionNames"),
            fake.val(msg, "versionNumber"), gpt, dict(samba.pol(guid, "Machine")))


@pytest.mark.parametrize("pack", [PROXY, EDU])
def test_fresh_gpo_gets_the_zone_map_extension_after_the_load(dc, pack):
    fake, env, sysvol, samba = dc
    _ap, rc = run(env, ANSWERS)
    assert rc == 0
    guid, msg = gpo(fake, pack)
    assert fake.val(msg, "gPCMachineExtensionNames") == REG_SAMBA + ZONE
    # Samba also registers the registry extension on the user side; lmn-gpo leaves it
    assert fake.val(msg, "gPCUserExtensionNames") == REG_SAMBA
    # load = 1, extension = 2; GPT.INI in lockstep
    assert fake.val(msg, "versionNumber") == "2"
    assert version._read_gpt_ini_version(os.path.join(sysvol, guid)) == 2
    # the first load of a fresh GPO found no zone-map group to glue into
    first = next(i for i, ld in enumerate(samba.loads) if ld["guid"] == guid)
    assert samba.ext_at_load[first]["gPCMachineExtensionNames"] == ""


def test_second_apply_is_byte_identical(dc):
    fake, env, sysvol, samba = dc
    run(env, ANSWERS)
    guids = [gpo(fake, p)[0] for p in (PROXY, EDU)]
    before = [state(fake, sysvol, samba, g) for g in guids]
    loads = len(samba.loads)
    _ap, rc = run(env, ANSWERS)
    assert rc == 0 and len(samba.loads) == loads
    assert [state(fake, sysvol, samba, g) for g in guids] == before


def test_upgrade_adds_it_to_an_existing_proxy_gpo_with_unchanged_values(dc, capsys):
    """A 12-proxy-zone-schule GPO as lmn-gpo 7.3.7 left it: registry values in place, only
    Samba's registry extension, version 1. The next apply loads nothing, registers the
    extension and bumps the machine version; the one after changes nothing."""
    fake, env, sysvol, samba = dc
    run(env, ANSWERS, packs=(PROXY,))
    guid, msg = gpo(fake, PROXY)
    msg.set("gPCMachineExtensionNames", REG_SAMBA)
    msg.set("versionNumber", "1")
    with open(os.path.join(sysvol, guid, "GPT.INI"), "w") as fh:
        fh.write("[General]\nVersion = 1\n\n")
    pol = dict(samba.pol(guid, "Machine"))
    loads = len(samba.loads)
    capsys.readouterr()
    # dry-run: says it, changes nothing
    _ap, rc = run(env, ANSWERS, packs=(PROXY,), dry_run=True)
    out = capsys.readouterr().out
    assert rc == 0 and "[dry-run] register IE-Zonemapping-CSE on gPCMachineExtensionNames" in out
    assert fake.val(msg, "gPCMachineExtensionNames") == REG_SAMBA
    assert fake.val(msg, "versionNumber") == "1"
    _ap, rc = run(env, ANSWERS, packs=(PROXY,))
    out = capsys.readouterr().out
    assert rc == 0 and len(samba.loads) == loads, "values unchanged: no load"
    assert "Registry unchanged" in out and "IE-Zonemapping-CSE registered" in out
    assert fake.val(msg, "gPCMachineExtensionNames") == REG_SAMBA + ZONE
    assert fake.val(msg, "versionNumber") == "2"
    assert version._read_gpt_ini_version(os.path.join(sysvol, guid)) == 2
    assert dict(samba.pol(guid, "Machine")) == pol
    after = state(fake, sysvol, samba, guid)
    run(env, ANSWERS, packs=(PROXY,))
    assert state(fake, sysvol, samba, guid) == after and len(samba.loads) == loads


def test_a_changed_host_reloads_and_keeps_the_extension(dc):
    fake, env, sysvol, samba = dc
    run(env, ANSWERS)
    guid, msg = gpo(fake, EDU)
    _ap, rc = run(env, {**ANSWERS, "edulution_host": "edu2.dev.lmschule.de"}, packs=(EDU,))
    assert rc == 0 and samba.loads[-1]["replace"] is True
    assert fake.val(msg, "gPCMachineExtensionNames") == REG_SAMBA + ZONE   # Samba: no-op
    assert fake.val(msg, "versionNumber") == "3"                           # the load only


def test_a_gpo_without_zone_values_gets_no_zone_map_extension(dc):
    fake, env, sysvol, samba = dc
    run(env, {}, packs=("21-office-trusted-schule",))
    for m in fake.search(base=POLICIES, scope="one", expr="(objectClass=groupPolicyContainer)"):
        if (fake.val(m, "displayName") or "").startswith("LMN-"):
            for attr in ("gPCMachineExtensionNames", "gPCUserExtensionNames"):
                assert not version.has_cse(fake.val(m, attr, "") or "", version.ZONEMAP_CSE)


def test_user_side_zone_values_register_on_the_user_attribute(dc):
    fake, env, sysvol, samba = dc
    eng = GpoEngine(env)
    guid, _ = eng.ensure("LMN-U-GLOBAL-zone-test")
    entry = {"keyname": regpol.ZONEMAP_KEY, "valuename": "https://site.example", "class": "USER",
             "type": "REG_SZ", "data": "2"}
    regpol.RegPol(eng).load(guid, [entry], gpo_dir=eng.sysvol_path(guid))
    msg = fake.get(f"CN={guid},{POLICIES}")
    assert fake.val(msg, "gPCUserExtensionNames") == REG_SAMBA + ZONE
    assert fake.val(msg, "gPCMachineExtensionNames") == REG_SAMBA
    assert int(fake.val(msg, "versionNumber")) == 2 << 16
