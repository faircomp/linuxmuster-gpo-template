"""Non-destructive end-to-end self-test of the GPO engine.

Creates a throwaway GPO ("LMN-SELFTEST-DELETEME"), loads a benign registry
value + a firewall rule, briefly links it to the first school's Devices OU,
applies grant/deny security-filter ACEs, verifies every side effect
(Registry.pol, versionNumber, CSE GUID, gPLink, DACL, aclcheck), then removes
everything and confirms it is gone. Safe to run on a test instance.
"""
from __future__ import annotations

import os

from . import ad
from . import env as envmod
from .gpo import GpoEngine, APPLY_GROUP_POLICY
from .regpol import RegPol, firewall_entries

TEST_NAME = "LMN-SELFTEST-DELETEME"
PROBE_KEY = r"Software\Policies\LmnGpo\Selftest"


def run(dry_run: bool = False) -> int:
    e = envmod.detect()
    if not e.schools:
        print("No school found — self-test not possible.")
        return 2
    school = e.schools[0]
    eng = GpoEngine(e, dry_run=dry_run)
    rp = RegPol(eng)

    steps: list[tuple[bool, str, str]] = []

    def step(ok: bool, label: str, detail: str = ""):
        steps.append((ok, label, detail))
        mark = "\033[32m✓\033[0m" if ok else "\033[31m✗\033[0m"
        print(f"  {mark} {label}" + (f"  — {detail}" if detail else ""))

    print(f"Self-test against school '{school.name}' (Devices OU: {school.devices_ou})\n")
    guid = None
    pol_base = f"CN=Policies,CN=System,{e.basedn}"
    try:
        guid, created = eng.ensure(TEST_NAME)
        step(bool(guid), "GPO created/found", f"{guid} ({'new' if created else 'existing'})")
        if dry_run:
            print("\n(dry-run: no real changes — verification skipped)")
            return 0

        entries = [
            {"keyname": PROBE_KEY, "valuename": "Probe", "class": "MACHINE",
             "type": "REG_DWORD", "data": 1},
            {"keyname": r"Software\Policies\Microsoft\Windows\DataCollection",
             "valuename": "AllowTelemetry", "class": "MACHINE",
             "type": "REG_DWORD", "data": 0},
        ]
        fw = {"profiles": {"domain": {"EnableFirewall": 1}},
              "rules": [{"id": "LMN-Selftest-RDP-In",
                         "string": "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|"
                                   "LPort=3389|Name=LMN Selftest RDP|EmbedCtxt=Remote Desktop|"}]}
        rp.load(guid, entries + firewall_entries(fw))

        pol = f"{eng.sysvol_path(guid)}/Machine/Registry.pol"
        size = os.path.getsize(pol) if os.path.exists(pol) else 0
        step(size > 8, "Machine/Registry.pol written", f"{size} Bytes")

        msg = ad.find_one(f"(cn={guid})", base=pol_base, scope="one",
                          attrs=["versionNumber", "gPCMachineExtensionNames"])
        ver = ad.val(msg, "versionNumber", "0")
        cse = ad.val(msg, "gPCMachineExtensionNames", "")
        step(int(ver) > 0, "versionNumber bumped", f"v{ver}")
        step("35378EAC" in cse.upper(), "Registry CSE registered", cse or "(empty)")

        # --- GptTmpl.inf (user rights + restricted groups) + Groups.xml (local admins) ---
        from .secedit import SecEdit
        from .gpp import GppGroups
        admin_sid = school.admins.sid if (school.admins and school.admins.sid) else "S-1-5-32-544"
        SecEdit(eng).apply(
            guid,
            privilege_rights={
                "SeRemoteInteractiveLogonRight": ["S-1-5-32-544", "S-1-5-32-555", admin_sid],
                "SeRemoteShutdownPrivilege": ["S-1-5-32-544", admin_sid],
            },
            group_membership=[{"member": admin_sid, "memberof": ["S-1-5-32-555"]}],
        )
        gadmins = e.global_admins
        GppGroups(eng).add_local_admins(
            guid, [{"name": f"{e.netbios}\\global-admins", "sid": gadmins.sid}] if gadmins else [])

        gpo_dir = eng.sysvol_path(guid)
        step(os.path.exists(os.path.join(gpo_dir, "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf")),
             "GptTmpl.inf written")
        step(os.path.exists(os.path.join(gpo_dir, "Machine/Preferences/Groups/Groups.xml")),
             "Groups.xml written")
        msg2 = ad.find_one(f"(cn={guid})", base=pol_base, scope="one",
                           attrs=["versionNumber", "gPCMachineExtensionNames"])
        cse2 = ad.val(msg2, "gPCMachineExtensionNames", "").upper()
        step(all(g in cse2 for g in ("35378EAC", "827D319E", "17D89FEC")),
             "all 3 CSE registered (Registry+Security+GPP)", cse2)
        step(int(ad.val(msg2, "versionNumber", "0")) >= 3, "versionNumber bumped further",
             f"v{ad.val(msg2, 'versionNumber', '0')}")

        eng.link(school.devices_ou, guid)
        step(guid.upper() in eng._linked_guids(school.devices_ou),
             "linked to Devices OU", school.devices_ou)

        ok0, _ = eng.aclcheck()
        step(ok0, "aclcheck clean (baseline after link)")

        if school.admins and school.admins.sid:
            eng.grant_apply(guid, school.admins.sid)
        if school.nopxe and school.nopxe.sid:
            eng.deny_apply(guid, school.nopxe.sid)
        sddl = (ad.descriptor_sddl(eng.gpo_dn(guid)) or "").lower()
        step(APPLY_GROUP_POLICY.lower() in sddl, "Grant-Apply ACE (admins) set")
        step("od;" in sddl or not (school.nopxe and school.nopxe.sid),
             "Deny-Apply ACE (noPXE) set")

        eng.reconcile_sysvol()
        ok1, out1 = eng.aclcheck()
        step(ok1, "aclcheck clean after filter+sysvolreset",
             "" if ok1 else (out1.splitlines()[0] if out1 else ""))
    finally:
        if guid and not dry_run:
            print("\nCleanup:")
            try:
                eng.unlink(school.devices_ou, guid)
            except Exception as exc:
                step(False, "unlink", str(exc))
            try:
                eng.delete(guid)
            except Exception as exc:
                step(False, "delete", str(exc))
            gone = ad.find_one(f"(cn={guid})", base=pol_base, scope="one") is None
            gone_fs = not os.path.exists(eng.sysvol_path(guid))
            step(gone and gone_fs, "GPO + sysvol completely removed")

    passed = sum(1 for ok, _, _ in steps if ok)
    total = len(steps)
    print(f"\n{'PASSED' if passed == total else 'FAILED'}: {passed}/{total} steps ok.")
    return 0 if passed == total else 1
