"""Non-destructive end-to-end self-test of the GPO engine.

Creates a throwaway GPO ("LMN-SELFTEST-DELETEME"), loads a benign registry
value + a firewall rule, writes a Drives.xml whose items are all DISABLED (a Delete and
a Replace with targeting, the shapes pack 20-drives writes), briefly links it to the
first school's Devices OU, switches that link to enforced and back IN PLACE (the gPLink
edit 20-drives relies on), applies grant/deny security-filter ACEs, verifies every side
effect (Registry.pol, versionNumber, CSE GUIDs, gPLink, DACL, aclcheck), then removes
everything and confirms it is gone. Safe to run on a test instance.
"""
from __future__ import annotations

import os

from . import ad, gplink, ui
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
        mark = ui.OK if ok else ui.BAD      # honours --no-color like every other command
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

        # --- Drives.xml in the 20-drives shape, every item disabled="1" -------------
        # Linked for a few seconds to OU=Devices it could only reach users via loopback,
        # and disabled items are never processed: a real logon in this window loses nothing.
        from .drives import GppDrives, render_managed, DRIVES_REL
        from .sophodrives import parse_drives_xml
        grp = [{"name": (f"{e.netbios}\\{school.admins.cn}" if school.admins
                         else "BUILTIN\\Administrators"), "sid": admin_sid}]
        server = (e.server_netbios or "server").lower()
        ditems = [
            {"kind": "del", "letter": "Q", "action": "D", "index": 0, "groups": grp,
             "disabled": True},
            {"kind": "map", "letter": "Q", "action": "R", "index": 0, "groups": grp,
             "path": f"\\\\{server}\\netlogon", "label": "lmn-gpo selftest",
             "exclude": [{"groups": grp}], "disabled": True},
        ]
        GppDrives(eng).set_content(guid, render_managed(ditems, guid))
        dpath = os.path.join(gpo_dir, DRIVES_REL)
        try:
            parsed = parse_drives_xml(open(dpath, encoding="utf-8").read())
        except (OSError, ValueError):
            parsed = []
        step(len(parsed) == 2 and all(i.disabled for i in parsed)
             and [i.action for i in parsed] == ["D", "R"],
             "Drives.xml written (Delete + Replace, all disabled)", dpath)
        msg3 = ad.find_one(f"(cn={guid})", base=pol_base, scope="one",
                           attrs=["versionNumber", "gPCUserExtensionNames"])
        step("5794DAFD" in (ad.val(msg3, "gPCUserExtensionNames", "") or "").upper()
             and int(ad.val(msg3, "versionNumber", "0")) >> 16 >= 1,
             "Drive Maps CSE on the user side + user version bumped",
             f"v{ad.val(msg3, 'versionNumber', '0')}")

        eng.link(school.devices_ou, guid)
        step(guid.upper() in eng._linked_guids(school.devices_ou),
             "linked to Devices OU", school.devices_ou)

        # --- enforce the EXISTING link in place, then take it back -----------------
        # samba-tool setlink refuses an existing link; set_link_options edits the gPLink.
        def others(value):
            return [lk.raw for lk in gplink.parse(value) if lk.guid != guid.upper()]

        def position(value):
            return [lk.guid for lk in gplink.parse(value)].index(guid.upper())

        before = eng.gplink_value(school.devices_ou)
        eng.link(school.devices_ou, guid, enforce=True)
        mid = eng.gplink_value(school.devices_ou)
        step(eng.link_options(school.devices_ou, guid) == gplink.GPLINK_ENFORCE,
             "existing link enforced in place (options 2)")
        step(others(mid) == others(before) and position(mid) == position(before),
             "other links byte-identical, link order unchanged",
             f"position {position(mid) + 1} of {len(gplink.parse(mid))}")
        eng.set_link_options(school.devices_ou, guid, 0)
        step(eng.gplink_value(school.devices_ou) == before,
             "link options restored (gPLink byte-identical to before)")

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
