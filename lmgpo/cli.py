"""`lmgpo` command-line entry point.

Subcommands implemented so far:
  doctor   environment self-check (read-only)
  env      dump the detected environment (text or --json)
  list     list Group Policy Objects in the directory and their links

The apply/setup/remove subcommands are added as the engine + catalog land.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

from . import ad, env as envmod

# Display-name prefix that marks every GPO this toolkit owns. Everything else
# (sophomorix:*, Default Domain Policy, ...) is left untouched.
GPO_PREFIX = "LMN-"

OK = "\033[32m✓\033[0m"
WARN = "\033[33m⚠\033[0m"
BAD = "\033[31m✗\033[0m"


def _color(enabled: bool):
    global OK, WARN, BAD
    if not enabled:
        OK, WARN, BAD = "[ok]", "[warn]", "[FAIL]"


def _gpo_load_available() -> bool:
    try:
        p = subprocess.run(["samba-tool", "gpo", "load", "--help"],
                           capture_output=True, text=True, timeout=20)
        return p.returncode == 0
    except Exception:
        return False


def _iter_gpos(basedn: str):
    """Yield (displayName, cn/guid, versionNumber) for every GPO in the directory."""
    base = f"CN=Policies,CN=System,{basedn}"
    for m in ad.search(base=base, scope="one", expr="(objectClass=groupPolicyContainer)",
                       attrs=["displayName", "cn", "versionNumber"]):
        yield (ad.val(m, "displayName", "?"), ad.val(m, "cn", "?"),
               ad.val(m, "versionNumber", "0"))


def _gplinks(basedn: str) -> dict[str, list[str]]:
    """Map GPO GUID -> list of container DNs that link it."""
    out: dict[str, list[str]] = {}
    import re
    for m in ad.search(expr="(gPLink=*)", attrs=["gPLink"]):
        gplink = ad.val(m, "gPLink", "")
        for guid in re.findall(r"CN=(\{[0-9A-Fa-f-]+\})", gplink, re.IGNORECASE):
            out.setdefault(guid.upper(), []).append(str(m.dn))
    return out


# --------------------------------------------------------------------------- #
# doctor
# --------------------------------------------------------------------------- #
def cmd_doctor(args) -> int:
    try:
        e = envmod.detect()
    except ad.NotADomainController as exc:
        print(f"{BAD} {exc}")
        print("    This tool must run as root on the linuxmuster.net Samba AD DC.")
        return 2

    print("linuxmuster-gpo-template — environment check\n")
    print(f"{OK} Samba AD DC detected: {e.samba_version or 'Samba'}")
    print(f"{OK} Realm {e.realm}   Base-DN {e.basedn}   NetBIOS {e.netbios}")

    ok = True

    def check(cond, good, bad):
        nonlocal ok
        print(f"{OK if cond else BAD} {good if cond else bad}")
        ok = ok and cond

    def warn(cond, good, bad):
        print(f"{OK if cond else WARN} {good if cond else bad}")

    check(bool(e.serverip), f"Server IP {e.serverip}   Subnet {e.subnet}",
          "Server IP could not be determined (setup.ini?)")
    check(os.path.isdir(e.sysvol_policies),
          f"sysvol Policies: {e.sysvol_policies}",
          f"sysvol Policies path missing: {e.sysvol_policies}")
    check(_gpo_load_available(), "samba-tool gpo load available",
          "samba-tool gpo load MISSING (Samba < 4.16?)")
    check(os.access(envmod.SECRET_ADMIN, os.R_OK),
          f"Admin secret readable: {envmod.SECRET_ADMIN}",
          f"Admin secret not readable: {envmod.SECRET_ADMIN}")

    sysvol_ok, sysvol_out = ad.sysvolcheck()
    warn(sysvol_ok, "samba-tool ntacl sysvolcheck: ok",
         "sysvolcheck reports discrepancies (sysvolreset may be needed) — details: "
         + (sysvol_out.splitlines()[0] if sysvol_out else ""))

    # Global groups
    print("\nGlobal groups:")
    for label, g in (("global-admins", e.global_admins), ("all-admins", e.all_admins),
                     ("role-globaladministrator", e.role_globaladmin),
                     ("role-schooladministrator", e.role_schooladmin)):
        if g and g.sid:
            print(f"  {OK} {label}: {g.sid}")
        else:
            print(f"  {WARN} {label}: not found")

    # Schools
    print(f"\nSchools ({len(e.schools)}):")
    if not e.schools:
        check(False, "", "No schools found under OU=SCHOOLS")
    for s in e.schools:
        tag = "default-school (empty prefix)" if s.is_default else f"prefix '{s.prefix}'"
        print(f"  • {s.name}  [{tag}]")
        if s.admins and s.admins.sid:
            print(f"      {OK} admin group: {s.admins.cn}  {s.admins.sid}")
        else:
            print(f"      {BAD} admin group not found")
            ok = False
        if s.nopxe and s.nopxe.sid:
            print(f"      {OK} noPXE group: {s.nopxe.cn}  {s.nopxe.sid}")
        else:
            print(f"      {WARN} noPXE group (cn=*nopxe*) not found "
                  "— without it the update split cannot be targeted")
        print(f"      devices OU: {s.devices_ou}")
        print(f"      rooms: {len(s.rooms)}"
              + (": " + ", ".join(r['name'] for r in s.rooms[:8]) if s.rooms else ""))

    # Existing GPOs
    print("\nExisting GPOs:")
    for name, guid, ver in _iter_gpos(e.basedn):
        mark = "  (ours)" if name.startswith(GPO_PREFIX) else (
            "  (sophomorix — do not touch)" if name.startswith("sophomorix:") else "")
        print(f"  • {name}  v{ver}{mark}")

    print(f"\n{'Everything essential is ok.' if ok else 'There are problems (see ' + BAD + ').'}")
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# env
# --------------------------------------------------------------------------- #
def cmd_env(args) -> int:
    try:
        e = envmod.detect()
    except ad.NotADomainController as exc:
        print(f"{BAD} {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(e.as_dict(), indent=2, ensure_ascii=False))
        return 0
    d = e.as_dict()
    d.pop("schools")
    for k, v in d.items():
        print(f"{k:18} {v}")
    for s in e.schools:
        print(f"\n[school] {s.name}")
        for k, v in s.as_dict().items():
            if k != "rooms":
                print(f"  {k:14} {v}")
        print(f"  rooms          {[r['name'] for r in s.rooms]}")
    return 0


# --------------------------------------------------------------------------- #
# list
# --------------------------------------------------------------------------- #
def cmd_list(args) -> int:
    try:
        e = envmod.detect()
    except ad.NotADomainController as exc:
        print(f"{BAD} {exc}", file=sys.stderr)
        return 2
    links = _gplinks(e.basedn)
    for name, guid, ver in _iter_gpos(e.basedn):
        if args.mine and not name.startswith(GPO_PREFIX):
            continue
        linked = links.get(guid.upper(), [])
        print(f"{name}  [{guid}]  v{ver}")
        for dn in linked:
            print(f"    ↳ linked to {dn}")
        if not linked:
            print("    (not linked)")
    return 0


def cmd_apply(args) -> int:
    from . import apply as applymod
    from . import catalog
    from . import setup as setupmod
    try:
        e = envmod.detect()
    except ad.NotADomainController as exc:
        print(f"{BAD} {exc}", file=sys.stderr)
        return 2
    packs = catalog.load_packs()
    answers = setupmod.load_site(args.config or setupmod.DEFAULT_SITE)
    if args.school:
        answers["schools"] = args.school
    if args.pack:
        answers["packs"] = args.pack
    if not args.dry_run and not args.yes:
        print("This changes real GPOs on the DC. Confirm with --yes or use --dry-run.")
        return 1
    return applymod.Applier(e, answers, dry_run=args.dry_run).run(packs)


def cmd_setup(args) -> int:
    from . import setup as setupmod
    try:
        return setupmod.run(args.config or setupmod.DEFAULT_SITE)
    except ad.NotADomainController as exc:
        print(f"{BAD} {exc}", file=sys.stderr)
        return 2


def cmd_remove(args) -> int:
    from . import apply as applymod
    try:
        e = envmod.detect()
    except ad.NotADomainController as exc:
        print(f"{BAD} {exc}", file=sys.stderr)
        return 2
    if not args.dry_run and not args.yes:
        print("This removes LMN GPOs. Confirm with --yes or use --dry-run.")
        return 1
    return applymod.remove(e, dry_run=args.dry_run, only_ids=args.pack)


def cmd_veyon_encrypt(args) -> int:
    from . import veyon
    import getpass
    pw = args.password or getpass.getpass("Veyon bind password: ")
    try:
        print(veyon.encrypt_bindpw(pw))
        return 0
    except Exception as exc:
        print(f"{BAD} {exc}", file=sys.stderr)
        return 2


def cmd_selftest(args) -> int:
    from . import selftest
    if not args.yes and not args.dry_run:
        print("The self-test creates a throwaway GPO, briefly links it to the")
        print("devices OU and then removes it again completely. Harmless on test")
        print("instances. To run: confirm with --yes (or --dry-run).")
        return 1
    try:
        return selftest.run(dry_run=args.dry_run)
    except ad.NotADomainController as exc:
        print(f"{BAD} {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lmgpo",
        description="GPO template toolkit for linuxmuster.net 7.x (Samba AD DC).")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("doctor", help="environment self-check (read-only)")
    sp.set_defaults(func=cmd_doctor)

    sp = sub.add_parser("env", help="dump the detected environment")
    sp.add_argument("--json", action="store_true", help="output as JSON")
    sp.set_defaults(func=cmd_env)

    sp = sub.add_parser("list", help="list GPOs and their links")
    sp.add_argument("--mine", action="store_true",
                    help=f"only GPOs with prefix '{GPO_PREFIX}'")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("setup", help="interactive setup wizard")
    sp.add_argument("--config", help="path to site.yaml (answers)")
    sp.set_defaults(func=cmd_setup)

    sp = sub.add_parser("apply", help="apply the catalog (non-interactive)")
    sp.add_argument("--config", help="site.yaml with answers")
    sp.add_argument("--school", action="append", help="only this/these school(s) (repeatable)")
    sp.add_argument("--pack", action="append", help="only this/these pack ID(s) (repeatable)")
    sp.add_argument("--dry-run", action="store_true", help="show only, change nothing")
    sp.add_argument("--yes", action="store_true", help="apply without confirmation")
    sp.set_defaults(func=cmd_apply)

    sp = sub.add_parser("remove", help="remove LMN GPOs")
    sp.add_argument("--pack", action="append", help="only remove this/these pack ID(s)")
    sp.add_argument("--dry-run", action="store_true", help="show only, change nothing")
    sp.add_argument("--yes", action="store_true", help="remove without confirmation")
    sp.set_defaults(func=cmd_remove)

    sp = sub.add_parser("veyon-encrypt-password",
                        help="encrypt the bind password for Veyon (hex for site.yaml)")
    sp.add_argument("--password", help="plaintext (otherwise interactive input)")
    sp.set_defaults(func=cmd_veyon_encrypt)

    sp = sub.add_parser("selftest",
                        help="non-destructive end-to-end test of the GPO engine")
    sp.add_argument("--yes", action="store_true",
                    help="run without confirmation (briefly links a harmless test GPO)")
    sp.add_argument("--dry-run", action="store_true", help="show only, change nothing")
    sp.set_defaults(func=cmd_selftest)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    _color(not args.no_color and sys.stdout.isatty())
    return args.func(args)
