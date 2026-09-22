"""`lmn-gpo` command-line entry point.

Subcommands:
  doctor    environment self-check (read-only)
  env       dump the detected environment (text or --json)
  list      list Group Policy Objects in the directory and their links (--mine)
  setup     interactive assistant, writes site.yaml
  apply     apply the catalog (--school/--pack/--dry-run/--yes/--defaults)
  remove    remove LMN-* GPOs (--school/--pack/--dry-run/--yes)
  selftest  throwaway-GPO end-to-end test
  veyon-encrypt-password
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

from . import __version__, ad, env as envmod, ui

# Display-name prefix that marks every GPO this toolkit owns. Everything else
# (sophomorix:*, Default Domain Policy, ...) is left untouched.
GPO_PREFIX = "LMN-"

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
        print(f"{ui.BAD} {exc}")
        print("    This tool must run as root on the linuxmuster.net Samba AD DC.")
        return 2

    print("linuxmuster-gpo-template — environment check\n")
    print(f"{ui.OK} Samba AD DC detected: {e.samba_version or 'Samba'}")
    print(f"{ui.OK} Realm {e.realm}   Base-DN {e.basedn}   NetBIOS {e.netbios}")

    ok = True

    def check(cond, good, bad):
        nonlocal ok
        print(f"{ui.OK if cond else ui.BAD} {good if cond else bad}")
        ok = ok and cond

    def warn(cond, good, bad):
        print(f"{ui.OK if cond else ui.WARN} {good if cond else bad}")

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
            print(f"  {ui.OK} {label}: {g.sid}")
        else:
            print(f"  {ui.WARN} {label}: not found")

    # Schools
    print(f"\nSchools ({len(e.schools)}):")
    if not e.schools:
        check(False, "", "No schools found under OU=SCHOOLS")
    for s in e.schools:
        tag = "default-school (empty prefix)" if s.is_default else f"prefix '{s.prefix}'"
        print(f"  • {s.name}  [{tag}]")
        if s.admins and s.admins.sid:
            print(f"      {ui.OK} admin group: {s.admins.cn}  {s.admins.sid}")
        else:
            print(f"      {ui.BAD} admin group not found")
            ok = False
        if s.nopxe and s.nopxe.sid:
            print(f"      {ui.OK} noPXE group: {s.nopxe.cn}  {s.nopxe.sid}")
        else:
            print(f"      {ui.WARN} noPXE group (cn=*nopxe*) not found "
                  "— without it the update split cannot be targeted")
        print(f"      devices OU: {s.devices_ou}")
        print(f"      rooms: {len(s.rooms)}"
              + (": " + ", ".join(r['name'] for r in s.rooms[:8]) if s.rooms else ""))

    # Security-filter prerequisites, resolved from the real site.yaml — the same check
    # `apply` runs before its first change. A pack whose exclusion group does not exist is
    # held back by apply (fail-closed), so this is a warning here, not a failure.
    print("\nSecurity-filter prerequisites (from site.yaml):")
    try:
        from . import apply as applymod
        from . import catalog
        from . import setup as setupmod
        cfg = setupmod.default_site()
        answers = setupmod.load_site(cfg)
        print(f"  config: {cfg}{'' if answers else '  (missing/empty — defaults assumed)'}")
        ap = applymod.Applier(e, answers, dry_run=True)
        raw = answers.get("teachernb", "nopxe")
        raw = str(raw).strip() if raw is not None else ""
        print(f"  teacher-notebook group (teachernb): {ap._teachernb()!r}"
              + ("  (empty in site.yaml — default assumed)" if not raw else ""))
        rows = ap.preflight(catalog.load_packs())
        if not rows:
            print(f"  {ui.OK} every security-filter group resolves")
        disabled = sorted({r[0] for r in rows if r[4] == "disabled" and r[2] != "only"})
        if disabled:
            print(f"  {ui.OK} teachernb: skip — @teachernb exclusions are off, these packs "
                  f"apply to every device: {', '.join(disabled)}")
        seen = set()
        for pid, label, kind, token, status, note in rows:
            if status == "partial":
                if note not in seen:
                    seen.add(note)
                    print(f"  {ui.OK} {note}")
                continue
            if status == "disabled" and kind != "only":
                continue
            what = "teachernb: skip" if status == "disabled" else note
            print(f"  {ui.WARN} {pid:26} {label:16} {kind:13} {token:12} {what}"
                  f"  → pack held back by apply (fail-closed)")
    except Exception as exc:
        print(f"  {ui.WARN} could not evaluate: {exc}")

    # Loopback prerequisite. A pack with `scope: school` that carries USER settings is
    # linked to OU=Devices (so the proxy host follows the device) - a sibling of the user
    # OUs. Without a pack that sets UserPolicyMode on those machines it reaches nobody,
    # while apply still reports success. Warning only: the GPOs themselves are correct,
    # so the exit code is unchanged.
    print("\nLoopback prerequisite (per-school user packs, from site.yaml):")
    try:
        from . import apply as applymod
        from . import catalog
        from . import setup as setupmod
        answers = setupmod.load_site(setupmod.default_site())
        ap = applymod.Applier(e, answers, dry_run=True)
        packs = catalog.load_packs()
        per_school = [p.id for p in ap.selected_packs(packs) if ap.needs_loopback(p)]
        rows = ap.loopback_gap(packs)
        if not per_school:
            print(f"  {ui.OK} no per-school user pack selected - loopback is not required")
        elif not rows:
            for sname, pid, how in ap.loopback_status(packs):
                print(f"  {ui.OK} {sname}: loopback is on ({pid}, {how}) - "
                      f"{', '.join(per_school)} reach their users")
        else:
            for pid, sname, cands in rows:
                print(f"  {ui.WARN} {pid:26} {sname:16} is linked to OU=Devices and delivers "
                      f"USER settings,")
                print(f"       but no pack with 'loopback:' is active on that school's "
                      f"devices → the GPO reaches NO user.")
                print(f"       Fix: add one of {', '.join(cands)} to 'packs:' in site.yaml.")
    except Exception as exc:
        print(f"  {ui.WARN} could not evaluate: {exc}")

    # Existing GPOs
    print("\nExisting GPOs:")
    for name, guid, ver in _iter_gpos(e.basedn):
        mark = "  (ours)" if name.startswith(GPO_PREFIX) else (
            "  (sophomorix — do not touch)" if name.startswith("sophomorix:") else "")
        print(f"  • {name}  v{ver}{mark}")

    print(f"\n{'Everything essential is ok.' if ok else 'There are problems (see ' + ui.BAD + ').'}")
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# env
# --------------------------------------------------------------------------- #
def cmd_env(args) -> int:
    try:
        e = envmod.detect()
    except ad.NotADomainController as exc:
        print(f"{ui.BAD} {exc}", file=sys.stderr)
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
        if not (s.nopxe and s.nopxe.sid):
            print(f"  {ui.WARN} no noPXE group — device exclusions (@nopxe/@teachernb) "
                  "cannot be targeted in this school")
    return 0


# --------------------------------------------------------------------------- #
# list
# --------------------------------------------------------------------------- #
def cmd_list(args) -> int:
    try:
        e = envmod.detect()
    except ad.NotADomainController as exc:
        print(f"{ui.BAD} {exc}", file=sys.stderr)
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
        print(f"{ui.BAD} {exc}", file=sys.stderr)
        return 2
    packs = catalog.load_packs()
    # A missing or empty answers file would make EVERY optional feature read as "off",
    # and since 1.3.0 apply removes the GPOs of packs whose precondition is gone — so a
    # mistyped --config or a site.yaml deleted from a repo folder would silently delete
    # real GPOs. Refuse to guess; --defaults is the explicit "I mean no optional features".
    cfg = args.config or setupmod.default_site()
    answers = setupmod.load_site(cfg)
    if not answers and not args.defaults:
        why = "does not exist" if not os.path.exists(cfg) else "is empty"
        print(f"{ui.BAD} answers file {why}: {cfg}")
        print("    Every optional package would count as disabled, and apply would REMOVE")
        print("    their GPOs. Run 'lmn-gpo setup', point --config at the right file, or")
        print("    pass --defaults if you really mean 'no optional features'.")
        return 2
    if args.school:
        known = [s.name for s in e.schools]
        unknown = [s for s in args.school if s not in known]
        if unknown:
            # A silent empty selection would still apply the global packs domain-wide.
            print(f"{ui.BAD} unknown school(s): {', '.join(unknown)} — detected: "
                  f"{', '.join(known) or 'none'}", file=sys.stderr)
            return 2
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
        print(f"{ui.BAD} {exc}", file=sys.stderr)
        return 2


def cmd_remove(args) -> int:
    from . import apply as applymod
    try:
        e = envmod.detect()
    except ad.NotADomainController as exc:
        print(f"{ui.BAD} {exc}", file=sys.stderr)
        return 2
    known = [s.name for s in e.schools]
    unknown = [s for s in (args.school or []) if s not in known]
    if unknown:
        print(f"{ui.BAD} unknown school(s): {', '.join(unknown)} — detected: "
              f"{', '.join(known) or 'none'}", file=sys.stderr)
        return 2
    if not args.dry_run and not args.yes:
        print("This removes LMN GPOs. Confirm with --yes or use --dry-run.")
        return 1
    return applymod.remove(e, dry_run=args.dry_run, only_ids=args.pack, schools=args.school)


def cmd_veyon_encrypt(args) -> int:
    from . import veyon
    import getpass
    pw = args.password or getpass.getpass("Veyon bind password: ")
    try:
        print(veyon.encrypt_bindpw(pw))
        return 0
    except Exception as exc:
        print(f"{ui.BAD} {exc}", file=sys.stderr)
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
        print(f"{ui.BAD} {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lmn-gpo",
        description="GPO template toolkit for linuxmuster.net 7.x (Samba AD DC).")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
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
    sp.add_argument("--defaults", action="store_true",
                    help="run without an answers file (every optional package counts as "
                         "disabled — this REMOVES their GPOs)")
    sp.set_defaults(func=cmd_apply)

    sp = sub.add_parser("remove", help="remove LMN GPOs")
    sp.add_argument("--school", action="append",
                    help="only the per-school GPOs of this/these school(s) (repeatable); "
                         "global GPOs are left in place")
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
    ui.set_color(not args.no_color and sys.stdout.isatty())
    return args.func(args)
