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
        print("    Dieses Tool muss auf dem linuxmuster.net Samba-AD-DC als root laufen.")
        return 2

    print("linuxmuster-gpo-template — Umgebungs-Check\n")
    print(f"{OK} Samba AD DC erkannt: {e.samba_version or 'Samba'}")
    print(f"{OK} Realm {e.realm}   Base-DN {e.basedn}   NetBIOS {e.netbios}")

    ok = True

    def check(cond, good, bad):
        nonlocal ok
        print(f"{OK if cond else BAD} {good if cond else bad}")
        ok = ok and cond

    def warn(cond, good, bad):
        print(f"{OK if cond else WARN} {good if cond else bad}")

    check(bool(e.serverip), f"Server-IP {e.serverip}   Subnetz {e.subnet}",
          "Server-IP nicht ermittelbar (setup.ini?)")
    check(os.path.isdir(e.sysvol_policies),
          f"sysvol Policies: {e.sysvol_policies}",
          f"sysvol Policies-Pfad fehlt: {e.sysvol_policies}")
    check(_gpo_load_available(), "samba-tool gpo load verfügbar",
          "samba-tool gpo load FEHLT (Samba < 4.16?)")
    check(os.access(envmod.SECRET_ADMIN, os.R_OK),
          f"Admin-Secret lesbar: {envmod.SECRET_ADMIN}",
          f"Admin-Secret nicht lesbar: {envmod.SECRET_ADMIN}")

    sysvol_ok, sysvol_out = ad.sysvolcheck()
    warn(sysvol_ok, "samba-tool ntacl sysvolcheck: ok",
         "sysvolcheck meldet Abweichungen (ggf. sysvolreset nötig) — Details: "
         + (sysvol_out.splitlines()[0] if sysvol_out else ""))

    # Global groups
    print("\nGlobale Gruppen:")
    for label, g in (("global-admins", e.global_admins), ("all-admins", e.all_admins),
                     ("role-globaladministrator", e.role_globaladmin),
                     ("role-schooladministrator", e.role_schooladmin)):
        if g and g.sid:
            print(f"  {OK} {label}: {g.sid}")
        else:
            print(f"  {WARN} {label}: nicht gefunden")

    # Schools
    print(f"\nSchulen ({len(e.schools)}):")
    if not e.schools:
        check(False, "", "Keine Schulen unter OU=SCHOOLS gefunden")
    for s in e.schools:
        tag = "default-school (Präfix leer)" if s.is_default else f"Präfix '{s.prefix}'"
        print(f"  • {s.name}  [{tag}]")
        if s.admins and s.admins.sid:
            print(f"      {OK} Admin-Gruppe: {s.admins.cn}  {s.admins.sid}")
        else:
            print(f"      {BAD} Admin-Gruppe nicht gefunden")
            ok = False
        if s.nopxe and s.nopxe.sid:
            print(f"      {OK} noPXE-Gruppe: {s.nopxe.cn}  {s.nopxe.sid}")
        else:
            print(f"      {WARN} noPXE-Gruppe (cn=*nopxe*) nicht gefunden "
                  "— Update-Split ist dann ohne diese Gruppe nicht targetbar")
        print(f"      Devices-OU: {s.devices_ou}")
        print(f"      Räume: {len(s.rooms)}"
              + (": " + ", ".join(r['name'] for r in s.rooms[:8]) if s.rooms else ""))

    # Existing GPOs
    print("\nVorhandene GPOs:")
    for name, guid, ver in _iter_gpos(e.basedn):
        mark = "  (unser)" if name.startswith(GPO_PREFIX) else (
            "  (sophomorix — nicht anfassen)" if name.startswith("sophomorix:") else "")
        print(f"  • {name}  v{ver}{mark}")

    print(f"\n{'Alles Wesentliche ok.' if ok else 'Es gibt Probleme (siehe ' + BAD + ').'}")
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
            print(f"    ↳ verlinkt an {dn}")
        if not linked:
            print("    (nicht verlinkt)")
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
        print("Das ändert echte GPOs auf dem DC. Mit --yes bestätigen oder --dry-run nutzen.")
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
        print("Das entfernt LMN-GPOs. Mit --yes bestätigen oder --dry-run nutzen.")
        return 1
    return applymod.remove(e, dry_run=args.dry_run, only_ids=args.pack)


def cmd_veyon_encrypt(args) -> int:
    from . import veyon
    import getpass
    pw = args.password or getpass.getpass("Veyon Bind-Passwort: ")
    try:
        print(veyon.encrypt_bindpw(pw))
        return 0
    except Exception as exc:
        print(f"{BAD} {exc}", file=sys.stderr)
        return 2


def cmd_selftest(args) -> int:
    from . import selftest
    if not args.yes and not args.dry_run:
        print("Der Selbsttest legt eine Wegwerf-GPO an, verlinkt sie kurz an die")
        print("Devices-OU und entfernt sie danach wieder restlos. Auf Testinstanzen")
        print("unbedenklich. Zum Ausführen: --yes bestätigen (oder --dry-run).")
        return 1
    try:
        return selftest.run(dry_run=args.dry_run)
    except ad.NotADomainController as exc:
        print(f"{BAD} {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lmgpo",
        description="GPO-Template-Toolkit für linuxmuster.net 7.x (Samba AD DC).")
    p.add_argument("--no-color", action="store_true", help="Farbausgabe deaktivieren")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("doctor", help="Umgebungs-Selbstcheck (read-only)")
    sp.set_defaults(func=cmd_doctor)

    sp = sub.add_parser("env", help="Erkannte Umgebung ausgeben")
    sp.add_argument("--json", action="store_true", help="als JSON ausgeben")
    sp.set_defaults(func=cmd_env)

    sp = sub.add_parser("list", help="GPOs und ihre Verlinkungen auflisten")
    sp.add_argument("--mine", action="store_true",
                    help=f"nur GPOs mit Präfix '{GPO_PREFIX}'")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("setup", help="interaktiver Setup-Assistent")
    sp.add_argument("--config", help="Pfad zur site.yaml (Antworten)")
    sp.set_defaults(func=cmd_setup)

    sp = sub.add_parser("apply", help="Katalog anwenden (nicht-interaktiv)")
    sp.add_argument("--config", help="site.yaml mit Antworten")
    sp.add_argument("--school", action="append", help="nur diese Schule(n) (wiederholbar)")
    sp.add_argument("--pack", action="append", help="nur diese Pack-ID(s) (wiederholbar)")
    sp.add_argument("--dry-run", action="store_true", help="nur anzeigen, nichts ändern")
    sp.add_argument("--yes", action="store_true", help="ohne Rückfrage anwenden")
    sp.set_defaults(func=cmd_apply)

    sp = sub.add_parser("remove", help="LMN-GPOs entfernen")
    sp.add_argument("--pack", action="append", help="nur diese Pack-ID(s) entfernen")
    sp.add_argument("--dry-run", action="store_true", help="nur anzeigen, nichts ändern")
    sp.add_argument("--yes", action="store_true", help="ohne Rückfrage entfernen")
    sp.set_defaults(func=cmd_remove)

    sp = sub.add_parser("veyon-encrypt-password",
                        help="Bind-Passwort für Veyon verschlüsseln (Hex für site.yaml)")
    sp.add_argument("--password", help="Klartext (sonst interaktive Eingabe)")
    sp.set_defaults(func=cmd_veyon_encrypt)

    sp = sub.add_parser("selftest",
                        help="nicht-destruktiver End-to-End-Test der GPO-Engine")
    sp.add_argument("--yes", action="store_true",
                    help="ohne Rückfrage ausführen (verlinkt kurz eine harmlose Test-GPO)")
    sp.add_argument("--dry-run", action="store_true", help="nur anzeigen, nichts ändern")
    sp.set_defaults(func=cmd_selftest)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    _color(not args.no_color and sys.stdout.isatty())
    return args.func(args)
