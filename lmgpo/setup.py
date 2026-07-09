"""Interactive setup assistant.

Auto-detects everything environment-specific, asks only the decisions, previews
as a dry-run, optionally saves the answers to a site.yaml (so `lmgpo apply` can
run unattended later / be reused per customer), then applies.
"""
from __future__ import annotations

import os

import yaml

from . import catalog
from . import env as envmod
from .apply import Applier, DEFAULT_ANSWERS

DEFAULT_SITE = "/etc/linuxmuster/lmgpo/site.yaml"


def load_site(path: str) -> dict:
    if path and os.path.exists(path):
        with open(path) as fh:
            return yaml.safe_load(fh) or {}
    return {}


def save_site(path: str, answers: dict) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "w") as fh:
        yaml.safe_dump(answers, fh, allow_unicode=True, sort_keys=False)


def _ask(prompt: str, default: str) -> str:
    try:
        r = input(f"  {prompt} [{default}]: ").strip()
    except EOFError:
        return default
    return r or default


def _ask_yesno(prompt: str, default: bool = True) -> bool:
    d = "J/n" if default else "j/N"
    try:
        r = input(f"  {prompt} [{d}]: ").strip().lower()
    except EOFError:
        return default
    if not r:
        return default
    return r in ("j", "ja", "y", "yes")


def run(site_path: str = DEFAULT_SITE) -> int:
    e = envmod.detect()
    packs = catalog.load_packs()
    answers = {**DEFAULT_ANSWERS, **load_site(site_path)}

    print("linuxmuster-gpo-template — Setup-Assistent\n")
    print(f"Erkannt: Realm {e.realm} · Server {e.serverip}/{e.subnet.split('/')[-1]} "
          f"· {len(e.schools)} Schule(n)")
    print("Gruppen: "
          + " ".join(f"{n}{'✓' if g and g.sid else '✗'}"
                     for n, g in (("global-admins ", e.global_admins),
                                  ("admins ", e.schools[0].admins if e.schools else None),
                                  ("nopxe ", e.schools[0].nopxe if e.schools else None))))
    print()

    # Schools
    if len(e.schools) > 1:
        allnames = ",".join(s.name for s in e.schools)
        sel = _ask(f"Für welche Schulen? (alle | Komma-Liste aus {allnames})", "alle")
        answers["schools"] = None if sel.strip().lower() in ("alle", "all") else \
            [x.strip() for x in sel.split(",") if x.strip()]
    else:
        answers["schools"] = None

    # Packs
    print("\n  Pakete im Katalog:")
    for p in packs:
        print(f"    - {p.id:22} {p.title}")
    if _ask_yesno("Alle Pakete übernehmen?", True):
        answers["packs"] = None
    else:
        sel = _ask("IDs (Komma-getrennt) aktivieren", ",".join(p.id for p in packs))
        answers["packs"] = [x.strip() for x in sel.split(",") if x.strip()]

    # Firewall scope
    fw = _ask("Firewall eingehend erlauben von: serverip | subnet | <eigene IP/CIDR>",
              answers.get("fwsource", "serverip"))
    answers["fwsource"] = fw

    # Teacher notebooks
    tnb = _ask("Lehrer-Notebooks = Gruppe (nopxe | skip | <Gruppen-CN>)",
               answers.get("teachernb", "nopxe"))
    answers["teachernb"] = tnb

    # KMS activation
    kms = _ask("KMS-Host für Windows-Aktivierung (leer = kein KMS)",
               answers.get("kmshost", "") or "")
    answers["kmshost"] = kms.strip()

    # Wallpaper / branding source dir
    print("  Hintergrundbilder: lege sie als wallpapers/<schule>.jpg ab (Fallback default.jpg).")
    wpd = _ask("Wallpaper-Quellverzeichnis (leer = repo wallpapers/)",
               answers.get("wallpaper_dir", "") or "")
    answers["wallpaper_dir"] = wpd.strip()

    # Veyon (optional, Design A: Roaming + Firewall-Standortsperre)
    print("  Veyon (Klassenraum-Steuerung, optional — leer lassen zum Überspringen):")
    vbd = _ask("Veyon Bind-DN (dedizierter read-only User, z.B. CN=global-veyon,OU=Management,OU=GLOBAL,...)",
               answers.get("veyon_binddn", "") or "")
    answers["veyon_binddn"] = vbd.strip()
    if answers["veyon_binddn"]:
        vph = _ask("Veyon Bind-Passwort-Hex (aus Configurator-Export oder 'lmgpo veyon-encrypt-password')",
                   answers.get("veyon_bindpw_hex", "") or "")
        answers["veyon_bindpw_hex"] = vph.strip()

    # Firefox (optional)
    if _ask_yesno("Firefox-Policies aktivieren (First-Run aus, saubere New-Tab, kein Werbekram)?",
                  bool(answers.get("firefox_enabled"))):
        answers["firefox_enabled"] = True
        hp = _ask("Firefox-Startseite (URL, global; leer = keine Startseite setzen)",
                  answers.get("firefox_homepage", "") or "")
        answers["firefox_homepage"] = hp.strip()
        if answers["firefox_homepage"]:
            answers["firefox_homepage_locked"] = _ask_yesno(
                "Startseite fest sperren (überschreibt/verriegelt die Nutzereinstellung)?",
                bool(answers.get("firefox_homepage_locked", True)))
        print("  (Pro-Schule andere Startseite? In site.yaml 'firefox_homepage_by_school: {<schule>: <url>}' setzen.)")
    else:
        answers["firefox_enabled"] = False

    # Proxy (optional, rollenbasiert, pro Schule, Roaming)
    if _ask_yesno("Rollen-Proxy aktivieren (Lehrer/Schüler/Staff je Port, pro Schule, Roaming)?",
                  bool(answers.get("proxy_enabled"))):
        answers["proxy_enabled"] = True
        ph = _ask("Proxy-Host global (pro Schule via 'proxy_host_by_school' in site.yaml überschreibbar)",
                  answers.get("proxy_host", "") or "")
        answers["proxy_host"] = ph.strip()
        ports = answers.get("proxy_port_by_role") or {"teacher": 3128, "student": 3129, "staff": 3130}
        pt = _ask("Port Lehrer", str(ports.get("teacher", 3128)))
        ps = _ask("Port Schüler", str(ports.get("student", 3129)))
        pst = _ask("Port Staff", str(ports.get("staff", 3130)))
        try:
            answers["proxy_port_by_role"] = {"teacher": int(pt), "student": int(ps), "staff": int(pst)}
        except ValueError:
            print("  (ungültiger Port — behalte Defaults 3128/3129/3130)")
        print("  Ausnahmen (kein Proxy): Default = <local> + *.<realm> + private Netze; via 'proxy_exceptions' anpassbar.")
    else:
        answers["proxy_enabled"] = False

    # WLAN (optional): Schüler-PSK + Lehrer-Enterprise
    if _ask_yesno("WLAN per GPO ausrollen (Schüler-PSK, vor Login / Lehrer-Enterprise via RADIUS)?", False):
        s = _ask("Schüler-WLAN SSID (leer = kein PSK; weitere via site.yaml 'wlan_psk_networks')", "")
        if s.strip():
            answers["wlan_psk_networks"] = [{"ssid": s.strip(), "psk": _ask("  Schüler-WLAN PSK", "").strip()}]
        es = _ask("Lehrer-WLAN SSID (Enterprise/PEAP; leer = kein Enterprise)", "")
        answers["wlan_enterprise_ssid"] = es.strip()
        if es.strip():
            answers["wlan_enterprise_servernames"] = _ask(
                "  RADIUS-Serverzertifikat-Name(n), ';' getrennt (optional)", "").strip()
            answers["wlan_enterprise_ca_cert"] = _ask(
                "  Pfad zum RADIUS-CA-Zertifikat (.cer/.pem)", "").strip()
            print("  Hinweis: reine User-Auth → erster Lehrer-Login einmalig via Kabel/Bootstrap-Netz.")

    # Preview
    print("\n── Vorschau (Dry-Run) ─────────────────────────────────────")
    if _ask_yesno("Vorschau anzeigen?", True):
        Applier(e, answers, dry_run=True).run(packs)

    # Save
    if _ask_yesno(f"\nAntworten in {site_path} speichern?", True):
        save_site(site_path, answers)
        print(f"  gespeichert: {site_path}")

    # Apply
    if _ask_yesno("\nJetzt WIRKLICH anwenden?", False):
        print("\n── Anwenden ───────────────────────────────────────────────")
        return Applier(e, answers, dry_run=False).run(packs)
    print("Nichts angewandt.")
    return 0
