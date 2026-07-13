"""Interactive setup assistant.

Auto-detects everything environment-specific, asks only the decisions, previews
as a dry-run, optionally saves the answers to a site.yaml (so `lmn-gpo apply` can
run unattended later / be reused per customer), then applies.
"""
from __future__ import annotations

import os

import yaml

from . import catalog
from . import env as envmod
from .apply import Applier, DEFAULT_ANSWERS

DEFAULT_SITE = "/etc/linuxmuster/lmn-gpo/site.yaml"
# Config path used before the rename to lmn-gpo; still read + migrated so no settings are lost.
LEGACY_SITE = "/etc/linuxmuster/lmgpo/site.yaml"


def default_site() -> str:
    """Preferred config path; fall back to the legacy location if only that one exists."""
    if os.path.exists(DEFAULT_SITE):
        return DEFAULT_SITE
    if os.path.exists(LEGACY_SITE):
        return LEGACY_SITE
    return DEFAULT_SITE


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
    d = "Y/n" if default else "y/N"
    try:
        r = input(f"  {prompt} [{d}]: ").strip().lower()
    except EOFError:
        return default
    if not r:
        return default
    return r in ("j", "ja", "y", "yes")


def _ask_wlan(answers: dict) -> None:
    """WLAN part of the assistant: any number of student PSK WLANs (loop) plus
    optionally one teacher enterprise WLAN. Mutates ``answers`` in place. Existing
    site.yaml entries are shown and left unchanged when declined."""
    print("\n  Roll out WLAN via GPO (optional):")
    print("    - Student WLAN(s): WPA2 with password (PSK), connect even BEFORE login.")
    print("      You can create MULTIPLE (e.g. one per site) — the notebooks receive")
    print("      all profiles and connect automatically to whichever WLAN is currently in")
    print("      range (roaming). Does not apply to teacher notebooks (d_nopxe).")
    print("    - Teacher WLAN: WPA2-Enterprise/PEAP via RADIUS — teachers only.")
    have_wlan = bool(answers.get("wlan_psk_networks") or answers.get("wlan_enterprise_ssid"))
    if not _ask_yesno("Set up WLAN now?", have_wlan):
        # WLAN not wanted -> existing site.yaml entries remain unchanged.
        return

    # --- Student WLANs (PSK), any number ---
    nets = list(answers.get("wlan_psk_networks") or [])
    if nets:
        print("  Already saved student WLANs:")
        for i, n in enumerate(nets, 1):
            print(f"    {i}. {n.get('ssid', '?')}")
        if _ask_yesno("Discard these and re-enter?", False):
            nets = []
    print("  Enter student WLANs — an empty SSID ends the input:")
    while True:
        ssid = _ask(f"    {len(nets) + 1}. SSID (empty = done)", "").strip()
        if not ssid:
            break
        psk = _ask(f"       Password (PSK) for '{ssid}', 8-63 characters", "").strip()
        if not (8 <= len(psk) <= 63):
            print("       ! PSK must be 8-63 characters — entry discarded, please retry.")
            continue
        nets.append({"ssid": ssid, "psk": psk})
        print(f"       + '{ssid}' added ({len(nets)} WLAN(s) total)")
    answers["wlan_psk_networks"] = nets

    # --- Teacher WLAN (Enterprise/PEAP) ---
    print("  Teacher WLAN (WPA2-Enterprise via RADIUS, teachers only):")
    es = _ask("    SSID (empty = no teacher WLAN)",
              answers.get("wlan_enterprise_ssid", "") or "").strip()
    answers["wlan_enterprise_ssid"] = es
    if es:
        answers["wlan_enterprise_servernames"] = _ask(
            "    Name(s) in the RADIUS server certificate, separated by ';' (empty = do not check server name)",
            answers.get("wlan_enterprise_servernames", "") or "").strip()
        answers["wlan_enterprise_ca_cert"] = _ask(
            "    Path to the RADIUS CA certificate file on THIS server (.cer/.pem)",
            answers.get("wlan_enterprise_ca_cert", "") or "").strip()
        print("    Note: The very first teacher login on a notebook requires cable/another")
        print("    network once (user auth); afterwards the WLAN connects automatically via SSO.")


def run(site_path: str = DEFAULT_SITE) -> int:
    e = envmod.detect()
    packs = catalog.load_packs()
    prior = load_site(site_path)
    if not prior and site_path == DEFAULT_SITE:
        prior = load_site(LEGACY_SITE)  # carry over answers from the pre-rename config
    answers = {**DEFAULT_ANSWERS, **prior}

    print("linuxmuster-gpo-template — setup assistant\n")
    print(f"Detected: realm {e.realm} · server {e.serverip}/{e.subnet.split('/')[-1]} "
          f"· {len(e.schools)} school(s)")
    print("Groups: "
          + " ".join(f"{n}{'✓' if g and g.sid else '✗'}"
                     for n, g in (("global-admins ", e.global_admins),
                                  ("admins ", e.schools[0].admins if e.schools else None),
                                  ("nopxe ", e.schools[0].nopxe if e.schools else None))))
    print()

    # Schools (default = earlier selection from the site.yaml)
    if len(e.schools) > 1:
        allnames = ",".join(s.name for s in e.schools)
        prior = answers.get("schools")
        default = ",".join(prior) if prior else "all"
        sel = _ask(f"For which schools? (all | comma list from {allnames})", default)
        answers["schools"] = None if sel.strip().lower() in ("alle", "all") else \
            [x.strip() for x in sel.split(",") if x.strip()]
    else:
        answers["schools"] = None

    # Packs (default = earlier selection: None = all, otherwise a subset)
    print("\n  Packs in the catalog:")
    for p in packs:
        print(f"    - {p.id:22} {p.title}")
    prior_packs = answers.get("packs")
    if _ask_yesno("Apply all packs?", prior_packs is None):
        answers["packs"] = None
    else:
        default_ids = ",".join(prior_packs) if prior_packs else ",".join(p.id for p in packs)
        sel = _ask("Enable IDs (comma-separated)", default_ids)
        answers["packs"] = [x.strip() for x in sel.split(",") if x.strip()]

    # Firewall scope
    fw = _ask("Allow firewall inbound from: serverip | subnet | <own IP/CIDR>",
              answers.get("fwsource", "serverip"))
    answers["fwsource"] = fw

    # Teacher notebooks
    tnb = _ask("Teacher notebooks = group (nopxe | skip | <group CN>)",
               answers.get("teachernb", "nopxe"))
    answers["teachernb"] = tnb

    # KMS activation
    kms = _ask("KMS host for Windows activation (empty = no KMS)",
               answers.get("kmshost", "") or "")
    answers["kmshost"] = kms.strip()

    # Wallpaper / branding source dir
    print("  Wallpapers: place them as wallpapers/<school>.jpg (fallback default.jpg).")
    wpd = _ask("Wallpaper source directory (empty = repo wallpapers/)",
               answers.get("wallpaper_dir", "") or "")
    answers["wallpaper_dir"] = wpd.strip()

    # Veyon (optional, design A: roaming + firewall site lock)
    print("  Veyon (classroom management, optional — leave empty to skip):")
    vbd = _ask("Veyon bind DN (dedicated read-only user, e.g. CN=global-veyon,OU=Management,OU=GLOBAL,...)",
               answers.get("veyon_binddn", "") or "")
    answers["veyon_binddn"] = vbd.strip()
    if answers["veyon_binddn"]:
        vph = _ask("Veyon bind password hex (from Configurator export or 'lmn-gpo veyon-encrypt-password')",
                   answers.get("veyon_bindpw_hex", "") or "")
        answers["veyon_bindpw_hex"] = vph.strip()

    # Firefox (optional)
    if _ask_yesno("Enable Firefox policies (first-run off, clean new tab, no promo clutter)?",
                  bool(answers.get("firefox_enabled"))):
        answers["firefox_enabled"] = True
        hp = _ask("Firefox homepage (URL, global; empty = do not set a homepage)",
                  answers.get("firefox_homepage", "") or "")
        answers["firefox_homepage"] = hp.strip()
        if answers["firefox_homepage"]:
            answers["firefox_homepage_locked"] = _ask_yesno(
                "Lock the homepage (overrides/locks the user setting)?",
                bool(answers.get("firefox_homepage_locked", True)))
        print("  (Different homepage per school? Set 'firefox_homepage_by_school: {<school>: <url>}' in site.yaml.)")
    else:
        answers["firefox_enabled"] = False

    # Proxy (optional, role-based, per school, roaming)
    if _ask_yesno("Enable role proxy (teacher/student/staff per port, per school, roaming)?",
                  bool(answers.get("proxy_enabled"))):
        answers["proxy_enabled"] = True
        ph = _ask("Proxy host global (overridable per school via 'proxy_host_by_school' in site.yaml)",
                  answers.get("proxy_host", "") or "")
        answers["proxy_host"] = ph.strip()
        ports = answers.get("proxy_port_by_role") or {"teacher": 3128, "student": 3129, "staff": 3130}
        pt = _ask("Port teacher", str(ports.get("teacher", 3128)))
        ps = _ask("Port student", str(ports.get("student", 3129)))
        pst = _ask("Port staff", str(ports.get("staff", 3130)))
        try:
            answers["proxy_port_by_role"] = {"teacher": int(pt), "student": int(ps), "staff": int(pst)}
        except ValueError:
            print("  (invalid port — keeping defaults 3128/3129/3130)")
        print("  Exceptions (no proxy): default = <local> + *.<realm> + private networks; adjustable via 'proxy_exceptions'.")
    else:
        answers["proxy_enabled"] = False

    # WLAN (optional): student PSK (multiple) + teacher enterprise
    _ask_wlan(answers)

    # UEFI boot order (opt-in, hardware-dependent)
    print("\n  UEFI boot order (optional): forces via startup script that network/PXE")
    print("    boots first (-> LINBO), in case Windows keeps pushing itself to the front.")
    answers["bootorder_pxe_first"] = _ask_yesno(
        "    Enable? (hardware-dependent — test on ONE device first, log under %SystemRoot%\\Temp)",
        bool(answers.get("bootorder_pxe_first")))

    # Preview
    print("\n-- Preview (dry run) ---------------------------------------")
    if _ask_yesno("Show preview?", True):
        Applier(e, answers, dry_run=True).run(packs)

    # Save
    if _ask_yesno(f"\nSave answers to {site_path}?", True):
        save_site(site_path, answers)
        print(f"  saved: {site_path}")

    # Apply
    if _ask_yesno("\nApply for REAL now?", False):
        print("\n-- Applying ------------------------------------------------")
        return Applier(e, answers, dry_run=False).run(packs)
    print("Nothing applied.")
    return 0
