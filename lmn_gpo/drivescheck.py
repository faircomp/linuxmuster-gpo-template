"""`lmn-gpo doctor`, section "Drive maps (20-drives)" - read-only.

Everything here is a warning, never a failure: the GPO may be fine and the deployment
around it not (a group re-created with a new SID, an enforced link switched off in the
GPMC, another GPO with drive maps processed later). Each warning says what to do.
"""
from __future__ import annotations

import os
import re
import subprocess

from . import ad, drivesconf, gplink, sophodrives, ui, version
from .drives import DRIVES_REL, render_managed

PACK_ID = "20-drives"


def _server_shares() -> set[str] | None:
    """Share names of this server (smb.conf incl. includes, plus registry shares)."""
    names: set[str] = set()
    ok = False
    for cmd in (["testparm", "-s"], ["net", "conf", "listshares"]):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except Exception:
            continue
        if p.returncode != 0:
            continue
        ok = True
        if cmd[0] == "testparm":
            names |= {m.lower() for m in re.findall(r"^\[([^\]]+)\]", p.stdout, re.M)}
        else:
            names |= {line.strip().lower() for line in p.stdout.splitlines() if line.strip()}
    names.discard("global")
    return names if ok else None


def _gpo_attrs(basedn: str, guid: str):
    return ad.find_one(f"(cn={guid})", base=f"CN=Policies,CN=System,{basedn}", scope="one",
                       attrs=["versionNumber", "gPCUserExtensionNames", "flags"])


def run(e, answers: dict, ap, all_packs) -> None:
    """Print the section. `ap` is the doctor's dry-run Applier (same answers)."""
    print("\nDrive maps (20-drives, drives.yaml):")
    pack = next((p for p in all_packs if p.id == PACK_ID), None)
    if pack is None:
        print(f"  {ui.WARN} pack {PACK_ID} is missing from the catalog")
        return
    name = f"LMN-{pack.type_letter}-GLOBAL-{pack.id}"
    guid = ap.eng.find_by_name(name)
    enabled = bool(answers.get("drives_enabled"))
    path = ap.drives_file()

    if not enabled:
        print(f"  {ui.OK} not enabled (opt-in: drives_enabled: true in site.yaml + {path})")
        if os.path.exists(path):
            print(f"       note: {path} exists, but drives_enabled is not true - it is not used")
        if guid:
            print(f"  {ui.WARN} {name} exists although drives_enabled is not true - the next "
                  f"'lmn-gpo apply' retires it (backup under /var/backups/lmn-gpo first)")
        return

    packs = answers.get("packs")
    if packs and PACK_ID not in packs:
        print(f"  {ui.WARN} drives_enabled is true, but site.yaml has an explicit 'packs:' list "
              f"without {PACK_ID} - apply never touches it. Add {PACK_ID} to 'packs:'.")

    cfg = ap.drives_config()
    plan = None
    if cfg is None:
        exc = ap._drives_error
        print(f"  {ui.WARN} {exc.source}: apply skips the pack (an existing GPO stays as it is):")
        for problem in exc.problems:
            print(f"         - {problem}")
    else:
        n = len(cfg.drives)
        print(f"  {ui.OK} {cfg.source}: schema ok, {n} entr{'y' if n == 1 else 'ies'}")
        try:
            plan = ap.drives_plan(cfg)
        except Exception as exc:
            print(f"  {ui.WARN} groups could not be resolved: {exc}")
    if plan is not None:
        bad = {t: r for t, r in plan.resolved.items() if not r.ok}
        good = len(plan.resolved) - len(bad)
        if not bad:
            print(f"  {ui.OK} groups: all {good} resolve to a SID")
        for token, res in bad.items():
            print(f"  {ui.WARN} group '{token}' {res.note or res.status} - apply holds the "
                  f"entry back" + (" and leaves the existing GPO untouched" if guid else ""))
        if plan.remove_letters:
            print(f"       linuxmuster default letters removed: "
                  f"{' '.join(plan.remove_letters)}  ({plan.remove_source})")
        for line in plan.lines():
            print(f"       {line}")

    # ---- the GPO, its link and its file --------------------------------------------
    if not guid:
        print(f"  {ui.WARN} {name} does not exist yet - run 'lmn-gpo apply --pack {PACK_ID} "
              f"--dry-run', then --yes")
    else:
        opts = ap.eng.link_options(e.schools_ou, guid)
        if opts == gplink.GPLINK_ENFORCE:
            print(f"  {ui.OK} {name} {guid} linked at {e.schools_ou} (enforced)")
        else:
            print(f"  {ui.WARN} link at {e.schools_ou}: {gplink.describe(opts)} - must be "
                  f"enforced and enabled, or sophomorix' school GPOs win the letters. "
                  f"'lmn-gpo apply' sets it again, in place.")
        msg = _gpo_attrs(e.basedn, guid)
        exts = (ad.val(msg, "gPCUserExtensionNames", "") or "").upper()
        if version.GPP_DRIVES_CSE.upper() not in exts:
            print(f"  {ui.WARN} the Drive Maps extension is not registered on the GPO "
                  f"(gPCUserExtensionNames) - Windows ignores Drives.xml. Run apply.")
        try:
            flags = int(ad.val(msg, "flags", "0") or 0)
        except ValueError:
            flags = 0
        if flags & 1:
            print(f"  {ui.WARN} the GPO's USER configuration is disabled (flags={flags}) - no "
                  f"drive is mapped. Re-enable it in the GPMC (GPO status).")
        ad_ver = int(ad.val(msg, "versionNumber", "0") or 0)
        gpt_ver = version._read_gpt_ini_version(ap.eng.sysvol_path(guid))
        if ad_ver != gpt_ver:
            print(f"  {ui.WARN} versionNumber {ad_ver} != GPT.INI {gpt_ver} - clients may "
                  f"skip the GPO. Run apply.")
        _drift(ap, e, guid, plan)

    # ---- processing order ------------------------------------------------------------
    print("  Processing order (recomputed from gPLink/gPOptions, MS-GPOL 3.2.5.1.5):")
    try:
        ok_lines, warn_lines = ap.drives_order(name, guid)
        if not guid:
            print("       (simulated: as it will be after the first apply)")
        for line in ok_lines:
            print(f"  {ui.OK} {line}")
        for line in warn_lines:
            print(f"  {ui.WARN} {line}")
        if warn_lines:
            print("       A GPO processed later wins the drive letter. Fix its link (not "
                  "enforced), or map the letter in drives.yaml instead.")
    except Exception as exc:
        print(f"  {ui.WARN} could not evaluate: {exc}")
    _block_inheritance(e)
    print(f"  {ui.OK} {PACK_ID} needs no loopback: OU=SCHOOLS is an ancestor of every user "
          f"and computer OU")

    # ---- sophomorix school GPOs (read-only) ---------------------------------------------
    _school_gpos(ap, e)

    # ---- paths on this server, H: twice ----------------------------------------------
    if cfg is not None:
        _paths(e, cfg, plan)
        if answers.get("home_drive_enabled") and any(d.home for d in cfg.drives):
            print(f"  {ui.WARN} H: comes twice (19-home-h and a 'home: true' entry) - harmless, "
                  f"but switch one off (home_drive_enabled: false retires 19-home-h)")
    print("       Rights: lmn-gpo maps drives, it sets no permissions on the shares.")


def _drift(ap, e, guid, plan) -> None:
    gpo_dir = ap.eng.sysvol_path(guid)
    path = os.path.join(gpo_dir, DRIVES_REL)
    try:
        current = open(path, encoding="utf-8").read()
    except OSError:
        print(f"  {ui.WARN} {DRIVES_REL} missing in the GPO - run apply")
        return
    try:
        items = sophodrives.parse_drives_xml(current)
    except ValueError as exc:
        print(f"  {ui.WARN} deployed Drives.xml: {exc}")
        return
    resolver = ap.drives_resolver()
    sid_drift = []
    for item in items:
        for name, sid, _neg, _user in item.groups:
            bare = name.split("\\", 1)[-1]
            if not bare:
                continue
            res = resolver.group(bare)
            if not res.ok:
                sid_drift.append(f"{item.letter}: group '{bare}' {res.note or res.status}")
            elif res.sid.upper() != sid.upper():
                sid_drift.append(f"{item.letter}: group '{bare}' now has SID {res.sid}, the "
                                 f"GPO still targets {sid} (deleted and re-created?)")
    for line in dict.fromkeys(sid_drift):
        print(f"  {ui.WARN} {line} - run apply")
    if plan is not None and plan.complete:
        want = render_managed(plan.items, guid)
        if want.replace("\r\n", "\n") != current.replace("\r\n", "\n"):
            print(f"  {ui.WARN} the deployed Drives.xml differs from what apply would write now "
                  f"(drives.yaml changed, or the GPO was edited in the GPMC) - run apply")
        elif not sid_drift:
            print(f"  {ui.OK} deployed Drives.xml matches drives.yaml and the current SIDs")


def _block_inheritance(e) -> None:
    dns = [e.schools_ou] + [s.dn for s in e.schools]
    for dn in dns:
        msg = ad.find_one("(objectClass=*)", base=dn, scope="base", attrs=["gPOptions"])
        if (ad.val(msg, "gPOptions", "0") or "0").strip() == "1":
            print(f"  {ui.OK} note: block inheritance is set on {dn} - 20-drives is enforced "
                  f"and not affected, other global LMN packs are")


def _school_gpos(ap, e) -> None:
    try:
        gpos = sophodrives.school_gpos(e.basedn, e.sysvol_policies)
    except Exception as exc:
        print(f"  {ui.WARN} sophomorix school GPOs could not be read: {exc}")
        return
    have = {g.school for g in gpos}
    for s in e.schools:
        if s.name not in have:
            print(f"  {ui.OK} note: no sophomorix:school:{s.name} GPO - that school has no "
                  f"linuxmuster default drives")
    resolver = ap.drives_resolver()
    dead: dict[tuple, list] = {}          # (letter, sid) -> schools whose item targets it
    for g in gpos:
        if g.error:
            print(f"  {ui.WARN} {g.display}: {g.error}")
            continue
        if g.items is None:
            print(f"       {g.display}: no Drives.xml")
            continue
        shown = " ".join(f"{i.letter}:" + ("(disabled)" if i.disabled else "")
                         for i in g.items)
        print(f"       {g.display}: {shown or 'no drive'}")
        for item in g.items:
            for _name, sid, _neg, _user in item.groups:
                if sid and not resolver.group(sid).ok:
                    dead.setdefault((item.letter, sid), []).append(g.school)
    for (letter, sid), schools in dead.items():
        print(f"       note: {letter}: of {', '.join(schools)} targets {sid}, which does not "
              f"exist in this domain - Windows never connects it (sophomorix template; "
              f"linuxclient7 filters by name and does)")


def _paths(e, cfg, plan) -> None:
    hosts = {x.lower() for x in (e.server_netbios, e.serverfqdn, e.dnsdomain) if x}
    shares = None
    checked = set()
    for ent in cfg.drives:
        if ent.home:
            continue
        path = drivesconf.substitute(ent.path, (e.server_netbios or "").lower(), e.serverfqdn)
        m = re.match(r"^\\\\([^\\]+)\\([^\\]+)", path)
        if not m or path in checked:
            continue
        checked.add(path)
        host, share = m.group(1).lower(), m.group(2).lower()
        if host not in hosts:
            print(f"       {ent.where} {path}: other server, not checked")
            continue
        if "%" in share:
            continue
        if shares is None:
            shares = _server_shares()
        if shares is None:
            print(f"       {ent.where} {path}: shares of this server could not be listed")
        elif share in shares:
            print(f"  {ui.OK} {ent.where} {path}: share '{share}' exists on this server")
        else:
            print(f"  {ui.WARN} {ent.where} {path}: no share '{share}' on this server "
                  f"(testparm / net conf)")
