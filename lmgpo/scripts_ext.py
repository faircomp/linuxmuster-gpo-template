"""Windows machine startup scripts (PowerShell) via a GPO.

Used to arm Wake-on-LAN on the NICs and force Fast-Startup off — the parts that
cannot be expressed as a fixed registry path (NIC instance keys differ per
machine). Writes Machine/Scripts/psscripts.ini + the .ps1 under
Machine/Scripts/Startup, registers the Scripts CSE {42B5FAAE-...} and bumps the
machine version.
"""
from __future__ import annotations

import os

from . import version

SCRIPTS_DIR_REL = "Machine/Scripts"
STARTUP_DIR_REL = "Machine/Scripts/Startup"
PSSCRIPTS_INI_REL = "Machine/Scripts/psscripts.ini"


class ScriptsExt:
    def __init__(self, engine):
        self.engine = engine

    def set_startup_powershell(self, guid: str, scripts: list[dict]) -> bool:
        """scripts: [{'file': 'wol-arm.ps1', 'content': '<ps1 text>'}]."""
        scripts = [s for s in scripts if s and s.get("file") and s.get("content")]
        if not scripts:
            return False
        gpo_dir = self.engine.sysvol_path(guid)
        ini = "[Startup]\r\n"
        for i, s in enumerate(scripts):
            ini += f"{i}CmdLine={s['file']}\r\n{i}Parameters=\r\n"
        if self.engine.dry_run:
            self.engine._log(f"    [dry-run] psscripts.ini + {len(scripts)} Startskript(e) "
                             f"→ {gpo_dir}/{STARTUP_DIR_REL}")
            for s in scripts:
                self.engine._log(f"        - {s['file']}")
            self.engine._log("    [dry-run] register Scripts-CSE + bump machine version")
            return True
        ini_path = os.path.join(gpo_dir, PSSCRIPTS_INI_REL)
        if os.path.exists(ini_path):
            def _n(s):
                return s.replace("\r\n", "\n")
            try:
                unchanged = _n(open(ini_path, encoding="utf-16").read()) == _n(ini) and all(
                    os.path.exists(p := os.path.join(gpo_dir, STARTUP_DIR_REL, s["file"]))
                    and _n(open(p, encoding="utf-8").read()) == _n(s["content"]) for s in scripts)
            except Exception:
                unchanged = False
            if unchanged:
                # Heal a possible partial prior run: ensure the CSE is registered.
                version.register_cse(guid, self.engine.env.basedn, version.SCRIPTS_CSE)
                self.engine._log("    Startskript(e) unverändert — übersprungen")
                return False
        startup_dir = os.path.join(gpo_dir, STARTUP_DIR_REL)
        os.makedirs(startup_dir, exist_ok=True)
        for s in scripts:
            with open(os.path.join(startup_dir, s["file"]), "w",
                      encoding="utf-8", newline="\r\n") as fh:
                fh.write(s["content"])
        # psscripts.ini is UTF-16LE with BOM (as Windows writes it).
        with open(os.path.join(gpo_dir, PSSCRIPTS_INI_REL), "w", encoding="utf-16") as fh:
            fh.write(ini)
        version.register_cse(guid, self.engine.env.basedn, version.SCRIPTS_CSE)
        version.bump(guid, self.engine.env.basedn, gpo_dir, machine=True)
        self.engine._log("    Startskript(e) + Scripts-CSE/Version gesetzt")
        return True
