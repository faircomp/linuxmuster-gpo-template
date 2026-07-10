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
SHUTDOWN_DIR_REL = "Machine/Scripts/Shutdown"
PSSCRIPTS_INI_REL = "Machine/Scripts/psscripts.ini"


class ScriptsExt:
    def __init__(self, engine):
        self.engine = engine

    def set_startup_powershell(self, guid: str, scripts: list[dict]) -> bool:
        """Backwards-compatible wrapper — startup scripts only."""
        return self.set_scripts_powershell(guid, startup=scripts)

    def set_scripts_powershell(self, guid: str, startup=None, shutdown=None) -> bool:
        """Write PowerShell startup and/or shutdown scripts into one psscripts.ini.

        startup/shutdown: [{'file': 'x.ps1', 'content': '<ps1 text>'}]. Both sections
        share the single Scripts CSE and one machine-version bump. Idempotent.
        """
        def _clean(lst):
            return [s for s in (lst or []) if s and s.get("file") and s.get("content")]
        startup, shutdown = _clean(startup), _clean(shutdown)
        if not startup and not shutdown:
            return False
        gpo_dir = self.engine.sysvol_path(guid)
        # one psscripts.ini with [Startup] and/or [Shutdown]; per-section .ps1 dirs
        ini = ""
        sections = []  # (relative dir, label, scripts)
        for name, rel, scr in (("Startup", STARTUP_DIR_REL, startup),
                               ("Shutdown", SHUTDOWN_DIR_REL, shutdown)):
            if not scr:
                continue
            ini += f"[{name}]\r\n"
            for i, s in enumerate(scr):
                ini += f"{i}CmdLine={s['file']}\r\n{i}Parameters=\r\n"
            sections.append((rel, name, scr))
        if self.engine.dry_run:
            for rel, name, scr in sections:
                self.engine._log(f"    [dry-run] psscripts.ini [{name}] + {len(scr)} Skript(e) "
                                 f"→ {gpo_dir}/{rel}")
                for s in scr:
                    self.engine._log(f"        - {s['file']}")
            self.engine._log("    [dry-run] register Scripts-CSE + bump machine version")
            return True
        ini_path = os.path.join(gpo_dir, PSSCRIPTS_INI_REL)
        if os.path.exists(ini_path):
            def _n(s):
                return s.replace("\r\n", "\n")
            try:
                unchanged = _n(open(ini_path, encoding="utf-16").read()) == _n(ini) and all(
                    os.path.exists(p := os.path.join(gpo_dir, rel, s["file"]))
                    and _n(open(p, encoding="utf-8").read()) == _n(s["content"])
                    for rel, _name, scr in sections for s in scr)
            except Exception:
                unchanged = False
            if unchanged:
                # Heal a possible partial prior run: ensure the CSE is registered.
                version.register_cse(guid, self.engine.env.basedn, version.SCRIPTS_CSE)
                self.engine._log("    Start-/Shutdownskript(e) unverändert — übersprungen")
                return False
        for rel, _name, scr in sections:
            d = os.path.join(gpo_dir, rel)
            os.makedirs(d, exist_ok=True)
            for s in scr:
                with open(os.path.join(d, s["file"]), "w",
                          encoding="utf-8", newline="\r\n") as fh:
                    fh.write(s["content"])
        # psscripts.ini is UTF-16LE with BOM (as Windows writes it).
        with open(ini_path, "w", encoding="utf-16") as fh:
            fh.write(ini)
        version.register_cse(guid, self.engine.env.basedn, version.SCRIPTS_CSE)
        version.bump(guid, self.engine.env.basedn, gpo_dir, machine=True)
        self.engine._log("    Start-/Shutdownskript(e) + Scripts-CSE/Version gesetzt")
        return True
