"""Registry-based policy via `samba-tool gpo load`.

`samba-tool gpo load` writes Machine/User Registry.pol, bumps GPT.INI + the AD
versionNumber in lockstep, and registers the Registry CSE GUID
{35378EAC-683F-11D2-A89A-00C04FBBCFA2} — the exact trio a Windows client checks
before applying Administrative-Template settings. Windows Defender Firewall
rules are ordinary registry-policy values, so they ride the same path.
"""
from __future__ import annotations

import json
import os
import tempfile

# winnt.h registry type numbers, for comparing against an existing Registry.pol.
_REG_TYPE_NUM = {"REG_SZ": 1, "REG_EXPAND_SZ": 2, "REG_BINARY": 3, "REG_DWORD": 4,
                 "REG_MULTI_SZ": 7, "REG_QWORD": 11}

FIREWALL_KEY = r"Software\Policies\Microsoft\WindowsFirewall"
FIREWALL_RULES_KEY = FIREWALL_KEY + r"\FirewallRules"
_PROFILE_KEYS = {"domain": "DomainProfile", "standard": "StandardProfile",
                 "private": "StandardProfile", "public": "PublicProfile"}


class RegPol:
    def __init__(self, engine):
        self.engine = engine

    def load(self, guid: str, entries: list[dict], *, replace: bool = False,
             gpo_dir: str | None = None) -> None:
        """Load a list of policy dicts (samba gpo-load JSON schema) into the GPO.

        Each entry: {keyname, valuename, class(MACHINE|USER|BOTH), type, data}.
        If gpo_dir is given and every entry is already present with the same
        value, the load is skipped (idempotent — no version bump on re-run).
        """
        entries = [e for e in entries if e]
        if not entries:
            return
        if gpo_dir and not self.engine.dry_run and _all_present(gpo_dir, entries):
            self.engine._log("    Registry unverändert — übersprungen")
            return
        if self.engine.dry_run and self.engine.verbose:
            for e in entries:
                print(f"    [dry-run] load {e['class']:7} {e['type']:12} "
                      f"{e['keyname']}\\{e['valuename']} = {e['data']!r}")
        fd, path = tempfile.mkstemp(suffix=".json", prefix="lmgpo-")
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(entries, fh)
            args = ["samba-tool", "gpo", "load", guid, "--content", path]
            if replace:
                args.append("--replace")
            self.engine._run(args)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def remove(self, guid: str, entries: list[dict]) -> None:
        """Remove policy values from the GPO (samba-tool gpo remove)."""
        entries = [e for e in entries if e]
        if not entries:
            return
        fd, path = tempfile.mkstemp(suffix=".json", prefix="lmgpo-rm-")
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(entries, fh)
            self.engine._run(["samba-tool", "gpo", "remove", guid, "--content", path])
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass


def _read_pol(path: str) -> dict:
    """(keyname.lower, valuename.lower) -> (type_num, data) from a Registry.pol."""
    if not os.path.exists(path):
        return {}
    try:
        from samba.dcerpc import preg
        from samba.ndr import ndr_unpack
        with open(path, "rb") as fh:
            data = fh.read()
        if len(data) < 8:
            return {}
        pol = ndr_unpack(preg.file, data)
        return {(e.keyname.lower(), e.valuename.lower()): (int(e.type), e.data)
                for e in pol.entries}
    except Exception:
        return {}


def _all_present(gpo_dir: str, entries: list[dict]) -> bool:
    """True iff every entry already exists in the GPO's Registry.pol(s)."""
    machine = _read_pol(os.path.join(gpo_dir, "Machine", "Registry.pol"))
    user = _read_pol(os.path.join(gpo_dir, "User", "Registry.pol"))
    for e in entries:
        cls = e["class"]
        pols = ([machine] if cls == "MACHINE" else [user] if cls == "USER"
                else [machine, user])
        want_type = _REG_TYPE_NUM.get(e["type"])
        for pol in pols:
            cur = pol.get((e["keyname"].lower(), e["valuename"].lower()))
            if cur is None or cur[0] != want_type:
                return False
            ctype, cdata = cur
            if ctype in (1, 2):        # REG_SZ / REG_EXPAND_SZ
                if str(cdata).rstrip("\x00") != str(e["data"]):
                    return False
            elif ctype in (4, 11):     # REG_DWORD / REG_QWORD
                try:
                    if int(cdata) != int(e["data"]):
                        return False
                except (ValueError, TypeError):
                    return False        # non-numeric -> force a regular load
            elif ctype == 7:           # REG_MULTI_SZ
                want = e["data"] if isinstance(e["data"], list) else [e["data"]]
                try:
                    cur_list = bytes(cdata).decode("utf-16-le").rstrip("\x00").split("\x00")
                except Exception:
                    return False
                if cur_list != [str(x) for x in want]:
                    return False
            else:                       # types we don't compare -> force a load
                return False
    return True


def firewall_entries(fw: dict) -> list[dict]:
    """Translate a catalog 'firewall' block into gpo-load registry entries.

    fw = {
      "profiles": {"domain": {...}, "standard": {...}, "public": {...}},   # optional
      "rules": [ {"id": "LMN-RDP-In-TCP", "string": "v2.31|Action=Allow|..."} ],
    }
    """
    out: list[dict] = []
    for pname, settings in (fw.get("profiles") or {}).items():
        subkey = _PROFILE_KEYS.get(pname.lower())
        if not subkey:
            continue
        base = f"{FIREWALL_KEY}\\{subkey}"
        for vname, val in settings.items():
            out.append({"keyname": base, "valuename": vname, "class": "MACHINE",
                        "type": "REG_DWORD", "data": int(val)})
    for rule in fw.get("rules") or []:
        out.append({"keyname": FIREWALL_RULES_KEY, "valuename": rule["id"],
                    "class": "MACHINE", "type": "REG_SZ", "data": rule["string"]})
    return out
