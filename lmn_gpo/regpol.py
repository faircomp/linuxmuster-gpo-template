"""Registry-based policy via `samba-tool gpo load`.

`samba-tool gpo load` writes Machine/User Registry.pol, bumps GPT.INI + the AD
versionNumber in lockstep, and registers the Registry CSE GUID
{35378EAC-683F-11D2-A89A-00C04FBBCFA2} — the exact trio a Windows client checks
before applying Administrative-Template settings. Windows Defender Firewall
rules are ordinary registry-policy values, so they ride the same path.

One registry policy needs a second extension: the Site to Zone Assignment List
(ZoneMapKey values). The registry extension only writes them; the "Internet Explorer
Zonemapping" extension turns them into the zone mappings Windows uses. RegPol.load
registers it on every GPO whose values include ZoneMapKey, after the load
(version.ZONEMAP_CSE, docs/RESEARCH.md section 10).
"""
from __future__ import annotations

import json
import os
import tempfile

from . import version

# winnt.h registry type numbers, for comparing against an existing Registry.pol.
_REG_TYPE_NUM = {"REG_SZ": 1, "REG_EXPAND_SZ": 2, "REG_BINARY": 3, "REG_DWORD": 4,
                 "REG_MULTI_SZ": 7, "REG_QWORD": 11}

# Site to Zone Assignment List (inetres.admx IZ_Zonemaps), machine or user side.
ZONEMAP_KEY = r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMapKey"
# Which extension-names attribute and which half of versionNumber belong to a class.
_SIDES = (("MACHINE", "Machine", "gPCMachineExtensionNames"),
          ("USER", "User", "gPCUserExtensionNames"))

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

        replace=True: `samba-tool gpo load --replace` writes a NEW Registry.pol for every
        class the entries name (samba policies.py replace_s; the other class's file is not
        touched), so a value that is no longer wanted disappears. The skip check is then
        "exactly these values", not "at least these".
        """
        entries = [e for e in entries if e]
        if not entries:
            return
        present = _exactly_present if replace else _all_present
        if gpo_dir and not self.engine.dry_run and present(gpo_dir, entries):
            self.engine._log("    Registry unchanged — skipped")
        else:
            self._load(guid, entries, replace)
        # Also when the values were unchanged: a GPO written before the zone-map extension
        # was registered (lmn-gpo up to 7.3.6) gets it now.
        self.ensure_zonemap_cse(guid, entries)

    def _load(self, guid: str, entries: list[dict], replace: bool) -> None:
        if self.engine.dry_run and self.engine.verbose:
            for e in entries:
                print(f"    [dry-run] load {e['class']:7} {e['type']:12} "
                      f"{e['keyname']}\\{e['valuename']} = {e['data']!r}")
        fd, path = tempfile.mkstemp(suffix=".json", prefix="lmn-gpo-")
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

    def ensure_zonemap_cse(self, guid: str, entries: list[dict]) -> bool:
        """Register the Internet Explorer Zonemapping extension on the side(s) whose entries
        carry ZoneMapKey values, and bump that half of versionNumber when the attribute
        changed, so a client notices. Idempotent: registered already = no write, no bump.
        Returns True if something was (or, in dry-run, would be) changed.

        Only ever AFTER `samba-tool gpo load`: the load registers the registry extension by
        appending '{35378eac-...}' inside the LAST group of whatever the attribute holds.
        Registered before the first load, the zone-map group would swallow it and the GPO
        would lose its registry extension (version.splice_cse)."""
        changed = False
        basedn = self.engine.env.basedn
        for cls, half, attr in _SIDES:
            if not zonemap_values(entries, cls):
                continue
            before = version.ext_names(guid, basedn, attr)
            if version.has_cse(before, version.ZONEMAP_CSE):
                continue
            changed = True
            if self.engine.dry_run:
                self.engine._log(f"    [dry-run] register IE-Zonemapping-CSE on {attr} + bump "
                                 f"{half.lower()} version")
                continue
            version.register_cse(guid, basedn, version.ZONEMAP_CSE, attr=attr)
            version.bump(guid, basedn, self.engine.sysvol_path(guid),
                         machine=half == "Machine", user=half == "User")
            self.engine._log(f"    IE-Zonemapping-CSE registered ({attr}) + {half.lower()} "
                             f"version bumped")
        return changed

    def remove(self, guid: str, entries: list[dict]) -> None:
        """Remove policy values from the GPO (samba-tool gpo remove)."""
        entries = [e for e in entries if e]
        if not entries:
            return
        fd, path = tempfile.mkstemp(suffix=".json", prefix="lmn-gpo-rm-")
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(entries, fh)
            self.engine._run(["samba-tool", "gpo", "remove", guid, "--content", path])
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass


def zonemap_values(entries: list[dict], cls: str) -> bool:
    """True iff an entry of class `cls` (MACHINE/USER; BOTH counts for either) sets a
    value under the Site to Zone Assignment List key."""
    want = ZONEMAP_KEY.lower()
    return any(e["keyname"].lower() == want and e["class"] in (cls, "BOTH")
               for e in entries if e)


def pol_has_zonemap(gpo_dir: str, sub: str) -> bool:
    """True iff the GPO's <sub>/Registry.pol (sub = Machine or User) holds a ZoneMapKey
    value. Unreadable or missing file: False."""
    want = ZONEMAP_KEY.lower()
    return any(key == want and not name.startswith("**")
               for key, name in _read_pol(os.path.join(gpo_dir, sub, "Registry.pol")))


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


def _exactly_present(gpo_dir: str, entries: list[dict]) -> bool:
    """True iff the Registry.pol of every class the entries name holds exactly these values
    and no other one - the idempotency check of a `--replace` load."""
    if not _all_present(gpo_dir, entries):
        return False
    want: dict[str, set] = {"Machine": set(), "User": set()}
    for e in entries:
        key = (e["keyname"].lower(), e["valuename"].lower())
        if e["class"] in ("MACHINE", "BOTH"):
            want["Machine"].add(key)
        if e["class"] in ("USER", "BOTH"):
            want["User"].add(key)
    for sub, keys in want.items():
        if keys and set(_read_pol(os.path.join(gpo_dir, sub, "Registry.pol"))) != keys:
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
