"""A fake `samba-tool gpo` + sam.ldb writes over FakeAD, so apply runs end to end.

Mimics exactly the behaviour lmn-gpo depends on: `gpo create` prints the new GUID;
`gpo setlink` PREPENDS the link and refuses a GPO that is already linked ("already linked
to this container", Samba netcmd/gpo.py cmd_setlink); dellink/del/backup; aclcheck and
sysvolreset succeed. versionNumber/extension names are written into the fake directory.
`gpo load` merges the JSON entries into Machine/User Registry.pol and raises the matching
half of GPT.INI and versionNumber, as Samba's RegistryGroupPolicies.merge_s() and
increment_gpt_ini() do (python/samba/policies.py).
"""
from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import uuid

from conftest import POLICIES
from lmn_gpo import gplink, regpol, version
from lmn_gpo.gpo import GpoEngine, GpoError

REGISTRY_EXT = "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
_REG_TYPES = {"REG_SZ": 1, "REG_EXPAND_SZ": 2, "REG_BINARY": 3, "REG_DWORD": 4,
              "REG_MULTI_SZ": 7, "REG_QWORD": 11}
_PREG_HEADER = b"PReg" + struct.pack("<I", 1)


def _utf16z(text: str) -> bytes:
    return (text + "\x00").encode("utf-16-le")


def _encode_data(type_num: int, data) -> bytes:
    if type_num == 4:
        return struct.pack("<I", int(data))
    if type_num == 11:
        return struct.pack("<Q", int(data))
    if type_num == 7:
        items = data if isinstance(data, list) else [data]
        return "".join(f"{x}\x00" for x in items).encode("utf-16-le") + b"\x00\x00"
    if type_num == 3:
        return bytes(data)
    return _utf16z(str(data))


def write_pol(path: str, entries: list[tuple[str, str, int, bytes]]) -> None:
    """Write a Registry.pol ([MS-GPREG] 2.2.1): header, then [key;value;type;size;data]."""
    sep = lambda c: c.encode("utf-16-le")  # noqa: E731
    out = bytearray(_PREG_HEADER)
    for key, value, type_num, raw in entries:
        out += (sep("[") + _utf16z(key) + sep(";") + _utf16z(value) + sep(";")
                + struct.pack("<I", type_num) + sep(";") + struct.pack("<I", len(raw))
                + sep(";") + raw + sep("]"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(bytes(out))


def read_pol_entries(path: str) -> list[tuple[str, str, int, bytes]]:
    """Parse a Registry.pol written by write_pol (or by Samba) without the samba bindings."""
    if not os.path.exists(path):
        return []
    data = open(path, "rb").read()
    assert data[:8] == _PREG_HEADER, f"not a PReg v1 file: {path}"
    pos, out = 8, []

    def string(at):
        end = at
        while data[end:end + 2] != b"\x00\x00":
            end += 2
        return data[at:end].decode("utf-16-le"), end + 2

    while pos < len(data):
        assert data[pos:pos + 2] == "[".encode("utf-16-le")
        key, pos = string(pos + 2)
        value, pos = string(pos + 2)
        type_num, = struct.unpack_from("<I", data, pos + 2)
        size, = struct.unpack_from("<I", data, pos + 8)
        raw = data[pos + 14:pos + 14 + size]
        pos += 14 + size
        assert data[pos:pos + 2] == "]".encode("utf-16-le")
        pos += 2
        out.append((key, value, type_num, raw))
    return out


def _decode_data(type_num: int, raw: bytes):
    if type_num == 4:
        return struct.unpack("<I", raw)[0]
    if type_num == 11:
        return struct.unpack("<Q", raw)[0]
    if type_num in (1, 2):
        return raw.decode("utf-16-le")
    return raw


def read_pol(path: str) -> dict:
    """The shape of regpol._read_pol: (key.lower, value.lower) -> (type, data)."""
    return {(k.lower(), v.lower()): (t, _decode_data(t, raw))
            for k, v, t, raw in read_pol_entries(path)}


def _samba_available() -> bool:
    try:
        from samba.dcerpc import preg  # noqa: F401
        from samba.ndr import ndr_unpack  # noqa: F401
    except ImportError:
        return False
    return True


class FakeSamba:
    def __init__(self, fake, sysvol):
        self.fake = fake
        self.sysvol = sysvol
        self.log: list[list[str]] = []

    def run(self, eng, args, *, needs_creds=True, input_text=None, check=True, mutating=True):
        if eng.dry_run and mutating:
            eng._log("    [dry-run] " + " ".join(args))
            return subprocess.CompletedProcess(args, 0, "", "")
        self.log.append(list(args))
        sub = args[1:3]
        out = ""
        if sub == ["gpo", "create"]:
            guid = "{%s}" % str(uuid.uuid4()).upper()
            self.fake.add(f"CN={guid},{POLICIES}", objectClass="groupPolicyContainer", cn=guid,
                          displayName=args[3], flags="0", versionNumber="0")
            os.makedirs(os.path.join(self.sysvol, guid, "Machine"), exist_ok=True)
            os.makedirs(os.path.join(self.sysvol, guid, "User"), exist_ok=True)
            with open(os.path.join(self.sysvol, guid, "GPT.INI"), "w") as fh:
                fh.write("[General]\r\nVersion=0\r\n")
            out = f"GPO '{args[3]}' created as {guid}\n"
        elif sub == ["gpo", "setlink"]:
            dn, guid = args[3], args[4]
            msg = self.fake.get(dn)
            value = (msg.get("gPLink") or [""])[0]
            if guid.upper() in gplink.guids(value):
                raise GpoError(f"samba-tool gpo setlink failed: GPO '{guid}' already linked "
                               f"to this container")
            opts = (2 if "--enforce" in args else 0) | (1 if "--disable" in args else 0)
            msg.set("gPLink", f"[LDAP://CN={guid},{POLICIES};{opts}]" + value)
        elif sub == ["gpo", "dellink"]:
            dn, guid = args[3], args[4]
            msg = self.fake.get(dn)
            links = [lk for lk in gplink.parse((msg.get("gPLink") or [""])[0])
                     if lk.guid != guid.upper()]
            msg.set("gPLink", gplink.encode(links))
        elif sub == ["gpo", "del"]:
            self.fake.entries.pop(f"CN={args[3]},{POLICIES}".lower(), None)
            shutil.rmtree(os.path.join(self.sysvol, args[3]), ignore_errors=True)
        elif sub == ["gpo", "backup"]:
            os.makedirs(os.path.join(args[5], args[3]), exist_ok=True)
        elif sub == ["gpo", "load"]:
            self.load(args[3], json.load(open(args[args.index("--content") + 1])),
                      replace="--replace" in args)
        return subprocess.CompletedProcess(args, 0, out, "")

    def load(self, guid, entries, *, replace=False):
        """samba-tool gpo load: merge_s() + increment_gpt_ini() + extension registration."""
        if replace:
            raise NotImplementedError("the fake only implements the merge mode of gpo load")
        changed = {"Machine": False, "User": False}
        for half in changed:
            path = os.path.join(self.sysvol, guid, half, "Registry.pol")
            pol = read_pol_entries(path)
            for e in entries:
                cls = e["class"].lower()
                if not (cls == "both" or cls == half.lower()):
                    continue
                changed[half] = True
                t = _REG_TYPES[e["type"]]
                item = (e["keyname"], e["valuename"], t, _encode_data(t, e["data"]))
                for i, cur in enumerate(pol):   # Samba matches key and value exactly
                    if cur[0] == e["keyname"] and cur[1] == e["valuename"]:
                        pol[i] = item
                        break
                else:
                    pol.append(item)
            if changed[half]:
                write_pol(path, pol)
        dn = f"CN={guid},{POLICIES}"
        msg = self.fake.get(dn)
        for attr in ("gPCMachineExtensionNames", "gPCUserExtensionNames"):
            cur = (msg.get(attr) or [""])[0] or "[]"
            if REGISTRY_EXT not in cur:
                msg.set(attr, "[" + cur.strip("[]") + REGISTRY_EXT + "]")
        if not (changed["Machine"] or changed["User"]):
            return
        gpt = os.path.join(self.sysvol, guid, "GPT.INI")
        ver = version._read_gpt_ini_version(os.path.join(self.sysvol, guid))
        machine, user = ver & 0xFFFF, ver >> 16
        ver = ((user + changed["User"]) << 16) + machine + changed["Machine"]
        with open(gpt, "w") as fh:
            fh.write(f"[General]\r\nVersion={ver}\r\n")
        msg.set("versionNumber", str(ver))

    def replace_gplink(self, eng, container_dn, old, new):
        msg = self.fake.get(container_dn)
        cur = (msg.get("gPLink") or [""])[0]
        if cur != old:
            raise RuntimeError("LDB_ERR_NO_SUCH_ATTRIBUTE (stale gPLink)")
        msg.set("gPLink", new)

    def write_ad_attr(self, guid, basedn, attr, value):
        self.fake.get(f"CN={guid},CN=Policies,CN=System,{basedn}").set(attr, value)

    def install(self, monkeypatch):
        fs = self
        monkeypatch.setattr(GpoEngine, "_run",
                            lambda eng, args, **kw: fs.run(eng, args, **kw))
        monkeypatch.setattr(GpoEngine, "_replace_gplink",
                            lambda eng, dn, old, new: fs.replace_gplink(eng, dn, old, new))
        monkeypatch.setattr(version, "_write_ad_attr", fs.write_ad_attr)
        if not _samba_available():
            # CI has no python3-samba: read Registry.pol with the pure-Python parser, so the
            # "unchanged -> no load, no version bump" decision is exercised there too.
            monkeypatch.setattr(regpol, "_read_pol", read_pol)
        return self

    def ran(self, *prefix) -> list:
        return [a for a in self.log if a[1:1 + len(prefix)] == list(prefix)]
