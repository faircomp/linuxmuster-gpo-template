"""A fake `samba-tool gpo` + sam.ldb writes over FakeAD, so apply runs end to end.

Mimics exactly the behaviour lmn-gpo depends on: `gpo create` prints the new GUID;
`gpo setlink` PREPENDS the link and refuses a GPO that is already linked ("already linked
to this container", Samba netcmd/gpo.py cmd_setlink); dellink/del/backup; aclcheck and
sysvolreset succeed. versionNumber/extension names are written into the fake directory.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import uuid

from conftest import POLICIES
from lmn_gpo import gplink, version
from lmn_gpo.gpo import GpoEngine, GpoError


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
        return subprocess.CompletedProcess(args, 0, out, "")

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
        return self

    def ran(self, *prefix) -> list:
        return [a for a in self.log if a[1:1 + len(prefix)] == list(prefix)]
