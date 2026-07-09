"""Security settings via GptTmpl.inf (User Rights + Restricted Groups).

`samba-tool gpo load` cannot set these, so we write the INI ourselves, register
the Security CSE and bump the (machine) version. Used for:
  - SeRemoteInteractiveLogonRight  ("Allow log on through Remote Desktop Services")
  - SeRemoteShutdownPrivilege      ("Force shutdown from a remote system")
  - [Group Membership] __Memberof  (add a domain group to a local group, additive)

User-rights assignments are AUTHORITATIVE (they replace), so callers must pass
the full desired member list including the built-in holders (e.g. Administrators
S-1-5-32-544).
"""
from __future__ import annotations

import os
import textwrap

from . import version

SECEDIT_REL = "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf"

_HEADER = ('[Unicode]\r\n'
           'Unicode=yes\r\n'
           '[Version]\r\n'
           'signature="$CHICAGO$"\r\n'
           'Revision=1\r\n')


def _star(sid: str) -> str:
    return sid if sid.startswith("*") else f"*{sid}"


def render(privilege_rights: dict[str, list[str]] | None,
           group_membership: list[dict] | None) -> str:
    out = _HEADER
    if privilege_rights:
        out += "[Privilege Rights]\r\n"
        for right, sids in privilege_rights.items():
            members = ",".join(_star(s) for s in sids)
            out += f"{right} = {members}\r\n"
    if group_membership:
        out += "[Group Membership]\r\n"
        for gm in group_membership:
            member = _star(gm["member"])
            of = ",".join(_star(s) for s in gm.get("memberof", []))
            out += f"{member}__Memberof = {of}\r\n"
            out += f"{member}__Members =\r\n"
    return out


class SecEdit:
    def __init__(self, engine):
        self.engine = engine

    def apply(self, guid: str, *, privilege_rights: dict | None = None,
              group_membership: list | None = None) -> bool:
        if not privilege_rights and not group_membership:
            return False
        content = render(privilege_rights, group_membership)
        path = os.path.join(self.engine.sysvol_path(guid), SECEDIT_REL)
        if not self.engine.dry_run and os.path.exists(path):
            try:
                if open(path, encoding="utf-16").read().replace("\r\n", "\n") == \
                        content.replace("\r\n", "\n"):
                    # Heal a possible partial prior run: ensure the CSE is registered.
                    version.register_cse(guid, self.engine.env.basedn, version.SECURITY_CSE)
                    self.engine._log("    GptTmpl.inf unverändert — übersprungen")
                    return False
            except Exception:
                pass
        if self.engine.dry_run:
            self.engine._log(f"    [dry-run] GptTmpl.inf → {path}:")
            self.engine._log(textwrap.indent(content.replace("\r\n", "\n").rstrip(), "        "))
            self.engine._log("    [dry-run] register Security-CSE + bump machine version")
            return True
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # GptTmpl.inf is UTF-16LE with BOM (matches Windows-authored templates).
        with open(path, "w", encoding="utf-16") as fh:
            fh.write(content)
        version.register_cse(guid, self.engine.env.basedn, version.SECURITY_CSE)
        version.bump(guid, self.engine.env.basedn, self.engine.sysvol_path(guid),
                     machine=True)
        self.engine._log(f"    GptTmpl.inf geschrieben + Security-CSE/Version gesetzt")
        return True
