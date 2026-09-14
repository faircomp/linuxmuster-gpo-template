"""Network drive mappings via Group Policy Preferences (Drives.xml).

Used for the H: home drive, which linuxmuster normally leaves to Winlogon: the DC
returns homeDrive/homeDirectory in the Kerberos PAC and Winlogon connects H: during
session setup. On a notebook that authenticates over 802.1X the link is often not up
at that moment, so H: silently stays missing while the desktop appears normally.

The Drive Maps CSE runs LATER in the same logon (after the GPO list is fetched) and,
unlike Winlogon, it is re-invoked when the machine regains connectivity to a Group
Policy server ([MS-GPOL] 3.2.7.1). So this is a safety net, not a speed-up: it does
not make H: appear sooner, it makes it appear at all.

The path is not hardcoded per school/role. A `FilterLdap` targeting item reads the
user's own homeDirectory attribute into a variable which the item's own `path` then
expands ([MS-GPPREF] 2.2.1.22: the LDAP query targeting item "can assign the value
that it retrieves from the directory service ... to an environment variable that can
be used later in the protocol processing"). One item therefore covers every school,
every role and every class - which matters because student homes carry the class in
the path (\\\\server\\<school>\\students\\<class>\\<user>) and there is no preference
variable for the class.

VERIFIED on a real client (Windows 11 24H2) rather than assumed: a second item on a
letter Winlogon never touches proved the variable really expands in `path`, for a
teacher (\\\\server\\schule2\\teachers\\zweit) and for a student with a class in the
path (\\\\server\\schule2\\students\\k1\\testscti).

Note: like Groups.xml, a file written here has no security.NTACL of its own until the
sysvol ACLs are reconciled - `Applier.run()` does that at the end of every apply. Do
not write these files outside an apply run or `samba-tool ntacl sysvolcheck` fails.
"""
from __future__ import annotations

import os
import textwrap
import uuid
from xml.sax.saxutils import quoteattr

from . import version

DRIVES_REL = "User/Preferences/Drives/Drives.xml"
_DRIVES_CLSID = "{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}"
_DRIVE_CLSID = "{935D1B74-9CB8-4e3c-9914-7DD559B7A417}"
# Deterministic so the XML is byte-stable across runs (idempotent). Matches the
# convention GPMC writes, which is upper case.
_CHANGED = "2024-01-01 00:00:00"


def _uid(guid: str, letter: str) -> str:
    return ("{%s}" % uuid.uuid5(uuid.NAMESPACE_DNS,
                                f"lmn-gpo-drive:{guid}:{letter}")).upper()


def _filters(item: dict) -> str:
    """Targeting items. FilterLdap doubles as the producer of the path variable."""
    parts = []
    attr = (item.get("from_ldap") or "").strip()
    if attr:
        # %LogonUser% is a documented preference process variable and carries the bare
        # user name, i.e. the sAMAccountName. The & must be escaped for XML, not for LDAP.
        parts.append(
            '      <FilterLdap bool="AND" not="0" binding="LDAP:" '
            'searchFilter="(&amp;(objectClass=user)(sAMAccountName=%LogonUser%))" '
            f'attribute={quoteattr(attr)} variableName={quoteattr(_var_name(attr))}/>'
        )
    for grp in item.get("groups") or []:
        if not grp.get("sid"):
            continue
        parts.append(
            f'      <FilterGroup bool="AND" not="0" name={quoteattr(grp.get("name", ""))} '
            f'sid={quoteattr(grp["sid"])} userContext="1" primaryGroup="0" localGroup="0"/>'
        )
    if not parts:
        return ""
    return "    <Filters>\r\n" + "\r\n".join(parts) + "\r\n    </Filters>\r\n"


def _var_name(attr: str) -> str:
    """Own namespace so we can never collide with a real Windows variable."""
    return "lmn" + attr[:1].upper() + attr[1:]


def render(items: list[dict], guid: str) -> str:
    body = []
    for it in items:
        letter = str(it["letter"]).strip().upper()[:1]
        path = it.get("path") or ""
        if it.get("from_ldap"):
            path = path or "%" + _var_name(it["from_ldap"]) + "%"
        # action "U" (Update) is the only fail-closed choice: on a letter that already
        # holds a working mapping it is a no-op (it cannot relocate an existing one),
        # and where the letter is free it creates the mapping. "R" (Replace) would
        # delete first and lose a working H: if the re-create then failed.
        action = str(it.get("action") or "U").strip().upper()[:1]
        # NEVER useLetter="0": that is "delete all, starting at" and wipes every
        # mapping from this letter through Z: (KB3091116).
        props = (
            f'    <Properties action={quoteattr(action)} thisDrive="SHOW" '
            f'allDrives="NOCHANGE" userName="" path={quoteattr(path)} '
            f'label={quoteattr(it.get("label") or "")} persistent="0" '
            f'useLetter="1" letter={quoteattr(letter)}/>\r\n'
        )
        body.append(
            f'  <Drive clsid="{_DRIVE_CLSID}" name="{letter}:" status="{letter}:" '
            f'image="2" changed="{_CHANGED}" uid="{_uid(guid, letter)}" '
            'bypassErrors="1">\r\n'
            + props + _filters(it) +
            '  </Drive>\r\n'
        )
    return (
        '<?xml version="1.0" encoding="utf-8"?>\r\n'
        f'<Drives clsid="{_DRIVES_CLSID}">\r\n'
        + "".join(body) +
        '</Drives>\r\n'
    )


class GppDrives:
    def __init__(self, engine):
        self.engine = engine

    def set_drives(self, guid: str, items: list[dict]) -> bool:
        items = [i for i in items if i and i.get("letter")]
        if not items:
            return False
        content = render(items, guid)
        path = os.path.join(self.engine.sysvol_path(guid), DRIVES_REL)
        if not self.engine.dry_run and os.path.exists(path):
            try:
                if open(path, encoding="utf-8").read().replace("\r\n", "\n") == \
                        content.replace("\r\n", "\n"):
                    # Heal a possible partial prior run: ensure the CSE is registered.
                    version.register_cse(guid, self.engine.env.basedn,
                                         version.GPP_DRIVES_CSE,
                                         attr="gPCUserExtensionNames")
                    self.engine._log("    Drives.xml unchanged — skipped")
                    return False
            except Exception:
                pass
        if self.engine.dry_run:
            self.engine._log(f"    [dry-run] Drives.xml → {path}:")
            self.engine._log(textwrap.indent(content.replace('\r\n', '\n').rstrip(), "        "))
            self.engine._log("    [dry-run] register GPP-Drives-CSE + bump user version")
            return True
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        # Drive Maps is user policy: the CSE goes on gPCUserExtensionNames and the USER
        # half of versionNumber is bumped. (Groups.xml is the machine counterpart.)
        version.register_cse(guid, self.engine.env.basedn, version.GPP_DRIVES_CSE,
                             attr="gPCUserExtensionNames")
        version.bump(guid, self.engine.env.basedn, self.engine.sysvol_path(guid),
                     user=True)
        self.engine._log("    Drives.xml written + GPP CSE/user version set")
        return True
