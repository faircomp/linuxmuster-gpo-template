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
from xml.sax.saxutils import escape, quoteattr

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



# --------------------------------------------------------------------------- #
# Pack 20-drives: the admin's own drive letters from drives.yaml
# --------------------------------------------------------------------------- #
# Item kinds, in the order they are written (GPP processes a file top to bottom):
#   "del"   Delete one of linuxmuster's default letters (action D, useLetter 1)
#   "home"  H: from the user's homeDirectory, exactly the 19-home-h item (action U)
#   "map"   the admin's own path (action R by default, U on request)
# The image index is the one GPMC shows for each action.
_IMAGE = {"C": "0", "R": "1", "U": "2", "D": "3"}


def _uid_managed(guid: str, kind: str, letter: str, index: int) -> str:
    """One UID per item. Two entries for the same letter must not share one, so the
    kind and the position among the items of that letter and kind are part of the name."""
    return ("{%s}" % uuid.uuid5(uuid.NAMESPACE_DNS,
                                f"lmn-gpo-drive:{guid}:{kind}:{letter}:{index}")).upper()


def _attr(value) -> str:
    """A double-quoted XML attribute value, then every non-ASCII character as a numeric
    character reference: sysvol XML stays pure ASCII (CI checks it), and a label with an
    umlaut survives intact (&#252;)."""
    text = escape(str(value), {'"': "&quot;", "\n": "&#10;", "\r": "&#13;", "\t": "&#9;"})
    return '"' + text.encode("ascii", "xmlcharrefreplace").decode("ascii") + '"'


def _group_items(groups: list[dict], indent: str, user: bool) -> list[str]:
    """FilterGroup items, any-of: the first one AND (with the collection's start value),
    every further one OR. Only items with a SID are ever written - Windows evaluates the
    SID, not the name, and a name-only item would match nobody (or, negated, everybody)."""
    out = []
    for i, grp in enumerate(g for g in groups if g.get("sid")):
        out.append(
            f'{indent}<FilterGroup bool="{"AND" if i == 0 else "OR"}" not="0" '
            f'name={_attr(grp.get("name", ""))} sid={_attr(grp["sid"])} '
            f'userContext="{1 if user else 0}" primaryGroup="0" localGroup="0"/>'
        )
    return out


def _condition(cond: dict, indent: str) -> list[str]:
    """One condition = (any of its user groups) AND (any of its device groups), each as
    its own FilterCollection, so the AND/OR of the items can never bleed into each other."""
    out = []
    for key, user in (("groups", True), ("devices", False)):
        items = _group_items(cond.get(key) or [], indent + "  ", user)
        if items:
            out.append(f'{indent}<FilterCollection bool="AND" not="0">')
            out.extend(items)
            out.append(f'{indent}</FilterCollection>')
    return out


def _managed_filters(item: dict) -> str:
    lines = []
    if item.get("kind") == "home":
        # exactly the 19-home-h producer of %lmnHomeDirectory% (proven on Windows 11 24H2)
        lines.append(
            '      <FilterLdap bool="AND" not="0" binding="LDAP:" '
            'searchFilter="(&amp;(objectClass=user)(sAMAccountName=%LogonUser%))" '
            f'attribute={quoteattr("homeDirectory")} '
            f'variableName={quoteattr(_var_name("homeDirectory"))}/>'
        )
    lines += _condition(item, "      ")
    # "the first matching entry wins": every earlier entry for the same letter is
    # excluded explicitly, so the result does not depend on how Replace and Update
    # interact on a letter that an earlier item has just mapped.
    for earlier in item.get("exclude") or []:
        inner = _condition(earlier, "        ")
        if not inner:
            continue
        lines.append('      <FilterCollection bool="AND" not="1">')
        lines.extend(inner)
        lines.append('      </FilterCollection>')
    if not lines:
        return ""
    return "    <Filters>\r\n" + "\r\n".join(lines) + "\r\n    </Filters>\r\n"


def render_managed(items: list[dict], guid: str) -> str:
    """Drives.xml for pack 20-drives, from resolved items (drivesconf.plan()).

    Each item: kind (del|home|map), letter, action (D|R|U), path, label, persistent,
    remove_policy, index, groups/devices [{name, sid}], exclude [{groups, devices}],
    disabled. Byte-stable for the same input: fixed timestamp, deterministic UIDs.
    """
    body = []
    for it in items:
        letter = str(it["letter"]).strip().upper()[:1]
        kind = it.get("kind", "map")
        action = str(it.get("action") or "R").strip().upper()[:1]
        if kind == "home":
            action = "U"
        elif kind == "del":
            action = "D"
        if kind == "home":
            path = "%" + _var_name("homeDirectory") + "%"
            this_drive = "SHOW"
            label = it.get("label") or "Home"
        elif kind == "del":
            path, this_drive, label = "", "NOCHANGE", ""
        else:
            path, this_drive, label = it.get("path") or "", "NOCHANGE", it.get("label") or ""
        persistent = "1" if (it.get("persistent") and kind == "map") else "0"
        extra = ""
        if it.get("remove_policy") and kind == "map" and action == "R":
            extra += ' removePolicy="1"'
        if it.get("disabled"):
            extra += ' disabled="1"'
        # NEVER useLetter="0": "delete all, starting at" wipes every mapping from this
        # letter through Z: (KB3091116). A Delete item names exactly one letter.
        props = (
            f'    <Properties action="{action}" thisDrive="{this_drive}" '
            f'allDrives="NOCHANGE" userName="" path={_attr(path)} '
            f'label={_attr(label)} persistent="{persistent}" '
            f'useLetter="1" letter="{letter}"/>\r\n'
        )
        body.append(
            f'  <Drive clsid="{_DRIVE_CLSID}" name="{letter}:" status="{letter}:" '
            f'image="{_IMAGE[action]}" changed="{_CHANGED}" '
            f'uid="{_uid_managed(guid, kind, letter, int(it.get("index", 0)))}"'
            f'{extra} bypassErrors="1">\r\n'
            + props + _managed_filters(it) +
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
        return self.set_content(guid, render(items, guid))

    def set_content(self, guid: str, content: str) -> bool:
        """Write a rendered Drives.xml. Unchanged content = no write, no version bump."""
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
            try:
                if open(path, encoding="utf-8").read().replace("\r\n", "\n") == \
                        content.replace("\r\n", "\n"):
                    self.engine._log("    [dry-run] Drives.xml unchanged")
                    return False
            except OSError:
                pass
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
