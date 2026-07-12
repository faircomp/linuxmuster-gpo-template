"""Local administrators via Group Policy Preferences (Groups.xml).

Additive membership of the built-in Administrators group (SID S-1-5-32-544) for
domain groups (global-admins everywhere, <school>-admins per school), using GPP
'Local Users and Groups' with action="U" (Update) so existing members are kept.
We write the XML, register the GPP-Groups CSE and bump the (machine) version.
"""
from __future__ import annotations

import os
import textwrap
import uuid
from xml.sax.saxutils import quoteattr

from . import version

GROUPS_REL = "Machine/Preferences/Groups/Groups.xml"
ADMINISTRATORS_SID = "S-1-5-32-544"
_GROUPS_CLSID = "{3125E937-EB16-4b4c-9934-544FC6D24D26}"
_GROUP_CLSID = "{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}"


def render(members: list[dict], *, changed: str, group_uid: str) -> str:
    """members: [{'name': 'EVSVBZ\\\\global-admins', 'sid': 'S-1-5-...'}]"""
    lines = []
    for m in members:
        lines.append(
            f'        <Member name={quoteattr(m["name"])} action="ADD" '
            f'sid={quoteattr(m["sid"])}/>'
        )
    members_xml = "\n".join(lines)
    return (
        '<?xml version="1.0" encoding="utf-8"?>\r\n'
        f'<Groups clsid="{_GROUPS_CLSID}">\r\n'
        f'  <Group clsid="{_GROUP_CLSID}" name="Administrators (built-in)" '
        f'image="2" changed={quoteattr(changed)} uid={quoteattr(group_uid)}>\r\n'
        '    <Properties action="U" newName="" description="" deleteAllUsers="0" '
        'deleteAllGroups="0" removeAccounts="0" '
        f'groupSid="{ADMINISTRATORS_SID}" groupName="Administrators (built-in)">\r\n'
        '      <Members>\r\n'
        f'{members_xml}\r\n'
        '      </Members>\r\n'
        '    </Properties>\r\n'
        '  </Group>\r\n'
        '</Groups>\r\n'
    )


class GppGroups:
    def __init__(self, engine):
        self.engine = engine

    def add_local_admins(self, guid: str, members: list[dict]) -> bool:
        """members: list of {'name': 'DOMAIN\\group', 'sid': 'S-1-5-...'}."""
        members = [m for m in members if m and m.get("sid")]
        if not members:
            return False
        # Deterministic changed/uid so the XML is byte-stable across runs (idempotent),
        # but uid is derived from the GPO guid so two GPOs never share a GPP item uid.
        changed = "2024-01-01 00:00:00"
        group_uid = "{%s}" % uuid.uuid5(uuid.NAMESPACE_DNS, "lmgpo-local-admins:" + guid)
        content = render(members, changed=changed, group_uid=group_uid)
        path = os.path.join(self.engine.sysvol_path(guid), GROUPS_REL)
        if not self.engine.dry_run and os.path.exists(path):
            try:
                if open(path, encoding="utf-8").read().replace("\r\n", "\n") == \
                        content.replace("\r\n", "\n"):
                    # Heal a possible partial prior run: ensure the CSE is registered.
                    version.register_cse(guid, self.engine.env.basedn, version.GPP_GROUPS_CSE)
                    self.engine._log("    Groups.xml unchanged — skipped")
                    return False
            except Exception:
                pass
        if self.engine.dry_run:
            self.engine._log(f"    [dry-run] Groups.xml → {path}:")
            self.engine._log(textwrap.indent(content.replace('\r\n', '\n').rstrip(), "        "))
            self.engine._log("    [dry-run] register GPP-Groups-CSE + bump machine version")
            return True
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        version.register_cse(guid, self.engine.env.basedn, version.GPP_GROUPS_CSE)
        version.bump(guid, self.engine.env.basedn, self.engine.sysvol_path(guid),
                     machine=True)
        self.engine._log("    Groups.xml written + GPP CSE/version set")
        return True
