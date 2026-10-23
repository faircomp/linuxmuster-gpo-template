"""Read Drives.xml files - sophomorix' school GPOs and our own - strictly read-only.

lmn-gpo never writes a sophomorix GPO. It only reads them, for two reasons:
  * `remove: all` in drives.yaml means "every letter a school GPO maps", and the WebUI
    (Clients -> Drives) can move a default drive to another letter, so the letters are
    read from the files instead of being assumed to be K P S T R;
  * `doctor` shows per school which letters are mapped, which ones the WebUI disabled,
    and whether a targeting SID exists at all (the sophomorix template ships S: with a
    fixed SID from another domain, so on Windows S: is never connected).
"""
from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from .drives import DRIVES_REL

SCHOOL_GPO_PREFIX = "sophomorix:school:"


@dataclass
class DriveItem:
    letter: str
    action: str
    path: str = ""
    label: str = ""
    disabled: bool = False
    uid: str = ""
    # every FilterGroup anywhere below the item: (name, sid, negated, user context)
    groups: list = field(default_factory=list)


def parse_drives_xml(text: str) -> list[DriveItem]:
    """Items of a Drives.xml. Raises ValueError on XML that does not parse."""
    try:
        root = ET.fromstring(text.encode("utf-8") if isinstance(text, str) else text)
    except ET.ParseError as exc:
        raise ValueError(f"Drives.xml does not parse: {exc}") from exc
    items = []
    for drive in root.iter("Drive"):
        props = drive.find("Properties")
        if props is None:
            continue
        letter = (props.get("letter") or drive.get("name", "")[:1] or "").upper()
        item = DriveItem(letter=letter, action=(props.get("action") or "").upper(),
                         path=props.get("path") or "", label=props.get("label") or "",
                         disabled=drive.get("disabled") == "1", uid=drive.get("uid") or "")
        filters = drive.find("Filters")
        if filters is not None:
            _collect_groups(filters, False, item.groups)
        items.append(item)
    return items


def _collect_groups(node, negated: bool, out: list) -> None:
    for child in node:
        neg = negated ^ (child.get("not") == "1")
        if child.tag == "FilterGroup":
            out.append((child.get("name") or "", (child.get("sid") or "").upper(), neg,
                        child.get("userContext", "1") == "1"))
        elif child.tag == "FilterCollection":
            _collect_groups(child, neg, out)


def read_drives_file(gpo_dir: str) -> list[DriveItem] | None:
    """Items of <gpo_dir>/User/Preferences/Drives/Drives.xml; None if there is no file."""
    path = os.path.join(gpo_dir, DRIVES_REL)
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as fh:
        return parse_drives_xml(fh.read())


def mapped_letters(items: list[DriveItem]) -> set[str]:
    """Letters a file maps (Create/Replace/Update), enabled or disabled."""
    return {i.letter for i in items if i.letter and i.action in ("C", "R", "U", "")}


@dataclass
class SchoolGpo:
    school: str
    guid: str
    display: str
    items: list | None = None      # None = no Drives.xml / unreadable
    error: str = ""


def school_gpos(basedn: str, sysvol_policies: str, ad_module=None) -> list[SchoolGpo]:
    """Every sophomorix:school:<school> GPO with its Drive items (read-only)."""
    if ad_module is None:
        from . import ad as ad_module
    out = []
    base = f"CN=Policies,CN=System,{basedn}"
    for msg in ad_module.search(base=base, scope="one",
                                expr="(objectClass=groupPolicyContainer)",
                                attrs=["displayName", "cn"]):
        name = ad_module.val(msg, "displayName", "") or ""
        if not name.startswith(SCHOOL_GPO_PREFIX):
            continue
        guid = ad_module.val(msg, "cn", "") or ""
        sg = SchoolGpo(school=name[len(SCHOOL_GPO_PREFIX):], guid=guid, display=name)
        try:
            sg.items = read_drives_file(os.path.join(sysvol_policies, guid))
        except (OSError, ValueError) as exc:
            sg.error = str(exc)
        out.append(sg)
    return sorted(out, key=lambda s: s.school)


def letters_of_schools(gpos: list[SchoolGpo]) -> tuple[set[str], str]:
    """All letters the school GPOs map, and a short source note for the output."""
    letters: set[str] = set()
    read = [g for g in gpos if g.items is not None]
    for g in read:
        letters |= mapped_letters(g.items)
    if read:
        src = "read from " + ", ".join(g.display for g in read) + " + sophomorix template"
    else:
        src = "sophomorix template (no school GPO Drives.xml readable)"
    return letters, src
