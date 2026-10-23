"""Parse and edit the gPLink attribute of a container (pure, no AD access).

Format ([MS-GPOL] 2.2.2): a concatenation of `[LDAP://<GPO DN>;<options>]`, where the
options are a decimal bit field: 1 = link disabled, 2 = link enforced. The order of the
entries is the link order Windows uses (see gporder.py), so an edit must never move one.

`samba-tool gpo setlink` refuses a GPO that is already linked ("already linked to this
container", Samba netcmd/gpo.py cmd_setlink) and has no command to change the options of
an existing link. `set_options()` is the in-place edit the engine needs instead: it
rewrites exactly one entry's options and leaves every other entry byte-identical, in the
same position - including entries GPMC wrote in its own spelling (`cn={...},cn=policies`).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

GPLINK_DISABLE = 1
GPLINK_ENFORCE = 2

_ENTRY = re.compile(r"\[(LDAP://)([^;\[\]]*);(\d+)\]", re.IGNORECASE)
_GUID = re.compile(r"^\s*CN=(\{[0-9A-Fa-f-]{36}\})\s*,", re.IGNORECASE)


@dataclass
class Link:
    dn: str          # the GPO DN as stored (spelling untouched)
    options: int
    raw: str         # the whole "[LDAP://...;n]" entry exactly as stored

    @property
    def guid(self) -> str:
        """The GPO GUID in upper case ('' if the DN is not a GPO DN)."""
        m = _GUID.match(self.dn)
        return m.group(1).upper() if m else ""

    @property
    def enforced(self) -> bool:
        return bool(self.options & GPLINK_ENFORCE)

    @property
    def disabled(self) -> bool:
        return bool(self.options & GPLINK_DISABLE)


def parse(value: str | None) -> list[Link]:
    """All entries in stored order. Raises ValueError on anything that is not a gPLink:
    an edit of a value we do not fully understand would risk losing the other links."""
    value = value or ""
    out, pos = [], 0
    for m in _ENTRY.finditer(value):
        if value[pos:m.start()].strip():
            raise ValueError(f"badly formed gPLink near {value[pos:m.start()]!r}")
        out.append(Link(dn=m.group(2), options=int(m.group(3)), raw=m.group(0)))
        pos = m.end()
    if value[pos:].strip():
        raise ValueError(f"badly formed gPLink near {value[pos:]!r}")
    return out


def encode(links: list[Link]) -> str:
    return "".join(link.raw for link in links)


def guids(value: str | None) -> list[str]:
    """GUIDs linked in this value, in stored order. Tolerant: a value that does not parse
    still yields the GUIDs a plain search finds (read-only callers must not crash)."""
    try:
        return [link.guid for link in parse(value) if link.guid]
    except ValueError:
        return [g.upper() for g in re.findall(r"CN=(\{[0-9A-Fa-f-]{36}\})", value or "",
                                              re.IGNORECASE)]


def options_of(value: str | None, guid: str) -> int | None:
    """The options of the first link to this GPO, or None if it is not linked."""
    for link in parse(value):
        if link.guid == guid.upper():
            return link.options
    return None


def set_options(value: str | None, guid: str, options: int) -> str:
    """Return the gPLink with the options of every link to `guid` set to `options`.

    Position and spelling of the edited entry are kept; all other entries are copied
    byte for byte. Raises ValueError if the GPO is not linked here.
    """
    links = parse(value)
    hit = False
    for link in links:
        if link.guid == guid.upper():
            hit = True
            link.options = int(options)
            # keep the stored prefix spelling ("LDAP://") and the DN exactly as they were
            m = _ENTRY.fullmatch(link.raw)
            link.raw = f"[{m.group(1)}{link.dn};{int(options)}]"
    if not hit:
        raise ValueError(f"{guid} is not linked in this gPLink")
    return encode(links)


def describe(options: int | None) -> str:
    """Human words for a link's options, as GPMC shows them."""
    if options is None:
        return "not linked"
    words = ["enforced" if options & GPLINK_ENFORCE else "not enforced"]
    if options & GPLINK_DISABLE:
        words.append("DISABLED")
    return ", ".join(words)
