"""Thin read-only helpers over the local Samba AD database (sam.ldb).

Runs on the linuxmuster.net Samba AD DC as root and talks directly to the
local ldb via the Samba python bindings (no network, no credentials needed
for reads). Everything here is read-only; writes go through samba-tool /
the gpo engine.
"""
from __future__ import annotations

import functools

SAM_LDB = "/var/lib/samba/private/sam.ldb"
SMB_CONF = "/etc/samba/smb.conf"


class NotADomainController(RuntimeError):
    """Raised when the Samba AD database / python bindings are unavailable."""


@functools.lru_cache(maxsize=1)
def _loadparm():
    try:
        from samba.param import LoadParm
    except ImportError as exc:  # pragma: no cover - only on non-DC hosts
        raise NotADomainController(
            "Samba python bindings not found — run this on the Samba AD DC."
        ) from exc
    lp = LoadParm()
    try:
        lp.load(SMB_CONF)
    except Exception:
        lp.load_default()
    return lp


@functools.lru_cache(maxsize=1)
def db():
    """Return a cached SamDB handle bound to the local sam.ldb (system session)."""
    import os

    if not os.path.exists(SAM_LDB):
        raise NotADomainController(f"{SAM_LDB} not found — not a Samba AD DC?")
    try:
        from samba.samdb import SamDB
        from samba.auth import system_session
    except ImportError as exc:  # pragma: no cover
        raise NotADomainController(
            "Samba python bindings not found — run this on the Samba AD DC."
        ) from exc
    return SamDB(url=SAM_LDB, session_info=system_session(), lp=_loadparm())


def base_dn() -> str:
    return str(db().domain_dn())


_SCOPES = {"base": 0, "one": 1, "sub": 2}  # ldb.SCOPE_BASE / ONELEVEL / SUBTREE


def search(base: str | None = None, scope: str = "sub",
           expr: str = "(objectClass=*)", attrs: list[str] | None = None):
    """Search the directory. Returns a list of ldb.Message objects."""
    import ldb

    d = db()
    scope_map = {"base": ldb.SCOPE_BASE, "one": ldb.SCOPE_ONELEVEL, "sub": ldb.SCOPE_SUBTREE}
    if base is None:
        base = d.domain_dn()
    try:
        res = d.search(base=base, scope=scope_map[scope], expression=expr, attrs=attrs)
    except ldb.LdbError:
        return []
    return list(res)


def val(msg, attr: str, default=None):
    """First value of an attribute as str, or default."""
    if msg is None or attr not in msg:
        return default
    return str(msg[attr][0])


def sid_of(msg):
    """Decode objectSid to its S-1-5-... string, or None."""
    if msg is None or "objectSid" not in msg:
        return None
    from samba.dcerpc import security
    from samba.ndr import ndr_unpack

    raw = bytes(msg["objectSid"][0])
    return str(ndr_unpack(security.dom_sid, raw))


def find_one(expr: str, base: str | None = None, scope: str = "sub",
             attrs: list[str] | None = None):
    """Return the first matching message or None."""
    if attrs is None:
        attrs = ["cn", "sAMAccountName", "objectSid", "sophomorixType"]
    res = search(base=base, scope=scope, expr=expr, attrs=attrs)
    return res[0] if res else None


def descriptor_sddl(dn: str) -> str | None:
    """Return the object's nTSecurityDescriptor as an SDDL string, or None."""
    res = search(base=dn, scope="base", attrs=["nTSecurityDescriptor"])
    if not res or "nTSecurityDescriptor" not in res[0]:
        return None
    from samba.dcerpc import security
    from samba.ndr import ndr_unpack

    raw = bytes(res[0]["nTSecurityDescriptor"][0])
    sd = ndr_unpack(security.descriptor, raw)
    try:
        return sd.as_sddl(security.dom_sid(db().get_domain_sid()))
    except Exception:
        return sd.as_sddl()


def sddl_trustee(sid: str) -> str:
    """Return the SDDL trustee token that as_sddl() renders for this SID.

    descriptor_sddl() abbreviates well-known / domain-relative SIDs to aliases
    (S-1-5-11->AU, RID-512->DA, RID-513->DU, ...). To compare a target SID against
    those stored ACEs robustly, normalise the target the same way (round-trip one
    ACE through from_sddl/as_sddl). Sophomorix group SIDs (RID>=1000) are not
    aliased and come back unchanged. Falls back to the raw SID on any error.
    """
    import re
    from samba.dcerpc import security

    try:
        dom = security.dom_sid(db().get_domain_sid())
        s = security.descriptor.from_sddl(f"D:(A;;CC;;;{sid})", dom).as_sddl(dom)
    except Exception:
        return sid
    m = re.search(r"\(A;;CC;;;([^)]+)\)", s)
    return m.group(1) if m else sid


def sysvolcheck() -> tuple[bool, str]:
    """Run `samba-tool ntacl sysvolcheck`. Returns (ok, output)."""
    import subprocess

    try:
        p = subprocess.run(
            ["samba-tool", "ntacl", "sysvolcheck"],
            capture_output=True, text=True, timeout=120,
        )
        out = (p.stdout + p.stderr).strip()
        return p.returncode == 0, out
    except Exception as exc:  # pragma: no cover
        return False, str(exc)
