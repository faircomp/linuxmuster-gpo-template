"""GPT.INI + AD versionNumber bumping and CSE registration.

Needed for the parts `samba-tool gpo load` does NOT handle (GptTmpl.inf, GPP
Groups.xml, startup scripts): after writing those files into sysvol we must
bump the version in GPT.INI *and* the AD `versionNumber` in lockstep and
register the matching Client-Side-Extension GUID on the GPO object, or Windows
ignores them.

Writes go straight to the local sam.ldb via the system session (same as
sophomorix' ldbmodify), so no Domain-Admin credentials are needed here.
"""
from __future__ import annotations

import os
import re

from . import ad

# CSE GUID -> tool-extension GUID (for GPMC/RSoP display; clients need the CSE).
CSE_TOOL = {
    "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}": "{D02B1F72-3407-48AE-BA88-E8213C6761F1}",  # Registry / Admin Templates
    "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}": "{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}",  # Security (GptTmpl.inf)
    "{17D89FEC-5C44-4972-B12D-241CAEF74509}": "{79F92669-4224-476C-9C5C-6EFB4D87DF4A}",  # GPP Local Users and Groups
    "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}": "{40B6664F-4972-11D1-A7CA-0000F87571E3}",  # Scripts (startup/shutdown)
}
SECURITY_CSE = "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"
GPP_GROUPS_CSE = "{17D89FEC-5C44-4972-B12D-241CAEF74509}"
SCRIPTS_CSE = "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}"


def _gpo_dn(guid: str, basedn: str) -> str:
    return f"CN={guid},CN=Policies,CN=System,{basedn}"


def read_version(guid: str, basedn: str) -> int:
    msg = ad.find_one(f"(cn={guid})", base=f"CN=Policies,CN=System,{basedn}",
                      scope="one", attrs=["versionNumber"])
    return int(ad.val(msg, "versionNumber", "0"))


def _write_ad_attr(guid: str, basedn: str, attr: str, value: str) -> None:
    import ldb

    d = ad.db()
    m = ldb.Message()
    m.dn = ldb.Dn(d, _gpo_dn(guid, basedn))
    m[attr] = ldb.MessageElement(value, ldb.FLAG_MOD_REPLACE, attr)
    d.modify(m)


def set_version(guid: str, basedn: str, sysvol_dir: str, version: int) -> None:
    """Write the version to both GPT.INI and the AD object, in lockstep."""
    gpt = os.path.join(sysvol_dir, "GPT.INI")
    with open(gpt, "w", newline="") as fh:
        fh.write(f"[General]\r\nVersion={version}\r\n")
    _write_ad_attr(guid, basedn, "versionNumber", str(version))


def _read_gpt_ini_version(sysvol_dir: str) -> int:
    try:
        with open(os.path.join(sysvol_dir, "GPT.INI"), encoding="latin-1") as fh:
            for line in fh:
                if line.strip().lower().startswith("version"):
                    return int(line.split("=", 1)[1].strip())
    except Exception:
        pass
    return 0


def bump(guid: str, basedn: str, sysvol_dir: str, *,
         machine: bool = False, user: bool = False) -> int:
    """Increment the machine and/or user counters and persist. Returns new value.

    Seeds from max(AD versionNumber, GPT.INI Version) so a stalled/diverged value
    can never re-issue a number a client already saw. Each counter is 16-bit.
    """
    v = max(read_version(guid, basedn), _read_gpt_ini_version(sysvol_dir))
    mv, uv = v & 0xFFFF, v >> 16
    if machine:
        mv = (mv + 1) & 0xFFFF
    if user:
        uv = (uv + 1) & 0xFFFF
    nv = (uv << 16) | mv
    set_version(guid, basedn, sysvol_dir, nv)
    return nv


def _parse_ext_groups(value: str) -> list[str]:
    """['{cse}{tool}', ...] from '[{cse}{tool}][{cse2}{tool2}]'."""
    return [g for g in re.findall(r"\[([^\]]*)\]", value or "") if g]


def _first_guid(group: str) -> str:
    m = re.search(r"\{[0-9A-Fa-f-]+\}", group)
    return m.group(0).upper() if m else ""


def register_cse(guid: str, basedn: str, cse: str,
                 attr: str = "gPCMachineExtensionNames") -> str:
    """Idempotently splice a CSE (with its tool GUID) into the extension-names
    attribute, keeping the list sorted case-insensitively by CSE GUID."""
    msg = ad.find_one(f"(cn={guid})", base=f"CN=Policies,CN=System,{basedn}",
                      scope="one", attrs=[attr])
    current = ad.val(msg, attr, "") or ""
    groups = _parse_ext_groups(current)
    if cse.upper() in {_first_guid(g) for g in groups}:
        return current  # already registered
    tool = CSE_TOOL.get(cse.upper(), CSE_TOOL.get(cse, ""))
    groups.append(f"{cse}{tool}")
    groups.sort(key=_first_guid)
    newval = "".join(f"[{g}]" for g in groups)
    _write_ad_attr(guid, basedn, attr, newval)
    return newval
