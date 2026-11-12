"""`lmn-gpo doctor`, section "Site to zone list" - read-only.

A GPO with Site to Zone Assignment List values (ZoneMapKey: 12-proxy-zone-schule,
22-edulution-trusted-schule) needs the "Internet Explorer Zonemapping" client-side extension
on the matching extension-names attribute. Without it Windows writes the values into
HKLM\\Software\\Policies\\...\\ZoneMapKey and never turns them into zone mappings: the site
keeps its old zone (lab, Windows 11, 2026-11-12; docs/RESEARCH.md section 10). lmn-gpo up to
7.3.7 did not register it; `lmn-gpo apply` from 7.3.8 on does. A warning, like the other
GPO-state checks: the exit code is unchanged.
"""
from __future__ import annotations

import os

from . import ad, regpol, ui, version

GPO_PREFIX = "LMN-"
_SIDES = (("Machine", "gPCMachineExtensionNames"), ("User", "gPCUserExtensionNames"))


def rows(e) -> list[tuple[str, str, str, bool]]:
    """(display name, GUID, attribute, registered) for every side of every LMN-* GPO whose
    Registry.pol holds a ZoneMapKey value, sorted by name."""
    base = f"CN=Policies,CN=System,{e.basedn}"
    out = []
    for m in ad.search(base=base, scope="one", expr="(objectClass=groupPolicyContainer)",
                       attrs=["displayName", "cn", "gPCMachineExtensionNames",
                              "gPCUserExtensionNames"]):
        name = ad.val(m, "displayName", "") or ""
        if not name.startswith(GPO_PREFIX):
            continue
        guid = ad.val(m, "cn", "") or ""
        gpo_dir = os.path.join(e.sysvol_policies, guid)
        for sub, attr in _SIDES:
            if regpol.pol_has_zonemap(gpo_dir, sub):
                out.append((name, guid, attr,
                            version.has_cse(ad.val(m, attr, "") or "", version.ZONEMAP_CSE)))
    return sorted(out)


def run(e) -> int:
    """Print the section. Returns the number of GPOs that lack the extension."""
    print("\nSite to zone list (ZoneMapKey: 12-proxy-zone-schule, 22-edulution-trusted-schule):")
    found = rows(e)
    if not found:
        print(f"  {ui.OK} no LMN-* GPO carries site-to-zone values")
        return 0
    missing = 0
    for name, guid, attr, registered in found:
        if registered:
            print(f"  {ui.OK} {name}: Internet Explorer Zonemapping extension registered")
            continue
        missing += 1
        print(f"  {ui.WARN} {name} {guid}: has ZoneMapKey values, but the 'Internet Explorer "
              f"Zonemapping' extension {version.ZONEMAP_CSE} is missing from {attr}")
        print("       Windows writes the values and never applies them - the sites keep their "
              "old zone. Run 'lmn-gpo apply' (it registers the extension and bumps the version).")
    return missing
