"""Load the declarative YAML policy catalog."""
from __future__ import annotations

import glob
import os
from dataclasses import dataclass, field

import yaml

from .paths import CATALOG_DIR, SCRIPTS_DIR


@dataclass
class Pack:
    id: str
    title: str
    scope: str = "global"          # global | school
    target: str = "computer"       # computer | user | both
    loopback: str = "none"         # none | merge | replace
    enabled: bool = True
    requires: str = ""             # "" | kmshost | wallpaper (skip pack if unmet)
    description: str = ""
    dsgvo: str = ""
    registry: list = field(default_factory=list)
    firewall: dict = field(default_factory=dict)
    privilege_rights: dict = field(default_factory=dict)
    restricted_groups: list = field(default_factory=list)
    local_admins: list = field(default_factory=list)
    startup_scripts: list = field(default_factory=list)
    shutdown_scripts: list = field(default_factory=list)
    wlan: dict = field(default_factory=dict)            # {mode: psk|enterprise} -> generated startup script
    drives: list = field(default_factory=list)          # GPP Drive Maps items (USER policy)
    filter_deny: list = field(default_factory=list)     # deny-apply these groups
    filter_apply: list = field(default_factory=list)    # EXCLUSIVE: only these groups apply
    # Device groups that must not receive this GPO AT ALL (deny Read). Needed instead of
    # filter_deny for user settings delivered via loopback: Apply is evaluated against the
    # user, so a device-group deny-Apply never matches (see GpoEngine.deny_read).
    filter_deny_read: list = field(default_factory=list)
    # Link at the pack's container with the Enforced flag (gPLinkOptions 2), so it is
    # processed after every non-enforced link below it (20-drives: after the sophomorix
    # school GPOs). apply sets it on a new link and restores it on an existing one.
    link_enforced: bool = False
    # Drive Maps items come from an admin file instead of `drives:` (20-drives:
    # "drives.yaml" = site.yaml's drives_file, default /etc/linuxmuster/lmn-gpo/drives.yaml).
    drives_source: str = ""

    @property
    def has_user(self) -> bool:
        if self.drives or self.drives_source:   # Drive Maps: user policy, no registry
            return True
        return any(str(e.get("class", "machine")).lower() in ("user", "both") for e in self.registry)

    @property
    def has_machine(self) -> bool:
        if any(str(e.get("class", "machine")).lower() in ("machine", "both") for e in self.registry):
            return True
        return bool(self.firewall or self.privilege_rights or self.restricted_groups
                    or self.local_admins or self.startup_scripts or self.shutdown_scripts
                    or self.wlan or self.loopback in ("merge", "replace"))

    @property
    def type_letter(self) -> str:
        u, m = self.has_user, self.has_machine
        return "CU" if (u and m) else "U" if u else "C"


LOOPBACK_VALUES = ("none", "merge", "replace")
DRIVES_SOURCES = ("", "drives.yaml")


def load_packs(catalog_dir: str = CATALOG_DIR) -> list[Pack]:
    packs = []
    for path in sorted(glob.glob(os.path.join(catalog_dir, "*.yaml"))):
        with open(path) as fh:
            data = yaml.safe_load(fh) or {}
        known = Pack.__dataclass_fields__.keys()
        pack = Pack(**{k: v for k, v in data.items() if k in known})
        # A typo ('mergee') would switch loopback off silently AND still let the per-school
        # user packs count as needing it - the two things that then look fine and do not
        # work. Fail loudly at load time instead.
        if pack.loopback not in LOOPBACK_VALUES:
            raise ValueError(f"{os.path.basename(path)}: loopback: {pack.loopback!r} is not "
                             f"one of {', '.join(LOOPBACK_VALUES)}")
        if pack.drives_source not in DRIVES_SOURCES:
            raise ValueError(f"{os.path.basename(path)}: drives_source: {pack.drives_source!r} "
                             f"is not one of {', '.join(repr(x) for x in DRIVES_SOURCES)}")
        if not isinstance(pack.link_enforced, bool):
            raise ValueError(f"{os.path.basename(path)}: link_enforced must be true or false")
        packs.append(pack)
    return packs


def load_script(name: str, scripts_dir: str = SCRIPTS_DIR) -> str:
    with open(os.path.join(scripts_dir, name), encoding="utf-8") as fh:
        return fh.read()
