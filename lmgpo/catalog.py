"""Load the declarative YAML policy catalog."""
from __future__ import annotations

import glob
import os
from dataclasses import dataclass, field

import yaml

CATALOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "catalog")
SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")


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
    wlan: dict = field(default_factory=dict)            # {mode: psk|enterprise} -> generated startup script
    filter_deny: list = field(default_factory=list)     # deny-apply these groups
    filter_apply: list = field(default_factory=list)    # EXCLUSIVE: only these groups apply

    @property
    def has_user(self) -> bool:
        return any(str(e.get("class", "machine")).lower() in ("user", "both") for e in self.registry)

    @property
    def has_machine(self) -> bool:
        if any(str(e.get("class", "machine")).lower() in ("machine", "both") for e in self.registry):
            return True
        return bool(self.firewall or self.privilege_rights or self.restricted_groups
                    or self.local_admins or self.startup_scripts or self.wlan
                    or self.loopback in ("merge", "replace"))

    @property
    def type_letter(self) -> str:
        u, m = self.has_user, self.has_machine
        return "CU" if (u and m) else "U" if u else "C"


def load_packs(catalog_dir: str = CATALOG_DIR) -> list[Pack]:
    packs = []
    for path in sorted(glob.glob(os.path.join(catalog_dir, "*.yaml"))):
        with open(path) as fh:
            data = yaml.safe_load(fh) or {}
        known = Pack.__dataclass_fields__.keys()
        packs.append(Pack(**{k: v for k, v in data.items() if k in known}))
    return packs


def load_script(name: str, scripts_dir: str = SCRIPTS_DIR) -> str:
    with open(os.path.join(scripts_dir, name), encoding="utf-8") as fh:
        return fh.read()
