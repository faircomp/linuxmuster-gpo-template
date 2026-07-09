"""Environment detection for a linuxmuster.net 7.x Samba AD DC.

Everything is discovered live from the directory + linuxmuster config so the
toolkit is portable across customers and Multischule setups: schools, their
prefixes, admin groups, the noPXE device group and rooms are read from AD,
never hardcoded.
"""
from __future__ import annotations

import ipaddress
import os
import re
import subprocess
from dataclasses import dataclass, field

from . import ad

SETUP_INI = "/var/lib/linuxmuster/setup.ini"
SECRET_ADMIN = "/etc/linuxmuster/.secret/administrator"


@dataclass
class Group:
    cn: str
    dn: str
    sid: str | None

    def as_dict(self):
        return {"cn": self.cn, "dn": self.dn, "sid": self.sid}


@dataclass
class School:
    name: str            # OU name, e.g. "default-school"
    dn: str
    prefix: str          # "" for default-school, "<name>-" otherwise
    is_default: bool
    devices_ou: str
    management_ou: str
    admins: Group | None = None      # per-school admins group
    nopxe: Group | None = None       # d_nopxe device group (non-LINBO clients)
    rooms: list = field(default_factory=list)   # [{name, dn}]

    def as_dict(self):
        return {
            "name": self.name, "dn": self.dn, "prefix": self.prefix,
            "is_default": self.is_default, "devices_ou": self.devices_ou,
            "management_ou": self.management_ou,
            "admins": self.admins.as_dict() if self.admins else None,
            "nopxe": self.nopxe.as_dict() if self.nopxe else None,
            "rooms": self.rooms,
        }


@dataclass
class Env:
    realm: str
    dnsdomain: str
    basedn: str
    netbios: str
    serverip: str
    subnet: str
    sysvol_policies: str
    schools_ou: str
    global_ou: str
    samba_version: str = ""
    serverfqdn: str = ""
    global_admins: Group | None = None
    all_admins: Group | None = None
    role_globaladmin: Group | None = None
    role_schooladmin: Group | None = None
    role_teacher: Group | None = None
    schools: list = field(default_factory=list)

    def school(self, name: str) -> School | None:
        for s in self.schools:
            if s.name == name:
                return s
        return None

    def admin_creds(self) -> tuple[str, str]:
        """('administrator', <password>) read from the linuxmuster secret."""
        with open(SECRET_ADMIN) as fh:
            return "administrator", fh.read().strip()

    def as_dict(self):
        return {
            "realm": self.realm, "dnsdomain": self.dnsdomain, "basedn": self.basedn,
            "netbios": self.netbios, "serverip": self.serverip, "subnet": self.subnet,
            "serverfqdn": self.serverfqdn,
            "sysvol_policies": self.sysvol_policies, "samba_version": self.samba_version,
            "schools_ou": self.schools_ou, "global_ou": self.global_ou,
            "global_admins": self.global_admins.as_dict() if self.global_admins else None,
            "all_admins": self.all_admins.as_dict() if self.all_admins else None,
            "role_globaladmin": self.role_globaladmin.as_dict() if self.role_globaladmin else None,
            "role_schooladmin": self.role_schooladmin.as_dict() if self.role_schooladmin else None,
            "role_teacher": self.role_teacher.as_dict() if self.role_teacher else None,
            "schools": [s.as_dict() for s in self.schools],
        }


def _read_setup_ini() -> dict:
    """Parse /var/lib/linuxmuster/setup.ini (tolerant 'key = value', ignores sections)."""
    out = {}
    try:
        with open(SETUP_INI) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith(("#", ";", "[")):
                    continue
                if "=" in line:
                    k, _, v = line.partition("=")
                    out[k.strip().lower()] = v.strip()
    except FileNotFoundError:
        pass
    return out


def _smbconf(param: str) -> str | None:
    try:
        p = subprocess.run(
            ["testparm", "-s", "--parameter-name", param],
            capture_output=True, text=True, timeout=30,
        )
        v = p.stdout.strip()
        return v or None
    except Exception:
        return None


def _samba_version() -> str:
    try:
        p = subprocess.run(["samba", "--version"], capture_output=True, text=True, timeout=15)
        return p.stdout.strip()
    except Exception:
        return ""


def _serverfqdn(fallback_dnsdomain: str) -> str:
    """The DC's dnsHostName from RootDSE (LDAPS ServerHost must match the cert CN)."""
    try:
        res = ad.search(base="", scope="base", attrs=["dnsHostName"])
        if res:
            v = ad.val(res[0], "dnsHostName")
            if v:
                return v
    except Exception:
        pass
    import socket
    try:
        fqdn = socket.getfqdn()
        if "." in fqdn:
            return fqdn
    except Exception:
        pass
    return f"server.{fallback_dnsdomain}" if fallback_dnsdomain else ""


def _rdn_value(dn: str) -> str:
    # "OU=Foo,OU=Bar,..." -> "Foo"
    first = dn.split(",", 1)[0]
    return first.split("=", 1)[1] if "=" in first else first


def _find_group(expr: str, base: str) -> Group | None:
    msg = ad.find_one(expr, base=base, scope="sub",
                      attrs=["cn", "objectSid", "sophomorixType"])
    if not msg:
        return None
    return Group(cn=ad.val(msg, "cn"), dn=str(msg.dn), sid=ad.sid_of(msg))


def _iface_prefix(ip: str) -> int | None:
    """Prefix length of the local interface carrying `ip` (from `ip -o -4 addr`)."""
    if not ip:
        return None
    try:
        p = subprocess.run(["ip", "-o", "-4", "addr", "show"],
                           capture_output=True, text=True, timeout=10)
        for line in p.stdout.splitlines():
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if m and m.group(1) == ip:
                return int(m.group(2))
    except Exception:
        pass
    return None


def _netmask_to_prefix(mask: str | None) -> int | None:
    if not mask:
        return None
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except Exception:
        return None


def _subnet_for(ip: str, prefix: int = 24) -> str:
    try:
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    except Exception:
        return ""


def detect() -> Env:
    """Discover the full environment. Raises ad.NotADomainController off a DC."""
    basedn = ad.base_dn()
    ini = _read_setup_ini()

    realm = ini.get("realm") or (_smbconf("realm") or "").upper()
    dnsdomain = ini.get("domainname") or (realm.lower() if realm else "")
    netbios = ini.get("workgroup") or _smbconf("workgroup") or (
        dnsdomain.split(".")[0].upper() if dnsdomain else "")
    serverip = ini.get("serverip") or ""
    prefix = _iface_prefix(serverip) or _netmask_to_prefix(ini.get("netmask")) or 24
    subnet = _subnet_for(serverip, prefix) if serverip else ""
    sysvol_policies = f"/var/lib/samba/sysvol/{dnsdomain}/Policies" if dnsdomain else ""
    schools_ou = f"OU=SCHOOLS,{basedn}"
    global_ou = f"OU=GLOBAL,{basedn}"

    env = Env(
        realm=realm, dnsdomain=dnsdomain, basedn=basedn, netbios=netbios,
        serverip=serverip, subnet=subnet, sysvol_policies=sysvol_policies,
        schools_ou=schools_ou, global_ou=global_ou, samba_version=_samba_version(),
    )
    env.serverfqdn = _serverfqdn(dnsdomain)

    # Global (cross-school) groups.
    env.global_admins = _find_group("(&(objectClass=group)(cn=global-admins))", global_ou)
    env.all_admins = _find_group("(&(objectClass=group)(cn=all-admins))", global_ou)
    env.role_globaladmin = _find_group(
        "(&(objectClass=group)(cn=role-globaladministrator))", global_ou)
    env.role_schooladmin = _find_group(
        "(&(objectClass=group)(cn=role-schooladministrator))", global_ou)
    env.role_teacher = _find_group("(&(objectClass=group)(cn=role-teacher))", global_ou)

    # Schools (Multischule-aware).
    for m in ad.search(base=schools_ou, scope="one",
                       expr="(objectClass=organizationalUnit)", attrs=["ou"]):
        name = ad.val(m, "ou") or _rdn_value(str(m.dn))
        sdn = str(m.dn)
        is_default = (name == "default-school")
        prefix = "" if is_default else f"{name}-"
        devices_ou = f"OU=Devices,{sdn}"
        management_ou = f"OU=Management,{sdn}"

        sch = School(name=name, dn=sdn, prefix=prefix, is_default=is_default,
                     devices_ou=devices_ou, management_ou=management_ou)

        # Per-school admins group: prefer the sophomorix-typed object, fall back to CN.
        sch.admins = (
            _find_group("(&(objectClass=group)(sophomorixType=admins))", management_ou)
            or _find_group(f"(&(objectClass=group)(cn={prefix}admins))", sdn)
        )
        # noPXE device group (non-LINBO domain clients -> auto-update ON).
        sch.nopxe = _find_group("(&(objectClass=group)(cn=*nopxe*))", devices_ou)

        # Rooms = child OUs of Devices, excluding the device-groups container.
        for r in ad.search(base=devices_ou, scope="one",
                           expr="(objectClass=organizationalUnit)", attrs=["ou"]):
            rn = ad.val(r, "ou") or _rdn_value(str(r.dn))
            if rn == "device-groups":
                continue
            sch.rooms.append({"name": rn, "dn": str(r.dn)})

        env.schools.append(sch)

    return env
