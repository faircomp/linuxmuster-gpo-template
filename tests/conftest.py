"""Shared fixtures: a fake multi-school domain (no Samba, no DC needed).

Layout (Kevin's site, 2026-10-23): default-school (groups without prefix) plus the
additional schools msg, gsg and gym (groups with prefix), every school with its
sophomorix:school:<school> GPO linked at OU=<school>, the global group 'verwaltung'.
"""
from __future__ import annotations

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fakead import FakeAD  # noqa: E402
from lmn_gpo.env import Env, Group, School  # noqa: E402

BASE = "DC=dev,DC=lmschule,DC=de"
SCHOOLS_OU = f"OU=SCHOOLS,{BASE}"
POLICIES = f"CN=Policies,CN=System,{BASE}"
DDP = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
SCHOOL_NAMES = ("default-school", "msg", "gsg", "gym")
DRIVES_CSE = "[{5794DAFD-BE60-433F-88A2-1A31939AC01F}{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}]"
REGISTRY_CSE = "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]"
SECURITY_GROUP = "-2147483646"
TEMPLATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures",
                        "sophomorix-school-Drives.xml")


def school_guid(name: str) -> str:
    n = SCHOOL_NAMES.index(name) + 1
    return "{5C000000-0000-0000-0000-%012d}" % n


def sid(rid: int) -> str:
    return f"S-1-5-21-111-222-333-{rid}"


GROUP_SIDS = {
    "teachers": sid(1105), "students": sid(1106), "staff": sid(1107),
    "msg-teachers": sid(1205), "gsg-teachers": sid(1305), "gym-teachers": sid(1405),
    "msg-students": sid(1206), "gsg-students": sid(1306), "gym-students": sid(1406),
    "role-teacher": sid(1103), "role-student": sid(1104), "role-staff": sid(1108),
    "verwaltung": sid(1500), "lk-msg": sid(1501), "d_verwaltung": sid(1502),
}


def gplink_value(*links) -> str:
    """links: (guid, options)."""
    return "".join(f"[LDAP://CN={g},{POLICIES};{o}]" for g, o in links)


def school_drives_xml(school: str) -> str:
    text = open(TEMPLATE, encoding="utf-8").read()
    return (text.replace("@@SERVER@@", "server").replace("@@SCHOOL@@", school)
            .replace("@@ROOTDNS@@", "DEV")
            .replace("@@TEACHERGROUP@@",
                     "teachers" if school == "default-school" else f"{school}-teachers"))


def build_domain(sysvol: str) -> FakeAD:
    fake = FakeAD(BASE)
    fake.add(BASE, objectClass="domainDNS", gPLink=gplink_value((DDP, 0)))
    fake.add(SCHOOLS_OU, objectClass="organizationalUnit", ou="SCHOOLS")
    fake.add(f"OU=GLOBAL,{BASE}", objectClass="organizationalUnit", ou="GLOBAL")
    fake.add(f"CN=System,{BASE}", objectClass="container")
    fake.add(POLICIES, objectClass="container")
    fake.add(f"CN={DDP},{POLICIES}", objectClass="groupPolicyContainer", cn=DDP,
             displayName="Default Domain Policy", gPCUserExtensionNames="", flags="0",
             versionNumber="1")
    for name, gsid in GROUP_SIDS.items():
        fake.add(f"CN={name},OU=Groups,OU=GLOBAL,{BASE}", objectClass="group", cn=name,
                 sAMAccountName=name, objectSid=gsid, groupType=SECURITY_GROUP)
    # a distribution group: never in the logon token
    fake.add(f"CN=newsletter,OU=GLOBAL,{BASE}", objectClass="group", cn="newsletter",
             sAMAccountName="newsletter", objectSid=sid(1600), groupType="8")
    for school in SCHOOL_NAMES:
        sdn = f"OU={school},{SCHOOLS_OU}"
        guid = school_guid(school)
        fake.add(sdn, objectClass="organizationalUnit", ou=school,
                 gPLink=gplink_value((guid, 0)))
        for ou in ("Teachers", "Students", "Management", "Devices"):
            fake.add(f"OU={ou},{sdn}", objectClass="organizationalUnit", ou=ou)
        fake.add(f"OU=5a,OU=Students,{sdn}", objectClass="organizationalUnit", ou="5a")
        fake.add(f"OU=r101,OU=Devices,{sdn}", objectClass="organizationalUnit", ou="r101")
        fake.add(f"CN={guid},{POLICIES}", objectClass="groupPolicyContainer", cn=guid,
                 displayName=f"sophomorix:school:{school}", flags="0",
                 gPCUserExtensionNames=DRIVES_CSE, versionNumber="23592973")
        d = os.path.join(sysvol, guid, "User", "Preferences", "Drives")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "Drives.xml"), "w", encoding="utf-8") as fh:
            fh.write(school_drives_xml(school))
    return fake


def school_obj(name: str) -> School:
    dn = f"OU={name},{SCHOOLS_OU}"
    return School(name=name, dn=dn, prefix="" if name == "default-school" else f"{name}-",
                  is_default=name == "default-school", devices_ou=f"OU=Devices,{dn}",
                  management_ou=f"OU=Management,{dn}",
                  admins=Group(cn="admins", dn=f"CN=admins,OU=Management,{dn}", sid=sid(1100)))


def make_env(sysvol: str = "/nonexistent") -> Env:
    return Env(realm="DEV.LMSCHULE.DE", dnsdomain="dev.lmschule.de", basedn=BASE,
               netbios="DEV", serverip="10.250.0.10", subnet="10.250.0.0/24",
               sysvol_policies=sysvol, schools_ou=SCHOOLS_OU, global_ou=f"OU=GLOBAL,{BASE}",
               serverfqdn="server.dev.lmschule.de", server_netbios="SERVER",
               schools=[school_obj(n) for n in SCHOOL_NAMES])


@pytest.fixture
def domain(tmp_path, monkeypatch):
    """(fake directory installed as lmn_gpo.ad, env, sysvol path)."""
    sysvol = str(tmp_path / "Policies")
    fake = build_domain(sysvol).install(monkeypatch)
    return fake, make_env(sysvol), sysvol


@pytest.fixture
def env():
    return make_env()
