"""Recompute the Group Policy processing order the way a Windows client builds it.

Pure functions (no AD) plus one loader. Used by `doctor` and `apply` to prove, per school,
that LMN-U-GLOBAL-20-drives is the LAST GPO with drive maps a client processes - without
loopback, with loopback Merge and with Replace, and for a teacher of one school at a
computer of another. Whatever runs later wins a drive letter.

The algorithm is [MS-GPOL] 3.2.5.1.5 "GPO Search", literally:
  * the SOM list starts at the object's own OU and walks up to the domain; the site is
    last ("An SOM MUST be prioritized higher in the list compared to its parent SOMs");
  * per SOM, every gPLink entry in stored order: a link with option bit 1 (disabled) is
    ignored; a NOT enforced link is PREPENDED to the non-enforced list (unless an earlier,
    deeper SOM blocked inheritance); an enforced link is APPENDED to the enforced list;
  * gPOptions = 1 (block inheritance) on a SOM drops the non-enforced links of every SOM
    after it (its parents), never the enforced ones;
  * the result is non-enforced + enforced, in processing order - the last one wins.
Consequences that matter here: inside one SOM the FIRST gPLink entry is processed LAST
(Samba's setlink inserts new links at the front, so the newest link wins there), and an
enforced link at OU=SCHOOLS comes after every non-enforced link anywhere below it.

Loopback ([MS-GPOL]/Group Policy processing): Merge = the user's list followed by the
computer's list (duplicates stay, the lab measured them in event 5312); Replace = the
computer's list only.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import gplink

DRIVES_CSE = "{5794DAFD-BE60-433F-88A2-1A31939AC01F}"
MODES = ("none", "merge", "replace")
MODE_WORDS = {"none": "without loopback", "merge": "loopback Merge",
              "replace": "loopback Replace"}


@dataclass
class Som:
    dn: str
    links: list = field(default_factory=list)    # [(GUID upper, options)] in gPLink order
    block_inheritance: bool = False


@dataclass
class GpoInfo:
    guid: str
    name: str
    user_drive_maps: bool = False    # Drive Maps CSE registered in gPCUserExtensionNames
    user_disabled: bool = False      # GPO 'flags' bit 1: user configuration disabled


def split_dn(dn: str) -> list[str]:
    """RDNs of a DN, honouring escaped commas."""
    return [p.strip() for p in re.split(r"(?<!\\),", dn) if p.strip()]


def som_chain(container_dn: str, soms: dict, domain_dn: str, site: Som | None = None) -> list:
    """The SOM list for an object sitting in `container_dn`: its OU, every parent OU, the
    domain, then the site. Plain containers (CN=...) are not SOMs and are skipped."""
    rdns = split_dn(container_dn)
    dom = domain_dn.lower()
    chain = []
    for i in range(len(rdns)):
        dn = ",".join(rdns[i:])
        if dn.lower() == dom:
            chain.append(soms.get(dom) or Som(domain_dn))
            break
        if rdns[i].upper().startswith("OU="):
            chain.append(soms.get(dn.lower()) or Som(dn))
    if site is not None:
        chain.append(site)
    return chain


def gpo_list(chain: list) -> list[str]:
    """GPO GUIDs in processing order for one SOM list ([MS-GPOL] 3.2.5.1.5)."""
    non_enforced: list[str] = []
    enforced: list[str] = []
    enforced_only = False
    for som in chain:
        links = [(g, o) for g, o in som.links if not o & gplink.GPLINK_DISABLE]
        for guid, opts in links:
            if not opts & gplink.GPLINK_ENFORCE and not enforced_only:
                non_enforced.insert(0, guid)
        for guid, opts in links:
            if opts & gplink.GPLINK_ENFORCE:
                enforced.append(guid)
        if som.block_inheritance:
            enforced_only = True
    return non_enforced + enforced


def user_policy_list(user_chain: list, computer_chain: list, mode: str) -> list[str]:
    """The GPO list a client processes USER policy from, in a loopback mode."""
    if mode == "replace":
        return gpo_list(computer_chain)
    if mode == "merge":
        return gpo_list(user_chain) + gpo_list(computer_chain)
    return gpo_list(user_chain)


def after_ours(order: list[str], ours: str, relevant) -> list[str] | None:
    """GPOs from `relevant` processed after the LAST occurrence of ours.
    None when ours is not in the list at all (it does not reach this client)."""
    ours = ours.upper()
    if ours not in order:
        return None
    last = len(order) - 1 - order[::-1].index(ours)
    out = []
    for guid in order[last + 1:]:
        if guid in relevant and guid != ours and guid not in out:
            out.append(guid)
    return out


@dataclass
class Finding:
    school: str
    mode: str
    kind: str                  # after | missing
    gpos: tuple = ()           # offending GUIDs (kind 'after')
    user_ou: str = ""
    computer_ou: str = ""
    count: int = 1             # how many OU combinations show the same finding


@dataclass
class SchoolLayout:
    name: str
    user_ous: list             # DNs of OUs that hold users (everything but OU=Devices)
    computer_ous: list         # OU=Devices and its sub-OUs


def check(soms: dict, gpos: dict, ours: str, schools: list, domain_dn: str,
          sites: list | None = None) -> tuple[list, dict]:
    """Evaluate every combination. Returns (findings, per-school counts).

    Cases: without loopback (each user OU of the school), Merge (users of EVERY school on
    this school's computers - the cross-school teacher), Replace (this school's computers).
    A GPO counts when it carries user Drive Maps and its user half is not disabled.
    """
    ours = ours.upper()
    relevant = {g for g, info in gpos.items()
                if info.user_drive_maps and not info.user_disabled}
    relevant.add(ours)
    site_list = sites or [None]
    cache: dict[tuple, list] = {}

    def lst(ou, site):
        key = (ou.lower(), site.dn.lower() if site else "")
        if key not in cache:
            cache[key] = gpo_list(som_chain(ou, soms, domain_dn, site))
        return cache[key]

    all_users = [(s.name, ou) for s in schools for ou in s.user_ous]
    findings: dict[tuple, Finding] = {}
    counts: dict[str, dict] = {}

    def record(school, mode, res, user_ou, computer_ou):
        c = counts.setdefault(school, {"checked": 0, "bad": 0})
        c["checked"] += 1
        if res is not None and not res:
            return
        c["bad"] += 1
        kind = "missing" if res is None else "after"
        key = (school, mode, kind, tuple(res or ()))
        if key in findings:
            findings[key].count += 1
        else:
            findings[key] = Finding(school, mode, kind, tuple(res or ()), user_ou, computer_ou)

    for site in site_list:
        for s in schools:
            for uou in s.user_ous:
                record(s.name, "none", after_ours(lst(uou, site), ours, relevant), uou, "")
            for cou in s.computer_ous:
                record(s.name, "replace", after_ours(lst(cou, site), ours, relevant), "", cou)
                for _uschool, uou in all_users:
                    order = lst(uou, site) + lst(cou, site)
                    record(s.name, "merge", after_ours(order, ours, relevant), uou, cou)
    return list(findings.values()), counts


# --------------------------------------------------------------------------- #
# loading from the directory (read-only)
# --------------------------------------------------------------------------- #
def load(env, ad_module=None):
    """(soms, gpos, schools, sites) from the local sam.ldb."""
    if ad_module is None:
        from . import ad as ad_module
    soms: dict[str, Som] = {}

    def add(msg):
        dn = str(msg.dn)
        try:
            links = [(lk.guid, lk.options) for lk in
                     gplink.parse(ad_module.val(msg, "gPLink", "") or "") if lk.guid]
        except ValueError:
            links = []
        opts = (ad_module.val(msg, "gPOptions", "0") or "0").strip()
        soms[dn.lower()] = Som(dn, links, opts == "1")

    for msg in ad_module.search(expr="(|(gPLink=*)(gPOptions=*))",
                                attrs=["gPLink", "gPOptions"]):
        add(msg)
    sites = []
    try:
        cfg = str(ad_module.db().get_config_basedn())
        for msg in ad_module.search(base=f"CN=Sites,{cfg}", scope="one",
                                    expr="(&(objectClass=site)(gPLink=*))",
                                    attrs=["gPLink", "gPOptions"]):
            add(msg)
            sites.append(soms[str(msg.dn).lower()])
    except Exception:
        sites = []

    gpos: dict[str, GpoInfo] = {}
    for msg in ad_module.search(base=f"CN=Policies,CN=System,{env.basedn}", scope="one",
                                expr="(objectClass=groupPolicyContainer)",
                                attrs=["cn", "displayName", "gPCUserExtensionNames", "flags"]):
        guid = (ad_module.val(msg, "cn", "") or "").upper()
        exts = (ad_module.val(msg, "gPCUserExtensionNames", "") or "").upper()
        try:
            flags = int(ad_module.val(msg, "flags", "0") or 0)
        except ValueError:
            flags = 0
        gpos[guid] = GpoInfo(guid, ad_module.val(msg, "displayName", guid) or guid,
                             DRIVES_CSE in exts, bool(flags & 1))

    layouts = []
    for school in env.schools:
        dev = school.devices_ou.lower()
        users, computers = [], []
        for msg in ad_module.search(base=school.dn, scope="sub",
                                    expr="(objectClass=organizationalUnit)", attrs=["ou"]):
            dn = str(msg.dn)
            if dn.lower() == school.dn.lower():
                continue
            if dn.lower() == dev or dn.lower().endswith("," + dev):
                computers.append(dn)
            else:
                users.append(dn)
        layouts.append(SchoolLayout(school.name, sorted(users), sorted(computers)))
    return soms, gpos, layouts, sites


def where_linked(soms: dict, guid: str) -> list[str]:
    """DNs (with link state) where a GPO is linked - for the warning text."""
    out = []
    for som in soms.values():
        for g, opts in som.links:
            if g == guid.upper():
                out.append(f"{som.dn} ({gplink.describe(opts)})")
    return out


def with_planned_link(soms: dict, container_dn: str, guid: str) -> dict:
    """A copy of `soms` in which `guid` is linked enforced at `container_dn`: an existing
    link keeps its position and gets exactly the options apply sets (2), a missing one is
    put first, where samba-tool setlink puts a new link. Lets doctor and a dry-run say
    what the order WILL be after apply."""
    out = {k: Som(v.dn, list(v.links), v.block_inheritance) for k, v in soms.items()}
    som = out.setdefault(container_dn.lower(), Som(container_dn))
    hits = [i for i, (g, _) in enumerate(som.links) if g == guid.upper()]
    for i in hits:
        som.links[i] = (guid.upper(), gplink.GPLINK_ENFORCE)
    if not hits:
        som.links.insert(0, (guid.upper(), gplink.GPLINK_ENFORCE))
    return out


def report(findings: list, counts: dict, gpos: dict, soms: dict, ours_name: str,
           letters_of=None) -> tuple[list, list]:
    """(ok lines, warning lines) for apply/doctor."""
    ok, warn = [], []
    bad_schools = {f.school for f in findings}
    for school in sorted(counts):
        if school not in bad_schools:
            ok.append(f"{school}: {ours_name} is the last GPO with drive maps for every user "
                      f"and computer OU (without loopback, Merge, Replace; "
                      f"{counts[school]['checked']} combinations, users of every school)")
    for f in sorted(findings, key=lambda x: (x.school, MODES.index(x.mode), x.kind)):
        where = (f"users in {f.user_ou}" if f.user_ou else "") + \
                (" on " if f.user_ou and f.computer_ou else "") + \
                (f"computers in {f.computer_ou}" if f.computer_ou else "")
        more = f" and {f.count - 1} more combination(s)" if f.count > 1 else ""
        if f.kind == "missing":
            warn.append(f"{f.school}, {MODE_WORDS[f.mode]}: {ours_name} does not reach "
                        f"{where}{more} (link missing, disabled or blocked)")
            continue
        for guid in f.gpos:
            info = gpos.get(guid)
            name = info.name if info else guid
            linked = "; ".join(where_linked(soms, guid)) or "link not found"
            letters = ""
            if letters_of:
                try:
                    lt = letters_of(guid)
                    letters = f" - it maps {' '.join(x + ':' for x in sorted(lt))}" if lt else ""
                except Exception:
                    letters = ""
            warn.append(f"{f.school}, {MODE_WORDS[f.mode]}: {name} runs AFTER {ours_name} "
                        f"for {where}{more}; linked at {linked}{letters}")
    return ok, warn
