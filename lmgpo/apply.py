"""Apply the policy catalog: for each pack, ensure a GPO, write its settings,
link it and security-filter it — resolving @placeholders from the detected
environment + the operator's answers. Multischule-aware and fully idempotent
(safe to run repeatedly; new packs are simply added, unchanged ones are no-ops).
"""
from __future__ import annotations

import os
import re
import shutil

from . import ad, catalog
from .gpo import GpoEngine
from .gpp import GppGroups
from .regpol import RegPol, firewall_entries
from .scripts_ext import ScriptsExt
from .secedit import SecEdit

GPO_PREFIX = "LMN-"
LOOPBACK_MODE = {"merge": 2, "replace": 1}
from .paths import WALLPAPER_DIR  # noqa: E402
WALLPAPER_EXTS = (".jpg", ".jpeg", ".png", ".bmp")

TYPE_MAP = {"dword": "REG_DWORD", "sz": "REG_SZ", "expand_sz": "REG_EXPAND_SZ",
            "multi_sz": "REG_MULTI_SZ", "qword": "REG_QWORD", "binary": "REG_BINARY"}
CLASS_MAP = {"machine": "MACHINE", "user": "USER", "both": "BOTH"}

DEFAULT_ANSWERS = {
    "schools": None,          # None = all detected schools
    "packs": None,            # None = all enabled packs
    "fwsource": "serverip",   # serverip | subnet | <literal cidr/ip>
    "teachernb": "nopxe",     # nopxe | skip | <group cn>
    "kmshost": "",            # KMS host FQDN/IP ("" = KMS pack skipped)
    "wallpaper_dir": "",      # source dir for <school>.jpg ("" = repo wallpapers/)
    "veyon_binddn": "",       # Veyon LDAP bind DN ("" = Veyon pack skipped)
    "veyon_bindpw_hex": "",   # Veyon bind password as Veyon-encrypted hex (see lmgpo/veyon.py)
    "firefox_enabled": False,          # gate the Firefox packs
    "firefox_homepage": "",            # global default homepage URL ("" = homepage pack skipped)
    "firefox_homepage_by_school": {},  # optional per-school override {schoolname: url}
    "firefox_homepage_locked": True,   # lock/override the homepage (user can't change it)
    "proxy_enabled": False,            # gate the role-based proxy packs
    "proxy_host": "",                  # global proxy host (or "" if per-school only)
    "proxy_host_by_school": {},        # per-school override {schoolname: host}
    "proxy_port_by_role": {"teacher": 3128, "student": 3129, "staff": 3130},
    "proxy_exceptions": "",            # ProxyOverride ("" = sensible default at apply time)
    "wlan_psk_networks": [],           # [{ssid, psk}] student PSK WLANs (all sites)
    "wlan_enterprise_ssid": "",        # teacher enterprise SSID (WPA2/PEAP, user-auth)
    "wlan_enterprise_servernames": "", # RADIUS server cert name(s), ';'-separated (optional)
    "wlan_enterprise_ca_cert": "",     # path to the RADIUS CA cert (PEM or DER)
    "bootorder_pxe_first": False,      # opt-in: UEFI boot order network/PXE first (startup script)
    "ntp_mode": "nt5ds",               # time-sync mode: nt5ds (domain/Samba way) | ntp (explicit server)
}


class Applier:
    def __init__(self, env, answers=None, dry_run=False):
        self.env = env
        self.answers = {**DEFAULT_ANSWERS, **(answers or {})}
        self.dry_run = dry_run
        self.eng = GpoEngine(env, dry_run=dry_run)
        self.rp = RegPol(self.eng)
        self.se = SecEdit(self.eng)
        self.gp = GppGroups(self.eng)
        self.sc = ScriptsExt(self.eng)
        self.results: list[dict] = []
        self._wp_cache: dict[str, str | None] = {}

    # ------------------------------------------------------------------ #
    # selection
    # ------------------------------------------------------------------ #
    def selected_schools(self):
        want = self.answers.get("schools")
        return list(self.env.schools) if not want else \
            [s for s in self.env.schools if s.name in want]

    def selected_packs(self, packs):
        want = self.answers.get("packs")
        out = [p for p in packs if p.enabled]
        return out if not want else [p for p in out if p.id in want]

    def _kmshost(self) -> str:
        return (self.answers.get("kmshost") or "").strip()

    # ------------------------------------------------------------------ #
    # wallpaper: copy per-school image into NETLOGON, return its UNC path
    # ------------------------------------------------------------------ #
    def _wallpaper_src(self, school):
        base = self.answers.get("wallpaper_dir") or WALLPAPER_DIR
        for cand in (school.name, "default"):
            for ext in WALLPAPER_EXTS:
                p = os.path.join(base, cand + ext)
                if os.path.exists(p):
                    return p
        return None

    def _wallpaper_unc(self, school):
        if school is None:
            return None
        if school.name in self._wp_cache:
            return self._wp_cache[school.name]
        src = self._wallpaper_src(school)
        if not src:
            self._wp_cache[school.name] = None
            return None
        ext = os.path.splitext(src)[1].lower()
        unc = f"\\\\{self.env.dnsdomain}\\NETLOGON\\lmgpo-wallpapers\\{school.name}{ext}"
        if not self.dry_run:
            dest_dir = f"/var/lib/samba/sysvol/{self.env.dnsdomain}/scripts/lmgpo-wallpapers"
            os.makedirs(dest_dir, exist_ok=True)
            shutil.copy(src, os.path.join(dest_dir, f"{school.name}{ext}"))
        self._wp_cache[school.name] = unc
        return unc

    # ------------------------------------------------------------------ #
    # placeholder resolution
    # ------------------------------------------------------------------ #
    def _fwsource(self):
        src = self.answers.get("fwsource", "serverip")
        return self.env.serverip if src == "serverip" else \
            self.env.subnet if src == "subnet" else src

    def _firefox_homepage(self, school):
        if not self.answers.get("firefox_enabled"):
            return ""
        byschool = self.answers.get("firefox_homepage_by_school") or {}
        if school and byschool.get(school.name):
            return str(byschool[school.name]).strip()
        return (self.answers.get("firefox_homepage") or "").strip()

    def _proxy_host(self, school):
        byschool = self.answers.get("proxy_host_by_school") or {}
        if school and byschool.get(school.name):
            return str(byschool[school.name]).strip()
        return (self.answers.get("proxy_host") or "").strip()

    def _proxy_port(self, role):
        ports = self.answers.get("proxy_port_by_role") or {}
        default = {"teacher": 3128, "student": 3129, "staff": 3130}
        return str(ports.get(role, default[role]))

    def _proxy_exceptions(self):
        ex = (self.answers.get("proxy_exceptions") or "").strip()
        if ex:
            return ex
        parts = ["<local>"]
        if self.env.dnsdomain:
            parts.append(f"*.{self.env.dnsdomain}")
        if self.env.serverip:
            parts.append(self.env.serverip)
        parts += ["10.*", "172.16.*", "192.168.*"]
        return ";".join(parts)

    def _reldn(self, dn):
        """DN relative to the BaseDN (strip the trailing ,DC=…). Veyon stores and
        compares LDAP group DNs base-relative, so AuthorizedUserGroups must match."""
        if not dn:
            return ""
        suffix = "," + self.env.basedn
        return dn[:-len(suffix)] if dn.lower().endswith(suffix.lower()) else dn

    def _resolve_str(self, s, school, extra=None):
        # order: @firefox-homepage-locked BEFORE @firefox-homepage (prefix collision).
        reps = {
            "@firefox-homepage-locked": "1" if self.answers.get("firefox_homepage_locked", True) else "0",
            "@firefox-homepage": self._firefox_homepage(school),
            "@proxy-host": self._proxy_host(school),
            "@proxy-port-teacher": self._proxy_port("teacher"),
            "@proxy-port-student": self._proxy_port("student"),
            "@proxy-port-staff": self._proxy_port("staff"),
            "@proxy-exceptions": self._proxy_exceptions(),
            "@serverfqdn": self.env.serverfqdn,
            "@ntp-type": "NTP" if str(self.answers.get("ntp_mode", "nt5ds")).lower() == "ntp" else "NT5DS",
            "@serverip": self.env.serverip,
            "@subnet": self.env.subnet,
            "@fwsource": self._fwsource(),
            "@netbios": self.env.netbios,
            "@kmshost": self._kmshost(),
            "@basedn": self.env.basedn,
            "@veyon-binddn": self.answers.get("veyon_binddn", "") or "",
            "@veyon-bindpw": self.answers.get("veyon_bindpw_hex", "") or "",
            # Veyon stores/compares group DNs base-relative (LdapClient::stripBaseDn),
            # therefore WITHOUT the ,DC=… suffix — otherwise AuthorizedUserGroups matches no teacher.
            "@role-teacher": self._reldn(self.env.role_teacher.dn) if self.env.role_teacher else "",
            "@all-teachers": self._reldn(self.env.all_teachers.dn) if self.env.all_teachers else "",
            "@school": school.name if school else "GLOBAL",
        }
        if extra:
            reps.update(extra)
        for k, v in reps.items():
            s = s.replace(k, str(v))
        return s

    def _find_group_sid(self, cn, base):
        msg = ad.find_one(f"(&(objectClass=group)(cn={cn}))", base=base, scope="sub",
                          attrs=["objectSid"])
        return ad.sid_of(msg) if msg else None

    def _group_sids(self, token, school, schools):
        if token in (None, ""):
            return []
        if token.upper().startswith("S-1-") or token.startswith("*S-1-"):
            return [token.lstrip("*")]
        targets = [school] if school else schools
        if token == "@global-admins":
            g = self.env.global_admins
            return [g.sid] if g and g.sid else []
        if token == "@admins":
            return [s.admins.sid for s in targets if s.admins and s.admins.sid]
        if token == "@nopxe":
            return [s.nopxe.sid for s in targets if s.nopxe and s.nopxe.sid]
        if token == "@teachernb":
            tnb = self.answers.get("teachernb", "nopxe")
            if tnb in (None, "", "skip"):
                return []
            if tnb == "nopxe":
                return [s.nopxe.sid for s in targets if s.nopxe and s.nopxe.sid]
            return [sid for s in targets if (sid := self._find_group_sid(tnb, s.dn))]
        if token in ("@role-teacher", "@role-student", "@role-staff"):
            cn = token[1:]
            msg = ad.find_one(f"(&(objectClass=group)(cn={cn}))", base=self.env.global_ou,
                              scope="sub", attrs=["objectSid"])
            return [ad.sid_of(msg)] if msg else []
        return []

    def _admins_members(self, tokens, school, schools):
        out, targets = [], ([school] if school else schools)
        for t in tokens:
            if t == "@global-admins" and self.env.global_admins and self.env.global_admins.sid:
                g = self.env.global_admins
                out.append({"name": f"{self.env.netbios}\\{g.cn}", "sid": g.sid})
            elif t == "@admins":
                for s in targets:
                    if s.admins and s.admins.sid:
                        out.append({"name": f"{self.env.netbios}\\{s.admins.cn}", "sid": s.admins.sid})
        return out

    def _priv_rights(self, pr, school, schools):
        out = {}
        for right, tokens in (pr or {}).items():
            sids = [sid for t in tokens for sid in self._group_sids(t, school, schools)]
            if sids:
                out[right] = sids
        return out

    def _restricted_groups(self, rg, school, schools):
        out = []
        for entry in rg or []:
            members = self._group_sids(entry.get("member"), school, schools)
            memberof = [sid for t in entry.get("memberof", []) for sid in self._group_sids(t, school, schools)]
            out.extend({"member": m, "memberof": memberof} for m in members)
        return out

    def _registry_entries(self, pack, school, extra):
        entries = []
        for e in pack.registry:
            raw = e["data"]
            if isinstance(raw, str):
                data = self._resolve_str(raw, school, extra)
            elif isinstance(raw, list):   # REG_MULTI_SZ (drop empty resolutions, e.g. missing group)
                data = [v for x in raw
                        if (v := (self._resolve_str(x, school, extra) if isinstance(x, str) else x))]
            else:
                data = raw
            t = TYPE_MAP.get(str(e.get("type", "dword")).lower(), "REG_DWORD")
            if t in ("REG_DWORD", "REG_QWORD") and isinstance(data, str):
                try:
                    data = int(data)
                except ValueError:
                    pass
            entries.append({
                "keyname": self._resolve_str(e["key"], school, extra),
                "valuename": self._resolve_str(e["name"], school, extra),
                "class": CLASS_MAP.get(str(e.get("class", "machine")).lower(), "MACHINE"),
                "type": t, "data": data})
        if pack.loopback in LOOPBACK_MODE:
            entries.append({"keyname": r"Software\Policies\Microsoft\Windows\System",
                            "valuename": "UserPolicyMode", "class": "MACHINE",
                            "type": "REG_DWORD", "data": LOOPBACK_MODE[pack.loopback]})
        if pack.firewall:
            fw = {"profiles": pack.firewall.get("profiles"),
                  "rules": [{"id": r["id"], "string": self._resolve_str(r["string"], school, extra)}
                            for r in pack.firewall.get("rules", [])]}
            entries.extend(firewall_entries(fw))
        return entries

    # ------------------------------------------------------------------ #
    # applicability (requires:) and one pack
    # ------------------------------------------------------------------ #
    def _apply_wlan(self, pack, guid):
        from . import wlan as wlanmod
        mode = pack.wlan.get("mode")
        if mode == "psk":
            content = wlanmod.build_psk_script(self.answers.get("wlan_psk_networks") or [])
            fname = "lmgpo-wlan-psk.ps1"
        elif mode == "enterprise":
            ca = wlanmod.read_cert_der(self.answers["wlan_enterprise_ca_cert"])
            content = wlanmod.build_enterprise_script(
                (self.answers.get("wlan_enterprise_ssid") or "").strip(),
                (self.answers.get("wlan_enterprise_servernames") or "").strip(), ca)
            fname = "lmgpo-wlan-enterprise.ps1"
        else:
            return
        self.sc.set_startup_powershell(guid, [{"file": fname, "content": content}])

    def _applicable(self, pack, school):
        req = (pack.requires or "").strip()
        if not req:
            return True
        if req == "kmshost":
            return bool(self._kmshost())
        if req == "wallpaper":
            return bool(self._wallpaper_unc(school))
        if req == "veyon":
            return bool((self.answers.get("veyon_binddn") or "").strip()
                        and (self.answers.get("veyon_bindpw_hex") or "").strip())
        if req == "firefox":
            return bool(self.answers.get("firefox_enabled"))
        if req == "firefox_homepage":
            return bool(self._firefox_homepage(school))
        if req == "proxy":
            return bool(self.answers.get("proxy_enabled"))
        if req == "proxy_school":
            return bool(self.answers.get("proxy_enabled") and self._proxy_host(school))
        if req == "wlan_psk":
            return bool(self.answers.get("wlan_psk_networks"))
        if req == "wlan_enterprise":
            return bool((self.answers.get("wlan_enterprise_ssid") or "").strip()
                        and (self.answers.get("wlan_enterprise_ca_cert") or "").strip())
        if req == "bootorder":
            return bool(self.answers.get("bootorder_pxe_first"))
        return True

    def apply_pack(self, pack, school, schools):
        if not self._applicable(pack, school):
            return
        if pack.scope == "school":
            scope_token, container = school.name, school.devices_ou
        else:
            scope_token, container = "GLOBAL", self.env.schools_ou
        name = f"{GPO_PREFIX}{pack.type_letter}-{scope_token}-{pack.id}"
        # Exclusive-filter packs must fail CLOSED: a fresh GPO applies to Authenticated
        # Users, and set_exclusive_filter only restricts when it gets ≥1 SID. If the
        # 'only these groups' filter resolves to zero SIDs (e.g. @nopxe but no school has
        # a d_nopxe group), linking would roll the GPO out to EVERYONE. Skip + warn.
        filter_apply_sids = []
        if pack.filter_apply:
            filter_apply_sids = [sid for token in pack.filter_apply
                                 for sid in self._group_sids(token, school, schools)]
            if not filter_apply_sids:
                print(f"\n▸ {name}")
                print(f"    ⚠ skipped: exclusive-filter group(s) {pack.filter_apply} "
                      f"not found — otherwise the GPO would apply to EVERYONE.")
                return
        print(f"\n▸ {name}")
        guid, _ = self.eng.ensure(name)
        extra = {"@wallpaper": self._wallpaper_unc(school)} if school else {}

        self.rp.load(guid, self._registry_entries(pack, school, extra), gpo_dir=self.eng.sysvol_path(guid))
        self.se.apply(guid,
                      privilege_rights=self._priv_rights(pack.privilege_rights, school, schools),
                      group_membership=self._restricted_groups(pack.restricted_groups, school, schools))
        self.gp.add_local_admins(guid, self._admins_members(pack.local_admins, school, schools))
        if pack.startup_scripts or pack.shutdown_scripts:
            def _load(lst):
                return [{"file": s["file"], "content": catalog.load_script(s["file"])} for s in lst]
            self.sc.set_scripts_powershell(guid, startup=_load(pack.startup_scripts),
                                           shutdown=_load(pack.shutdown_scripts))
        if pack.wlan:
            self._apply_wlan(pack, guid)
        self.eng.link(container, guid)
        for token in pack.filter_deny:
            for sid in self._group_sids(token, school, schools):
                self.eng.deny_apply(guid, sid)
        if filter_apply_sids:
            self.eng.set_exclusive_filter(guid, filter_apply_sids)
        self.results.append({"pack": pack.id, "gpo": name, "guid": guid})

    def run(self, packs):
        packs = self.selected_packs(packs)
        schools = self.selected_schools()
        print(f"Applying to {len(schools)} school(s): {', '.join(s.name for s in schools)}")
        if self._kmshost():
            print(f"KMS host: {self._kmshost()}")
        for pack in packs:
            if pack.scope == "school":
                for school in schools:
                    self.apply_pack(pack, school, schools)
            else:
                self.apply_pack(pack, None, schools)

        reconciled = True
        if not self.dry_run:
            print("\nReconciling sysvol/AD ACL:")
            reconciled = self.eng.reconcile_sysvol()
        ok, out = self.eng.aclcheck()
        print(f"\naclcheck: {'ok' if ok else 'MISMATCH — ' + (out.splitlines()[0] if out else '')}")
        print(f"Done: {len(self.results)} GPO(s) applied.")

        problems = []
        if not self.dry_run and not reconciled:
            problems.append(
                "sysvolreset was skipped (Domain Admins has a gidNumber). The self-written "
                "GptTmpl/Groups/script files may then not have correct sysvol ACLs → clients "
                "might NOT apply these GPOs. Please check the sysvol ACLs manually "
                "(samba-tool ntacl get/set).")
        if not ok:
            problems.append("gpo aclcheck reports a mismatch between the AD and sysvol ACL.")
        if problems:
            print()
            for p in problems:
                print(f"⚠ WARNING: {p}")
            return 1
        return 0


def remove(env, dry_run=False, only_ids=None):
    """Remove all LMN- GPOs (or a subset by pack id): unlink then delete."""
    eng = GpoEngine(env, dry_run=dry_run)
    base = f"CN=Policies,CN=System,{env.basedn}"
    gplinks: dict[str, list[str]] = {}
    for m in ad.search(expr="(gPLink=*)", attrs=["gPLink"]):
        for guid in re.findall(r"CN=(\{[0-9A-Fa-f-]+\})", ad.val(m, "gPLink", "")):
            gplinks.setdefault(guid.upper(), []).append(str(m.dn))

    removed = 0
    for msg in ad.search(base=base, scope="one", expr="(objectClass=groupPolicyContainer)",
                         attrs=["displayName", "cn"]):
        name, guid = ad.val(msg, "displayName", ""), ad.val(msg, "cn", "")
        if not name.startswith(GPO_PREFIX):
            continue
        if only_ids and not any(name.endswith("-" + pid) for pid in only_ids):
            continue
        print(f"▸ removing {name} {guid}")
        for container in gplinks.get(guid.upper(), []):
            eng.unlink(container, guid)
        eng.delete(guid)
        removed += 1
    if not dry_run and removed:
        eng.reconcile_sysvol()
    print(f"\n{removed} GPO(s) removed.")
    return 0
