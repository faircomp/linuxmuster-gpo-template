"""Apply the policy catalog: for each pack, ensure a GPO, write its settings,
link it and security-filter it — resolving @placeholders from the detected
environment + the operator's answers. Multischule-aware and fully idempotent
(safe to run repeatedly; new packs are simply added, unchanged ones are no-ops).
"""
from __future__ import annotations

import datetime
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
RETIRE_BACKUP_DIR = "/var/backups/lmn-gpo"
# Preconditions that depend on a FILE rather than on an operator answer. A missing file is
# usually an accident (wallpaper dir moved, share not mounted, source checkout replaced by
# the .deb, which uses a different wallpaper path) — deleting the GPO over that would throw
# away work. These are reported and skipped instead of retired.
NON_RETIRABLE_REQUIRES = {"wallpaper"}
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
    "kmshost": "",            # Windows KMS host FQDN/IP ("" = KMS pack skipped)
    "kms_port": "1688",       # Windows KMS port (default 1688)
    "kms_office_host": "",    # Office KMS host ("" = fall back to kmshost; both empty = pack skipped)
    "kms_office_port": "1688",  # Office KMS port (default 1688)
    "wallpaper_dir": "",      # source dir for <school>.jpg ("" = repo wallpapers/)
    "veyon_binddn": "",       # Veyon LDAP bind DN ("" = Veyon pack skipped)
    "veyon_bindpw_hex": "",   # Veyon bind password as Veyon-encrypted hex (see lmn_gpo/veyon.py)
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
    "display_off_seconds": 0,          # display-off timeout in seconds; 0 = never switch off
    # Time sync: "ntp" (explicit NTP against the server) is the default because the
    # "domain way" (nt5ds) needs MS-SNTP replies signed via Samba's ntp_signd socket, and
    # that chain is broken on a stock linuxmuster/Ubuntu 24.04 DC (see docs/RESEARCH.md).
    # A client then rejects every reply and sits at "Local CMOS Clock" forever.
    "ntp_mode": "ntp",                 # ntp (explicit server, works out of the box) | nt5ds (signed, needs a working ntp_signd)
    "pointandprint_enabled": False,    # opt-in: allow non-admin Point-and-Print driver install
    "printservers_extra": [],          # extra/external print server FQDNs to also trust
}


def _gplink_map() -> dict[str, list[str]]:
    """Map GPO GUID (upper case) -> list of container DNs that link it."""
    out: dict[str, list[str]] = {}
    for m in ad.search(expr="(gPLink=*)", attrs=["gPLink"]):
        for guid in re.findall(r"CN=(\{[0-9A-Fa-f-]+\})", ad.val(m, "gPLink", "")):
            out.setdefault(guid.upper(), []).append(str(m.dn))
    return out


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
        self.retired: list[str] = []
        self.warnings: list[str] = []   # non-fatal problems that must still fail the run
        self._links: dict[str, list[str]] | None = None   # gPLink map, built on first retire
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

    def _ntp_type(self) -> str:
        """NT5DS only when explicitly asked for. Anything unrecognised falls back to NTP,
        never to NT5DS: NT5DS needs MS-SNTP replies signed via Samba's ntp_signd, and when
        that chain is broken the client silently never syncs at all (see docs/RESEARCH.md).
        A typo must not select the mode that fails invisibly."""
        mode = str(self.answers.get("ntp_mode", "ntp")).strip().lower()
        if mode not in ("ntp", "nt5ds"):
            print(f"    \u26a0 ntp_mode {mode!r} is not 'ntp' or 'nt5ds' - using 'ntp'.")
            return "NTP"
        return "NT5DS" if mode == "nt5ds" else "NTP"

    def _display_off(self) -> str:
        """Display-off timeout in seconds; 0 = never. Anything unparsable falls back to 0
        (never) rather than to a timeout — a dark beamer is the more visible failure."""
        try:
            v = int(self.answers.get("display_off_seconds", 0))
        except (TypeError, ValueError):
            v = 0
        return str(max(0, v))

    def _kms_port(self) -> str:
        return str(self.answers.get("kms_port") or "1688").strip() or "1688"

    def _kms_office_host(self) -> str:
        """Office KMS host — its own setting, falling back to the Windows one.

        Office does NOT read the Windows KMS key, so it needs its own value; but the
        common school case is a single KMS server activating both, hence the fallback.
        """
        return ((self.answers.get("kms_office_host") or "").strip()
                or self._kmshost())

    def _kms_office_port(self) -> str:
        return str(self.answers.get("kms_office_port") or "1688").strip() or "1688"

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
        unc = f"\\\\{self.env.dnsdomain}\\NETLOGON\\lmn-gpo-wallpapers\\{school.name}{ext}"
        if not self.dry_run:
            dest_dir = f"/var/lib/samba/sysvol/{self.env.dnsdomain}/scripts/lmn-gpo-wallpapers"
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

    def _printserver_list(self) -> str:
        """Trusted Point-and-Print servers: this server (matching how sophomorix connects,
        i.e. the NetBIOS name) plus its FQDN and IP, plus any configured extra servers.
        Semicolon-separated, no spaces — the Point and Print Restrictions ServerList format."""
        servers = [self.env.server_netbios, self.env.serverfqdn, self.env.serverip]
        servers += list(self.answers.get("printservers_extra") or [])
        seen, out = set(), []
        for srv in servers:
            srv = str(srv).strip()
            if srv and srv.lower() not in seen:
                seen.add(srv.lower())
                out.append(srv)
        return ";".join(out)

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
            "@printserver-list": self._printserver_list(),
            "@display-off": self._display_off(),
            "@ntp-type": self._ntp_type(),
            "@serverip": self.env.serverip,
            "@subnet": self.env.subnet,
            "@fwsource": self._fwsource(),
            "@netbios": self.env.netbios,
            "@kms-office-host": self._kms_office_host(),
            "@kms-office-port": self._kms_office_port(),
            "@kms-port": self._kms_port(),
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
        # Escape RFC 4515 specials (backslash first, and '*' so an operator-supplied CN
        # cannot turn into a wildcard match) — same treatment as GpoEngine.find_by_name.
        safe = (str(cn).replace("\\", "\\5c").replace("*", "\\2a")
                .replace("(", "\\28").replace(")", "\\29").replace("\x00", "\\00"))
        msg = ad.find_one(f"(&(objectClass=group)(cn={safe}))", base=base, scope="sub",
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
            fname = "lmn-gpo-wlan-psk.ps1"
        elif mode == "enterprise":
            ca = wlanmod.read_cert_der(self.answers["wlan_enterprise_ca_cert"])
            content = wlanmod.build_enterprise_script(
                (self.answers.get("wlan_enterprise_ssid") or "").strip(),
                (self.answers.get("wlan_enterprise_servernames") or "").strip(), ca)
            fname = "lmn-gpo-wlan-enterprise.ps1"
        else:
            return
        self.sc.set_startup_powershell(guid, [{"file": fname, "content": content}])

    def _applicable(self, pack, school):
        req = (pack.requires or "").strip()
        if not req:
            return True
        if req == "kmshost":
            return bool(self._kmshost())
        if req == "kms_office":
            return bool(self._kms_office_host())
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
        if req == "pointandprint":
            return bool(self.answers.get("pointandprint_enabled"))
        return True

    def _backup_before_delete(self, name, guid) -> str | None:
        """samba-tool gpo backup into /var/backups/lmn-gpo/<timestamp>/ before deleting."""
        if self.dry_run:
            return None
        try:
            stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            dest = os.path.join(RETIRE_BACKUP_DIR, f"{stamp}-{name}")
            os.makedirs(dest, exist_ok=True)
            self.eng.backup(guid, dest)
            return dest
        except Exception as exc:            # a failed backup must not block the removal
            print(f"    ⚠ backup failed ({exc}) — continuing")
            return None

    def preflight(self, packs, schools=None):
        """Resolve every security-filter token BEFORE anything is written.

        An exclusion that resolves to no group is the dangerous case: the GPO then reaches
        exactly the devices or users it was meant to spare, and the per-pack output only
        says so once the change has already been made. Returns a list of
        (pack_id, scope_label, kind, token) for every token that matches no group.
        """
        packs = self.selected_packs(packs)
        schools = list(schools if schools is not None else self.selected_schools())
        rows = []
        for pack in packs:
            targets = [(s, s.name) for s in schools] if pack.scope == "school" \
                else [(None, "GLOBAL")]
            # a global pack is linked domain-wide, so it must resolve against every school
            pool = schools if pack.scope == "school" else list(self.env.schools)
            for school, label in targets:
                if not self._applicable(pack, school):
                    continue
                for kind, tokens in (("exclude", pack.filter_deny),
                                     ("exclude-read", pack.filter_deny_read),
                                     ("only", pack.filter_apply)):
                    for token in tokens:
                        if not self._group_sids(token, school, pool):
                            rows.append((pack.id, label, kind, token))
        return rows

    def print_preflight(self, packs, schools=None) -> bool:
        """Print the prerequisite check. True when everything resolves."""
        rows = self.preflight(packs, schools)
        if not rows:
            print("Prerequisite check: all security-filter groups resolve. ✓")
            return True
        print("\n⚠ Prerequisite check — these filters match NO group:")
        for pid, label, kind, token in rows:
            print(f"    {pid:26} {label:16} {kind:13} {token}")
        print("    'exclude'/'exclude-read': the GPO WILL apply to those devices/users.")
        print("    'only': the pack is skipped entirely (fail-closed).")
        print("    Fix: create the group, or set 'teachernb' in site.yaml to the group you "
              "actually use.")
        return False

    def _retire(self, name):
        """Unlink + delete the GPO of a pack whose precondition is no longer met.

        Without this, clearing a setting (e.g. emptying kmshost) only made _applicable()
        return False — the GPO stayed linked and kept applying the OLD value forever. That
        is especially bad for the KMS packs: their keys live outside the four Policies
        branches, so every client they still reach gets the stale host tattooed on.
        Applying is declarative, so a pack that no longer applies is removed here.
        """
        guid = self.eng.find_by_name(name)
        if not guid:
            return
        print(f"\n▸ {name}")
        print("    precondition no longer met → unlinking + deleting this GPO")
        dest = self._backup_before_delete(name, guid)
        if dest:
            print(f"    backup: {dest}")
        if self._links is None:
            self._links = _gplink_map()
        for container in self._links.get(guid.upper(), []):
            self.eng.unlink(container, guid)
        self.eng.delete(guid)
        self.retired.append(name)

    def apply_pack(self, pack, school, schools):
        if pack.scope == "school":
            scope_token, container = school.name, school.devices_ou
        else:
            scope_token, container = "GLOBAL", self.env.schools_ou
        name = f"{GPO_PREFIX}{pack.type_letter}-{scope_token}-{pack.id}"
        if not self._applicable(pack, school):
            if (pack.requires or "").strip() in NON_RETIRABLE_REQUIRES:
                if self.eng.find_by_name(name):
                    print(f"\n▸ {name}")
                    print(f"    ⚠ '{pack.requires}' not found on disk — GPO left untouched "
                          f"(not deleted). Fix the source path, or remove it deliberately "
                          f"with 'lmn-gpo remove --pack {pack.id}'.")
                    self.warnings.append(
                        f"{name}: precondition '{pack.requires}' missing — GPO kept, not updated")
                return
            self._retire(name)
            return
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
        # Exclusions must never fail silently: an unresolvable group means the GPO reaches
        # exactly the machines/users it was meant to spare, with nothing in the output to
        # show for it. (filter_apply already fails closed above; a deny cannot fail closed
        # without disabling the pack for everyone, so it is reported loudly instead and
        # makes the run exit non-zero.)
        def _deny(tokens, action, what):
            for token in tokens:
                sids = self._group_sids(token, school, schools)
                if not sids:
                    print(f"    ⚠ exclusion {token} matched no group — this GPO is NOT "
                          f"excluded from those devices/users!")
                    self.warnings.append(
                        f"{name}: {what} {token} resolved to no group — nothing excluded")
                    continue
                for sid in sids:
                    action(guid, sid)

        _deny(pack.filter_deny, self.eng.deny_apply, "deny-apply")
        _deny(pack.filter_deny_read, self.eng.deny_read, "deny-read")
        if filter_apply_sids:
            self.eng.set_exclusive_filter(guid, filter_apply_sids)
        self.results.append({"pack": pack.id, "gpo": name, "guid": guid})

    def run(self, packs):
        packs = self.selected_packs(packs)
        schools = self.selected_schools()
        print(f"Applying to {len(schools)} school(s): {', '.join(s.name for s in schools)}")
        self.print_preflight(packs, schools)
        if self._kmshost():
            print(f"KMS host (Windows): {self._kmshost()}:{self._kms_port()}")
        if self._kms_office_host():
            src = "own setting" if (self.answers.get("kms_office_host") or "").strip() \
                else "same as Windows"
            print(f"KMS host (Office):  {self._kms_office_host()}:{self._kms_office_port()}  ({src})")
        for pack in packs:
            if pack.scope == "school":
                for school in schools:
                    self.apply_pack(pack, school, schools)
            else:
                # A global pack is linked at OU=SCHOOLS, i.e. it reaches EVERY school —
                # so its exclusion groups must be resolved against every school too, not
                # just the ones selected for this run. Otherwise `apply --school a` would
                # leave school b's teacher notebooks unexcluded while still applying to them.
                self.apply_pack(pack, None, list(self.env.schools))

        reconciled = True
        if not self.dry_run:
            print("\nReconciling sysvol/AD ACL:")
            reconciled = self.eng.reconcile_sysvol()
        ok, out = self.eng.aclcheck()
        print(f"\naclcheck: {'ok' if ok else 'MISMATCH — ' + (out.splitlines()[0] if out else '')}")
        print(f"Done: {len(self.results)} GPO(s) applied."
              + (f" {len(self.retired)} retired (precondition removed)." if self.retired else ""))
        if self.retired:
            print("  Note: the KMS registry values are outside the Policies branches and are")
            print("  NOT withdrawn from clients by removing the GPO — they stay tattooed until")
            print("  cleared locally (slmgr.vbs /ckms, ospp.vbs /remhst).")

        problems = list(self.warnings)
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
    gplinks = _gplink_map()

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
