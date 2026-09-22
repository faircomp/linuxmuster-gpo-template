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
from .drives import GppDrives
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
    # Veyon bandwidth (pack 10b). Quality enum is inverted: 0=Highest(lossless) .. 4=Lowest.
    "veyon_monitoring_interval_ms": 2000,  # thumbnail refresh in ms (Veyon default 1000)
    "veyon_monitoring_quality": 3,         # thumbnails: 3 = Low (Veyon default 2 = Medium)
    "veyon_remote_quality": 2,             # remote view: 2 = Medium (Veyon default 0 = lossless)
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
    # Teacher enterprise WLANs. A LIST, because teachers roam between sites with their
    # notebook: every teacher SSID and every RADIUS CA must be present on every teacher
    # notebook. [{ssid, servernames, ca_cert}] - order is the connection preference.
    "wlan_enterprise_networks": [],
    # Single-network form, still honoured and folded into the list above.
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
        self.dm = GppDrives(self.eng)
        self.sc = ScriptsExt(self.eng)
        self.results: list[dict] = []
        self.retired: list[str] = []
        self.skipped: list[str] = []    # optional packs whose feature is not enabled
        self.held_back: list[str] = []  # packs whose exclusion group is missing (fail-closed)
        self.warnings: list[str] = []   # non-fatal problems that must still fail the run
        self._links: dict[str, list[str]] | None = None   # gPLink map, built on first retire
        self._warned: set[str] = set()   # de-duplicate per-field validation warnings
        # packs whose precondition failed because a FILE was missing, not because the
        # operator switched them off - those must never be retired (a typo in a path
        # would otherwise delete a working GPO)
        self._file_precondition_failed: set[str] = set()
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

    def _veyon_quality(self, key: str, default: int) -> str:
        """Veyon image-quality enum, 0=Highest(lossless) .. 4=Lowest. Out-of-range values
        are clamped rather than written through: Veyon silently ignores a bad enum and
        falls back to its own default, which would look like the pack doing nothing."""
        try:
            v = int(self.answers.get(key, default))
        except (TypeError, ValueError):
            v = default
        if not 0 <= v <= 4:
            # _resolve_str runs per registry field, so warn once per run, not nine times.
            if key not in self._warned:
                self._warned.add(key)
                print(f"    ⚠ {key}={v} is outside 0-4 (0=Highest .. 4=Lowest) - using {default}.")
            v = default
        return str(v)

    def _veyon_interval(self) -> str:
        """Thumbnail refresh in ms. Floor of 100 ms so a typo cannot turn the monitoring
        grid into a denial of service against the classroom switch."""
        try:
            v = int(self.answers.get("veyon_monitoring_interval_ms", 2000))
        except (TypeError, ValueError):
            v = 2000
        return str(max(100, v))

    def _wlan_enterprise_networks(self) -> list:
        """Teacher enterprise WLANs as a normalised list, newest form first.

        Accepts both the list form (wlan_enterprise_networks) and the older three single
        keys, so an existing site.yaml keeps working unchanged.
        """
        nets = []
        for n in (self.answers.get("wlan_enterprise_networks") or []):
            if isinstance(n, dict) and (n.get("ssid") or "").strip():
                nets.append({"ssid": str(n["ssid"]).strip(),
                             "servernames": str(n.get("servernames") or "").strip(),
                             "ca_cert": str(n.get("ca_cert") or "").strip()})
        if not nets:
            ssid = (self.answers.get("wlan_enterprise_ssid") or "").strip()
            if ssid:
                nets.append({"ssid": ssid,
                             "servernames": (self.answers.get("wlan_enterprise_servernames") or "").strip(),
                             "ca_cert": (self.answers.get("wlan_enterprise_ca_cert") or "").strip()})
        return nets

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

    def _firefox_homepage_url(self, school):
        """The configured homepage URL (per-school override first), ignoring the gate."""
        byschool = self.answers.get("firefox_homepage_by_school") or {}
        if school and byschool.get(school.name):
            return str(byschool[school.name]).strip()
        return (self.answers.get("firefox_homepage") or "").strip()

    def _firefox_homepage(self, school):
        # The homepage pack is a sub-option of the Firefox packs: without firefox_enabled
        # the URL is ignored. _skip_reason() tells the operator so.
        if not self.answers.get("firefox_enabled"):
            return ""
        return self._firefox_homepage_url(school)

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
            "@veyon-monitoring-interval": self._veyon_interval(),
            "@veyon-monitoring-quality": self._veyon_quality("veyon_monitoring_quality", 3),
            "@veyon-remote-quality": self._veyon_quality("veyon_remote_quality", 2),
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
        if token in ("@nopxe", "@teachernb"):
            return [sid for _, sid in self._device_group_sids(token, targets) if sid]
        if token in ("@role-teacher", "@role-student", "@role-staff"):
            cn = token[1:]
            msg = ad.find_one(f"(&(objectClass=group)(cn={cn}))", base=self.env.global_ou,
                              scope="sub", attrs=["objectSid"])
            return [ad.sid_of(msg)] if msg else []
        return []

    def _teachernb(self) -> str:
        """The teachernb answer: 'nopxe' (default), 'skip' (no teacher notebooks) or a CN."""
        tnb = self.answers.get("teachernb", "nopxe")
        return "skip" if tnb in (None, "", "skip") else str(tnb).strip()

    def _device_group_label(self, token) -> str:
        if token == "@teachernb" and self._teachernb() not in ("nopxe", "skip"):
            return f"'{self._teachernb()}'"
        return "d_nopxe"

    def _device_group_sids(self, token, targets):
        """[(school, sid-or-None)] for the device group behind @nopxe / @teachernb.

        Resolved per school (the CN is searched below each school's DN), so a group that
        exists in one school only is reported as absent for the others.
        """
        tnb = self._teachernb() if token == "@teachernb" else "nopxe"
        if tnb == "skip":
            return [(s, None) for s in targets]
        if tnb == "nopxe":
            return [(s, s.nopxe.sid if s.nopxe and s.nopxe.sid else None) for s in targets]
        return [(s, self._find_group_sid(tnb, s.dn)) for s in targets]

    def _exclusion(self, token, school, schools):
        """Resolve one filter_deny / filter_deny_read / filter_apply token for a pack scope.

        Returns (sids, status, note):
          'ok'        sids to filter with (note names schools of a global pack that have
                      no such group — nothing is excluded there)
          'disabled'  teachernb: skip — the operator says there are no teacher notebooks,
                      the exclusion is dropped and the pack applies to every device
          'missing'   the group exists nowhere in this scope — the pack is held back
                      (fail-closed) instead of reaching the devices it was meant to spare
        """
        if token == "@teachernb" and self._teachernb() == "skip":
            return [], "disabled", "teachernb: skip"
        if token in ("@nopxe", "@teachernb"):
            targets = [school] if school else schools
            per = self._device_group_sids(token, targets)
            sids = [sid for _, sid in per if sid]
            without = [s.name for s, sid in per if not sid]
            label = self._device_group_label(token)
            if not sids:
                return [], "missing", f"no {label} group in {', '.join(without) or 'any school'}"
            note = (f"no {label} group in {', '.join(without)} — nothing excluded there"
                    if without else "")
            return sids, "ok", note
        sids = self._group_sids(token, school, schools)
        return (sids, "ok", "") if sids else ([], "missing", "group not found")

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
            nets = []
            for n in self._wlan_enterprise_networks():
                # Print what is actually being pinned per network: a wrong file fails
                # silently on the client (no prompt - DisableUserPromptForServerValidation).
                try:
                    print(f"    {n['ssid']}: RADIUS CA pinned: "
                          f"{wlanmod.describe_cert(n['ca_cert'])}")
                    nets.append({**n, "ca_der": wlanmod.read_cert_der(n["ca_cert"])})
                except Exception as exc:
                    print(f"    \u26a0 {n['ssid']}: {exc}")
                    self.warnings.append(f"teacher Wi-Fi '{n['ssid']}': {exc}")
            if not nets:
                return
            content = wlanmod.build_enterprise_script(nets)
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
            nets = self._wlan_enterprise_networks()
            if not nets:
                return False
            missing = [n for n in nets if not (n["ca_cert"] and os.path.isfile(n["ca_cert"]))]
            if missing:
                # A path that does not exist used to sail through here and blow up mid-apply.
                # It must never RETIRE the GPO either - a typo would delete a working one.
                self._file_precondition_failed.add(pack.id)
                if pack.id not in self._warned:
                    self._warned.add(pack.id)
                    for n in missing:
                        msg = (f"RADIUS CA missing for '{n['ssid']}': "
                               f"{n['ca_cert'] or '(no ca_cert set)'}")
                        self.warnings.append(f"{msg} - teacher Wi-Fi pack skipped")
                        print(f"    \u26a0 {msg} - teacher Wi-Fi pack skipped (GPO left untouched).")
                return False
            return True
        if req == "home_drive":
            return bool(self.answers.get("home_drive_enabled"))
        if req == "bootorder":
            return bool(self.answers.get("bootorder_pxe_first"))
        if req == "pointandprint":
            return bool(self.answers.get("pointandprint_enabled"))
        return True

    def _skip_reason(self, pack, school) -> str:
        """Why an optional pack is not applicable, in site.yaml terms ('' = applicable).

        Printed on the pack's line, so a half-configured feature (a Firefox homepage URL
        without firefox_enabled, a proxy host without proxy_enabled) is never a silent
        no-op again.
        """
        req = (pack.requires or "").strip()
        if not req or self._applicable(pack, school):
            return ""
        sname = school.name if school else "<school>"
        if req == "kmshost":
            return "kmshost is empty"
        if req == "kms_office":
            return "kms_office_host and kmshost are empty"
        if req == "wallpaper":
            base = self.answers.get("wallpaper_dir") or WALLPAPER_DIR
            return f"no wallpaper {base}/{sname}.jpg|png (or default.*)"
        if req == "veyon":
            return "veyon_binddn / veyon_bindpw_hex not set"
        if req == "firefox":
            return "firefox_enabled is not true"
        if req == "firefox_homepage":
            if not self.answers.get("firefox_enabled"):
                url = self._firefox_homepage_url(school)
                return ("firefox_enabled is not true"
                        + (f" (the configured homepage {url!r} is ignored)" if url else ""))
            return f"no firefox_homepage (or firefox_homepage_by_school[{sname}]) URL"
        if req == "proxy":
            return "proxy_enabled is not true"
        if req == "proxy_school":
            if not self.answers.get("proxy_enabled"):
                host = self._proxy_host(school)
                return ("proxy_enabled is not true"
                        + (f" (the configured proxy host {host!r} is ignored)" if host else ""))
            return f"no proxy_host (or proxy_host_by_school[{sname}])"
        if req == "wlan_psk":
            return "wlan_psk_networks is empty"
        if req == "wlan_enterprise":
            return "wlan_enterprise_networks / wlan_enterprise_ssid not set"
        if req == "home_drive":
            return "home_drive_enabled is not true"
        if req == "bootorder":
            return "bootorder_pxe_first is not true"
        if req == "pointandprint":
            return "pointandprint_enabled is not true"
        return f"'{req}' precondition not met"

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

        Returns one row (pack_id, scope_label, kind, token, status, note) per token that
        does not resolve cleanly:
          status 'missing'   no group in the pack's scope — the pack is held back
                             ('exclude'/'exclude-read') or skipped ('only'); fail-closed
          status 'disabled'  teachernb: skip — the exclusion is dropped, the pack applies
                             to every device ('only' packs are skipped)
          status 'partial'   global pack; some schools have no such group, nothing is
                             excluded there (informational)
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
                        sids, status, note = self._exclusion(token, school, pool)
                        if status == "ok" and note:
                            rows.append((pack.id, label, kind, token, "partial", note))
                        elif status != "ok":
                            rows.append((pack.id, label, kind, token, status, note))
        return rows

    def print_preflight(self, packs, schools=None) -> bool:
        """Print the prerequisite check. True when no pack is held back or skipped."""
        rows = self.preflight(packs, schools)
        hard = [r for r in rows if r[4] == "missing" or (r[4] == "disabled" and r[2] == "only")]
        disabled = sorted({r[0] for r in rows if r[4] == "disabled" and r[2] != "only"})
        partial = {}
        for pid, _label, _kind, token, status, note in rows:
            if status == "partial":
                partial.setdefault(note, set()).add(pid)
        if not rows:
            print("Prerequisite check: all security-filter groups resolve. ✓")
            return True
        print("Prerequisite check:")
        if disabled:
            print("    teachernb: skip — @teachernb exclusions are off, these packs apply to "
                  "every device: " + ", ".join(disabled))
        for note, pids in sorted(partial.items()):
            print(f"    note: {note} ({', '.join(sorted(pids))})")
        if hard:
            print("    ⚠ these filters match NO group in their scope — the pack is held back "
                  "(GPO not created, an existing one left untouched):")
            for pid, label, kind, token, status, note in hard:
                what = "teachernb: skip" if status == "disabled" else note
                print(f"        {pid:26} {label:16} {kind:13} {token:12} {what}")
            print("    Fix: create the group, or set 'teachernb' in site.yaml to the group CN "
                  "you use ('skip' = there are no teacher notebooks).")
        return not hard

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
            return False
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
        return True

    def _hold_back(self, name, pack, reason):
        """Fail closed: an exclusion that resolves to no group would make the GPO reach
        exactly the devices it was meant to spare, so the pack is not applied in this scope.
        One line, no exit-code drama: nothing was changed, and the preflight said why."""
        existing = self.eng.find_by_name(name)
        print(f"\n▸ {name}  held back: {reason}"
              + (f" — existing GPO left untouched (remove it deliberately with "
                 f"'lmn-gpo remove --pack {pack.id}')" if existing else " — GPO not created"))
        self.held_back.append(name)

    def _drive_items(self, pack, school, schools):
        """Catalog drive entries -> Drives.xml items, group tokens resolved to SIDs."""
        out = []
        for it in pack.drives:
            if not isinstance(it, dict) or not it.get("letter"):
                continue
            item = dict(it)
            groups = []
            for token in it.get("only") or []:
                for sid in self._group_sids(token, school, schools):
                    groups.append({"name": str(token).lstrip("@"), "sid": sid})
            if it.get("only") and not groups:
                # Same rule as filter_apply: an unresolvable "only these groups" must not
                # silently widen the item to everyone.
                print(f"    \u26a0 drive {it['letter']}: group(s) {it['only']} not found - "
                      f"item skipped (it would otherwise apply to EVERYONE).")
                self.warnings.append(
                    f"{pack.id}: drive {it['letter']} group {it['only']} unresolved - item skipped")
                continue
            item["groups"] = groups
            out.append(item)
        return out

    def apply_pack(self, pack, school, schools):
        if pack.scope == "school":
            scope_token, container = school.name, school.devices_ou
        else:
            scope_token, container = "GLOBAL", self.env.schools_ou
        name = f"{GPO_PREFIX}{pack.type_letter}-{scope_token}-{pack.id}"
        if not self._applicable(pack, school):
            keep = ((pack.requires or "").strip() in NON_RETIRABLE_REQUIRES
                    or pack.id in self._file_precondition_failed)
            if keep and self.eng.find_by_name(name):
                print(f"\n▸ {name}")
                print(f"    ⚠ '{pack.requires}' precondition file missing — GPO left untouched "
                      f"(not deleted). Fix the source path, or remove it deliberately "
                      f"with 'lmn-gpo remove --pack {pack.id}'.")
                self.warnings.append(
                    f"{name}: precondition '{pack.requires}' missing — GPO kept, not updated")
            elif not keep and self._retire(name):
                pass
            elif pack.id not in self._file_precondition_failed:   # that case warned already
                # Not enabled and no GPO to retire: say so in one line instead of vanishing
                # from the output (a homepage URL without firefox_enabled looked like a bug).
                print(f"\n▸ {name}  skipped: {self._skip_reason(pack, school)}")
                self.skipped.append(name)
            return
        # Exclusive-filter packs must fail CLOSED: a fresh GPO applies to Authenticated
        # Users, and set_exclusive_filter only restricts when it gets ≥1 SID. If the
        # 'only these groups' filter resolves to zero SIDs (e.g. @teachernb but no school
        # has a d_nopxe group), linking would roll the GPO out to EVERYONE. Skip + say so.
        filter_apply_sids = []
        if pack.filter_apply:
            for token in pack.filter_apply:
                sids, status, _note = self._exclusion(token, school, schools)
                filter_apply_sids += sids
            if not filter_apply_sids:
                why = ("teachernb: skip" if self._teachernb() == "skip"
                       and "@teachernb" in pack.filter_apply
                       else f"exclusive-filter group(s) {pack.filter_apply} not found")
                print(f"\n▸ {name}  skipped: {why} — otherwise the GPO would apply to EVERYONE")
                self.skipped.append(name)
                return
        # Exclusions are resolved BEFORE anything is written. One that matches no group
        # in this scope holds the pack back (fail-closed) — never "warn, exit 1, but the
        # GPO is created and reaches the devices it should have spared anyway".
        denies, notes = [], []
        for tokens, action in ((pack.filter_deny, self.eng.deny_apply),
                               (pack.filter_deny_read, self.eng.deny_read)):
            for token in tokens:
                sids, status, note = self._exclusion(token, school, schools)
                if status == "missing":
                    self._hold_back(name, pack, f"exclusion {token} matches no group ({note})")
                    return
                if status == "ok" and note:
                    notes.append(note)
                denies += [(action, sid) for sid in sids]
        print(f"\n▸ {name}")
        for note in notes:
            print(f"    note: {note}")
        guid, _ = self.eng.ensure(name)
        extra = {"@wallpaper": self._wallpaper_unc(school)} if school else {}

        self.rp.load(guid, self._registry_entries(pack, school, extra), gpo_dir=self.eng.sysvol_path(guid))
        self.se.apply(guid,
                      privilege_rights=self._priv_rights(pack.privilege_rights, school, schools),
                      group_membership=self._restricted_groups(pack.restricted_groups, school, schools))
        self.gp.add_local_admins(guid, self._admins_members(pack.local_admins, school, schools))
        if pack.drives:
            self.dm.set_drives(guid, self._drive_items(pack, school, schools))
        if pack.startup_scripts or pack.shutdown_scripts:
            def _load(lst):
                return [{"file": s["file"], "content": catalog.load_script(s["file"])} for s in lst]
            self.sc.set_scripts_powershell(guid, startup=_load(pack.startup_scripts),
                                           shutdown=_load(pack.shutdown_scripts))
        if pack.wlan:
            self._apply_wlan(pack, guid)
        self.eng.link(container, guid)
        for action, sid in denies:
            action(guid, sid)
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
              + (f" {len(self.retired)} retired (precondition removed)." if self.retired else "")
              + (f" {len(self.skipped)} skipped (feature not enabled)." if self.skipped else "")
              + (f" {len(self.held_back)} held back (exclusion group missing)."
                 if self.held_back else ""))
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


def parse_gpo_name(name, scopes):
    """Split 'LMN-<C|U|CU>-<scope>-<pack-id>' into (type, scope, pack_id); None if not ours.

    School names and pack ids both contain hyphens (default-school, 07-admins-schule), so
    the scope is matched against the known scope names (school OU names + GLOBAL), longest
    first — 'one' must not swallow a school called 'one-x'.
    """
    if not name.startswith(GPO_PREFIX):
        return None
    m = re.match(r"(CU|C|U)-(.*)$", name[len(GPO_PREFIX):])
    if not m:
        return None
    typ, rest = m.group(1), m.group(2)
    for scope in sorted(scopes, key=len, reverse=True):
        if rest.startswith(scope + "-") and len(rest) > len(scope) + 1:
            return typ, scope, rest[len(scope) + 1:]
    return None


def selected_for_removal(name, scopes, only_ids=None, schools=None) -> bool:
    """Does this GPO fall under `remove --pack ... --school ...`?

    --school limits the removal to that school's per-school GPOs; a global GPO
    (scope GLOBAL, linked at OU=SCHOOLS) reaches every school and is therefore never
    removed by a school selection — the same rule `apply --school` follows.
    """
    if not name.startswith(GPO_PREFIX):
        return False
    parsed = parse_gpo_name(name, scopes)
    if schools and (parsed is None or parsed[1] not in schools):
        return False
    if only_ids:
        if parsed is not None:
            return parsed[2] in only_ids
        return any(name.endswith("-" + pid) for pid in only_ids)   # unknown scope, old rule
    return True


def remove(env, dry_run=False, only_ids=None, schools=None):
    """Remove LMN- GPOs — all, a subset by pack id and/or by school: unlink then delete."""
    eng = GpoEngine(env, dry_run=dry_run)
    base = f"CN=Policies,CN=System,{env.basedn}"
    gplinks = _gplink_map()
    scopes = [s.name for s in env.schools] + ["GLOBAL"]
    if schools:
        print(f"Removing the per-school GPOs of: {', '.join(schools)} "
              "(global LMN-*-GLOBAL-* GPOs are left in place)")

    removed = 0
    for msg in ad.search(base=base, scope="one", expr="(objectClass=groupPolicyContainer)",
                         attrs=["displayName", "cn"]):
        name, guid = ad.val(msg, "displayName", ""), ad.val(msg, "cn", "")
        if not selected_for_removal(name, scopes, only_ids, schools):
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
