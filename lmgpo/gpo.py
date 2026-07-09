"""GPO engine: create / find / link / security-filter / backup / delete.

Wraps `samba-tool gpo` (which needs Domain-Admin credentials) and `samba-tool
dsacl` for security filtering. Reads for idempotency go through the local
sam.ldb via `ad`. All operations are idempotent and support dry-run.
"""
from __future__ import annotations

import re
import subprocess

from . import ad

# "Apply Group Policy" control-access right (MS-GPOL).
APPLY_GROUP_POLICY = "edacfd8f-ffb3-11d1-b41d-00a0c968f939"
# Read ACE the GPO object hands to a trustee together with Apply.
GPO_READ_ACE = "(A;CI;LCRPLORC;;;{sid})"
AUTH_USERS = "S-1-5-11"


class GpoError(RuntimeError):
    pass


class GpoEngine:
    def __init__(self, env, dry_run: bool = False, verbose: bool = True):
        self.env = env
        self.dry_run = dry_run
        self.verbose = verbose
        self._creds = None

    # ------------------------------------------------------------------ #
    # low level
    # ------------------------------------------------------------------ #
    def creds(self) -> str:
        if self._creds is None:
            user, pw = self.env.admin_creds()
            self._creds = f"{user}%{pw}"
        return self._creds

    def _log(self, msg: str):
        if self.verbose:
            print(msg)

    def _run(self, args: list[str], *, needs_creds: bool = True,
             input_text: str | None = None, check: bool = True,
             mutating: bool = True) -> subprocess.CompletedProcess:
        """Run samba-tool. In dry-run, mutating calls are printed, not executed."""
        shown = list(args)
        if needs_creds:
            args = args + ["-U", self.creds()]
            shown = shown + ["-U", "administrator%******"]
        if self.dry_run and mutating:
            self._log("    [dry-run] " + " ".join(shown)
                      + (f"  <<<{input_text!r}" if input_text else ""))
            return subprocess.CompletedProcess(shown, 0, "", "")
        p = subprocess.run(args, input=input_text, capture_output=True, text=True)
        if check and p.returncode != 0:
            raise GpoError(f"{' '.join(shown)} failed: {p.stderr.strip() or p.stdout.strip()}")
        return p

    # ------------------------------------------------------------------ #
    # lookup
    # ------------------------------------------------------------------ #
    def find_by_name(self, display: str) -> str | None:
        """Return the GUID ({...}) of the GPO with this displayName, or None."""
        base = f"CN=Policies,CN=System,{self.env.basedn}"
        # escape parens/backslash in the filter value
        safe = display.replace("\\", "\\5c").replace("(", "\\28").replace(")", "\\29")
        msg = ad.find_one(f"(&(objectClass=groupPolicyContainer)(displayName={safe}))",
                          base=base, scope="one", attrs=["cn", "displayName"])
        return ad.val(msg, "cn") if msg else None

    def gpo_dn(self, guid: str) -> str:
        return f"CN={guid},CN=Policies,CN=System,{self.env.basedn}"

    def sysvol_path(self, guid: str) -> str:
        return f"{self.env.sysvol_policies}/{guid}"

    # ------------------------------------------------------------------ #
    # create / ensure / delete / backup
    # ------------------------------------------------------------------ #
    def create(self, display: str) -> str:
        p = self._run(["samba-tool", "gpo", "create", display])
        if self.dry_run:
            return "{DRYRUN-GUID}"
        m = re.search(r"\{[0-9A-Fa-f-]{36}\}", p.stdout)
        if not m:
            raise GpoError(f"could not parse new GUID from: {p.stdout}")
        guid = m.group(0)
        self._log(f"    GPO angelegt: {display} {guid}")
        return guid

    def ensure(self, display: str) -> tuple[str, bool]:
        """Return (guid, created). Idempotent — reuses an existing GPO by name."""
        existing = self.find_by_name(display)
        if existing:
            self._log(f"    GPO existiert: {display} {existing}")
            return existing, False
        return self.create(display), True

    def delete(self, guid: str):
        self._run(["samba-tool", "gpo", "del", guid])
        self._log(f"    GPO gelöscht: {guid}")

    def backup(self, guid: str, tmpdir: str) -> str:
        self._run(["samba-tool", "gpo", "backup", guid, "--tmpdir", tmpdir], mutating=False)
        return f"{tmpdir}/{guid}"

    # ------------------------------------------------------------------ #
    # linking (idempotent)
    # ------------------------------------------------------------------ #
    def _linked_guids(self, container_dn: str) -> set[str]:
        msg = ad.find_one("(gPLink=*)", base=container_dn, scope="base", attrs=["gPLink"])
        gplink = ad.val(msg, "gPLink", "") if msg else ""
        return {g.upper() for g in re.findall(r"CN=(\{[0-9A-Fa-f-]+\})", gplink)}

    def link(self, container_dn: str, guid: str, *, enforce: bool = False,
             disable: bool = False) -> bool:
        """Link GPO to a container. Returns True if a change was made."""
        if guid.upper() in self._linked_guids(container_dn) and not (enforce or disable):
            self._log(f"    Link vorhanden: {guid} → {container_dn}")
            return False
        args = ["samba-tool", "gpo", "setlink", container_dn, guid]
        if enforce:
            args.append("--enforce")
        if disable:
            args.append("--disable")
        self._run(args)
        self._log(f"    verlinkt: {guid} → {container_dn}"
                  + (" (enforced)" if enforce else ""))
        return True

    def unlink(self, container_dn: str, guid: str) -> bool:
        if guid.upper() not in self._linked_guids(container_dn):
            return False
        self._run(["samba-tool", "gpo", "dellink", container_dn, guid])
        self._log(f"    Link entfernt: {guid} ⇹ {container_dn}")
        return True

    # ------------------------------------------------------------------ #
    # security filtering (via dsacl)
    # ------------------------------------------------------------------ #
    def _has_apply_ace(self, guid: str, sid: str, deny: bool) -> bool:
        """True if an Apply-Group-Policy allow/deny ACE for this SID already exists."""
        sddl = ad.descriptor_sddl(self.gpo_dn(guid)) or ""
        want = "OD" if deny else "OA"
        for ace in re.findall(r"\(([^)]*)\)", sddl):
            f = ace.split(";")
            if len(f) >= 6 and f[0].upper() == want and "CR" in f[2].upper() \
               and f[3].lower() == APPLY_GROUP_POLICY.lower() \
               and f[5].upper() == sid.upper():
                return True
        return False

    def grant_apply(self, guid: str, sid: str) -> None:
        """Grant Read + Apply-Group-Policy to a trustee SID on the GPO object."""
        if not self.dry_run and self._has_apply_ace(guid, sid, deny=False):
            self._log(f"    Filter: Apply für {sid} bereits erlaubt")
            return
        sddl = (f"(OA;CI;CR;{APPLY_GROUP_POLICY};;{sid})"
                + GPO_READ_ACE.format(sid=sid))
        self._run(["samba-tool", "dsacl", "set", "--objectdn", self.gpo_dn(guid),
                   "--action", "allow", "--sddl", sddl])
        self._log(f"    Filter: Apply erlaubt für {sid} auf {guid}")

    def deny_apply(self, guid: str, sid: str) -> None:
        """Deny Apply-Group-Policy to a trustee SID (deny wins over allow).

        Used for the update split: the 'updates off' GPO applies to all devices
        via Authenticated Users but carries a Deny-Apply ACE for the noPXE group,
        so non-LINBO clients fall through to the Windows default (updates on).
        Idempotent — will not append a duplicate ACE on re-run.
        """
        if not self.dry_run and self._has_apply_ace(guid, sid, deny=True):
            self._log(f"    Filter: Apply für {sid} bereits verweigert")
            return
        sddl = f"(OD;CI;CR;{APPLY_GROUP_POLICY};;{sid})"
        self._run(["samba-tool", "dsacl", "set", "--objectdn", self.gpo_dn(guid),
                   "--action", "deny", "--sddl", sddl])
        self._log(f"    Filter: Apply verweigert für {sid} auf {guid}")

    def set_exclusive_filter(self, guid: str, sids: list) -> None:
        """Filter the GPO so ONLY the given group SIDs apply it — for user-role
        loopback GPOs. Removes Authenticated Users' 'Apply Group Policy' ACE (keeps
        AU Read for MS16-072) and grants each SID Read + Apply. Idempotent.

        Uses samba.sd_utils.SDUtils so the DACL is re-canonicalised server-side
        (dsacl can add but not cleanly remove the AU-Apply ACE).
        """
        sids = [s for s in sids if s]
        if not sids:
            return
        if self.dry_run:
            self._log(f"    [dry-run] Exklusiv-Filter: nur {sids} (AU-Apply entfernen) auf {guid}")
            return
        from samba.sd_utils import SDUtils

        sdu = SDUtils(ad.db())
        dn = self.gpo_dn(guid)
        # Remove Authenticated Users' Apply-Group-Policy ACE (keep AU Read). A freshly
        # created GPO has exactly (OA;CI;CR;<AGP>;;AU); if already gone, ignore.
        try:
            sdu.dacl_delete_aces(dn, f"(OA;CI;CR;{APPLY_GROUP_POLICY};;AU)")
        except Exception:
            pass
        for sid in sids:
            if not self._has_apply_ace(guid, sid, deny=False):
                sdu.dacl_add_ace(dn, f"(OA;CI;CR;{APPLY_GROUP_POLICY};;{sid})")
                sdu.dacl_add_ace(dn, f"(A;CI;LCRPLORC;;;{sid})")
        self._log(f"    Exklusiv-Filter: nur {len(sids)} Gruppe(n), AU nur noch Read, auf {guid}")

    def aclcheck(self) -> tuple[bool, str]:
        p = self._run(["samba-tool", "gpo", "aclcheck"], needs_creds=True,
                      check=False, mutating=False)
        out = "\n".join(l for l in (p.stdout + p.stderr).splitlines()
                        if "setproctitle" not in l and "insecure" not in l).strip()
        return p.returncode == 0, out

    def domain_admins_has_gidnumber(self) -> bool:
        msg = ad.find_one("(sAMAccountName=Domain Admins)", attrs=["gidNumber"])
        return bool(ad.val(msg, "gidNumber"))

    def reconcile_sysvol(self) -> bool:
        """Re-sync sysvol NT ACLs with the AD DACLs (as GPMC would).

        Needed after security-filtering changes so `gpo aclcheck` stays clean.
        Guarded: skipped (with a warning) if Domain Admins carries a gidNumber,
        where sysvolreset can strip ACLs.
        """
        if self.domain_admins_has_gidnumber():
            self._log("    ⚠ Domain Admins hat eine gidNumber → sysvolreset übersprungen "
                      "(Risiko). sysvol/AD-ACL bitte manuell prüfen.")
            return False
        self._run(["samba-tool", "ntacl", "sysvolreset"], needs_creds=False)
        self._log("    sysvol-ACLs mit AD abgeglichen (sysvolreset).")
        return True
