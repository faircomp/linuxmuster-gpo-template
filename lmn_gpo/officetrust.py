"""Office trusted locations for the network drives (pack 21-office-trusted-schule).

Office blocks VBA macros in files from the Internet zone, and a file share that Windows does
not count as Local intranet or Trusted sites is treated like the internet: macros there are
blocked and "Unblock" in the file properties does nothing (Microsoft Learn,
"Macros from the internet are blocked by default in Office"). A *trusted location* skips that
check. This module turns the drives a user of one school can have into policy trusted
locations; docs/RESEARCH.md section 9 has the sources.

Three layers, each testable without a domain controller:

  *_sources()  the drives: H: (the share roots of the school's homeDirectory values), the
               enabled default drives of the sophomorix school GPO and, while 20-drives is
               switched on, the entries of drives.yaml; dfs_sources() adds, for a path on
               this server whose share is a DFS proxy (`msdfs proxy`, as
               linuxmuster-fileserver sets it up), the same path on the proxy target
  plan()       one UNC location per path - a path below another one is covered by it,
               because every location allows subfolders - and one drive-letter location per
               letter. More than MAX_LOCATIONS is an error, never a silent cut.
  entries()    the registry values for `samba-tool gpo load`, key and value names exactly as
               Microsoft's ADMX files spell them (access16/excel16/word16/ppt16/office16.admx,
               Administrative Template files 5568.1000)
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .drivesconf import substitute

OFFICE_KEY = r"software\policies\microsoft\office\16.0"
# The application key below OFFICE_KEY, per ADMX file (access16, excel16, word16, ppt16).
APP_KEYS = {"access": "access", "excel": "excel", "word": "word", "powerpoint": "powerpoint"}
APP_ORDER = ("access", "excel", "word", "powerpoint")
# "Trusted Location #1" .. "#20": twenty policies per application in every ADMX file.
MAX_LOCATIONS = 20
# The path forms that can be written: the UNC path the drive is mapped to, the drive letter,
# and the DFS target of a share on this server. Measured on Windows 11 with Access (lab
# 2026-11-12, docs/RESEARCH.md section 9): Office checks the path as the file was opened, and
# a letter and the UNC path it is mapped to cover each other; the DFS target only covers files
# opened through \\fs.<domain>\... itself. Default therefore unc + letter, dfs on request.
FORMS = ("unc", "letter", "dfs")
DEFAULT_FORMS = ("unc", "letter")
ROLES = ("teacher", "student", "staff")
DESCRIPTION_PREFIX = "lmn-gpo"
# office16.admx L_Allowmixofpolicyanduserlocations
COMMON_KEY = OFFICE_KEY + r"\common\security\trusted locations"
ALLOW_USER_LOCATIONS = "allow user locations"


@dataclass
class DriveSource:
    letter: str        # "H"
    path: str          # UNC path of the drive (for H: the share root of homeDirectory)
    origin: str        # where it comes from, for the output
    form: str = "unc"  # unc | dfs (the msdfs proxy target of a share on this server)


@dataclass
class Location:
    kind: str                                    # unc | dfs | letter
    path: str                                    # '\\server\school\' or 'H:\'
    letters: list = field(default_factory=list)
    origins: list = field(default_factory=list)

    @property
    def description(self) -> str:
        return DESCRIPTION_PREFIX + " " + " ".join(f"{x}:" for x in self.letters)


@dataclass
class TrustPlan:
    locations: list = field(default_factory=list)   # [Location], Location1 first
    notes: list = field(default_factory=list)       # sources that could not be used

    def lines(self) -> list[str]:
        out = []
        for i, loc in enumerate(self.locations, 1):
            letters = " ".join(f"{x}:" for x in loc.letters)
            out.append(f"location{i:<3} {loc.path:40} {letters}".rstrip())
        return out


# --------------------------------------------------------------------------- #
# paths
# --------------------------------------------------------------------------- #
def _parts(path: str) -> list[str]:
    """['host', 'share', 'folder', ...] of a UNC path, [] if it is not one."""
    if not isinstance(path, str) or not path.startswith("\\\\"):
        return []
    parts = path[2:].rstrip("\\").split("\\")
    if len(parts) < 2 or any(not p for p in parts):
        return []
    return parts


def share_root(path: str) -> str:
    r"""'\\host\share\' of a UNC path, '' if it is not one."""
    parts = _parts(path)
    return f"\\\\{parts[0]}\\{parts[1]}\\" if parts else ""


def static_path(path: str) -> str:
    r"""The UNC path with one trailing backslash, cut before the first component that holds
    a variable ('%LogonUser%' is a Group Policy Preferences variable that Office would not
    expand). '' when not even '\\host\share' is left."""
    parts = _parts(path)
    keep = []
    for p in parts:
        if "%" in p or "@@" in p:
            break
        keep.append(p)
    if len(keep) < 2:
        return ""
    return "\\\\" + "\\".join(keep) + "\\"


def _covers(outer: str, inner: str) -> bool:
    """Is `inner` the same as or below `outer`? Both end in a backslash; case-insensitive,
    like Windows paths."""
    return inner.casefold().startswith(outer.casefold())


# --------------------------------------------------------------------------- #
# sources
# --------------------------------------------------------------------------- #
def home_sources(home_directories) -> list[DriveSource]:
    """H: from the homeDirectory values of a school's users: their share roots, not one
    path per user (a student's home carries the class)."""
    roots: dict[str, str] = {}
    for hd in home_directories:
        root = share_root(str(hd or "").strip())
        if root:
            roots.setdefault(root.casefold(), root)
    return [DriveSource("H", root, "homeDirectory") for root in
            sorted(roots.values(), key=str.casefold)]


def sophomorix_sources(items, origin: str) -> list[DriveSource]:
    """The default drives of a sophomorix school GPO (sophodrives.DriveItem): every item
    that maps a letter and is not disabled (the WebUI disables a default drive in place)."""
    out = []
    for it in items or []:
        if it.disabled or not it.letter or it.action not in ("C", "R", "U", ""):
            continue
        out.append(DriveSource(it.letter.upper(), it.path, origin))
    return out


def proxy_root(value: str) -> str:
    r"""'\\host\share\' of an `msdfs proxy` value ('//fs.domain/share' or '\fs\share'),
    '' if it does not name a host and a share."""
    parts = [p for p in str(value or "").strip().replace("/", "\\").split("\\") if p]
    if len(parts) < 2 or any("%" in p for p in parts):
        return ""
    return "\\\\" + "\\".join(parts) + "\\"


def dfs_sources(sources, server_names, proxy_of) -> list[DriveSource]:
    r"""The DFS twins of the sources. A path on this server (host in `server_names`,
    case-insensitive) whose share is an msdfs proxy - `proxy_of(share)` returns the
    smb.conf value, '' for none - is trusted on the target as well:
    '\\server\school\x' -> '\\fs.domain\school\x'. The client really connects to the
    target (lab: Get-SmbConnection), and which of the two names Office checks is not
    measured yet."""
    names = {str(n).lower() for n in server_names if n}
    out = []
    for src in sources:
        parts = _parts(src.path)
        if not parts or parts[0].lower() not in names:
            continue
        root = proxy_root(proxy_of(parts[1]))
        if not root:
            continue
        path = root + "\\".join(parts[2:])
        out.append(DriveSource(src.letter, path, f"{src.origin} (msdfs proxy)", "dfs"))
    return out


def drives_yaml_sources(cfg, server: str, serverfqdn: str = "") -> list[DriveSource]:
    """The entries of a validated drives.yaml (drivesconf.DrivesConfig). `home: true` is H:,
    which the homeDirectory roots already cover. Taken from the file, not from the resolved
    plan: an entry held back for an unknown group still names a drive the admin wants."""
    return [DriveSource(e.letter, substitute(e.path, server, serverfqdn), f"drives.yaml {e.where}")
            for e in cfg.drives if not e.home and e.path]


# --------------------------------------------------------------------------- #
# the plan
# --------------------------------------------------------------------------- #
def plan(sources, forms=DEFAULT_FORMS) -> TrustPlan:
    r"""UNC locations, then DFS-target locations (each sorted by path), then drive-letter
    locations (sorted by letter); `forms` picks which of the three are written.

    A path below another one is merged into it: every location is written with
    'allow subfolders', so the outer one already covers it. Paths are compared
    case-insensitively but never across host names - `\\server\x` and `\\server.domain\x`
    are two strings to Office, so they stay two locations. Forms that are not wanted are
    dropped BEFORE merging, so a path never vanishes into an outer one that is not written.
    """
    out = TrustPlan()
    cands: dict[str, Location] = {}
    letters: dict[str, Location] = {}
    for src in sources:
        letter = (src.letter or "").upper()
        path = static_path(src.path)
        if not path:
            out.notes.append(f"{letter}: {src.path or '(no path)'} ({src.origin}) is not a "
                             f"UNC path \\\\server\\share - not trusted")
            continue
        if src.form in forms:
            loc = cands.setdefault(path.casefold(), Location(src.form, path))
            if letter and letter not in loc.letters:
                loc.letters.append(letter)
            if src.origin not in loc.origins:
                loc.origins.append(src.origin)
        if letter and src.form == "unc":
            lloc = letters.setdefault(letter, Location("letter", f"{letter}:\\", [letter]))
            if src.origin not in lloc.origins:
                lloc.origins.append(src.origin)

    kept: list[Location] = []
    for loc in sorted(cands.values(), key=lambda x: (x.path.count("\\"), x.path.casefold())):
        outer = next((k for k in kept if _covers(k.path, loc.path)), None)
        if outer is None:
            kept.append(loc)
            continue
        for x in loc.letters:
            if x not in outer.letters:
                outer.letters.append(x)
        for o in loc.origins:
            if o not in outer.origins:
                outer.origins.append(o)
    for loc in kept:
        loc.letters.sort()
    for form in ("unc", "dfs"):
        out.locations += sorted((k for k in kept if k.kind == form),
                                key=lambda x: x.path.casefold())
    if "letter" in forms:
        out.locations += [letters[x] for x in sorted(letters)]
    return out


def problems(p: TrustPlan) -> list[str]:
    """Why this plan must not be written ([] = fine)."""
    n = len(p.locations)
    if n == 0:
        return ["no drive could be determined (no homeDirectory, no default drive, no "
                "drives.yaml entry) - nothing to trust"]
    if n > MAX_LOCATIONS:
        return [f"{n} trusted locations needed, Office takes at most {MAX_LOCATIONS} per "
                f"application (Trusted Location #1-#{MAX_LOCATIONS}) - nothing is cut, the "
                f"pack is held back: drop drives from drives.yaml, or set "
                f"office_trusted_forms to fewer forms"]
    return []


# --------------------------------------------------------------------------- #
# registry values
# --------------------------------------------------------------------------- #
def entries(p: TrustPlan, apps) -> list[dict]:
    """`samba-tool gpo load` entries, all USER policy (the ADMX policies are class="User").

    Per application: allownetworklocations=1 (without it Office ignores every policy
    location on a network path) and location1..N with path (REG_EXPAND_SZ, the ADMX
    marks it expandable), allowsubfolders=1 and description. The optional `date` field
    is left out: it is informational, and a changing value would make every apply a
    change. Plus 'allow user locations'=1 in Common, which keeps Office's own and the
    user's locations next to the policy ones.
    """
    out = []
    for app in [a for a in APP_ORDER if a in apps]:
        base = f"{OFFICE_KEY}\\{APP_KEYS[app]}\\security\\trusted locations"
        out.append(_entry(base, "allownetworklocations", "REG_DWORD", 1))
        for i, loc in enumerate(p.locations, 1):
            key = f"{base}\\location{i}"
            out.append(_entry(key, "path", "REG_EXPAND_SZ", loc.path))
            out.append(_entry(key, "allowsubfolders", "REG_DWORD", 1))
            out.append(_entry(key, "description", "REG_SZ", loc.description))
    out.append(_entry(COMMON_KEY, ALLOW_USER_LOCATIONS, "REG_DWORD", 1))
    return out


def _entry(key, name, typ, data) -> dict:
    return {"keyname": key, "valuename": name, "class": "USER", "type": typ, "data": data}


# --------------------------------------------------------------------------- #
# site.yaml answers
# --------------------------------------------------------------------------- #
def _words(value) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = [x for x in value.replace(",", " ").split() if x]
    if not isinstance(value, list):
        return None
    return [str(x).strip().lower() for x in value if str(x).strip()]


def parse_apps(value) -> tuple[list[str], str]:
    """office_trusted_apps -> (apps, problem). Default [access]; [] is not 'off'."""
    words = _words(["access"] if value is None else value)
    if words is None:
        return [], f"office_trusted_apps must be a list, got {value!r}"
    bad = [w for w in words if w not in APP_KEYS]
    if bad:
        return [], (f"office_trusted_apps: unknown application(s) {', '.join(bad)} "
                    f"(allowed: {', '.join(APP_ORDER)})")
    if not words:
        return [], ("office_trusted_apps is empty - to switch the pack off set "
                    "office_trusted_enabled: false")
    return [a for a in APP_ORDER if a in words], ""


def parse_roles(value) -> tuple[list[str], str]:
    """office_trusted_roles -> (filter tokens, problem). 'all', [] or unset = every user
    (no filter); otherwise a subset of teacher, student, staff."""
    if value is None or (isinstance(value, str) and value.strip().lower() in ("", "all")):
        return [], ""
    words = _words(value)
    if words is None:
        return [], f"office_trusted_roles must be 'all' or a list, got {value!r}"
    if words == ["all"] or not words:
        return [], ""
    bad = [w for w in words if w not in ROLES]
    if bad:
        return [], (f"office_trusted_roles: unknown role(s) {', '.join(bad)} "
                    f"(allowed: all, or any of {', '.join(ROLES)})")
    return [f"@role-{r}" for r in ROLES if r in words], ""


def parse_forms(value) -> tuple[tuple, str]:
    """office_trusted_forms -> (forms, problem). Default DEFAULT_FORMS: the UNC path and the
    drive letter; the DFS target only on request (measured, docs/RESEARCH.md section 9)."""
    words = _words(list(DEFAULT_FORMS) if value is None else value)
    if words is None or not words:
        return (), f"office_trusted_forms must be a list of {', '.join(FORMS)}, got {value!r}"
    bad = [w for w in words if w not in FORMS]
    if bad:
        return (), (f"office_trusted_forms: unknown form(s) {', '.join(bad)} "
                    f"(allowed: {', '.join(FORMS)})")
    return tuple(f for f in FORMS if f in words), ""
