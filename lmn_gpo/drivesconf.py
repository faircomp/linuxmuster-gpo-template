"""drives.yaml: the admin's own drive letters for pack 20-drives.

Three layers, each testable without a domain controller:

  load()/parse()  read and validate the file (no AD). Every problem is collected and
                  reported with its position ("entry 3 (V:)"), nothing is guessed.
  plan()          resolve group names to SIDs through a resolver object and turn the
                  configuration into Drives.xml items plus one display row per entry.
                  An entry whose groups do not ALL resolve is held back, never widened.
  AdResolver      the resolver used on the DC: sAMAccountName -> SID, domain-wide.

Why a file of its own and not a key in site.yaml: `lmn-gpo setup` rewrites site.yaml with
yaml.safe_dump (comments and order are lost), and site.yaml holds secrets (mode 0600). This
file holds none, may be copied between servers and kept under version control, and lmn-gpo
only ever reads it.
"""
from __future__ import annotations

import difflib
import os
import re
from dataclasses import dataclass, field

import yaml

DEFAULT_FILE = "/etc/linuxmuster/lmn-gpo/drives.yaml"
# The letters of sophomorix' school GPO template (sophomorix-samba/config-devel/gpo/school/
# User/Preferences/Drives/Drives.xml): K program, P projects, S students, T share, R iso.
DEFAULT_LETTERS = ("K", "P", "R", "S", "T")
LETTERS = "DEFGHIJKLMNOPQRSTUVWXYZ"
ROLE_TOKENS = ("@role-teacher", "@role-student", "@role-staff")

_TOP_KEYS = ("version", "linuxmuster_defaults", "drives", "example")
_DEFAULTS_KEYS = ("remove", "for_groups")
_ENTRY_KEYS = ("letter", "label", "path", "home", "groups", "devices", "action", "reconnect")
_UNC = re.compile(r"^\\\\([^\\]+)\\([^\\]+)(\\[^\\]+)*$")
_SID = re.compile(r"^\*?S-1-\d+(-\d+)+$", re.IGNORECASE)


class DrivesConfigError(ValueError):
    """drives.yaml is missing or invalid. `problems` lists every finding."""

    def __init__(self, source: str, problems: list[str]):
        self.source = source
        self.problems = list(problems)
        super().__init__(f"{source}: " + "; ".join(self.problems))


@dataclass
class DriveEntry:
    index: int                 # 1-based position in the file
    letter: str
    label: str = ""
    path: str = ""
    home: bool = False
    groups: list = field(default_factory=list)
    devices: list = field(default_factory=list)
    action: str = "replace"    # replace | update
    reconnect: bool = False

    @property
    def where(self) -> str:
        return f"entry {self.index} ({self.letter}:)"

    @property
    def catch_all(self) -> bool:
        return not self.groups and not self.devices


@dataclass
class DrivesConfig:
    source: str
    remove: object = field(default_factory=list)      # "all" or a list of letters
    for_groups: list = field(default_factory=list)
    drives: list = field(default_factory=list)        # [DriveEntry]


# --------------------------------------------------------------------------- #
# loading and validation
# --------------------------------------------------------------------------- #
def _bool_key_hint(key) -> str:
    # YAML 1.1 (PyYAML) reads off/on/yes/no as booleans, also as mapping KEYS.
    return (f"key {key!r}: YAML reads off/on/yes/no as true/false - "
            f"use 'remove' for the linuxmuster default letters") if isinstance(key, bool) \
        else f"unknown key {key!r}"


def _names(value, what: str, problems: list[str]) -> list[str]:
    """A list of group names; a single name is accepted as a list of one."""
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        problems.append(f"{what}: must be a list of group names, got {type(value).__name__}")
        return []
    out = []
    for v in value:
        if not isinstance(v, str) or not v.strip():
            problems.append(f"{what}: {v!r} is not a group name (quote it)")
            continue
        if v.strip() not in out:
            out.append(v.strip())
    return out


def _letter(value, what: str, problems: list[str]) -> str:
    if not isinstance(value, str) or len(value.strip().rstrip(":")) != 1:
        problems.append(f"{what}: letter {value!r} must be one drive letter D-Z")
        return ""
    letter = value.strip().rstrip(":").upper()
    if letter not in LETTERS:
        problems.append(f"{what}: letter {letter}: is not allowed (D-Z only; A-C are "
                        f"floppy/system letters)")
        return ""
    return letter


def parse(data, source: str = "drives.yaml") -> DrivesConfig:
    """Validate an already loaded YAML document. Raises DrivesConfigError."""
    problems: list[str] = []
    if not isinstance(data, dict):
        raise DrivesConfigError(source, ["the file must be a YAML mapping (version:, "
                                         "linuxmuster_defaults:, drives:)"])
    for key in data:
        if key not in _TOP_KEYS:
            problems.append(_bool_key_hint(key) + f" (allowed: {', '.join(_TOP_KEYS[:3])})")
    if data.get("example"):
        problems.append("this is still the shipped EXAMPLE: adapt paths and groups to this "
                        "site, then delete the line 'example: true'")
    if data.get("version") != 1:
        problems.append(f"version: must be 1, got {data.get('version')!r}")

    cfg = DrivesConfig(source=source)
    defaults = data.get("linuxmuster_defaults")
    if defaults is None:
        defaults = {}
    if not isinstance(defaults, dict):
        problems.append("linuxmuster_defaults: must be a mapping (remove:, for_groups:)")
        defaults = {}
    for key in defaults:
        if key not in _DEFAULTS_KEYS:
            problems.append("linuxmuster_defaults: " + _bool_key_hint(key)
                            + f" (allowed: {', '.join(_DEFAULTS_KEYS)})")
    remove = defaults.get("remove", [])
    if remove is None:
        remove = []
    if isinstance(remove, str) and remove.strip().lower() == "all":
        cfg.remove = "all"
    elif isinstance(remove, list):
        letters = []
        for v in remove:
            letter = _letter(v, "linuxmuster_defaults.remove", problems)
            if letter == "H":
                problems.append("linuxmuster_defaults.remove: H: cannot be removed - it is "
                                "the home drive every account carries (homeDrive)")
            elif letter and letter not in letters:
                letters.append(letter)
        cfg.remove = sorted(letters)
    else:
        problems.append(f"linuxmuster_defaults.remove: must be 'all', [] or a list of "
                        f"letters, got {remove!r}")
    cfg.for_groups = _names(defaults.get("for_groups"), "linuxmuster_defaults.for_groups",
                            problems)

    entries = data.get("drives")
    if entries is None:
        entries = []
    if not isinstance(entries, list):
        problems.append("drives: must be a list of entries (- letter: ...)")
        entries = []
    for i, raw in enumerate(entries, 1):
        where = f"entry {i}"
        if not isinstance(raw, dict):
            problems.append(f"{where}: must be a mapping (letter:, path:, ...)")
            continue
        if isinstance(raw.get("letter"), str):
            where = f"entry {i} ({raw['letter'].strip().rstrip(':').upper()}:)"
        for key in raw:
            if key not in _ENTRY_KEYS:
                problems.append(f"{where}: " + _bool_key_hint(key)
                                + f" (allowed: {', '.join(_ENTRY_KEYS)})")
        letter = _letter(raw.get("letter"), where, problems)
        ent = DriveEntry(index=i, letter=letter or "?")
        label = raw.get("label")
        if label is not None and not isinstance(label, str):
            problems.append(f"{where}: label {label!r} must be text (quote it)")
        elif label:
            if any(ord(c) < 32 for c in label):
                problems.append(f"{where}: label contains control characters")
            ent.label = label.strip()
        home = raw.get("home", False)
        if not isinstance(home, bool):
            problems.append(f"{where}: home must be true or false")
            home = False
        ent.home = home
        path = raw.get("path")
        if home and path:
            problems.append(f"{where}: give either 'path' or 'home: true', not both")
        elif not home and not path:
            problems.append(f"{where}: needs 'path' (a UNC path \\\\server\\share...) or "
                            f"'home: true'")
        elif path:
            if not isinstance(path, str):
                problems.append(f"{where}: path must be text")
            elif any(ord(c) < 32 for c in path):
                problems.append(f"{where}: path contains control characters")
            elif not _UNC.match(path.strip()):
                problems.append(f"{where}: path {path!r} is not a UNC path "
                                f"\\\\server\\share[\\folder] (no trailing backslash) - "
                                f"in YAML write it in single quotes")
            else:
                ent.path = path.strip()
        if letter == "H" and not home:
            problems.append(f"{where}: H: is the home drive (sophomorix sets homeDrive H: on "
                            f"every account) - only 'home: true' may use it")
        if home and letter and letter != "H":
            problems.append(f"{where}: 'home: true' is only allowed on H:")
        ent.groups = _names(raw.get("groups"), f"{where}: groups", problems)
        ent.devices = _names(raw.get("devices"), f"{where}: devices", problems)
        action = raw.get("action")
        if action is not None:
            word = str(action).strip().lower() if isinstance(action, str) else ""
            if word not in ("replace", "update"):
                problems.append(f"{where}: action {action!r} must be replace or update")
            elif home:
                problems.append(f"{where}: 'home: true' always uses update (like 19-home-h) "
                                f"- remove 'action'")
            else:
                ent.action = word
        reconnect = raw.get("reconnect", False)
        if not isinstance(reconnect, bool):
            problems.append(f"{where}: reconnect must be true or false")
        elif reconnect:
            if home:
                problems.append(f"{where}: reconnect is not available for 'home: true'")
            elif ent.action != "replace":
                problems.append(f"{where}: reconnect needs action replace (it is written with "
                                f"removePolicy, which Windows only accepts on Replace)")
            ent.reconnect = True
        cfg.drives.append(ent)

    # Same letter more than once: allowed, the first matching entry wins. An entry for
    # everybody therefore has to be the LAST one for its letter, or the later ones could
    # never match.
    by_letter: dict[str, list[DriveEntry]] = {}
    for ent in cfg.drives:
        by_letter.setdefault(ent.letter, []).append(ent)
    for letter, ents in by_letter.items():
        for ent in ents[:-1]:
            if ent.catch_all and letter != "?":
                later = ", ".join(str(e.index) for e in ents if e.index > ent.index)
                problems.append(f"{ent.where}: has no groups/devices, so it matches everybody "
                                f"and entry {later} for {letter}: could never apply - move it "
                                f"last or give it groups")
    if not cfg.drives and not cfg.remove:
        problems.append("nothing configured: no drives and no linuxmuster default letters to "
                        "remove")
    if problems:
        raise DrivesConfigError(source, problems)
    return cfg


def load(path: str) -> DrivesConfig:
    """Read and validate drives.yaml. Raises DrivesConfigError (missing file included)."""
    if not path or not os.path.isfile(path):
        raise DrivesConfigError(path or DEFAULT_FILE, ["file not found"])
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise DrivesConfigError(path, [f"cannot be read: {exc}"]) from exc
    return parse(data, path)


# --------------------------------------------------------------------------- #
# group resolution
# --------------------------------------------------------------------------- #
@dataclass
class Resolved:
    token: str
    status: str            # ok | missing | ambiguous
    name: str = ""         # canonical sAMAccountName ('' for a bare well-known SID)
    sid: str = ""
    note: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def _ldap_escape(value: str) -> str:
    # RFC 4515, backslash first; '*' too, so a name can never become a wildcard search
    return (str(value).replace("\\", "\\5c").replace("*", "\\2a").replace("(", "\\28")
            .replace(")", "\\29").replace("\x00", "\\00"))


class AdResolver:
    """Group name -> SID from the local sam.ldb, by sAMAccountName (unique domain-wide).

    Not by CN below some OU: in a multi-school domain a group in default-school and one
    created with `--school global` can carry the same CN, while sAMAccountName cannot
    clash. Only SECURITY groups resolve - a distribution group is not in the logon token,
    so a targeting item with its SID would never match.
    """

    def __init__(self, ad_module=None):
        if ad_module is None:
            from . import ad as ad_module
        self.ad = ad_module
        self._cache: dict[str, Resolved] = {}
        self._all: list[str] | None = None

    def _suggest(self, name: str) -> str:
        if self._all is None:
            try:
                self._all = sorted({self.ad.val(m, "sAMAccountName", "") for m in
                                    self.ad.search(expr="(objectClass=group)",
                                                   attrs=["sAMAccountName"])} - {""})
            except Exception:
                self._all = []
        close = difflib.get_close_matches(name, self._all, n=2, cutoff=0.85)
        return f" (did you mean {' or '.join(close)}?)" if close else ""

    def group(self, token: str, computer: bool = False) -> Resolved:
        token = str(token).strip()
        if token in self._cache:
            return self._cache[token]
        res = self._lookup(token)
        self._cache[token] = res
        return res

    def _lookup(self, token: str) -> Resolved:
        if _SID.match(token):
            sid = token.lstrip("*").upper()
            msgs = self.ad.search(expr=f"(objectSid={sid})",
                                  attrs=["sAMAccountName", "objectSid"])
            if msgs:
                return Resolved(token, "ok", self.ad.val(msgs[0], "sAMAccountName", ""), sid)
            if not sid.startswith("S-1-5-21-"):       # well-known SID: not an object here
                return Resolved(token, "ok", "", sid, "well-known SID")
            return Resolved(token, "missing", note="does not exist in the domain")
        if token.startswith("@"):
            if token not in ROLE_TOKENS:
                return Resolved(token, "missing",
                                note=f"is not a known token ({', '.join(ROLE_TOKENS)})")
            name = token[1:]
        else:
            name = token
        msgs = self.ad.search(
            expr=f"(&(objectClass=group)(sAMAccountName={_ldap_escape(name)}))",
            attrs=["sAMAccountName", "objectSid", "groupType"])
        if not msgs:
            return Resolved(token, "missing", note="not found" + self._suggest(name))
        if len(msgs) > 1:
            return Resolved(token, "ambiguous",
                            note=f"is ambiguous ({len(msgs)} groups carry this name)")
        msg = msgs[0]
        gtype = self.ad.val(msg, "groupType")
        if gtype is not None:
            try:
                if not int(gtype) & 0x80000000:
                    return Resolved(token, "missing", note="is a distribution group, not a "
                                    "security group - it is not in the logon token")
            except ValueError:
                pass
        sid = self.ad.sid_of(msg)
        if not sid:
            return Resolved(token, "missing", note="has no objectSid")
        return Resolved(token, "ok", self.ad.val(msg, "sAMAccountName", name), sid)


# --------------------------------------------------------------------------- #
# the plan: what apply writes, and what it holds back
# --------------------------------------------------------------------------- #
@dataclass
class Row:
    where: str             # "remove" or "entry 3 (V:)"
    kind: str              # del | home | map
    letters: str           # "K P R S T" or "V"
    action: str            # delete | update | replace
    path: str
    groups: str            # display: "teachers|lk-msg" or "all users"
    devices: str
    status: str            # ok | held
    note: str = ""


@dataclass
class DrivesPlan:
    items: list = field(default_factory=list)       # input for drives.render_managed()
    rows: list = field(default_factory=list)        # [Row]
    remove_letters: list = field(default_factory=list)
    remove_source: str = ""
    resolved: dict = field(default_factory=dict)    # token -> Resolved

    @property
    def held(self) -> list:
        return [r for r in self.rows if r.status == "held"]

    @property
    def complete(self) -> bool:
        return not self.held

    def lines(self) -> list[str]:
        """The table apply and doctor print, one line per row."""
        out = []
        for r in self.rows:
            letters = " ".join(f"{x}:" for x in r.letters.split())
            if r.status == "held":
                out.append(f"{letters:16} held back ({r.where}): {r.note}")
                continue
            who = r.groups + (f"  on {r.devices}" if r.devices else "")
            path = r.path if r.kind != "del" else ""
            out.append(f"{letters:16} {r.action:8} {path:36} {who}".rstrip())
        return out


def _display(names: list[str], resolved: dict) -> str:
    return "|".join((resolved[n].name or n) if n in resolved else n for n in names)


def substitute(path: str, server: str, serverfqdn: str = "") -> str:
    """@serverfqdn / @server -> this server (longest token first). @server is the NetBIOS
    name in lower case, exactly what sophomorix writes for @@SERVER@@ in its own
    Drives.xml, so admin paths and linuxmuster's look the same in Explorer."""
    if serverfqdn:
        path = path.replace("@serverfqdn", serverfqdn)
    return path.replace("@server", server)


def plan(cfg: DrivesConfig, resolver, *, netbios: str, server: str, serverfqdn: str = "",
         sopho_letters=None, sopho_source: str = "") -> DrivesPlan:
    """Turn a validated configuration into Drives.xml items.

    Fail closed, per entry: an entry is written only when EVERY group it names resolves
    (two of three is not 'a narrower entry', it is a different one). The default-letter
    Delete items are written only when every `for_groups` group resolves - otherwise the
    defaults would be removed for everyone instead of for those groups.
    """
    out = DrivesPlan()

    def resolve(names, computer=False):
        res = [resolver.group(n, computer=computer) for n in names]
        for n, r in zip(names, res):
            out.resolved[n] = r
        bad = [r for r in res if not r.ok]
        refs = [{"name": f"{netbios}\\{r.name}" if r.name else "", "sid": r.sid}
                for r in res if r.ok]
        return refs, bad

    def why(bad) -> str:
        return "; ".join(f"group '{b.token}' {b.note or b.status}" for b in bad)

    # 1. linuxmuster's default letters
    if cfg.remove == "all":
        letters = set(DEFAULT_LETTERS) | {x.upper() for x in (sopho_letters or ())}
        letters.discard("H")
        out.remove_letters = sorted(x for x in letters if x in LETTERS)
        out.remove_source = sopho_source or "sophomorix template K P R S T"
    else:
        out.remove_letters = list(cfg.remove or [])
        out.remove_source = "drives.yaml"
    if out.remove_letters:
        refs, bad = resolve(cfg.for_groups)
        who = _display(cfg.for_groups, out.resolved) if cfg.for_groups else "all users"
        if bad:
            out.rows.append(Row("remove", "del", " ".join(out.remove_letters), "delete", "",
                                who, "", "held",
                                why(bad) + " - the linuxmuster default drives stay"))
        else:
            out.rows.append(Row("remove", "del", " ".join(out.remove_letters), "delete", "",
                                who, "", "ok"))
            for letter in out.remove_letters:
                out.items.append({"kind": "del", "letter": letter, "action": "D", "index": 0,
                                  "groups": refs, "devices": []})

    # 2. H: (home) first, then the other letters, each in file order
    written: dict[str, list[dict]] = {}       # letter -> conditions of written entries
    seen: dict[str, int] = {}                 # letter -> entries so far (stable UID index)
    ordered = [e for e in cfg.drives if e.home] + [e for e in cfg.drives if not e.home]
    for ent in ordered:
        index = seen.get(ent.letter, 0)
        seen[ent.letter] = index + 1
        groups, bad_g = resolve(ent.groups)
        devices, bad_d = resolve(ent.devices, computer=True)
        kind = "home" if ent.home else "map"
        action = "update" if (ent.home or ent.action == "update") else "replace"
        path = "%homeDirectory%" if ent.home else substitute(ent.path, server, serverfqdn)
        who = _display(ent.groups, out.resolved) if ent.groups else "all users"
        devs = _display(ent.devices, out.resolved)
        if bad_g or bad_d:
            out.rows.append(Row(ent.where, kind, ent.letter, action, path, who, devs, "held",
                                why(bad_g + bad_d)))
            continue
        cond = {"groups": groups, "devices": devices}
        item = {"kind": kind, "letter": ent.letter, "index": index,
                "action": "U" if action == "update" else "R",
                "path": "" if ent.home else path, "label": ent.label,
                "persistent": ent.reconnect, "remove_policy": ent.reconnect,
                "groups": groups, "devices": devices,
                "exclude": list(written.get(ent.letter, []))}
        written.setdefault(ent.letter, []).append(cond)
        out.items.append(item)
        note = ""
        if item["exclude"]:
            note = f"unless an earlier {ent.letter}: entry matches"
        out.rows.append(Row(ent.where, kind, ent.letter, action, path, who, devs, "ok", note))
    return out
