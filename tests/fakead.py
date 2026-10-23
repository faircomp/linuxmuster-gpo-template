"""A tiny in-memory stand-in for lmn_gpo.ad (sam.ldb), enough for the read paths.

Supports the filters lmn-gpo uses: equality, presence (attr=*), simple substrings
(cn=*nopxe*), &, | and !, with RFC 4515 escapes. Attribute names and values compare
case-insensitively, like AD. Messages behave like ldb messages for ad.val():
`attr in msg`, `msg[attr][0]`, `msg.dn`.
"""
from __future__ import annotations

import fnmatch
import re


class Msg:
    def __init__(self, dn: str, attrs: dict):
        self.dn = dn
        self._a = {}
        for k, v in attrs.items():
            self._a[k.lower()] = [str(x) for x in (v if isinstance(v, (list, tuple)) else [v])]

    def __contains__(self, attr):
        return attr.lower() in self._a

    def __getitem__(self, attr):
        return self._a[attr.lower()]

    def get(self, attr):
        return self._a.get(attr.lower())

    def set(self, attr, value):
        self._a[attr.lower()] = [str(value)]


def _unescape(v: str) -> str:
    return re.sub(r"\\([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), v)


def _parse(expr: str, i: int = 0):
    """Return (node, next index). node: ('and'|'or', [nodes]) | ('not', node) | ('cmp', a, v)."""
    assert expr[i] == "(", expr[i:]
    i += 1
    if expr[i] in "&|":
        op = "and" if expr[i] == "&" else "or"
        i += 1
        kids = []
        while expr[i] == "(":
            node, i = _parse(expr, i)
            kids.append(node)
        assert expr[i] == ")"
        return (op, kids), i + 1
    if expr[i] == "!":
        node, i = _parse(expr, i + 1)
        assert expr[i] == ")"
        return ("not", node), i + 1
    j = expr.index(")", i)
    attr, _, value = expr[i:j].partition("=")
    return ("cmp", attr.strip(), value), j + 1


def _match(node, msg: Msg) -> bool:
    kind = node[0]
    if kind == "and":
        return all(_match(n, msg) for n in node[1])
    if kind == "or":
        return any(_match(n, msg) for n in node[1])
    if kind == "not":
        return not _match(node[1], msg)
    _, attr, value = node
    vals = msg.get(attr)
    if value == "*":
        return bool(vals)
    if not vals:
        return False
    if "*" in value and "\\2a" not in value:
        pat = _unescape(value).lower()
        return any(fnmatch.fnmatchcase(v.lower(), pat) for v in vals)
    want = _unescape(value).lower()
    return any(v.lower() == want for v in vals)


class FakeDb:
    def __init__(self, fake):
        self.fake = fake

    def get_config_basedn(self):
        return f"CN=Configuration,{self.fake.basedn}"


class FakeAD:
    def __init__(self, basedn: str):
        self.basedn = basedn
        self.entries: dict[str, Msg] = {}

    def add(self, dn: str, **attrs) -> Msg:
        msg = Msg(dn, attrs)
        self.entries[dn.lower()] = msg
        return msg

    def get(self, dn: str) -> Msg | None:
        return self.entries.get(dn.lower())

    # --- the lmn_gpo.ad interface -------------------------------------------------
    def search(self, base=None, scope="sub", expr="(objectClass=*)", attrs=None):
        base = (base or self.basedn).lower()
        node, _ = _parse(expr)
        out = []
        for dn, msg in self.entries.items():
            if scope == "base":
                inside = dn == base
            elif scope == "one":
                inside = dn.endswith("," + base) and "," not in dn[: -len(base) - 1].replace(
                    "\\,", "")
            else:
                inside = dn == base or dn.endswith("," + base)
            if inside and _match(node, msg):
                out.append(msg)
        return out

    def find_one(self, expr, base=None, scope="sub", attrs=None):
        res = self.search(base=base, scope=scope, expr=expr, attrs=attrs)
        return res[0] if res else None

    @staticmethod
    def val(msg, attr, default=None):
        if msg is None or attr not in msg:
            return default
        return str(msg[attr][0])

    @staticmethod
    def sid_of(msg):
        if msg is None or "objectSid" not in msg:
            return None
        return str(msg["objectSid"][0])

    def db(self):
        return FakeDb(self)

    def install(self, monkeypatch):
        """Route lmn_gpo.ad through this directory for the rest of the test."""
        from lmn_gpo import ad
        monkeypatch.setattr(ad, "search", self.search)
        monkeypatch.setattr(ad, "find_one", self.find_one)
        monkeypatch.setattr(ad, "sid_of", self.sid_of)
        monkeypatch.setattr(ad, "db", self.db)
        return self
