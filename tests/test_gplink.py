"""gPLink parsing/editing and the engine's enforced-link handling."""
from __future__ import annotations

import pytest

from conftest import POLICIES, SCHOOLS_OU, gplink_value, make_env
from lmn_gpo import gplink
from lmn_gpo.gpo import GpoEngine, GpoError

A = "{AAAAAAAA-0000-0000-0000-000000000001}"
B = "{BBBBBBBB-0000-0000-0000-000000000002}"
C = "{CCCCCCCC-0000-0000-0000-000000000003}"
# what GPMC writes: lower-case cn=, its own spelling of the DN
GPMC_B = f"[LDAP://cn={B.lower()},cn=policies,cn=system,DC=dev,DC=lmschule,DC=de;1]"


def test_parse_samba_and_gpmc_spelling():
    value = gplink_value((A, 0)) + GPMC_B + gplink_value((C, 3))
    links = gplink.parse(value)
    assert [(lk.guid, lk.options) for lk in links] == [(A, 0), (B, 1), (C, 3)]
    assert gplink.encode(links) == value
    assert links[1].disabled and not links[1].enforced
    assert links[2].disabled and links[2].enforced
    assert gplink.guids(value) == [A, B, C]


def test_parse_rejects_garbage_and_guids_stays_tolerant():
    assert gplink.parse("") == [] and gplink.parse(None) == []
    for bad in ("[LDAP://CN=x;0]junk", "garbage", "[LDAP://CN=x;y]"):
        with pytest.raises(ValueError):
            gplink.parse(bad)
    assert gplink.guids(f"junk[LDAP://CN={A},{POLICIES};0") == [A]


def test_set_options_touches_only_its_own_entry():
    value = gplink_value((C, 0)) + GPMC_B + gplink_value((A, 0))
    new = gplink.set_options(value, A.lower(), 2)
    assert new == gplink_value((C, 0)) + GPMC_B + gplink_value((A, 2))
    assert gplink.options_of(new, A) == 2
    # the GPMC-spelled entry keeps its spelling, in place, when it is the one edited
    new = gplink.set_options(value, B, 2)
    assert new == gplink_value((C, 0)) + GPMC_B.replace(";1]", ";2]") + gplink_value((A, 0))
    with pytest.raises(ValueError):
        gplink.set_options(value, "{DDDDDDDD-0000-0000-0000-000000000004}", 2)


def test_options_of_and_describe():
    value = gplink_value((A, 2), (B, 0))
    assert gplink.options_of(value, A) == 2 and gplink.options_of(value, C) is None
    assert gplink.describe(2) == "enforced"
    assert gplink.describe(3) == "enforced, DISABLED"
    assert gplink.describe(0) == "not enforced"
    assert gplink.describe(None) == "not linked"


# --------------------------------------------------------------------------- #
# GpoEngine.link / set_link_options against a fake container
# --------------------------------------------------------------------------- #
class Recorder(GpoEngine):
    """GpoEngine with the directory and samba-tool replaced by a dict and a log."""

    def __init__(self, gplinks: dict, dry_run=False):
        super().__init__(make_env(), dry_run=dry_run, verbose=True)
        self.gplinks = gplinks
        self.calls = []
        self.writes = []

    def gplink_value(self, container_dn):
        return self.gplinks.get(container_dn, "")

    def _run(self, args, **kw):
        self.calls.append(args)
        if not self.dry_run and args[:3] == ["samba-tool", "gpo", "setlink"]:
            opts = (2 if "--enforce" in args else 0) | (1 if "--disable" in args else 0)
            self.gplinks[args[3]] = gplink_value((args[4], opts)) + self.gplinks.get(args[3], "")

    def _replace_gplink(self, container_dn, old, new):
        assert self.gplinks.get(container_dn, "") == old, "compare-and-swap value mismatch"
        self.writes.append((container_dn, old, new))
        self.gplinks[container_dn] = new


def test_new_link_goes_through_setlink_with_enforce():
    eng = Recorder({})
    assert eng.link(SCHOOLS_OU, A, enforce=True) is True
    assert eng.calls == [["samba-tool", "gpo", "setlink", SCHOOLS_OU, A, "--enforce"]]
    assert eng.link_options(SCHOOLS_OU, A) == 2 and not eng.writes


def test_existing_link_is_enforced_in_place_never_by_setlink():
    before = gplink_value((B, 0), (A, 0), (C, 0))
    eng = Recorder({SCHOOLS_OU: before})
    assert eng.link(SCHOOLS_OU, A, enforce=True) is True
    assert not eng.calls, "samba-tool setlink refuses an existing link"
    assert eng.writes == [(SCHOOLS_OU, before, gplink_value((B, 0), (A, 2), (C, 0)))]


@pytest.mark.parametrize("opts", [1, 3, 0])
def test_disabled_or_unenforced_link_is_restored_to_exactly_2(opts):
    eng = Recorder({SCHOOLS_OU: gplink_value((A, opts))})
    eng.link(SCHOOLS_OU, A, enforce=True)
    assert eng.link_options(SCHOOLS_OU, A) == 2


def test_enforced_link_is_left_alone(capsys):
    eng = Recorder({SCHOOLS_OU: gplink_value((A, 2))})
    assert eng.link(SCHOOLS_OU, A, enforce=True) is False
    assert not eng.writes and not eng.calls
    assert "Link present" in capsys.readouterr().out


def test_plain_link_keeps_7_3_5_behaviour():
    # every other pack: an existing link is never touched, whatever its options
    eng = Recorder({SCHOOLS_OU: gplink_value((A, 2))})
    assert eng.link(SCHOOLS_OU, A) is False
    eng = Recorder({SCHOOLS_OU: gplink_value((A, 0))})
    assert eng.link(SCHOOLS_OU, A) is False
    assert not eng.writes and not eng.calls
    eng = Recorder({})
    eng.link(SCHOOLS_OU, A)
    assert eng.calls == [["samba-tool", "gpo", "setlink", SCHOOLS_OU, A]]


def test_gpmc_spelled_link_counts_as_linked():
    eng = Recorder({SCHOOLS_OU: GPMC_B})
    assert B in eng._linked_guids(SCHOOLS_OU)
    eng.link(SCHOOLS_OU, B, enforce=True)
    assert not eng.calls and eng.gplinks[SCHOOLS_OU] == GPMC_B.replace(";1]", ";2]")


def test_dry_run_changes_nothing(capsys):
    before = gplink_value((A, 0))
    eng = Recorder({SCHOOLS_OU: before}, dry_run=True)
    assert eng.link(SCHOOLS_OU, A, enforce=True) is True
    assert not eng.writes and eng.gplinks[SCHOOLS_OU] == before
    out = capsys.readouterr().out
    assert "[dry-run] link options" in out and "not enforced -> enforced" in out


def test_set_link_options_on_a_missing_link_is_an_error():
    eng = Recorder({SCHOOLS_OU: gplink_value((B, 0))})
    with pytest.raises(GpoError):
        eng.set_link_options(SCHOOLS_OU, A, 2)


def test_set_link_options_wraps_write_errors():
    eng = Recorder({SCHOOLS_OU: gplink_value((A, 0))})

    def fail(*a):
        raise RuntimeError("LDB_ERR_NO_SUCH_ATTRIBUTE")
    eng._replace_gplink = fail
    with pytest.raises(GpoError, match="could not update the link options"):
        eng.set_link_options(SCHOOLS_OU, A, 2)


def test_replace_gplink_is_a_compare_and_swap_on_real_ldb(tmp_path, monkeypatch):
    """The ldb message: delete the old value + add the new one in ONE modify. A stale old
    value makes the whole modify fail instead of dropping a link written meanwhile.
    Needs the ldb Python module (python3-ldb, on the DC); skipped elsewhere."""
    ldb = pytest.importorskip("ldb")
    from lmn_gpo import ad
    db = ldb.Ldb(str(tmp_path / "t.ldb"))
    dn = "OU=SCHOOLS,DC=dev,DC=lmschule,DC=de"
    old = gplink_value((B, 0), (A, 0))
    db.add({"dn": dn, "objectClass": "organizationalUnit", "gPLink": old})
    monkeypatch.setattr(ad, "db", lambda: db)
    eng = GpoEngine(make_env())
    new = gplink.set_options(old, A, 2)
    eng._replace_gplink(dn, old, new)
    got = db.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["gPLink"])[0]
    assert [str(v) for v in got["gPLink"]] == [new]
    with pytest.raises(ldb.LdbError):
        eng._replace_gplink(dn, old, gplink.set_options(old, A, 0))   # stale: must fail
    got = db.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["gPLink"])[0]
    assert [str(v) for v in got["gPLink"]] == [new]
