"""Drives.xml generation: byte-stable, targeting, Delete/Replace, duplicate letters."""
from __future__ import annotations

import itertools
import os
import xml.dom.minidom as md
import xml.etree.ElementTree as ET

import yaml

from conftest import GROUP_SIDS, ROOT
from lmn_gpo import catalog, drivesconf, drives
from test_resolution import DictResolver

GUID = "{11111111-2222-3333-4444-555555555555}"
GOLDEN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden")


def golden(name: str) -> str:
    with open(os.path.join(GOLDEN, name), encoding="utf-8", newline="") as fh:
        return fh.read()


def example_plan():
    data = yaml.safe_load(open(os.path.join(ROOT, "examples", "drives.yaml.example"),
                               encoding="utf-8"))
    data.pop("example")
    return drivesconf.plan(drivesconf.parse(data), DictResolver(), netbios="DEV",
                           server="server", sopho_letters={"K", "P", "S", "T", "R"},
                           sopho_source="test")


def render(entries, remove=(), for_groups=(), guid=GUID):
    c = drivesconf.parse({"version": 1, "drives": entries,
                          "linuxmuster_defaults": {"remove": list(remove),
                                                   "for_groups": list(for_groups)}})
    p = drivesconf.plan(c, DictResolver(), netbios="DEV", server="server")
    return drives.render_managed(p.items, guid)


# --------------------------------------------------------------------------- #
# 19-home-h must not change by a single byte (proven on Windows 11 24H2)
# --------------------------------------------------------------------------- #
def test_19_home_h_is_byte_identical_to_7_3_5():
    pack = {p.id: p for p in catalog.load_packs()}["19-home-h"]
    for guid, name in (("{00000000-0000-0000-0000-000000000000}", "zero"),
                       ("{31B2F340-016D-11D2-945F-00C04FB984F9}", "ddp")):
        assert drives.render([dict(i) for i in pack.drives], guid) == \
            golden(f"19-home-h-{name}.Drives.xml")


# --------------------------------------------------------------------------- #
# shape of the 20-drives file
# --------------------------------------------------------------------------- #
def test_example_render_is_byte_stable_and_matches_golden():
    a = drives.render_managed(example_plan().items, GUID)
    b = drives.render_managed(example_plan().items, GUID)
    assert a == b
    assert a == golden("20-drives-example.Drives.xml")


def test_wellformed_ascii_crlf_and_never_useletter_0():
    xml = drives.render_managed(example_plan().items, GUID)
    xml.encode("ascii")
    md.parseString(xml.replace("\r\n", "\n"))
    assert "\n" not in xml.replace("\r\n", "")
    assert 'useLetter="0"' not in xml
    root = ET.fromstring(xml)
    for drive in root.iter("Drive"):
        assert drive.get("bypassErrors") == "1"
        assert drive.find("Properties").get("useLetter") == "1"


def test_deletes_first_then_home_then_maps_with_the_right_actions():
    root = ET.fromstring(drives.render_managed(example_plan().items, GUID))
    seq = [(d.find("Properties").get("action"), d.find("Properties").get("letter"),
            d.get("image")) for d in root.iter("Drive")]
    assert seq == [("D", "K", "3"), ("D", "P", "3"), ("D", "R", "3"), ("D", "S", "3"),
                   ("D", "T", "3"), ("U", "H", "2"), ("R", "M", "1"), ("R", "G", "1"),
                   ("R", "Y", "1"), ("R", "V", "1")]
    first = root.find("Drive/Properties")
    assert first.get("path") == "" and first.get("thisDrive") == "NOCHANGE"


def test_home_item_is_the_19_home_h_item():
    root = ET.fromstring(render([{"letter": "H", "home": True, "label": "Home"}]))
    ours = root.find("Drive")
    pack = {p.id: p for p in catalog.load_packs()}["19-home-h"]
    theirs = ET.fromstring(drives.render([dict(i) for i in pack.drives], GUID)).find("Drive")
    assert ET.tostring(ours.find("Properties")) == ET.tostring(theirs.find("Properties"))
    assert ET.tostring(ours.find("Filters")) == ET.tostring(theirs.find("Filters"))
    assert ours.get("image") == theirs.get("image") == "2"


def test_any_of_groups_in_one_collection_devices_in_another():
    root = ET.fromstring(render([{"letter": "M", "path": r"\\s\m",
                                  "groups": ["msg-teachers", "lk-msg"],
                                  "devices": ["d_verwaltung"]}]))
    cols = root.findall("Drive/Filters/FilterCollection")
    assert [(c.get("bool"), c.get("not")) for c in cols] == [("AND", "0"), ("AND", "0")]
    users = cols[0].findall("FilterGroup")
    assert [(g.get("bool"), g.get("name"), g.get("sid"), g.get("userContext")) for g in users] \
        == [("AND", "DEV\\msg-teachers", GROUP_SIDS["msg-teachers"], "1"),
            ("OR", "DEV\\lk-msg", GROUP_SIDS["lk-msg"], "1")]
    dev = cols[1].findall("FilterGroup")
    assert [(g.get("name"), g.get("userContext")) for g in dev] == [("DEV\\d_verwaltung", "0")]


def test_entry_for_everybody_has_no_filters():
    root = ET.fromstring(render([{"letter": "M", "path": r"\\s\m"}]))
    assert root.find("Drive/Filters") is None


def test_umlaut_quotes_and_ampersand_are_escaped_ascii():
    xml = render([{"letter": "S", "path": r"\\s\Sch\"ler & co", "label": 'Schüler "A"'}])
    xml.encode("ascii")
    assert 'label="Sch&#252;ler &quot;A&quot;"' in xml
    assert r'path="\\s\Sch\&quot;ler &amp; co"' in xml
    assert ET.fromstring(xml).find("Drive/Properties").get("label") == 'Schüler "A"'


def test_reconnect_writes_persistent_and_removepolicy_with_replace():
    root = ET.fromstring(render([{"letter": "M", "path": r"\\s\m", "reconnect": True},
                                 {"letter": "N", "path": r"\\s\n", "action": "update"}]))
    m, n = root.findall("Drive")
    assert (m.get("removePolicy"), m.find("Properties").get("persistent"),
            m.find("Properties").get("action")) == ("1", "1", "R")
    assert (n.get("removePolicy"), n.find("Properties").get("persistent"),
            n.find("Properties").get("action"), n.get("image")) == (None, "0", "U", "2")


def test_uids_unique_stable_and_per_gpo():
    entries = [{"letter": "S", "path": r"\\s\a", "groups": ["msg-teachers"]},
               {"letter": "S", "path": r"\\s\b", "groups": ["gsg-teachers"]}]
    one = [d.get("uid") for d in ET.fromstring(render(entries, remove=["S"])).iter("Drive")]
    assert len(one) == len(set(one)) == 3
    assert one == [d.get("uid") for d in ET.fromstring(render(entries, remove=["S"]))
                   .iter("Drive")]
    other = [d.get("uid") for d in ET.fromstring(render(entries, remove=["S"], guid="{A}"))
             .iter("Drive")]
    assert not set(one) & set(other)
    assert all(u == u.upper() and u.startswith("{") for u in one)


def test_disabled_items_for_the_selftest():
    items = [{"kind": "del", "letter": "Q", "action": "D", "disabled": True}]
    assert ET.fromstring(drives.render_managed(items, GUID)).find("Drive").get("disabled") == "1"


# --------------------------------------------------------------------------- #
# targeting semantics: evaluate the filters like the GPP client does
# --------------------------------------------------------------------------- #
def _eval_list(nodes, user_sids, computer_sids) -> bool:
    """[MS-GPPREF] targeting: items in order, each combined with the running result by its
    own bool (AND/OR), negated by not=1; a collection is a parenthesised sub-list."""
    result = True
    for node in nodes:
        if node.tag == "FilterGroup":
            pool = user_sids if node.get("userContext") == "1" else computer_sids
            value = node.get("sid") in pool
        elif node.tag == "FilterCollection":
            value = _eval_list(list(node), user_sids, computer_sids)
        elif node.tag == "FilterLdap":
            value = True                     # homeDirectory present
        else:
            raise AssertionError(node.tag)
        if node.get("not") == "1":
            value = not value
        result = (result and value) if node.get("bool") == "AND" else (result or value)
    return result


def applies(drive, user_sids, computer_sids=()) -> bool:
    filters = drive.find("Filters")
    return True if filters is None else _eval_list(list(filters), set(user_sids),
                                                   set(computer_sids))


def test_first_matching_entry_wins_for_every_group_combination():
    entries = [
        {"letter": "S", "path": r"\\s\msg", "groups": ["msg-teachers", "lk-msg"]},
        {"letter": "S", "path": r"\\s\gsg", "groups": ["gsg-teachers"],
         "devices": ["d_verwaltung"]},
        {"letter": "S", "path": r"\\s\gym", "groups": ["gym-teachers"]},
        {"letter": "S", "path": r"\\s\rest"},
    ]
    root = ET.fromstring(render(entries))
    maps = [d for d in root.iter("Drive") if d.find("Properties").get("action") == "R"]
    names = ["msg-teachers", "lk-msg", "gsg-teachers", "gym-teachers", "teachers"]
    for n in range(len(names) + 1):
        for combo in itertools.combinations(names, n):
            user = {GROUP_SIDS[x] for x in combo}
            for computer in (set(), {GROUP_SIDS["d_verwaltung"]}):
                got = [d.find("Properties").get("path") for d in maps
                       if applies(d, user, computer)]
                # the reference: the first entry whose own condition matches
                want = None
                for e in entries:
                    g_ok = not e.get("groups") or any(GROUP_SIDS[x] in user for x in e["groups"])
                    d_ok = not e.get("devices") or any(GROUP_SIDS[x] in computer
                                                       for x in e["devices"])
                    if g_ok and d_ok:
                        want = e["path"]
                        break
                assert got == [want], (combo, computer, got, want)


def test_deletes_follow_for_groups():
    root = ET.fromstring(render([], remove=["K", "T"], for_groups=["role-teacher", "role-staff"]))
    dels = list(root.iter("Drive"))
    assert len(dels) == 2
    for d in dels:
        assert applies(d, {GROUP_SIDS["role-teacher"]})
        assert applies(d, {GROUP_SIDS["role-staff"]})
        assert not applies(d, {GROUP_SIDS["role-student"]})
    root = ET.fromstring(render([], remove=["K"]))
    assert applies(next(root.iter("Drive")), set())         # for_groups [] = everybody


def test_render_without_sid_never_writes_a_filtergroup():
    items = [{"kind": "map", "letter": "M", "action": "R", "path": r"\\s\m",
              "groups": [{"name": "DEV\\x", "sid": ""}]}]
    assert "FilterGroup" not in drives.render_managed(items, GUID)
