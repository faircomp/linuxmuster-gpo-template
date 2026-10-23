"""drives.yaml schema validation (no AD)."""
from __future__ import annotations

import os

import pytest
import yaml

from conftest import ROOT
from lmn_gpo import drivesconf

EXAMPLE = os.path.join(ROOT, "examples", "drives.yaml.example")


def problems(data) -> list[str]:
    with pytest.raises(drivesconf.DrivesConfigError) as exc:
        drivesconf.parse(data)
    return exc.value.problems


def ok(**over):
    data = {"version": 1, "drives": [{"letter": "M", "path": r"\\server\msg",
                                      "groups": ["msg-teachers"]}]}
    data.update(over)
    return data


def test_example_is_refused_until_adapted_and_valid_afterwards():
    data = yaml.safe_load(open(EXAMPLE, encoding="utf-8"))
    assert any("EXAMPLE" in p for p in problems(dict(data)))
    data.pop("example")
    cfg = drivesconf.parse(data)
    assert cfg.remove == "all"
    assert cfg.for_groups == ["role-teacher", "role-staff"]
    assert [(d.letter, d.home, d.path, d.groups) for d in cfg.drives] == [
        ("H", True, "", []),
        ("M", False, r"\\@server\msg", ["msg-teachers"]),
        ("G", False, r"\\@server\gsg", ["gsg-teachers"]),
        ("Y", False, r"\\@server\gym", ["gym-teachers"]),
        ("V", False, r"\\verwaltung\verwaltung", ["verwaltung"]),
    ]
    assert [d.label for d in cfg.drives] == ["Home", "MSG Shares", "GSG Shares", "GYM Shares",
                                             "Verwaltung"]


def test_example_is_pure_ascii():
    open(EXAMPLE, "rb").read().decode("ascii")


def test_minimal_file_and_defaults():
    cfg = drivesconf.parse(ok())
    ent = cfg.drives[0]
    assert (ent.letter, ent.action, ent.reconnect, ent.label, ent.devices) == \
        ("M", "replace", False, "", [])
    assert cfg.remove == [] and cfg.for_groups == []


def test_letters_are_normalised():
    cfg = drivesconf.parse(ok(drives=[{"letter": "m:", "path": r"\\s\x"}]))
    assert cfg.drives[0].letter == "M"


@pytest.mark.parametrize("entry,needle", [
    ({"letter": "H", "path": r"\\s\home"}, "only 'home: true' may use it"),
    ({"letter": "C", "path": r"\\s\x"}, "D-Z only"),
    ({"letter": "MN", "path": r"\\s\x"}, "one drive letter"),
    ({"letter": "M", "home": True}, "only allowed on H:"),
    ({"letter": "H", "home": True, "path": r"\\s\x"}, "not both"),
    ({"letter": "M"}, "needs 'path'"),
    ({"letter": "M", "path": "s\\x"}, "not a UNC path"),
    ({"letter": "M", "path": r"\\server"}, "not a UNC path"),
    ({"letter": "M", "path": "\\\\server\\share\\"}, "not a UNC path"),
    ({"letter": "M", "path": "\\\\server\\\\share"}, "not a UNC path"),
    ({"letter": "M", "path": "\\\\server\\sh\nare"}, "control characters"),
    ({"letter": "M", "path": r"\\s\x", "action": "create"}, "replace or update"),
    ({"letter": "H", "home": True, "action": "replace"}, "always uses update"),
    ({"letter": "M", "path": r"\\s\x", "action": "update", "reconnect": True},
     "reconnect needs action replace"),
    ({"letter": "M", "path": r"\\s\x", "reconnect": "yes please"}, "true or false"),
    ({"letter": "M", "path": r"\\s\x", "label": False}, "must be text"),
    ({"letter": "M", "path": r"\\s\x", "groups": [1]}, "not a group name"),
    ({"letter": "M", "path": r"\\s\x", "groups": {"a": 1}}, "must be a list"),
    ({"letter": "M", "path": r"\\s\x", "group": ["x"]}, "unknown key 'group'"),
    ({"letter": "M", "path": r"\\s\x", True: 1}, "YAML reads off/on/yes/no"),
])
def test_invalid_entries(entry, needle):
    found = problems(ok(drives=[entry]))
    assert any(needle in p for p in found), found


@pytest.mark.parametrize("data,needle", [
    ({"drives": [{"letter": "M", "path": r"\\s\x"}]}, "version: must be 1"),
    ({"version": 2, "drives": [{"letter": "M", "path": r"\\s\x"}]}, "version: must be 1"),
    ({"version": 1, "drive": []}, "unknown key 'drive'"),
    ({"version": 1}, "nothing configured"),
    ({"version": 1, "drives": {"letter": "M"}}, "must be a list"),
    ({"version": 1, "linuxmuster_defaults": {"remove": ["H"]}}, "H: cannot be removed"),
    ({"version": 1, "linuxmuster_defaults": {"remove": "some"}}, "must be 'all'"),
    ({"version": 1, "linuxmuster_defaults": {"remove": ["B"]}}, "D-Z only"),
    ({"version": 1, "linuxmuster_defaults": {"remove": "all", "for": []}}, "unknown key"),
    ({"version": 1, "linuxmuster_defaults": []}, "must be a mapping"),
    ([1, 2], "must be a YAML mapping"),
])
def test_invalid_files(data, needle):
    found = problems(data)
    assert any(needle in p for p in found), found


def test_off_is_read_as_boolean_and_explained():
    # YAML 1.1: `off:` as a key is False - the reason the key is called `remove`
    data = yaml.safe_load("version: 1\nlinuxmuster_defaults:\n  off: all\n"
                          "drives: [{letter: M, path: '\\\\s\\x'}]\n")
    found = problems(data)
    assert any("use 'remove'" in p for p in found), found


def test_remove_variants():
    assert drivesconf.parse({"version": 1, "linuxmuster_defaults": {"remove": "ALL"}}).remove \
        == "all"
    cfg = drivesconf.parse({"version": 1,
                            "linuxmuster_defaults": {"remove": ["t", "K", "K:"],
                                                     "for_groups": "role-teacher"}})
    assert cfg.remove == ["K", "T"] and cfg.for_groups == ["role-teacher"]
    assert drivesconf.parse(ok(linuxmuster_defaults={"remove": None})).remove == []


def test_same_letter_twice_first_match_wins_but_catch_all_must_be_last():
    entries = [{"letter": "S", "path": r"\\s\a", "groups": ["lk-msg"]},
               {"letter": "S", "path": r"\\s\b"}]
    cfg = drivesconf.parse(ok(drives=entries))
    assert [d.index for d in cfg.drives] == [1, 2]
    found = problems(ok(drives=list(reversed(entries))))
    assert any("entry 1 (S:)" in p and "could never apply" in p and "entry 2" in p
               for p in found), found
    # a device-only entry is not a catch-all
    entries = [{"letter": "S", "path": r"\\s\a", "devices": ["d_verwaltung"]},
               {"letter": "S", "path": r"\\s\b"}]
    drivesconf.parse(ok(drives=entries))


def test_every_problem_is_reported_at_once():
    found = problems({"version": 3, "drives": [{"letter": "C", "path": "x"},
                                               {"letter": "H", "path": r"\\s\x"}]})
    assert len(found) >= 4, found
    assert any(p.startswith("entry 1 (C:)") for p in found)
    assert any(p.startswith("entry 2 (H:)") for p in found)


def test_load_missing_and_broken_files(tmp_path):
    with pytest.raises(drivesconf.DrivesConfigError) as exc:
        drivesconf.load(str(tmp_path / "nope.yaml"))
    assert exc.value.problems == ["file not found"]
    bad = tmp_path / "drives.yaml"
    bad.write_text("version: 1\ndrives: [\n", encoding="utf-8")
    with pytest.raises(drivesconf.DrivesConfigError) as exc:
        drivesconf.load(str(bad))
    assert "cannot be read" in exc.value.problems[0]
    good = tmp_path / "good.yaml"
    good.write_text("version: 1\ndrives:\n  - letter: V\n    label: Verwaltung\n"
                    "    path: '\\\\verwaltung\\verwaltung'\n    groups: [verwaltung]\n",
                    encoding="utf-8")
    cfg = drivesconf.load(str(good))
    assert cfg.source == str(good) and cfg.drives[0].path == r"\\verwaltung\verwaltung"


def test_umlaut_label_is_accepted(tmp_path):
    f = tmp_path / "d.yaml"
    f.write_text("version: 1\ndrives:\n  - letter: S\n    label: Schüler\n"
                 "    path: '\\\\s\\x'\n", encoding="utf-8")
    assert drivesconf.load(str(f)).drives[0].label == "Schüler"
