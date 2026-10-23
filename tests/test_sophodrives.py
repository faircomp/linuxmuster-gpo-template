"""Reading sophomorix' school Drives.xml (read-only).

The fixture is sophomorix4's template byte for byte
(sophomorix-samba/config-devel/gpo/school/User/Preferences/Drives/Drives.xml, bionic eb0bbcc8).
"""
from __future__ import annotations

import os

from conftest import SCHOOL_NAMES, school_drives_xml, school_guid
from lmn_gpo import sophodrives

SOPHO_S_SID = "S-1-5-21-453622583-2410402998-3896360232-1110"


def test_template_letters_paths_and_the_foreign_s_sid():
    items = sophodrives.parse_drives_xml(school_drives_xml("gsg"))
    assert [(i.letter, i.action) for i in items] == [("K", "U"), ("P", "U"), ("S", "U"),
                                                     ("T", "U"), ("R", "U")]
    assert sophodrives.mapped_letters(items) == {"K", "P", "S", "T", "R"}
    assert items[0].path == r"\\server\gsg\program"
    s = items[2]
    assert s.groups == [("DEV\\gsg-teachers", SOPHO_S_SID, False, True)]
    assert not any(i.disabled for i in items)


def test_webui_disabled_and_moved_letters():
    text = school_drives_xml("default-school")
    text = text.replace('name="R:" status="R:"', 'name="R:" status="R:" disabled="1"', 1)
    text = text.replace('letter="K"/>', 'letter="X"/>', 1)        # WebUI moved K: to X:
    items = sophodrives.parse_drives_xml(text)
    assert {i.letter for i in items if i.disabled} == {"R"}
    assert sophodrives.mapped_letters(items) == {"X", "P", "S", "T", "R"}


def test_negated_and_nested_groups_are_collected():
    text = ('<Drives><Drive name="S:"><Properties action="R" letter="S" path="\\\\s\\x"/>'
            '<Filters><FilterCollection bool="AND" not="1"><FilterGroup bool="AND" not="0" '
            'name="DEV\\a" sid="S-1-5-21-1-1-1-1" userContext="0"/></FilterCollection>'
            '</Filters></Drive><Drive name="D:"><Properties action="D" letter="D"/></Drive>'
            '</Drives>')
    items = sophodrives.parse_drives_xml(text)
    assert items[0].groups == [("DEV\\a", "S-1-5-21-1-1-1-1", True, False)]
    assert sophodrives.mapped_letters(items) == {"S"}, "a Delete item maps nothing"


def test_broken_xml_is_reported_not_guessed():
    import pytest
    with pytest.raises(ValueError):
        sophodrives.parse_drives_xml("<Drives><Drive>")


def test_school_gpos_from_the_directory(domain):
    fake, env, sysvol = domain
    gpos = sophodrives.school_gpos(env.basedn, sysvol, fake)
    assert [g.school for g in gpos] == sorted(SCHOOL_NAMES)
    assert all(g.items and not g.error for g in gpos)
    letters, src = sophodrives.letters_of_schools(gpos)
    assert letters == {"K", "P", "S", "T", "R"}
    assert "sophomorix:school:gsg" in src
    # a school GPO without Drives.xml
    os.remove(os.path.join(sysvol, school_guid("gym"), "User", "Preferences", "Drives",
                           "Drives.xml"))
    gpos = sophodrives.school_gpos(env.basedn, sysvol, fake)
    assert next(g for g in gpos if g.school == "gym").items is None
    _letters, src = sophodrives.letters_of_schools(gpos)
    assert "gym" not in src
