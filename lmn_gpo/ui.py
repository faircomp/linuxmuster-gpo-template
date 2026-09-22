"""Terminal markers shared by every subcommand.

`lmn-gpo --no-color` (or a stdout that is not a terminal) switches them to plain ASCII tags,
so logs and automation see [ok]/[warn]/[FAIL] instead of ANSI sequences — in `doctor` and
`selftest` alike. Read them as `ui.OK` at call time; `from .ui import OK` would copy the
initial value and miss the switch.
"""
from __future__ import annotations

_COLOR = {"ok": "\033[32m✓\033[0m", "warn": "\033[33m⚠\033[0m", "bad": "\033[31m✗\033[0m"}
_PLAIN = {"ok": "[ok]", "warn": "[warn]", "bad": "[FAIL]"}

OK = _COLOR["ok"]
WARN = _COLOR["warn"]
BAD = _COLOR["bad"]


def set_color(enabled: bool) -> None:
    """Select the colored glyphs or the plain tags for the rest of the run."""
    global OK, WARN, BAD
    src = _COLOR if enabled else _PLAIN
    OK, WARN, BAD = src["ok"], src["warn"], src["bad"]
