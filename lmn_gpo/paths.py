"""Resolve the toolkit's read-only data directories (catalog, scripts, lib, wallpapers).

Works both from a source checkout (repo layout: ``catalog/`` sits next to ``lmn_gpo/``)
and from an installed .deb, where the data lives under ``/usr/share/lmn-gpo``. Override
the base with the ``LMN_GPO_DATA_DIR`` environment variable.
"""
from __future__ import annotations

import os

# Repo root when run from a source checkout (parent of the lmn_gpo/ package dir).
_SRC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_INSTALLED_DATA = "/usr/share/lmn-gpo"
_INSTALLED_WALLPAPERS = "/var/lib/lmn-gpo/wallpapers"


def _is_source() -> bool:
    """True when we run from the repo (catalog/ is a sibling of lmn_gpo/)."""
    return os.path.isdir(os.path.join(_SRC_ROOT, "catalog"))


def data_root() -> str:
    env = os.environ.get("LMN_GPO_DATA_DIR")
    if env and os.path.isdir(env):
        return env
    return _SRC_ROOT if _is_source() else _INSTALLED_DATA


DATA_ROOT = data_root()
CATALOG_DIR = os.path.join(DATA_ROOT, "catalog")
SCRIPTS_DIR = os.path.join(DATA_ROOT, "scripts")
LIB_DIR = os.path.join(DATA_ROOT, "lib")
# Wallpapers are admin-provided content, not shipped data: repo wallpapers/ when running
# from source, else a writable admin dir created by the package.
WALLPAPER_DIR = (os.path.join(_SRC_ROOT, "wallpapers")
                 if _is_source() else _INSTALLED_WALLPAPERS)
