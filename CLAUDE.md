# linuxmuster-gpo-template (lmn-gpo) — Windows Group Policy toolkit for linuxmuster.net 7.x

Builds, links and permissions Windows 11 GPOs directly on the linuxmuster.net Samba AD DC,
without the Windows GPMC: a declarative YAML catalog, an idempotent apply engine, a setup
wizard, `doctor`, `selftest` and a dry-run mode. The product core is the catalog packs and the
PowerShell client scripts; the Python is the engine around them. `README.md` (English first,
German below) is the admin view; this file is the project map for contributors and agents.
Kevin speaks German; answer in German, write code, commits and changelog entries in English.

## Overview

| Component | Path | Stack |
|---|---|---|
| CLI + engine | `lmn_gpo/` (`cli.py` argparse entry; `./lmn-gpo-cli` launcher for a source checkout, `/usr/bin/lmn-gpo` when installed) | Python 3.12 (Ubuntu 24.04), `python3-samba` (`samba`/`ldb` bindings, `samba-tool gpo load`), `python3-yaml`; no PyPI deps, no venv |
| Catalog packs | `catalog/*.yaml` (33 packs `NN-name.yaml`; `*-schule` packs are applied per school) | YAML schema documented in `README.md` |
| Client scripts | `scripts/*.ps1` (startup/shutdown scripts, `lmn-gpo-check.ps1` client diagnostics); `lmn_gpo/wlan.py` and `lmn_gpo/drives.py` generate more at apply time | Windows PowerShell 5.1, **pure ASCII** |
| Data | `lib/veyon-default-pub.pem`; `wallpapers/` (admin-provided, not committed) | installed to `/usr/share/lmn-gpo`, wallpapers to `/var/lib/lmn-gpo` |
| Packaging | `debian/changelog` (version source) + `packaging/` (`build-deb.sh`, `control`, `copyright`, postinst/prerm/postrm); `make deb` → `dist/lmn-gpo_<version>_all.deb` | `dpkg-deb`, plain `dist-packages` install; classic `debian/` with `dh --with python3` is a later PR |
| Tests | `.github/workflows/ci.yml` fast tier (py_compile, catalog YAML, ASCII-only `.ps1`, generated Wi-Fi scripts, Drives.xml shape, PowerShell parser, `--version` == changelog); `lmn-gpo selftest --yes` on a real DC (throwaway GPO) | GitHub-hosted runner with `pwsh`; the selftest runs in the lab via the hub |
| Docs | `README.md` (bilingual), `docs/RESEARCH.md` (verified Windows/Samba facts), `docs/VEYON-PLAN.md` | |

## Constraints (do not violate)

- **Version:** the top entry of `debian/changelog` is the only hand-edited version (`7.3.N`, dist
  `lmn73`, signature `Kevin Stenzel <mail@kevin-stenzel.de>`). `packaging/build-deb.sh` reads it
  with `dpkg-parsechangelog`, fills `Version: @VERSION@` in `packaging/control` and generates
  `lmn_gpo/_version.py` inside the package; a source checkout reads the changelog itself
  (`lmn_gpo/__init__.py`). `lmn-gpo --version` must always equal it (CI asserts). Never bump it
  in a feature PR; Kevin bumps and tags `v7.3.N`, and `release.yml` refuses a mismatching tag.
  The binary package name stays `lmn-gpo`.
- **Every shipped or generated `.ps1` is pure ASCII.** Windows PowerShell 5.1 reads a BOM-less
  script in the system codepage; a UTF-8 em dash becomes a curly quote and ends the string.
  Non-ASCII payloads (SSIDs, XML) travel base64-encoded. `\"` is not an escape in PowerShell.
  CI parses every script, including the generated ones, with the real parser.
- **Drive Maps:** never emit `useLetter="0"` (KB3091116: deletes every mapping from that letter
  to Z:); keep `action="U"` and `bypassErrors="1"`. Drive Maps is USER policy: CSE on
  `gPCUserExtensionNames`, user half of `versionNumber`.
- **Idempotent, fail closed.** An exclusion group that resolves to nothing (`filter_deny`,
  `filter_deny_read`) is an error, not a silent no-op. A precondition that depends on a FILE
  (wallpaper, RADIUS CA) skips the pack and keeps its GPO; an operator answer that switches a
  feature off retires the GPO only after `samba-tool gpo backup`. `apply` refuses to run without
  an answers file unless `--defaults` is given.
- **Only `LMN-*` GPOs are ours.** sophomorix' GPOs and the Default Domain Policy are never
  touched. GPT.INI and the AD `versionNumber` are bumped in lockstep and the matching CSE GUID
  registered, or Windows ignores the change.
- **No PyPI dependencies:** the package installs into `/usr/lib/python3/dist-packages` and
  depends only on Ubuntu packages (`python3-yaml`, `python3-samba`, `samba-common-bin`,
  `openssl`). Do not add a venv.
- **No real-server actions outside the hub's lab workflow** (`../../CLAUDE.md`: lock and
  snapshot first). `lmn-gpo apply` on the lab DC only after `bin/lab-snapshot`.

## Way of working

- Hub: this repo lives under `linuxmusterDEV/packages/linuxmuster-gpo-template`; read
  `../../CLAUDE.md` and `../../docs/paket-konventionen.md` first. GitHub `origin` =
  `https://github.com/faircomp/linuxmuster-gpo-template` (org `faircomp`, default branch `main`).
- Branch `feat/<topic>` or `fix/<topic>` from `main`; English conventional commits
  `type(scope): subject` (from September 2026 on; the older history is sentence style).
- Fast tier locally before every commit (what `ci.yml` runs): `python3 -m py_compile lmn_gpo/*.py`,
  `python3 -c "import yaml, glob; [yaml.safe_load(open(f)) for f in glob.glob('catalog/*.yaml')]"`,
  the ASCII check of `scripts/*.ps1`, and `test "$(./lmn-gpo-cli --version)" = "lmn-gpo $(dpkg-parsechangelog -S Version)"`.
  The PowerShell parser check needs `pwsh`; without a local install use the container:
  `docker run --rm -v "$PWD":/src -w /src mcr.microsoft.com/powershell:latest pwsh -File <check.ps1>`
  (the check is the `pwsh` step in `ci.yml`).
- `make deb` builds `dist/lmn-gpo_<version>_all.deb` (needs `dpkg-dev`, no root). CI builds it in
  `ghcr.io/linuxmuster/lmndev-runner:24.04` and installs it on ubuntu-24.04
  (`lmn-gpo --help`/`--version`); the same container build locally:
  `mkdir -p dist && docker run --rm -u root -v "$PWD":/src -w /src ghcr.io/linuxmuster/lmndev-runner:24.04 make deb`.
- Lab test via the hub: `bin/lab-lock acquire`, `bin/lab-snapshot`, `bin/lab-deploy lmn-test
  dist/lmn-gpo_*.deb`, then on the DC `lmn-gpo doctor` and `lmn-gpo selftest --yes` (throwaway
  GPO, non-destructive); `apply --dry-run` before any real apply; journal in `work/gpo-template/`.
- Changelog entry (`debian/changelog`, top block, `urgency=medium`) in the same PR as the change,
  written for admins: what changes on the clients and what has to be re-rolled.
- No formatter yet (no ruff, no pyproject): keep the existing style (snake_case, module docstrings,
  about 100 columns) and do not reformat code the change does not touch.
