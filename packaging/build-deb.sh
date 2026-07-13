#!/bin/sh
# Build the lmn-gpo .deb from this source tree using dpkg-deb.
# Needs only dpkg-deb and a POSIX shell (no debhelper required).
#
#   packaging/build-deb.sh [OUTPUT_DIR]      # default: <repo>/dist
set -e

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
PKG=lmn-gpo
VERSION=$(sed -n 's/^Version: //p' "$HERE/control")
ARCH=all
OUTDIR=${1:-$REPO/dist}

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
ROOT="$STAGE/$PKG"

echo "Building $PKG $VERSION ($ARCH) ..."

# ---- file tree -----------------------------------------------------------
install -d "$ROOT/DEBIAN" \
           "$ROOT/usr/bin" \
           "$ROOT/usr/lib/python3/dist-packages/lmn_gpo" \
           "$ROOT/usr/share/$PKG" \
           "$ROOT/usr/share/doc/$PKG" \
           "$ROOT/var/lib/$PKG/wallpapers"

# Python module (source .py only; no __pycache__)
for f in "$REPO"/lmn_gpo/*.py; do
    install -m 644 "$f" "$ROOT/usr/lib/python3/dist-packages/lmn_gpo/"
done

# Read-only data shared by the toolkit
cp -a "$REPO/catalog" "$ROOT/usr/share/$PKG/catalog"
cp -a "$REPO/scripts" "$ROOT/usr/share/$PKG/scripts"
cp -a "$REPO/lib"     "$ROOT/usr/share/$PKG/lib"

# CLI launcher -> /usr/bin/lmn-gpo
cat > "$ROOT/usr/bin/$PKG" <<'PY'
#!/usr/bin/env python3
"""Command-line entry point for the lmn-gpo toolkit."""
import sys

from lmn_gpo.cli import main

if __name__ == "__main__":
    sys.exit(main())
PY

# Documentation
install -m 644 "$REPO/README.md" "$ROOT/usr/share/doc/$PKG/README.md"
[ -d "$REPO/docs" ] && cp -a "$REPO/docs" "$ROOT/usr/share/doc/$PKG/docs"
install -m 644 "$HERE/copyright" "$ROOT/usr/share/doc/$PKG/copyright"
gzip -9nc "$HERE/changelog" > "$ROOT/usr/share/doc/$PKG/changelog.Debian.gz"

# ---- normalise ownership-independent permissions -------------------------
find "$ROOT/usr" "$ROOT/var" -type d -exec chmod 755 {} +
find "$ROOT/usr" "$ROOT/var" -type f -exec chmod 644 {} +
chmod 755 "$ROOT/usr/bin/$PKG"

# ---- control + maintainer scripts ---------------------------------------
INSTKB=$(du -k -s --exclude=DEBIAN "$ROOT" | cut -f1)
{ cat "$HERE/control"; echo "Installed-Size: $INSTKB"; } > "$ROOT/DEBIAN/control"
for s in postinst prerm postrm; do
    install -m 755 "$HERE/$s" "$ROOT/DEBIAN/$s"
done

# ---- build ---------------------------------------------------------------
mkdir -p "$OUTDIR"
DEB="$OUTDIR/${PKG}_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$ROOT" "$DEB"
echo "Built: $DEB"
