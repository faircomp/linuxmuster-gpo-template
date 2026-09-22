# Uniform entry points across the faircomp packages (hub: docs/paket-konventionen.md).
# dpkg-buildpackage writes the .deb, .changes and .buildinfo one level ABOVE the source
# tree (no longer into dist/); -tc cleans the tree afterwards. debian/rules overrides the
# dh_auto_* steps so debhelper never calls back into this Makefile. The bare -I keeps
# dpkg-source's default ignore list (.git, .gitignore, editor backups, ...); an -I<pattern>
# alone would replace it. Needs dpkg-dev and debhelper; no root required.
.PHONY: all deb clean

all: deb

deb:
	dpkg-buildpackage -us -uc -tc -I -I".github"

clean:
	debian/rules clean
