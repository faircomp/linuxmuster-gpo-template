# Uniform entry points across the faircomp packages (hub: docs/paket-konventionen.md).
# `make deb` wraps packaging/build-deb.sh until the debian/ conversion replaces it with
# dpkg-buildpackage. Needs dpkg-dev (dpkg-parsechangelog, dpkg-deb); no root required.
.PHONY: all deb clean

all: deb

deb:
	sh packaging/build-deb.sh

clean:
	rm -rf dist
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
