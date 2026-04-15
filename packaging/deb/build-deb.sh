#!/usr/bin/env bash
# build-deb.sh — build the crab-certbundle .deb package
#
# Run from the project root:
#
#   bash packaging/deb/build-deb.sh
#
# The finished .deb is placed in debbuild/ at the project root.
#
# Requirements (Ubuntu 22.04 / 24.04):
#   sudo apt-get install -y dpkg-dev debhelper python3-pip gcc libssl-dev libffi-dev
#
# The resulting package is architecture-specific (typically amd64) because the
# vendored cryptography/cffi wheels contain compiled C extensions.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Read version from setup.cfg
VERSION=$(python3 -c "
import configparser, sys
c = configparser.ConfigParser()
c.read('$PROJECT_ROOT/setup.cfg')
print(c['metadata']['version'])
")

PACKAGE="crab-certbundle"
SRCNAME="${PACKAGE}-${VERSION}"
BUILDDIR="${PROJECT_ROOT}/debbuild"
SRCDIR="${BUILDDIR}/${SRCNAME}"

echo "==> Building ${PACKAGE} ${VERSION}"
echo "    Project root : ${PROJECT_ROOT}"
echo "    Build dir    : ${BUILDDIR}"
echo ""

# ── Clean previous build ────────────────────────────────────────────────────
rm -rf "${BUILDDIR}"
mkdir -p "${BUILDDIR}"

# ── Create source snapshot ──────────────────────────────────────────────────
# Use git archive if inside a git repo, else fall back to rsync.
cd "${PROJECT_ROOT}"
if git rev-parse --git-dir >/dev/null 2>&1; then
    echo "==> Creating source archive from git"
    git archive --format=tar --prefix="${SRCNAME}/" HEAD \
        | tar -x -C "${BUILDDIR}"
else
    echo "==> Copying source tree (no git repo found)"
    rsync -a --exclude='.git' --exclude='debbuild' --exclude='*.egg-info' \
        "${PROJECT_ROOT}/" "${SRCDIR}/"
fi

# ── Overlay debian/ directory ───────────────────────────────────────────────
echo "==> Installing debian/ directory"
cp -r "${SCRIPT_DIR}/debian" "${SRCDIR}/debian"
# rules must be executable
chmod +x "${SRCDIR}/debian/rules"

# ── Build the .deb ──────────────────────────────────────────────────────────
echo "==> Running dpkg-buildpackage"
cd "${SRCDIR}"
dpkg-buildpackage -us -uc -b

# ── Collect artefacts ───────────────────────────────────────────────────────
echo ""
echo "==> Build complete.  Packages in ${BUILDDIR}:"
ls -lh "${BUILDDIR}"/*.deb "${BUILDDIR}"/*.buildinfo "${BUILDDIR}"/*.changes 2>/dev/null || true
