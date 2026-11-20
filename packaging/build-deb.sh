#!/usr/bin/env bash
#
# Build a binary .deb package for Debian / Ubuntu.
#
# The package is hand-crafted with dpkg-deb (no debhelper / dpkg-buildpackage
# toolchain needed, mirroring how `make rpm` drives rpmbuild directly):
#   * `dpkg-shlibdeps` resolves the module's shared-library references against
#     the building distro's package database, producing distribution-correct
#     runtime Depends (e.g. `libcurl4t64` on Ubuntu vs `libcurl4` on Debian,
#     `libssl3` vs `libssl3t64`, ...);
#   * the module is staged into /lib/<multiarch>/security — the PAM module
#     directory Debian/Ubuntu libpam searches at runtime (the same
#     architecture-aware path the in-repo e2e sandbox uses);
#   * /etc/pam_oidc_device.conf ships as a 0600 conffile so dpkg preserves
#     local operator configuration across upgrades.
#
# Must run on a Debian/Ubuntu host with the build dependencies plus
# dpkg-dev (dpkg-deb / dpkg-shlibdeps / dpkg-architecture):
#   sudo apt-get install -y build-essential dpkg-dev python3 \
#     libpam0g-dev libcurl4-openssl-dev libjson-c-dev libcmocka-dev libssl-dev
#
# CI: the "distro-build" job in .github/workflows/distro-build.yml runs
# `make deb` on Debian 13 and Ubuntu 26.04 LTS.
#
# Usage: packaging/build-deb.sh <name> <version> "<description>"
#
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <name> <version> <description>" >&2
  exit 1
fi
NAME="$1"
VERSION="$2"
DESCRIPTION="$3"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# --- tooling -------------------------------------------------------------
for tool in dpkg-deb dpkg-shlibdeps dpkg-architecture dpkg make tar gzip python3; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "make deb: '$tool' not found — run on a Debian/Ubuntu host with the build" >&2
    echo "dependencies and dpkg-dev installed (see packaging/build-deb.sh header)." >&2
    exit 1
  }
done

MULTIARCH="$(dpkg-architecture -qDEB_HOST_MULTIARCH)"
ARCH="$(dpkg --print-architecture)"
PAM_DIR="/lib/${MULTIARCH}/security"
STAGE="build/deb"
# Debian package names allow only lowercase alphanumerics plus '-+.'
# (dpkg-deb rejects the Package: field otherwise), so the .deb ships
# under the dash form of the module name while every in-package file
# (pam_oidc_device.so, /etc/pam_oidc_device.conf) keeps it.
DEBNAME="${NAME//_/-}"
DEBFILE="build/${DEBNAME}_${VERSION}_${ARCH}.deb"

# Start from a pristine tree (mirrors `make rpm: clean`): stale objects or a
# previous module .so must not leak into the package.
make clean
make build

# --- stage the package tree ------------------------------------------------
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" "$STAGE/etc" "$STAGE/${PAM_DIR}" \
  "$STAGE/usr/share/doc/${DEBNAME}/third_party"
install -m 0755 "${NAME}.so" "${STAGE}/${PAM_DIR}/${NAME}.so"
# 0600: the module load-time permission invariant (config.c rejects looser
# modes); matches the RPM's %config(noreplace) %attr(0600, root, root).
install -m 0600 "config/${NAME}.conf" "${STAGE}/etc/${NAME}.conf"
install -m 0644 LICENSE README.md CHANGELOG.md SECURITY.md THIRD_PARTY_NOTICES.md \
  "${STAGE}/usr/share/doc/${DEBNAME}/"
# Ship the vendored QR encoder attribution (Project Nayuki, MIT) with the
# package; the full license text also lives in the encoder file headers.
install -m 0644 third_party/qrcodegen/AUTHORS \
  "${STAGE}/usr/share/doc/${DEBNAME}/third_party/AUTHORS"

# dpkg must know the config file so upgrades preserve the local copy.
echo "/etc/${NAME}.conf" > "${STAGE}/DEBIAN/conffiles"

# --- DEBIAN/control --------------------------------------------------------
# dpkg-shlibdeps (dpkg >= 1.17; trixie ships 1.22, resolute 1.23) behaves as
# if it is always invoked inside a Debian source build tree:
#   * it unconditionally loads debian/control from the cwd
#     (Dpkg::Control::Info->new; "cannot read debian/control" otherwise) and
#     requires a parseable Build-Depends field in the source stanza;
#   * with -O it prints its result as substvars lines, one per field, in the
#     standard substvars "name=value" format (observed on dpkg 1.22.22):
#       shlibs:Pre-Depends=libc6 (>= 2.38)    # when filed as Pre-Depends
#       shlibs:Depends=libpam0g (>= ...), libcurl4t64 (>= ...), ...
# The binary must be analyzed from inside a package build tree (as
# dh_shlibdeps does): dpkg-shlibdeps walks the analyzed file's ancestor
# directories for a DEBIAN/ subdir (Dpkg::Path::get_pkg_root_dir) and
# searches those package trees first, so pointing it at the package staging
# directory (whose DEBIAN/ subdirectory holds the control files) made that
# directory the "package root" and it produced no dependencies at all.
# We therefore run it from a scratch source tree (minimal debian/control)
# with the .so copied at its final install path inside that tree, merge
# whatever shlibs fields come out into a single Depends: line for the
# control file, and keep stderr so a real failure is diagnosable.
FAKESRC="$(mktemp -d)"
trap 'rm -rf "$FAKESRC"' EXIT
mkdir -p "$FAKESRC/debian"
printf 'Source: %s\nBuild-Depends: dpkg-dev\n' "$NAME" > "$FAKESRC/debian/control"
install -d -m 0755 "${FAKESRC}${PAM_DIR}"
install -m 0755 "${ROOT}/${STAGE}/${PAM_DIR}/${NAME}.so" \
  "${FAKESRC}${PAM_DIR}/${NAME}.so"
ERRF="$(mktemp)"
SHLIB="$(cd "$FAKESRC" \
  && dpkg-shlibdeps -O "${FAKESRC}${PAM_DIR}/${NAME}.so" 2>"$ERRF" \
  | sed -nE 's/^shlibs:(Pre-)?Depends[:=][[:space:]]*//p' \
  | tr '\n' ',' | sed 's/,$//')" || {
  cat "$ERRF" >&2; rm -f "$ERRF"
  echo "make deb: dpkg-shlibdeps failed" >&2
  exit 1;
}
[ -n "$SHLIB" ] || { cat "$ERRF" >&2; rm -f "$ERRF"
  echo "make deb: dpkg-shlibdeps produced no dependencies" >&2
  exit 1; }
rm -f "$ERRF"

INSTALLED_KB="$(du -sk "$STAGE" | cut -f1)"
cat > "${STAGE}/DEBIAN/control" <<EOF
Package: ${DEBNAME}
Version: ${VERSION}
Architecture: ${ARCH}
Homepage: https://github.com/ncsa/pam_oidc_device
Maintainer: NCSA CyberInfrastructure <help@ncsa.illinois.edu>
Installed-Size: ${INSTALLED_KB}
Section: admin
Priority: optional
Depends: ${SHLIB}
Description: ${DESCRIPTION}
 Native Linux PAM module that authenticates the local account out-of-band
 via the OAuth 2.0 Device Authorization Grant (RFC 8628) with PKCE
 (RFC 7636), binding the provider identity to the requested local user.
 Installs ${PAM_DIR}/${NAME}.so and a 0600 /etc/${NAME}.conf template.
EOF

# --- build + verify ---------------------------------------------------------
dpkg-deb --build --root-owner-group -Zgzip "$STAGE" "$DEBFILE"
echo "make deb: package contents:"
dpkg-deb --contents "$DEBFILE"
