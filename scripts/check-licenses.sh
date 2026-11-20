#!/usr/bin/env bash
#
# Third-party license compliance gate (THIRD_PARTY_NOTICES.md / license-audit.yml).
#
# Pure bash/grep/find — no toolchain required (runs on macOS dev hosts and CI):
#   L1  THIRD_PARTY_NOTICES.md exists at the repo root and is non-trivial.
#   L2  Every vendored component in third_party/*/ carries (a) license text
#       (a LICENSE/COPYING file or a recognized in-source license header),
#       (b) an attribution file (AUTHORS or NOTICE), and (c) a provenance pin
#       (vendor-provenance.txt).
#   L3  No copyleft license text (GPL/LGPL/AGPL) anywhere in third_party/.
#   L4  Every runtime dependency declared by the RPM spec `Requires:` line is
#       declared in THIRD_PARTY_NOTICES.md.
#
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "[license] FAIL: $*" >&2; exit 1; }

echo "[license] L1: THIRD_PARTY_NOTICES.md present at repo root"
[ -s THIRD_PARTY_NOTICES.md ] || fail "THIRD_PARTY_NOTICES.md missing or empty at repo root"

echo "[license] L2: vendored components carry license text + attribution + provenance"
shopt -s nullglob
comps=(third_party/*/)
[ "${#comps[@]}" -gt 0 ] || fail "third_party/ holds no components — add a component or remove the gate"
for d in "${comps[@]}"; do
  n="${d%/}"
  n="${n#third_party/}"
  if ! find "$d" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'COPYING*' \) | grep -q . \
     && ! grep -rIqE 'Permission is hereby granted|MIT License|MIT licence|BSD[- ]?(2|3)?[- ]?[Cc]lause|Apache License|GNU (General|Lesser General|Affero General) Public License' "$d"; then
    fail "$n: no license text found (add a LICENSE/COPYING file or keep the upstream license header in the source)"
  fi
  find "$d" -maxdepth 1 -type f \( -iname 'AUTHORS' -o -iname 'NOTICE' \) | grep -q . \
    || fail "$n: missing attribution file (AUTHORS or NOTICE)"
  [ -f "$d/vendor-provenance.txt" ] \
    || fail "$n: missing vendor-provenance.txt (upstream pin + local SHA-256 digests)"
  echo "  [license]   $n: OK"
done

echo "[license] L3: no copyleft license text in third_party/"
if grep -rInE 'GNU (General|Lesser General|Affero General) Public License|GPLv?[23](-only|-or-later)?|GNU GPL' third_party/; then
  fail "copyleft license text found in third_party/ — copyleft components must not be vendored without explicit review"
fi

echo "[license] L4: RPM spec runtime dependencies (all Requires: lines, EL + SUSE branches) declared in THIRD_PARTY_NOTICES.md"
spec=""
for f in packaging/*.spec; do [ -f "$f" ] && spec="$f"; done
[ -n "$spec" ] || fail "no packaging/*.spec found"
# Collect every Requires: line — the spec carries per-distro branches
# (%if 0%{?suse_version}) with SUSE-specific binary package names
# (libcurl4, libjson-c5, ...), so the union of all lines must be declared.
reqs="$(awk 'tolower($1) == "requires:" { line=$0; sub(/^[[:space:]]*[Rr]equires:[[:space:]]*/, "", line); print line }' "$spec" | tr ',' ' ' | sort -u)"
[ -n "$reqs" ] || fail "no Requires: line found in $spec"
for dep in $reqs; do
  grep -qi -- "$dep" THIRD_PARTY_NOTICES.md \
    || fail "runtime dependency '$dep' ($spec) is not declared in THIRD_PARTY_NOTICES.md"
  echo "  [license]   $dep: declared"
done

echo "[license] OK — notices present, vendored license/provenance intact, spec runtime deps declared."
