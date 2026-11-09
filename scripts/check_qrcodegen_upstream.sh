#!/bin/sh
# check_qrcodegen_upstream.sh — periodic upstream-drift audit for the vendored
# Project Nayuki QR Code generator (C edition) in third_party/qrcodegen/.
#
# What it does:
#   1. Verifies the local files still match the SHA-256 digests recorded in
#      third_party/qrcodegen/vendor-provenance.txt (detects unreviewed local
#      edits to vendored code).
#   2. Fetches the upstream files at the PINNED upstream commits and applies
#      third_party/qrcodegen/local-deviations.patch (the only documented
#      semantic deviations; see third_party/qrcodegen/AUTHORS).
#   3. Compares token-normalized content of (upstream + patch) vs. the tree —
#      independent of whitespace/formatting and of clang-format version, so a
#      clang-format skew can never produce a false "drift" report.
#   4. Queries the upstream GitHub API for the newest commits touching the two
#      files; if upstream has advanced past the pin, the job fails with a
#      review checklist ("frozen" must not silently become "abandoned").
#
# Run it any time; it is network-dependent (raw.githubusercontent.com,
# api.github.com). The monthly audit + PR/`third_party/**` gate is
# .github/workflows/vendor-audit.yml.
#
# Exit codes:
#   0  clean (local integrity OK, no semantic drift, pin is current)
#   1  local or semantic drift (review third_party/qrcodegen and fix)
#   2  upstream advanced past the pin (review the diff and re-vendor)
#   3  environment or network failure

set -u

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
VDIR="$REPO_ROOT/third_party/qrcodegen"
META="$VDIR/vendor-provenance.txt"
PATCH="$VDIR/local-deviations.patch"

[ -f "$META" ] || { echo "FATAL: missing $META"; exit 3; }
[ -f "$PATCH" ] || { echo "FATAL: missing $PATCH"; exit 3; }
command -v curl >/dev/null 2>&1 || { echo "FATAL: curl not found"; exit 3; }
command -v python3 >/dev/null 2>&1 || { echo "FATAL: python3 not found"; exit 3; }

meta_get() { sed -n "s/^$1=//p" "$META" | tail -n 1; }

REPO_API=$(meta_get upstream_repo)
PATH_C=$(meta_get upstream_path_c)
PATH_H=$(meta_get upstream_path_h)
PIN_C=$(meta_get qrcodegen_c_pin)
PIN_H=$(meta_get qrcodegen_h_pin)
SHA_C=$(meta_get qrcodegen_c_sha256)
SHA_H=$(meta_get qrcodegen_h_sha256)

for v in REPO_API PATH_C PATH_H PIN_C PIN_H SHA_C SHA_H; do
    [ -n "$(eval echo \$$v)" ] || { echo "FATAL: vendor-provenance.txt is missing $v"; exit 3; }
done

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# --- 1) Local integrity -------------------------------------------------------
echo "== 1/4 Local integrity (recorded SHA-256 digests)"
actual_c=$(sha256_of "$VDIR/qrcodegen.c")
actual_h=$(sha256_of "$VDIR/qrcodegen.h")
if [ "$actual_c" != "$SHA_C" ] || [ "$actual_h" != "$SHA_H" ]; then
    echo "FAIL: local vendored files no longer match vendor-provenance.txt"
    [ "$actual_c" != "$SHA_C" ] && echo "  qrcodegen.c: $actual_c != $SHA_C"
    [ "$actual_h" != "$SHA_H" ] && echo "  qrcodegen.h: $actual_h != $SHA_H"
    echo "  Review the local changes; if intentional, refresh the digests after the"
    echo "  token-equivalence check below also passes."
    exit 1
fi
echo "   OK: qrcodegen.c/.h match the recorded digests"

# --- 2) Fetch upstream at the pinned revisions --------------------------------
TMPDIR_DRIFT=$(mktemp -d)
trap 'rm -rf "$TMPDIR_DRIFT"' EXIT INT TERM
BASE="https://raw.githubusercontent.com/$REPO_API"

echo "== 2/4 Fetching upstream (pinned commits)"
curl -fsSL "$BASE/$PIN_C/$PATH_C" -o "$TMPDIR_DRIFT/qrcodegen.c" || {
    echo "FAIL: could not fetch upstream c/qrcodegen.c @ $PIN_C"
    exit 3
}
curl -fsSL "$BASE/$PIN_H/$PATH_H" -o "$TMPDIR_DRIFT/qrcodegen.h" || {
    echo "FAIL: could not fetch upstream c/qrcodegen.h @ $PIN_H"
    exit 3
}
echo "   OK: fetched $PATH_C @ $PIN_C"
echo "       fetched $PATH_H @ $PIN_H"

# --- 3) Token-level equivalence (upstream + documented patch vs. tree) --------
echo "== 3/4 Semantic equivalence (token-normalized, format-insensitive)"
cd "$TMPDIR_DRIFT" || exit 3
git init -q . 2>/dev/null || true
if ! git apply -p3 "$PATCH" 2>git_apply.err; then
    echo "FAIL: local-deviations.patch no longer applies to the pinned upstream"
    echo "       (the pinned revision must have changed, or the patch is stale)"
    cat git_apply.err
    exit 1
fi

if ! python3 - "$TMPDIR_DRIFT" "$VDIR" <<'PY'
import re
import sys

tmpdir, vdir = sys.argv[1], sys.argv[2]


def normalize(src):
    """Token-normalize C source: blank out string/char literals, strip comments,
    delete ALL whitespace. Two sources are equivalent iff their token streams
    (including preprocessor directives) are identical — immune to any
    clang-format version skew."""
    src = re.sub(r'"(\\.|[^"\\])*"', '""', src)
    src = re.sub(r"'(\\.|[^'\\])*'", "''", src)
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    src = re.sub(r"//[^\n]*", "", src)
    return "".join(src.split())


ok = True
for name in ("qrcodegen.c", "qrcodegen.h"):
    upstream = normalize(open(f"{tmpdir}/{name}", encoding="utf-8").read())
    local = normalize(open(f"{vdir}/{name}", encoding="utf-8").read())
    if upstream == local:
        print(f"   OK: {name} is token-identical to pinned upstream + local-deviations.patch")
        continue
    ok = False
    print(f"FAIL: {name} has SEMANTIC drift vs. pinned upstream + documented patch")
    for i in range(min(len(upstream), len(local))):
        if upstream[i] != local[i]:
            print("   first difference at token position", i)
            print("   upstream+patch:", repr(upstream[max(0, i - 80) : i + 80]))
            print("   local tree:    ", repr(local[max(0, i - 80) : i + 80]))
            break

sys.exit(0 if ok else 1)
PY
then
    exit 1
fi

# --- 4) Freshness: has upstream advanced past the pin? -------------------------
echo "== 4/4 Upstream freshness (GitHub API)"
freshness_skipped=0
for pair in "c:$PATH_C:$PIN_C" "h:$PATH_H:$PIN_H"; do
    path=${pair#*:}
    pin=${path#*:}
    path=${path%:*}
    body=$(curl -s -w '\n%{http_code}' "https://api.github.com/repos/$REPO_API/commits?path=$path&per_page=1")
    if [ $? -ne 0 ]; then
        echo "WARN: API query for $path failed (network); skipping freshness for this file"
        freshness_skipped=1
        continue
    fi
    code=$(printf '%s' "$body" | tail -n 1)
    payload=$(printf '%s' "$body" | sed '$d')
    if [ "$code" = "403" ] || [ "$code" = "429" ]; then
        echo "WARN: GitHub API rate limited (HTTP $code); freshness check skipped for $path"
        freshness_skipped=1
        continue
    fi
    if [ "$code" != "200" ]; then
        echo "WARN: unexpected HTTP $code from the GitHub API for $path; skipping freshness"
        freshness_skipped=1
        continue
    fi
    latest=$(printf '%s' "$payload" | python3 -c \
        'import json,sys; d=json.load(sys.stdin); print(d[0]["sha"] if d else "")')
    if [ -n "$latest" ] && [ "$latest" != "$pin" ]; then
        echo "FAIL: upstream has ADVANCED for $path"
        echo "      pinned: $pin"
        echo "      latest: $latest"
        echo "  New upstream commits since the pin (review, then re-vendor if warranted):"
        curl -fsSL "https://api.github.com/repos/$REPO_API/commits?path=$path&per_page=20" \
            | python3 -c 'import json,sys
for c in json.load(sys.stdin):
    print("   ", c["sha"][:12], c["commit"]["author"]["date"], "-", c["commit"]["message"].splitlines()[0])' \
            || echo "   (commit listing unavailable)"
        echo "  Re-vendoring procedure: see third_party/qrcodegen/AUTHORS."
        exit 2
    fi
    echo "   OK: $path still at pinned commit $pin"
done

[ "$freshness_skipped" -eq 1 ] && echo "   (freshness check partially skipped — see warnings above)"

echo "PASS: vendored qrcodegen is intact, undrifting, and up to date at its pins"
exit 0