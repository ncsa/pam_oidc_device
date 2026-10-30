#!/usr/bin/env bash
#
# scripts/lint.sh — the single source of truth for local lint/static checks.
#
# It runs the EXACT commands used by the "Lint and Static Analysis" workflow
# (.github/workflows/lint.yml) so that "passes locally" reliably predicts
# "passes in CI":
#
#   1. clang-format  --dry-run --Werror   src/*.c include/*.h tests/*.c
#   2. clang-tidy    src/*.c -- -Iinclude -D_GNU_SOURCE
#   3. cppcheck      --enable=all ... src/
#   4. flawfinder    --minlevel=3 --error-level=3 src/ include/
#
# Run it directly (./scripts/lint.sh), via `make lint`, or through the
# .githooks/pre-commit hook.
#
# Each check is guarded: if a tool is missing it prints a notice and skips
# instead of failing (important on macOS, which has no libpam). clang-tidy
# additionally requires the PAM headers to be resolvable, because it must
# actually parse the translation units. A check whose tool IS present still
# fails the gate on any finding.
#
set -uo pipefail

# Always run from the repository root (this script lives in <root>/scripts/).
cd "$(dirname "$0")/.." || exit 2

CC="${CC:-gcc}"
status=0

note() { printf '  [lint] %s\n' "$1"; }
skip() { printf '  [lint] skip %-12s (%s)\n' "$1" "$2"; }

# --- 1. clang-format (style gate; no system headers required) ---------------
if command -v clang-format >/dev/null 2>&1; then
  note "clang-format --dry-run --Werror src/*.c include/*.h tests/*.c"
  if ! clang-format --dry-run --Werror src/*.c include/*.h tests/*.c; then
    echo "clang-format check FAILED. Auto-fix with: clang-format -i src/*.c include/*.h tests/*.c" >&2
    status=1
  fi
else
  skip "clang-format" "clang-format not installed"
fi

# --- 2. clang-tidy (needs the full dev header set to parse the TUs) ---------
# Gate on whether a real translation unit syntax-checks with the project
# flags, NOT on "does one header exist": macOS ships a stub security/pam_appl.h
# (so a trivial #include compiles) but lacks json-c/curl, so the real TUs do
# not build there and clang-tidy would flood with false errors.
TUS_COMPILE_OK=0
if "$CC" -Iinclude -D_GNU_SOURCE -fPIC -fsyntax-only src/config.c >/dev/null 2>&1; then
  TUS_COMPILE_OK=1
fi

if command -v clang-tidy >/dev/null 2>&1; then
  if [ "$TUS_COMPILE_OK" -eq 1 ]; then
    note "clang-tidy src/*.c -- -Iinclude -D_GNU_SOURCE"
    if ! clang-tidy src/*.c -- -Iinclude -D_GNU_SOURCE; then
      echo "clang-tidy FAILED. Fix the findings above (see .clang-tidy for the check set)." >&2
      status=1
    fi
  else
    skip "clang-tidy" "dev headers incomplete (src/config.c does not syntax-check)"
  fi
else
  skip "clang-tidy" "clang-tidy not installed"
fi

# --- 3. cppcheck (standalone parser; no system headers required) ------------
if command -v cppcheck >/dev/null 2>&1; then
  note "cppcheck --enable=all --std=c99 -I include/ src/  (CI flags)"
  if ! cppcheck --enable=all \
        --suppress=missingIncludeSystem \
        --suppress=unusedFunction \
        --suppress=constParameterCallback \
        --error-exitcode=1 \
        --std=c99 \
        -I include/ \
        src/; then
    echo "cppcheck FAILED." >&2
    status=1
  fi
else
  skip "cppcheck" "cppcheck not installed"
fi

# --- 4. flawfinder (text-based security scanner; no headers required) -------
if command -v flawfinder >/dev/null 2>&1; then
  note "flawfinder --minlevel=3 --error-level=3 src/ include/"
  if ! flawfinder --minlevel=3 --error-level=3 src/ include/; then
    echo "flawfinder found >=3 severity issues in src/ and include/." >&2
    status=1
  fi
else
  skip "flawfinder" "flawfinder not installed"
fi

# --- Summary ----------------------------------------------------------------
if [ "$status" -eq 0 ]; then
  note "OK — all available lint checks passed."
else
  note "FAILED — one or more checks reported problems (see above)."
fi
exit "$status"