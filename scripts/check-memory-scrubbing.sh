#!/usr/bin/env bash
#
# scripts/check-memory-scrubbing.sh — Memory-management inspection gate.
#
# Enforces the project's secret-hygiene invariant (`.agents/context.md` §4.1): sensitive
# buffers — OAuth tokens, PKCE verifier/challenge, client secret, form POST
# fields, HTTP response bodies, and provider-parsed JSON trees — must be
# zeroed with a dead-code-elimination-proof primitive (`secure_memzero()`
# or `explicit_bzero()`; JSON trees via `secure_zero_json_tree()`) BEFORE
# their release (`free()` / `json_object_put()`). A plain `memset()` may be
# optimized away when it is the last use of a buffer, so it is never
# accepted as a scrub on its own.
#
# This check is pure bash/grep: it needs no PAM headers, no compiler, and no
# third-party tools, so it runs identically on macOS development hosts and
# in CI. It is wired into:
#   * `make check-scrub` (Makefile target)
#   * scripts/lint.sh step 5 (i.e. `make lint` and .githooks/pre-commit)
#   * the "memory-scrub" job in .github/workflows/lint.yml (every push/PR)
#
# Checks:
#   S1  Every free() of a sensitive heap buffer requires a same-file
#       secure_memzero()/explicit_bzero() scrub of that same buffer,
#       with at least one scrub ordered BEFORE the buffer's first free()
#       (scrub-before-release).
#   S2  A file that zeroes a sensitive buffer with plain memset() must
#       also perform a secure scrub of that same buffer in the same
#       file. Plain memset remains acceptable for *initialization*
#       (top-of-function zero-init, where the optimizer keeps the
#       writes); it is never acceptable as the *only* zeroing.
#   S3  Every json_object_put() of a provider-parsed JSON tree handle —
#       including pointer/dereference forms such as json_object_put(*tok_json)
#       — must be paired with a same-file secure_zero_json_tree() scrub of
#       that handle (json-c retains private heap copies of each parsed
#       string that json_object_put() releases with a plain free()).
#       Documented non-sensitive trees may be listed in JSON_PII_ALLOWLIST.
#
# Known limitations (this is a lexical inspection, not a data-flow
# analysis):
#   * A sensitive buffer that is freed WITHOUT scrubbing on one path can
#     still pass S1/S2 if another path in the same file scrubs before
#     release. The CMocka sanitizer run (`make test-sanitize`) and the
#     security audit passes (`.agents/context.md` §10.1) remain the backstop.
#   * S3 matches `json_object_put(handle)`, `json_object_put(*handle)` and
#     `json_object_put(&handle)`; releases through other expressions (array
#     indexing, temporaries) remain out of scope.
#
set -uo pipefail

# Always run from the repository root (this script lives in <root>/scripts/).
cd "$(dirname "$0")/.." || exit 2

fail=0
note() { printf '  [scrub] %s\n' "$1"; }
err() {
  printf '  [scrub] FAIL: %s\n' "$1" >&2
  fail=1
}

# Accepted anti-DCE zeroing primitives (`.agents/context.md` §4.1).
SCRUB_RE='(secure_memzero|explicit_bzero)\('

# --- S1: scrub-before-release for sensitive heap buffers ----------------------
# Sensitive heap-allocated buffers that are released with free(). For each
# occurrence, a same-file secure scrub of that buffer must exist, and the
# first scrub must be ordered before the first free.
S1_IDS='postfields token_postfields access_token payload_b64 payload_json_str'
S1_LITERALS='resp->body'

s1_check() { # $1=file  $2=anchor ERE fragment  $3=display name
  local f="$1" pat="$2" name="$3"
  local frees scrubs first_free first_scrub
  frees=$(grep -nE "free\(${pat}\)" "$f" | cut -d: -f1)
  [ -z "$frees" ] && return 0
  scrubs=$(grep -nE "${SCRUB_RE}${pat}" "$f" | cut -d: -f1)
  if [ -z "$scrubs" ]; then
    err "$f: free of sensitive buffer '${name}' has no same-file secure_memzero()/explicit_bzero() scrub"
    return 0
  fi
  first_free=$(printf '%s\n' "$frees" | sort -n | head -n1)
  first_scrub=$(printf '%s\n' "$scrubs" | sort -n | head -n1)
  if [ "$first_scrub" -gt "$first_free" ]; then
    err "$f: scrub of '${name}' (line ${first_scrub}) is ordered AFTER its first free() (line ${first_free})"
  fi
}

note "S1: sensitive heap buffers scrubbed before free()"
for f in src/*.c; do
  for id in $S1_IDS; do
    s1_check "$f" "$id" "$id"
  done
  for lit in $S1_LITERALS; do
    s1_check "$f" "$lit" "$lit"
  done
done

# --- S2: plain memset is never sufficient as a scrub --------------------------
# If a file memsets a sensitive anchor, it must also secure-scrub that same
# anchor somewhere in the same file. `.{0,1}` after the open paren permits
# the address-of form (memset(&dev, ...)).
S2_ANCHORS='postfields token_postfields access_token client_secret code_verifier code_challenge device_code payload_b64 payload_json_str auth_hdr resp->body dev cfg prompt_buf jwt_sub'

note "S2: plain memset() only tolerated alongside a secure scrub"
for f in src/*.c; do
  for a in $S2_ANCHORS; do
    if grep -qE "memset\(.{0,1}${a}," "$f"; then
      if ! grep -qE "${SCRUB_RE}.{0,1}${a}," "$f"; then
        err "$f: plain memset() of sensitive buffer '${a}' with no same-file secure_memzero()/explicit_bzero() scrub"
      fi
    fi
  done
done

# --- S3: provider JSON trees scrubbed before json_object_put() ---------------
# Trees whose contents are documented as non-sensitive (no tokens, no PII)
# may be exempted; every exemption must carry a justification.
JSON_PII_ALLOWLIST='doc' # http.c: OIDC discovery metadata (endpoints / methods only)

note "S3: json_object_put() paired with secure_zero_json_tree()"
for f in src/*.c; do
  handles=$(grep -oE 'json_object_put\([*&]?[A-Za-z_][A-Za-z0-9_]*\)' "$f" | sed -E 's/json_object_put\(|\)//g; s/[*&]//g' | sort -u)
  [ -z "$handles" ] && continue
  for h in $handles; do
    case " $JSON_PII_ALLOWLIST " in
      *" $h "*) continue ;;
    esac
    if ! grep -qE "secure_zero_json_tree\(\*?${h}" "$f"; then
      err "$f: json_object_put(${h}) without a same-file secure_zero_json_tree(${h}) scrub"
    fi
  done
done

# --- Summary ------------------------------------------------------------------
if [ "$fail" -eq 0 ]; then
  note "OK — sensitive-buffer scrub discipline holds in src/."
else
  note "FAILED — scrub the sensitive buffer(s) above with secure_memzero() / explicit_bzero() / secure_zero_json_tree() before release." >&2
fi
exit "$fail"
