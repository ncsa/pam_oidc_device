# Fuzz harnesses (`make fuzz`)

Opt-in crash / undefined-behavior / memory-leak fuzzing for the module's pure,
input-parsing leaf functions. **This is not part of `make lint` and is not run
by any CI workflow** — it is a standalone, on-demand hardening tool.

## Why loose fuzzing is a good fit here

The module's attack surface is dominated by *parsing attacker- or
operator-supplied bytes into fixed-size, NUL-terminated buffers and JSON trees*:

- the config file (root/0600 operator input, but still parsed with a custom
  section/value parser and `strncpy`-bounded coercions),
- the JWT payload (Base64URL decode + `json_tokener_parse` on the provider's
  bytes),
- the terminal strings and URLs shown to the user.

These functions are the natural targets: they are pure enough to drive with
arbitrary bytes, already `NULL`-safe with respect to `pam_handle_t` (the CMocka
suite already calls them with a `NULL` PAM handle), and reachable through
`fmemopen()`/direct argument passing without standing up a PAM stack.

## What's fuzzed

| harness (`tests/fuzz/`)      | target function(s)                                  |
|------------------------------|------------------------------------------------------|
| `fuzz_config.c`              | `parse_config_file`                                  |
| `fuzz_jwt_extract.c`         | `jwt_extract_claim_string`                           |
| `fuzz_token_meta.c`          | `verify_token_metadata`                              |
| `fuzz_string_validators.c`   | `is_valid_https_url`, `is_safe_terminal_string`, `is_safe_user_code`, `copy_checked`, `parse_loglevel` |
| `fuzz_verify_claim.c`        | `verify_claim` (regex *subject* only; pattern fixed) |
| `fuzz_pkce.c`                | `pkce_compute_s256_challenge`                        |

Each harness re-instruments the full module source set under
`-fsanitize=fuzzer,address,undefined,leak` (clang/libFuzzer + ASan/UBSan/LSan —
the same sanitizer set as `make test-sanitize`) and exposes a single
`LLVMFuzzerTestOneInput`.

## Running

`make fuzz` first runs a **preflight check** that fails fast with the exact
install command for your platform, instead of a raw compiler/linker error. You
need **clang** (libFuzzer is clang-native; gcc has no bundled libFuzzer) plus the
module's native dev packages.

Prerequisites:

```bash
# RHEL / Rocky / Fedora
dnf install -y clang pam-devel libcurl-devel json-c-devel openssl-devel

# Debian / Ubuntu
apt-get install -y clang libpam0g-dev libcurl4-openssl-dev libjson-c-dev libssl-dev
```

On **macOS / Windows** there is no native `libpam` package, so the harnesses
cannot build or run locally. `make fuzz` detects this and prints the container
command; equivalently, run the whole thing in the `ubuntu:24.04` CI-mirror
container (`.agents/context.md` §3.3):

```bash
docker run --rm -v "$PWD:/work" -w /work \
  -e DEBIAN_FRONTEND=noninteractive -e TZ=America/Chicago \
  ubuntu:24.04 bash -lc '
    echo "tzdata tzdata/Areas select America" | debconf-set-selections &&
    echo "tzdata tzdata/Zones/America select Chicago" | debconf-set-selections &&
    apt-get update -qq &&
    apt-get install -y clang make libpam0g-dev libcurl4-openssl-dev libjson-c-dev libssl-dev &&
    make fuzz FUZZ_MAX_TIME=30
  '
```

(Preseeding `tzdata` to Chicago + `DEBIAN_FRONTEND=noninteractive` keeps the
`apt-get` run fully unattended — without it, `tzdata`'s postinst can block on an
interactive "Please select the time zone" prompt.)

Usage (on a Linux host, after the prerequisites above):

```bash
make fuzz                              # build + run every harness (30 s each by default)
make fuzz FUZZ_MAX_TIME=600           # longer, deeper pass
make fuzz FUZZ_TARGETS=config         # just one harness
make fuzz-build                       # compile the harnesses only (no run)
```

Each run is bounded (`-max_total_time`); new "interesting" inputs and any crash
reproducers are written under `build/fuzz/` (git-ignored). The committed seed
corpus in `tests/fuzz/seed/` is copied into `build/fuzz/` and **never mutated**.

## Seed corpus

`tests/fuzz/seed/<target>/` holds a few hand-picked starting points (a valid
minimal/full config, a valid + malformed JWT, an ANSI-escape blob, a PKCE
verifier, …) derived from the CMocka vectors, so the fuzzer reaches deep paths
quickly instead of cold-starting.

## Triage

On `FAIL`, `make fuzz` leaves a minimal reproducer at `build/fuzz/crash-*`.
Reproduce and attach a stack trace with:

```bash
ASAN_OPTIONS=abort_on_malloc=0 ./build/fuzz/fuzz_<target> build/fuzz/crash-XXXXXX
```

A confirmed, reproducible in-bounds overflow / UBSan error / leak in a target
function is a real defect: fix it, add a regression test to
`tests/test_suite.c`, and rerun.
