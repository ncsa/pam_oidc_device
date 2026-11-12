# AGENTS.md — pam_oidc_device

**Purpose.** This is the canonical, tool-agnostic entry point for every AI/GenAI coding
agent (Copilot, Cline, Cursor, Roo, Claude Code, Codex, Gemini, …) working on
`pam_oidc_device` — a Linux PAM module for the OAuth 2.0 Device Authorization Grant
(RFC 8628) + PKCE (RFC 7636).

**Keep this file thin.** It holds only the commands you run and the hard boundaries you
never cross, so any tool that reads it gets an immediately-usable, non-bloated rule set.
Deep architecture, security & protocol guardrails, CI-mirrored gate detail, RFC
compliance, and reference/audit material live in [`.agents/context.md`](.agents/context.md).

**Read order before any significant task:** this file → `.agents/context.md` →
[`.agents/memory.md`](.agents/memory.md) (append-only LLM memory: prior decisions,
gotchas, verification status).

**Never edit the tool shims.** `CLAUDE.md`, `.github/copilot-instructions.md`,
`.clinerules`, `.cursorrules`, `.roorules`, and `.windsurfrules` are all symlinks to this
file. Edit only `AGENTS.md` (and the `.agents/*` docs) — one edit serves every tool.

---

## Build & Verification (copy-paste; mirrors CI)

This project is **Make-only** (no CMake/Meson). Object files and `build/` are generated in
the tree and git-ignored. Do not guess include paths or flags — build through the `Makefile`.

```bash
make lint                  # clang-format + clang-tidy + cppcheck + flawfinder + memory-scrub (CI-mirrored)
make clean && make CC=gcc  # gcc build (must be zero-warning)
make clean && make CC=clang# clang build (must be zero-warning)
make test CC=gcc           # CMocka suite under gcc
make test CC=clang         # CMocka suite under clang
make test-sanitize CC=clang# ASan+UBSan+LSan: builds AND RUNS the suite (the CI sanitizer gate)
clang-tidy src/*.c -- -Iinclude -D_GNU_SOURCE   # the exact CI clang-tidy gate
make check-scrub           # memory-scrub discipline (pure bash, works on macOS)
make check-licenses        # third-party / RPM-Requires license audit (pure bash, works on macOS)
make sandbox               # e2e: installed module through a real PAM stack vs the in-repo HTTPS mock IdP (Docker)
make rpm                   # EL/SUSE (Rocky 8/9/10, openSUSE Leap 16.0)
make deb                   # Debian 13 / Ubuntu 26.04 LTS
```

**Non-Linux (macOS) hosts:** `libpam` has no macOS/Windows package, so the native build/test
gates do **not** run here — a failing native build is an *environment limitation, not a
code defect*. Run the authoritative gates in a `ubuntu:24.04` container that mirrors CI, or
let GitHub Actions do it. See `.agents/context.md` §3.3 for the container recipe and the
macOS-only checks that *do* work.

---

## Boundaries

### Always do
- Run `make lint` and keep the build zero-warning under **both** `gcc` and `clang`
  (`-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Wformat-security`; CI adds `-Werror`).
- Scrub sensitive buffers (`client_secret`, `device_code`, `access_token`, `Authorization`)
  with `secure_memzero()`/`explicit_bzero()` — **never plain `memset()`** — and scrub
  provider-parsed JSON trees with `secure_zero_json_tree()` before `json_object_put()`.
- Use `CLOCK_MONOTONIC` + `clock_nanosleep` for all timing; never wall-clock `time()` for
  relative timeouts.
- Enforce HTTPS-only endpoints, TLS 1.2+, and `CURLOPT_SSL_VERIFYPEER=1` /
  `CURLOPT_SSL_VERIFYHOST=2` on every request.
- Free/cleanup every resource (curl handles, JSON trees, dynamic strings) on **all** exit
  paths, including error branches and `goto cleanup`.

### Ask first
- Any change to the config schema, public headers in `include/`, packaging specs, or CI
  workflows.
- Bumping the module version — it must stay in sync across `include/metadata.h`, `Makefile`
  (`VERSION ?=`), `packaging/pam_oidc_device.spec`, `packaging/gen-changelog.py`, and
  `.agents/context.md`.

### Never do
- Run `make install`, modify `/etc/pam.d/`, or touch system `/etc/` config without explicit
  user authorization.
- Run `rm -rf` on any path outside `build/` or `rpmbuild/`.
- Disable TLS/certificate validation, or weaken the config-file safety checks
  (`O_NOFOLLOW | O_CLOEXEC`, regular-file + `root:root` + `0600`/`0640`).
- Use banned C APIs: `strcpy`, `sprintf`, `strcat`, VLAs, unchecked `malloc`/`realloc`, or
  `getenv()` to source secrets.
- Hand-edit `third_party/` (the vendored `qrcodegen` encoder is provenance-pinned) or the
  tool shims.

**Off-limits directories/files:** `build/`, `rpmbuild/`, `third_party/`, `config/*.secret.conf`,
and system `/etc/`.

---

## C conventions

- **Standard:** C99/C11, compiled with `-D_GNU_SOURCE`. Flags and linkage come from the
  `Makefile` (`-fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -z relro -z now`).
- **Ownership:** caller-frees the buffers a function returns; teardown via `goto cleanup`.
- **Error handling:** PAM functions return `pam_status_t`; internal helpers use a consistent
  success/fail convention — follow the surrounding code.
- **Memory discipline:** see the scrub rules above; the invariant is mechanically enforced by
  `make check-scrub`.
- **Secret handling:** treat access/refresh tokens as ephemeral in-memory secrets; zero them
  before `pam_sm_authenticate()` returns.

For module architecture, subsystem ownership, RFC compliance notes, and the full CI gate
rationale, read [`.agents/context.md`](.agents/context.md).
