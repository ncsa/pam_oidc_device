# pam_oidc_device — Deep Agent Context & Rules

> **Purpose.** This is the *deep* reference document for AI/GenAI coding agents (Copilot, Cline,
> Cursor, Roo, Claude Code, …) working on `pam_oidc_device`. It holds the architecture map,
> module boundaries, security & protocol guardrails, the CI-mirrored verification gates, RFC
> compliance notes, the reference library, and the audit-pass prompts.
>
> **Wiring.** The root `AGENTS.md` is the thin, canonical entry point (build/test commands +
> hard boundaries). `CLAUDE.md`, `.github/copilot-instructions.md`, and the `.*rules` files are
> all symlinks to that root `AGENTS.md`; this file is the detailed companion they point readers
> to. Edit the deep content here — never edit through the tool shims.
>
> **Companion.** Machine-oriented memory of prior AI work (decisions, gotchas, verification
> status) is kept separately in [`.agents/memory.md`](.agents/memory.md) and must be read before
> starting any significant task — see [§7](#7-machine-memory-log-protocol-agentsmemorymd).

---

## Contents

| §  | Section                                            | Read it when…                                                |
|----|----------------------------------------------------|--------------------------------------------------------------|
| 1  | Project Overview & Architecture                    | You need the mental model of the module and its subsystems.  |
| 2  | Tech Stack & Build Dependencies                    | You need languages, libraries, and the toolchain.            |
| 3  | Verification Gates (CI-Mirrored)                   | Before, during, and after **any** code change.               |
| 4  | Code & Security Guardrails                         | Writing or reviewing `src/`, `include/`, or config code.     |
| 5  | Protocol Compliance & Implementation Gotchas       | Touching the device flow, PKCE, JWT, or polling logic.       |
| 6  | Agent Operational Safety Rules                     | Before running **any** command on the host.                  |
| 7  | Machine Memory Log Protocol                        | Starting and finishing significant work.                     |
| 8  | Contributor & Pull-Request Quality Bar             | Preparing a commit or pull request.                          |
| 9  | Reference Library                                  | You need authoritative specs and background reading.         |
| 10 | Specialized Review Workflows (Audit Passes)        | Performing reviews, audits, or pre-release verification.     |

---

## 1. Project Overview & Architecture

- **Project identity:** `pam_oidc_device` (v0.3.3, see `include/metadata.h`) is a Linux Pluggable
  Authentication Module (PAM) written in C.
- **Core purpose:** out-of-band user authentication via the OAuth 2.0 Device Authorization Grant
  (RFC 8628) and OpenID Connect (OIDC), extended with PKCE (RFC 7636).
- **Maintainer & license:** NCSA CyberInfrastructure, MIT License.
- **Primary subsystems:**
  - `src/pam_module.c` — PAM entry points (`pam_sm_authenticate`, `pam_sm_setcred`) and the
    monotonic polling orchestrator.
  - `src/config.c` — configuration file parsing, strict POSIX filesystem safety, and regex setup.
  - `src/http.c` — thread-safe cURL HTTP transport layer and level-filtered syslog audit logging
    (`pam_oauth_log`).
  - `src/identity.c` — POSIX extended-regex identity-claim extraction and group/role
    authorization checks.
  - `src/jwt.c` — local Base64URL parsing and claims-only JWT inspection (`exp`, `nbf`, `iss`,
    `aud`) via OpenSSL — **does not verify the JWT signature**.
  - `src/pkce.c` — RFC 7636 PKCE: CSPRNG `code_verifier` generation and S256 `code_challenge`
    computation, binding the token exchange to the originating device flow.
  - `src/qr.c` — terminal QR rendering of the verification URI, wrapping the vendored
    ISO/IEC 18004 encoder in `third_party/qrcodegen/` (config-validated inputs only, so no
    escape-sequence injection into the QR block).
  - `include/metadata.h` — single source of truth for module metadata and identity macros.
- **Repository layout:**
  - `src/`, `include/` — module code and public headers.
  - `tests/` — CMocka suite (`tests/test_suite.c`, run via `tests/runner`), plus `lsan.supp`
    (intentional third-party LSan suppressions), `tests/qr_scan` (QR fixture tooling), and
    `tests/e2e/` (one-command device-flow sandbox: `Dockerfile`, `mock_oidc.py` HTTPS mock IdP,
    `pam_driver.c` deterministic PAM driver, `run_e2e.sh` 9-scenario harness, config/PAM-stack
    fixtures — `make sandbox` / `make sandbox-shell`, mirrored by the CI `e2e-sandbox` job).
  - `config/pam_oidc_device.conf` — sample/documented configuration.
  - `docs/` — operator documentation (getting started, testing, access control,
    JWT validation, threat model, packaging); `docs/developer/` — developer
    review guide and roadmap; `examples/` —
    provider-specific config examples (CILogon, Entra ID, Keycloak).
  - `scripts/lint.sh` — the CI-mirrored lint gate (single source of truth behind `make lint`).
  - `packaging/` — RPM spec (`pam_oidc_device.spec`, EL + SUSE `Requires:`/`BuildRequires:`
    branches), changelog generator, and DEB build script (`build-deb.sh` → `make deb`).
  - `third_party/qrcodegen/` — vendored QR encoder (MIT; provenance + drift audit in-directory).
  - Root docs: `README.md` (new-user hub: why, how it works, quickstart,
    documentation map), `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`,
    `THIRD_PARTY_NOTICES.md` (authoritative third-party license/provenance record; summary in
    the README; enforced by the `license-audit` workflow).

---

## 2. Tech Stack & Build Dependencies

- **Language:** modern C (compiled with `-D_GNU_SOURCE`; C99/C11 standards).
- **Required libraries:**
  - `libpam` — PAM extension framework
  - `libcurl` — HTTPS network client
  - `json-c` — JSON payload parsing
  - `libcrypto` / OpenSSL — Base64URL decoding and cryptographic routines
  - `cmocka` / `libcmocka-devel` — unit-testing suite
- **Toolchain:** CI builds with **both** `gcc` and `clang`; the lint gate uses `clang-format`,
  `clang-tidy`, `cppcheck`, and `flawfinder`; packaging uses `rpmbuild` (EL/SUSE hosts for
  `make rpm`) and the dpkg toolchain (`dpkg-deb` / `dpkg-shlibdeps` / `dpkg-architecture`
  via `dpkg-dev`, Debian/Ubuntu hosts for `make deb`).

---

## 3. Verification Gates (CI-Mirrored)

When completing **any** code modification, refactoring, or bug fix, execute this validation loop
sequentially and **never commit or push until it passes**. The lint/static-analysis commands must
match `.github/workflows/lint.yml` **verbatim** — do not "improve" the file scope (never drop
`tests/*.c` from clang-format, never add `tests/*.c` to clang-tidy) or the local result stops
predicting CI.

### 3.1 The mandatory loop

1. **Pre-commit gate (enable once per clone):** point git at the repo hooks so every `git commit`
   runs the lint gate automatically:
   ```bash
   git config core.hooksPath .githooks
   ```
   `.githooks/pre-commit` invokes `scripts/lint.sh` (clang-format + clang-tidy + cppcheck +
   flawfinder + memory-scrub inspection, CI-mirrored). Tools that aren't installed — or that
   can't compile the translation units here (e.g. no PAM headers on macOS) — are skipped with a
   notice, so the gate never dead-ends a commit. Bypass only in a genuine emergency with
   `git commit --no-verify`.

2. **Format code** (fix, then verify against the exact CI scope):
   ```bash
   clang-format -i src/*.c include/*.h tests/*.c
   clang-format --dry-run --Werror src/*.c include/*.h tests/*.c
   ```
   The second line is the *failing* check CI runs — it must report no diff.

3. **Run clang-tidy (mirror CI exactly):**
   ```bash
   clang-tidy src/*.c -- -Iinclude -D_GNU_SOURCE
   ```
   CI gates clang-tidy to `src/*.c`; `include/` headers are still analyzed via `.clang-tidy`'s
   `HeaderFilterRegex: 'include/.*'`, and `tests/*.c` is intentionally *not* clang-tidy-gated in
   CI (covered by the compiler + tests). With `WarningsAsErrors: '*'`, **any** diagnostic in user
   code is a hard error. Do not suppress findings or disable checks to make the gate pass — fix
   the underlying code instead. (The single justified `NOLINT` is the `misc-no-recursion` on the
   intentionally recursive `secure_zero_json_tree()`.)

4. **Run cppcheck (mirror CI):**
   ```bash
   cppcheck --enable=warning \
            --enable=style \
            --enable=performance \
            --enable=portability \
            --suppress=missingIncludeSystem \
            --suppress=unusedFunction \
            --suppress=staticFunction \
            --suppress=constParameterCallback \
            --error-exitcode=1 \
            --std=c99 \
            -I include/ \
            src/
   ```
   The `--enable` set is deliberately the four defect severities, not `--enable=all`:
   `error` severity is always checked regardless, and leaving `information`/`debug`
   off stops newer cppcheck releases from surfacing purely diagnostic messages
   (`checkersReport`, `normalCheckLevelMaxBranches`) that `--error-exitcode=1` would
   otherwise treat as hard failures.

5. **Run flawfinder (mirror CI):**
   ```bash
   flawfinder --minlevel=3 --error-level=3 src/ include/
   ```

   **Shortcut:** `make lint` runs steps 1–5 in one shot (single source of truth: `scripts/lint.sh`).

6. **Memory-scrub inspection (CI-enforced — the `memory-scrub` job in `lint.yml`):**
   `scripts/check-memory-scrubbing.sh` (also `make check-scrub`) lexically verifies the §4.1
   secret-hygiene invariant in `src/*.c`: every `free()` of a sensitive heap buffer requires a
   same-file `secure_memzero()`/`explicit_bzero()` scrub of that buffer ordered before the
   first free; plain `memset()` of a sensitive buffer is only tolerated when a secure scrub of
   it also exists in the file; and every `json_object_put()` of a provider-parsed JSON tree is
   paired with a same-file `secure_zero_json_tree()` scrub. Pure bash/grep — no PAM headers or
   toolchain required, so it runs on macOS and in CI:
   ```bash
   make check-scrub
   ```

7. **Sanitizer build & test (the CI-enforced gate is `make test-sanitize CC=clang`):**
   - `make test-sanitize` — **builds AND runs** the CMocka suite under ASan + UBSan + LSan
     (recompiling the module with sanitizer flags). This is the *only* sanitizer job CI enforces:
     the `sanitize-test` job in `.github/workflows/build.yml` runs `make test-sanitize CC=clang`.
     It is the gate that actually *detects* heap overflow/underflow, use-after-free, undefined
     behavior, and memory leaks; known intentional third-party process-lifetime allocations
     (libcurl global state) are documented in `tests/lsan.supp`.
   - `make sanitize` — compile-only smoke check under the same instrumentation. **Not a CI
     gate** — no CI job runs it, and it is subsumed by `make test-sanitize`, which compiles the
     module with identical flags. Run it only as an optional fast pre-check.
   ```bash
   make test-sanitize CC=clang
   ```

8. **Run unit tests (CI runs the suite under *both* compilers):** the `compile-matrix` job in
   `.github/workflows/build.yml` executes the CMocka suite (non-sanitized baseline) under both
   `gcc` and `clang`:
   ```bash
   make test CC=gcc
   make test CC=clang
   ```

9. **Verify compiler warnings (both compilers, as in CI's `compile-matrix`):** the normal build
   must complete with zero warnings under the full `CFLAGS`
   (`-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Wformat-security`), since CI
   builds the module with *both* compilers:
   ```bash
   make clean && make CC=gcc
   make clean && make CC=clang
   ```

10. **Native-distro package builds (CI-enforced, on every push/PR to `main`):**
    - `make rpm` — the `distro-build` job in `.github/workflows/distro-build.yml` runs it
      inside **Rocky Linux 8/9/10** (EL) and **openSUSE Leap 16.0** (SUSE) containers (then
      installs the produced RPM and verifies `/lib64/security/pam_oidc_device.so` and
      `/etc/pam_oidc_device.conf`); on SUSE the spec's `%if 0%{?suse_version}` branch selects
      SUSE binary package names (`pam-devel`/`libcurl-devel`/`libjson-c-devel`/
      `libopenssl-devel`/`libcmocka-devel` build-time; `pam`/`libcurl4`/`libjson-c5`/
      `openssl` runtime). `make rpm` needs the `rpmbuild` toolchain (EL/dnf or SUSE/zypper
      hosts).
    - `make deb` — the same `distro-build` job builds and installs the binary `.deb`
      (hand-crafted by `packaging/build-deb.sh` with `dpkg-deb` + `dpkg-shlibdeps`, no
      debhelper; module lands in `/lib/<multiarch>/security`, config as a `0600` conffile)
      on **Debian 13** and **Ubuntu 26.04 LTS**. Needs `dpkg-dev` + build deps on a
      Debian/Ubuntu host.
    ```bash
    make rpm   # EL/SUSE
    make deb   # Debian/Ubuntu
    ```

11. **License & third-party compliance (CI-enforced — the `license-audit` workflow, on every
    push/PR to `main`, monthly, and on demand):** the `license-compliance` job runs
    `scripts/check-licenses.sh` (`make check-licenses`, pure bash — runs on macOS too):
    `THIRD_PARTY_NOTICES.md` exists at the repo root; every `third_party/*/` component carries
    license text + an `AUTHORS`/`NOTICE` attribution + a `vendor-provenance.txt` pin; no
    copyleft (GPL/LGPL/AGPL) text appears in `third_party/`; and every RPM-spec `Requires:`
    runtime dependency — **all** `Requires:` lines (EL and SUSE per-distro branches) — is
    declared in `THIRD_PARTY_NOTICES.md`. The `dependency-graph-audit`
    job queries the GitHub dependency graph (`scripts/audit-dependency-graph.py`) and fails on
    any indexed package with an off-allowlist license. The GraphQL `dependencyGraph` field is
    feature-gated per account, so the job falls back to the public REST `dependencies`
    endpoint when that field is absent from the served schema; a REST 404 (feature off /
    private repo / no indexed data — the current state for this repo) yields a clean INFO
    no-op, while any other query failure hard-fails (a no-op today for this pure-C project;
    it activates automatically once GitHub indexes a recognized manifest):
    ```bash
    make check-licenses
    ```

### 3.2 Completion criteria

Do not mark a task as completed unless every gate CI enforces exits cleanly with code `0`:

- `make lint` (clang-format / clang-tidy / cppcheck / flawfinder / memory-scrub — mirrors `lint.yml`),
- `make CC=gcc` + `make test CC=gcc` and `make CC=clang` + `make test CC=clang` (the
  `compile-matrix` job),
- `make test-sanitize CC=clang` (the `sanitize-test` job),
- the `e2e-sandbox` job (`tests/e2e/run_e2e.sh`: installed module driven through a real PAM
  stack against the in-repo HTTPS mock OIDC provider; locally: `make sandbox`),
- `make rpm` on EL8/EL9/EL10 **and** openSUSE Leap 16.0, plus `make deb` on Debian 13 +
  Ubuntu 26.04 LTS (all the `distro-build` jobs in `.github/workflows/distro-build.yml`),
- the `license-audit` workflow (`make check-licenses` + the GitHub dependency-graph audit).

`make sanitize` is *not* a CI gate and must not be reported as one.

### 3.3 Non-Linux (macOS / Windows) hosts

The loop in §3.1 assumes a **Linux PAM host**. `libpam` has no Homebrew/MacPorts/Windows package,
and `include/pam_oidc_device.h` pulls in `<security/pam_*.h>`, so the native `make` /
`make sanitize` / `make test` / `clang-tidy` gates do **not** run on macOS. Do **not** treat a
failing native build on macOS as a code defect — it is an environment limitation. Instead:

- Run the gates in a **Linux container that mirrors CI** (`ubuntu:24.04` + `libpam0g-dev
  libcurl4-openssl-dev libjson-c-dev libcmocka-dev libssl-dev clang clang-tidy`) — see below.
- Or push the branch and let the **GitHub Actions** `ubuntu-latest` workflows (`lint.yml`,
  `build.yml`) run the authoritative gates.
- For PAM-independent pure-C logic, do an **isolated compile-check** under the project's strict
  warning flags, and **validate base64url test fixtures with Python**.

**Preferred local workaround — a Linux container that mirrors CI** (Docker, OrbStack, colima, or
UTM):

```bash
docker run -it --rm \
  -v "$PWD:/work" -w /work \
  -e DEBIAN_FRONTEND=noninteractive \
  ubuntu:24.04 \
  bash -lc '
    set -e
    apt-get update
    apt-get install -y build-essential clang clang-format clang-tidy cppcheck \
      libpam0g-dev libcurl4-openssl-dev libjson-c-dev libcmocka-dev libssl-dev
    make clean
    make CC=gcc && make test CC=gcc       # compile-matrix: gcc build + CMocka suite
    make clean
    make CC=clang && make test CC=clang   # compile-matrix: clang build + CMocka suite
    clang-tidy src/*.c -- -Iinclude -D_GNU_SOURCE   # lint.yml gate
    make test-sanitize CC=clang           # sanitize-test: ASan/UBSan/LSan (builds AND RUNS)
  '
```

The `make rpm` gate (the EL/SUSE entries of the `distro-build` job) cannot be mirrored in that
Ubuntu container — it requires an EL image (e.g. `rockylinux:9` with `rpm-build`, `pam-devel`,
…, as in `distro-build.yml`) — or simply run it in CI.

**Lightweight checks that DO work on macOS (no PAM needed):**

- **Pre-commit gate (recommended):** `git config core.hooksPath .githooks`; `.githooks/pre-commit`
  then runs `scripts/lint.sh` on every commit — clang-format and the memory-scrub inspection
  run locally while clang-tidy / cppcheck / flawfinder are skipped with a notice when their
  tools or headers are unavailable (e.g. macOS).
- **Memory-scrub inspection (always works):** `make check-scrub`
  (`scripts/check-memory-scrubbing.sh`) is pure bash/grep — no PAM headers or toolchain needed —
  and verifies the §4.1 scrub-before-release discipline in `src/*.c`.
- **License compliance (always works):** `make check-licenses`
  (`scripts/check-licenses.sh`) is likewise pure bash/grep and enforces `THIRD_PARTY_NOTICES.md`
  + vendored-component license/attribution/provenance + the spec `Requires:` cross-declaration
  (the `license-compliance` job of `license-audit.yml`).
- **Formatting:** `brew install clang-format`, then `clang-format -i src/*.c include/*.h tests/*.c`
  and verify with the exact CI check
  `clang-format --dry-run --Werror src/*.c include/*.h tests/*.c`.
- **Isolated compile-check of PAM-independent logic** (e.g. JWT `exp`/`nbf` arithmetic,
  base64url helpers, `is_safe_*` string validation): copy the target function into a small
  harness with stub PAM/json-c declarations and compile it under the project's exact warning
  flags (`-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Wformat-security`) to catch
  type/warning/format errors early.

- **Validate test fixtures with Python:** when a new CMocka test adds base64url JWT payloads,
  decode them to confirm they map to the intended JSON before relying on CI:
  ```bash
  python3 - <<'PY'
  import base64, json
  def b64url_dec(seg):
      return json.loads(base64.urlsafe_b64decode(seg + '=' * (-len(seg) % 4)))
  # <paste the base64url payload segments from your new test here>
  print(b64url_dec("eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC90ZW5hbnQvIn0"))
  PY
  ```

**The quality bar is unchanged.** A native macOS build is **not** a substitute for the Linux
gates. A task is only complete when `make lint`, the gcc+clang build/test matrix,
`make test-sanitize CC=clang`, the EL8/EL9/EL10 `make rpm` job, and the native-distro
`distro-build` jobs (openSUSE Leap 16.0 RPM; Debian 13 / Ubuntu 26.04 LTS DEB) — i.e. the full CI pipeline —
pass in a **Linux** environment.

---

## 4. Code & Security Guardrails

The rules in this section are **non-negotiable** for any code you write or review in this repo.

### 4.1 Memory scrubbing

- **NEVER** scrub sensitive buffers (`client_secret`, `device_code`, `access_token`, and the
  app-owned `Authorization` header buffer) with standard `memset()`.
- **ALWAYS** use `secure_memzero()` or `explicit_bzero()` to prevent optimizing-compiler
  dead-code elimination of the zero-fill loop.
- Scrub json-c-parsed credential/PII strings by zeroing every string leaf before
  `json_object_put()` (`secure_zero_json_tree`); libcurl's internal `Authorization` header copy
  cannot be securely zero-filled via the public cURL API (it is reclaimed by the allocator on
  `curl_slist_free_all()`).
- This discipline is mechanically enforced by `scripts/check-memory-scrubbing.sh`
  (`make check-scrub`; part of `make lint` and the CI `memory-scrub` job): sensitive buffers
  must be scrubbed with `secure_memzero()`/`explicit_bzero()` before `free()`, and
  provider-parsed JSON trees with `secure_zero_json_tree()` before `json_object_put()`.
- Treat access and refresh tokens as ephemeral in-memory secrets: zero them immediately after
  use and before `pam_sm_authenticate()` exits — using the secure functions above, never plain
  `memset()`.

### 4.2 Filesystem & I/O hardening

- Configuration loading must use `O_NOFOLLOW | O_CLOEXEC` flags on `open()` calls; the config
  path must also be a regular file (`S_ISREG`) owned by root (`st_uid == 0`).
- Permissions must be restricted to `0600` or `0640` owned by `root:root` (`st_gid == 0`).

### 4.3 Terminal & transport protection

- Enforce strict HTTPS URL schemes for all OIDC endpoints (`is_valid_https_url`).
- Dynamic terminal inputs must be validated to reject ANSI escape sequences and C0/C1 control
  characters: provider URLs via `is_valid_https_url` and user codes via `is_safe_user_code`.
- The prompt template is confined to the root-owned, permission-restricted config file, and the
  fully rendered prompt is validated line-by-line by `is_safe_terminal_string` inside
  `render_prompt_message()` (newlines permitted; all other bytes must be printable ASCII).
- Ensure cURL global state is initialized thread-safely via `pthread_once`.

### 4.4 Timing & timeouts

- Use `CLOCK_MONOTONIC` and `clock_nanosleep` for all polling intervals and deadlines. Do not
  use wall-clock `time()` for relative timeouts.

### 4.5 Authentication-flow hardening requirements

- **Extend the device flow with PKCE (RFC 7636):** although RFC 8628 originally treated device
  codes as sufficient proof, modern identity providers (IdPs) recommend or support pairing the
  Device Grant with PKCE. Generate a high-entropy `code_verifier` on the C side, send
  `code_challenge` in the initial `/device/authorization` request, and pass `code_verifier`
  during token polling to prevent device-code replay or interception attacks.
- **Strict local-to-remote identity binding:** do not grant authorization solely because the
  token exchange succeeded. Validate the returned identity (e.g. `sub`, `preferred_username`,
  or a custom claim from the OIDC `/userinfo` endpoint or decoded JWT) against the local Linux
  system user returned by `pam_get_user()`. Explicitly disable or restrict `root`
  authentication unless mapped through a strict local alias file.
- **Mitigate out-of-band device-code phishing:** RFC 8628 flows are vulnerable to phishing,
  where an attacker triggers a flow and sends the `user_code` to a victim. The module must
  output clear context via `PAM_TEXT_INFO` (e.g. host IP, system identifier, requested scope)
  so the user can verify what they are authorizing on their secondary device.
- **Enforce TLS 1.2+ and strict certificate validation:** explicitly set
  `CURLOPT_SSL_VERIFYPEER = 1L` and `CURLOPT_SSL_VERIFYHOST = 2L`, and enforce minimum TLS
  1.2/1.3 versions. Never allow certificate validation to be disabled via module options.

---

## 5. Protocol Compliance & Implementation Gotchas

### 5.1 OAuth 2.0 Device Authorization Grant (RFC 8628)

- **Grant type:** must strictly use `urn:ietf:params:oauth:grant-type:device_code` when querying
  the token endpoint.
- **Polling & backoff:** the standard polling interval defaults to 5s (`MIN_POLL_INTERVAL`);
  treat that as a floor. If the provider returns `error: "slow_down"`, increase the interval by
  +5s per RFC 8628 §3.5.
- **Non-retryable errors:** only `authorization_pending` and `slow_down` allow loop
  continuation; all other well-formed `4xx` OAuth `error` payloads must break polling
  immediately. Treat `429`/`5xx` (including empty, `{}`, or HTML proxy bodies) as transient and
  retry with backoff *within* the device-authorization deadline.

### 5.2 Related specifications

- **RFC 7636** — Proof Key for Code Exchange (see §4.5 and `src/pkce.c`).
- **RFC 7519** — JSON Web Token (claims-only inspection in `src/jwt.c`).
- **RFC 7662** — Token Introspection (`introspection_endpoint` is accepted-but-unused; a
  load-time notice is emitted).
- **RFC 4648 §5** — unpadded Base64URL encoding.
- **RFC 3986** — URI generic syntax & percent-encoding.
- **WCAG 2.1 Level AA** — conformance baseline for repository documentation
  and the documented terminal user experience: the shared technical baseline
  of the three mandates on NCSA/UIUC public-facing content — IITAA 2.1
  (30 ILCS 587), ADA Title II (28 CFR Part 35, effective April 2026), and
  Rehabilitation Act § 508 (29 U.S.C. § 794d, via 36 CFR Part 1194); see §8.
- **Project guidelines:** consult `CONTRIBUTING.md` and `README.md`.

### 5.3 C & PAM implementation gotchas

1. **Process boundary & memory-leak accumulation:** PAM modules execute in the address space of
   the caller (`sshd`, `sudo`, `login`). Any leaked memory or open file descriptors persist for
   the lifetime of the host process. Ensure all HTTP client handles (e.g. `curl_easy_cleanup`),
   JSON parsers (e.g. `json_object_put`), and dynamic strings are freed on all execution paths.
2. **Signal handling & interruptible polling:** if a user cancels an SSH session (or sends
   `SIGINT`/`SIGTERM`), standard network calls can hang. The HTTP polling loop must respect
   signal interruptions, break gracefully, clean up resources, and return `PAM_AUTH_ERR` or
   `PAM_AUTHINFO_UNAVAIL`.
3. **Polling interval & backoff enforcement:** implement strict compliance with the
   authorization server's `interval` response. On `slow_down`, RFC 8628 requires increasing the
   polling interval by at least 5 seconds; failing to do so can trigger rate-limiting or DDoS
   defenses on the server side.
4. **Session timeouts vs. PAM timeouts:** PAM authentication blocks execution. Long polling
   timeouts (e.g. waiting 15 minutes for `expires_in`) can trigger SSH `LoginGraceTime` or
   `systemd-pam` module timeouts. Configure a conservative maximum timeout on the PAM module
   side (e.g. 60–120 seconds) independent of the server's maximum code expiration.
5. **Reentrancy and thread safety:** with `libcurl`, call `curl_global_init()` properly or rely
   on static module initialization (via `pthread_once`). Ensure thread-safe calls when parsing
   JSON responses or evaluating crypto primitives.

---

## 6. Agent Operational Safety Rules

- **Prohibited system commands:** do NOT install system-wide PAM modules (`make install`),
  modify `/etc/pam.d/`, or touch system `/etc/` configurations directly without explicit user
  authorization.
- **Isolated testing:** perform all test execution strictly within the repository workspace
  using `make test` and the `tests/runner` binaries.
- **Destructive commands:** do NOT run `rm -rf` on paths outside `build/` or `rpmbuild/`.
- **Output discipline:** always run build/test commands in quiet mode (e.g. `make -s`,
  `pytest --tb=short`), and do not run commands that emit over 50 lines of output unless
  requested.

---

## 7. Machine Memory Log Protocol (`.agents/memory.md`)

[`.agents/memory.md`](.agents/memory.md) is an accumulating, *machine-oriented* memory of
AI-assisted work on this repo — **not** a user-facing changelog (that is `CHANGELOG.md`).

- **Read it first:** before starting a significant task, read `.agents/memory.md` (and this
  file) to recover prior context, decisions, and gotchas.
- **Update it strategically:** after completing a *significant* AI-assisted change (a feature, a
  refactor, a non-trivial bug fix, or a notable environment/CI decision), append a new entry to
  its **Interaction Log** (newest first) using the entry format defined at the top of that file,
  and promote any durable, reusable takeaway into its **Standing Invariants** section.
- **Do NOT:** log trivial / format-only edits, or duplicate what `CHANGELOG.md` already records
  for end users.
- Every entry must state **verification status** explicitly — what was verified locally vs. what
  still requires the Linux gates / CI.

---

## 8. Contributor & Pull-Request Quality Bar

- Ensure the GitHub Actions build and static-analysis pipelines pass completely (see §3 for the
  full gate list and §3.2 for the completion criteria).
- Commit messages should clearly describe the rationale behind the change.
- Code **must** compile cleanly under
  `-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Wformat-security -O2 -g` with zero
  warnings, under **both** `gcc` and `clang`.
- `clang-tidy` must run clean across `src/*.c` using `-- -Iinclude -D_GNU_SOURCE` (exactly
  matching the CI `clang-tidy` job in `.github/workflows/lint.yml`), honoring the `.clang-tidy`
  config where `WarningsAsErrors: '*'` turns any user-code diagnostic into a hard error —
  see §3.1 step 3.
- All existing and new tests in `tests/test_suite.c` must pass under both compilers and the
  sanitizer run (see §3.1 steps 6–7).
- Wiping of sensitive memory buffers must use `secure_memzero()` or `explicit_bzero()` (see
  §4.1).
- Documentation must remain **WCAG 2.1 Level AA** conformant (shared baseline
  of IITAA 2.1, ADA Title II, and Rehabilitation Act § 508; see §5.2 and the
  `README.md` `## Accessibility` section): semantic heading structure, tables
  with header rows, meaningful alt text on every image, no information conveyed
  by color alone, and a prose figure description (e.g., "**Figure N — …**")
  preceding every ASCII-art diagram. Terminal-UX claims in docs must track the
  implementation: the prompt is always plain text (QR is off-by-default and
  strictly supplemental), fully keyboard-driven (**Enter** to begin,
  **Ctrl-C** → `PAM_ABORT`), with no user-uncancellable time limits, and failed
  attempts must deliver a user-visible, plain-text, actionable notice through
  the PAM conversation (`notify_user_failure()` in `src/pam_module.c` —
  best-effort, deliberately generic wording; detailed causes stay in the audit
  log only). Never leave a new failure path log-only.
- **Guide navigation & link labels (WCAG 2.4.4 / 2.4.5):** every long guide
  (4+ H2 sections: `docs/getting-started.md`, `docs/testing.md`,
  `docs/jwt-validation.md`, `docs/access-control.md`, `docs/threat-model.md`)
  begins with a `## Table of Contents` in the threat-model format; link labels
  are descriptive and context-unique (no bare-URL labels, no repeated
  unanchored link text); prose uses words, not symbols — no `≠` and no inline
  `→` arrows in prose (use "results in", "maps to", "shows", etc.).
- Follow the agent operational safety rules in §6 when verifying changes.

---

## 9. Reference Library

**Standards & specifications:**

- [RFC 8628 — OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628):
  the foundational IETF standard for the device flow.
- [RFC 7636 — Proof Key for Code Exchange (PKCE)](https://www.rfc-editor.org/rfc/rfc7636).
- [RFC 7519 — JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519).
- [RFC 7662 — OAuth 2.0 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662).
- [RFC 4648 — Base64URL Encoding (§5)](https://www.rfc-editor.org/rfc/rfc4648).
- [RFC 3986 — URI Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986).
- [IETF OAuth 2.0 Security Best Current Practice (BCP)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics):
  latest guidance on threat models, client isolation, token handling, and transport security.

**Background & implementation references:**

- [Authlete Device Flow Technical Deep-Dive](https://developers.authlete.com/protocols-and-flows/advanced-flows/oauth-2-0-device-authorization-grant-device-flow):
  detailed protocol mechanics, parameter breakdown, and implementation state diagrams.
- [Okta Threat Research: Device Code Phishing](https://www.okta.com/blog/threat-intelligence/device-code-phishing--it-s-phishing-with-dynamite/):
  analysis of real-world exploitation vectors against RFC 8628 flows and mitigations.
- [Ping Identity: Device Authorization Grant with PKCE](https://docs.pingidentity.com/pingoneaic/am-oauth2/oauth2-device-flow-pkce.html):
  guide to extending RFC 8628 with PKCE parameters (`code_challenge` / `code_verifier`).
- [Nithe14/pam_oauth2_device (GitHub)](https://github.com/Nithe14/pam_oauth2_device): an example
  implementation of a Linux PAM module utilizing the OAuth 2.0 Device Authorization Grant.

**Project documents:** `README.md`, `CONTRIBUTING.md`, `SECURITY.md`,
`CHANGELOG.md`, `docs/` (getting started, testing, access control, JWT
validation, threat model, packaging), `docs/developer/review.md` (developer
review guide), `docs/developer/roadmap.md`, `examples/README.md` (provider
integration examples & discovery).

### 9.1 OAuth 2.0 Device Authorization Grant (RFC 8628) — Vendor & Implementation Reference

This reference defines the IETF standards, commercial OIDC providers, academic/research identity
federations, reference PAM implementations, and cross-vendor behavioral variances that
`pam_oidc_device` must support.

#### 1. Core IETF Specifications

* **RFC 8628 — OAuth 2.0 Device Authorization Grant:** https://www.rfc-editor.org/info/rfc8628/
  * Defines the `/device_authorization` endpoint, `urn:ietf:params:oauth:grant-type:device_code`
    token grant, OIDC discovery metadata (`device_authorization_endpoint`), polling error codes
    (`authorization_pending`, `slow_down`, `access_denied`, `expired_token`), and Section 5/6
    security and usability rules (base-20 user code charset, TLS enforcement, and remote phishing
    mitigations).
* **RFC 9700 — Best Current Practice for OAuth 2.0 Security:** https://www.rfc-editor.org/info/rfc9700/
  * Security baseline deprecating Resource Owner Password Credentials (ROPC) in favor of the
    Device Authorization Grant on input-constrained or headless systems.

#### 2. Commercial & Enterprise OIDC Providers

* **Microsoft Entra ID (Azure AD) — Microsoft Identity Platform:** https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code
  * **Endpoints & Setup:** Uses `/{tenant}/oauth2/v2.0/devicecode` and
    `/{tenant}/oauth2/v2.0/token`. Requires **Allow public client flows** enabled in the App
    Registration.
  * **Behavior:** Defaults `expires_in` to `900` seconds (15 minutes). Returns an extra localized
    `message` field in the device authorization response (customizable via `?mkt=xx-XX`). Uses
    `authorization_declined` in addition to `access_denied` when a user rejects the prompt. Issues
    `id_token` and `refresh_token` when `openid` and `offline_access` scopes are requested.
* **Okta — Configure Device Authorization Grant Flow:** https://developer.okta.com/docs/guides/device-authorization-grant/main/
  * **Shared Device Guide:** https://www.okta.com/blog/identity-security/device-flow-and-okta-shared-device-authentication-for-consumers/
  * **Endpoints & Setup:** Requires configuring a **Native Application** with the
    `Device Authorization` grant enabled on both the client and the Custom Authorization Server's
    **Access Policy Rule**.
  * **Behavior:** User codes default to a 10-minute lifetime (`600` seconds). Supports
    `verification_uri_complete` for terminal QR code rendering and documents shared/public device
    session-clearing practices.
* **Auth0 — Device Authorization Flow & Implementation Guide:** https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow
  * **Native Device Quickstart:** https://auth0.com/docs/quickstart/native/device
  * **Endpoints & Setup:** Requires **Native** application type, **OIDC Conformant** toggle
    enabled, and **Device Code** grant type enabled (plus **Allow Offline Access** on the API for
    refresh tokens).
  * **Behavior:** Allows tenant-level customization of `user_code` character set, format, and
    length (enforcing minimums of 8 characters for BASE20 letters or 9 for numbers). Recommends
    immediately discarding `device_code` in memory once exchanged for tokens.
* **Keycloak — Securing Applications and Services with OIDC:** https://www.keycloak.org/securing-apps/oidc-layers
  * **Architectural Design Spec:** https://github.com/keycloak/keycloak-community/blob/main/design/oauth2-device-authorization-grant.md
  * **Endpoints & Setup:** Exposes `/realms/{realm}/protocol/openid-connect/auth/device` and
    `/realms/{realm}/device`. Requires enabling **OAuth 2.0 Device Authorization Grant** on the
    client and supports per-realm or per-client overrides for `Device Code Lifespan` (default
    `600s`) and `Device Polling Interval` (default `5s`).
  * **Behavior:** Implements "User Code Verification First" so per-client authentication flow
    overrides apply, and enforces consent display so users verify device identity against
    phishing.
* **Google Identity — OAuth 2.0 for TV and Limited-Input Device Applications:** https://developers.google.com/identity/protocols/oauth2/limited-input-device
  * **Endpoints & Setup:** Uses `https://oauth2.googleapis.com/device/code` (advertised in
    `.well-known/openid-configuration` as `device_authorization_endpoint`) and requires the **TVs
    and Limited Input devices** OAuth client type.
  * **Behavior:** Deviates from RFC 8628 by returning `verification_url` instead of
    `verification_uri` in the JSON response. Supports only a restricted subset of Google scopes.
* **Ping Identity (PingAM) — Device Authorization Grant Endpoint:** https://docs.pingidentity.com/pingam/8.1/am-oauth2/rest-api-oauth2-device-code.html
  * **Behavior:** Documents `/oauth2/device/code` and `/oauth2/device/user` along with optional
    PKCE extensions (`Device authorization grant with PKCE`) for public clients.
* **AWS IAM Identity Center — OIDC API Reference:** https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/Welcome.html
  * **StartDeviceAuthorization API:** https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_StartDeviceAuthorization.html
  * **Behavior:** Uses dynamic client registration (`RegisterClient`) followed by JSON-encoded
    requests to `/device_authorization` and `/token` rather than `application/x-www-form-urlencoded`,
    and omits standard OIDC `id_token` issuance in some portal configurations.

#### 3. Academic & Research Federation OIDC Providers

* **CILogon — OAuth 2.0 Device Flow & OIDC Documentation:** https://www.cilogon.org/device
  * **General OIDC Docs:** https://www.cilogon.org/oidc
  * **Reference CLI Shell Script:** https://cilogon.org/deviceflow.sh
  * **Endpoints & Setup:** Advertises `https://cilogon.org/oauth2/device_authorization` and
    `https://cilogon.org/oauth2/token` via `https://cilogon.org/.well-known/openid-configuration`
    (staging environment at `https://test.cilogon.org`).
  * **Behavior:** Supports both **Confidential Clients** (`client_id` + `client_secret` via form
    POST) and **Public Clients** (`client_id` only). Defaults to `expires_in: 900` (15 minutes) and
    `interval: 5`, issuing formatted `user_code` values (e.g., `PLK-NGF-V77`) alongside
    `verification_uri_complete` (`https://cilogon.org/device/?user_code=...`). Supports the
    `org.cilogon.userinfo` scope for federated SAML/eduPerson claims (`eppn` /
    `eduPersonPrincipalName`, `eptid`, `eduPersonScopedAffiliation`, `ou`, `idp_name`).
* **Globus Auth — API & Headless CLI Reference (Unsupported Caveat):** https://docs.globus.org/api/auth/reference/
  * **Headless Login Docs:** https://docs.globus.org/cli/reference/login/
  * **Behavior:** Globus Auth (`https://auth.globus.org`) does **not** implement RFC 8628 and omits
    `device_authorization_endpoint` from `https://auth.globus.org/.well-known/openid-configuration`.
    Headless logins (`globus login --no-local-server`) rely on a copy-paste OAuth 2.0 Authorization
    Code flow (`https://auth.globus.org/v2/web/auth-code`). Research sites requiring RFC 8628
    alongside Globus authenticate against **CILogon** directly.
* **INDIGO IAM (WLCG, INFN, ESCAPE, EOSC) — Obtaining a Token from a CLI:** https://indigo-iam.github.io/v/current/docs/tasks/user/getting-a-token/
  * **Behavior:** Exposes `/devicecode` via `.well-known/openid-configuration` and explicitly
    deprecates ROPC in favor of the device flow. Supports self-service and RFC 7591 dynamic client
    registration with `urn:ietf:params:oauth:grant-type:device_code` enabled by default, plus
    optional `audience` parameters on token requests per **WLCG Common JWT Profiles**.
* **CERN SSO (Keycloak) — OAuth 2.0 Device Code Authorization Grant:** https://auth.docs.cern.ch/user-documentation/oidc/device-code/
  * **Behavior:** Enables `urn:ietf:params:oauth:grant-type:device_code` by default for new OIDC
    client registrations, supports both public and confidential clients, and returns `cern_roles`
    claims for authorization mapping.
* **EGI Check-in / LS Login / eduTEAMS (GÉANT AARC) — Service Provider OIDC Guide:** https://docs.egi.eu/providers/check-in/sp/
  * **Behavior:** Implements the **AARC Blueprint Architecture (BPA)** and **REFEDS Assurance
    Framework**, encoding Virtual Organization (VO) memberships in `eduperson_entitlement` URNs
    (e.g., `urn:mace:egi.eu:group:...`) and persistent user identifiers in `eduperson_unique_id`.

#### 4. Reference PAM & Research CLI Implementations

* **`ICS-MU/pam_oauth2_device` (C++ PAM Module for Research Infrastructures):** https://github.com/ICS-MU/pam_oauth2_device
  * Security-reviewed by the University of Basel and the Swiss Institute of Bioinformatics (evolved
    from `ondrejvelisek/pam_oauth2_device` and SLAC's `pam_oauth2_device`). Renders terminal QR
    codes from `verification_uri_complete`, maps configurable OIDC claims (`username_attribute`
    such as `sub`, `eppn`, or `preferred_username`) to local POSIX/LDAP accounts, and injects MFA
    enforcement (`require_mfa`) into authorization requests.
* **`Nithe14/pam_oauth2_device` (Rust PAM Implementation):** https://github.com/Nithe14/pam_oauth2_device
  * Integrates alongside SSSD/NSS for local account resolution, validates token claims (`active`,
    `username`, `scope`, `exp`), and explicitly blocks `root` logins via the OIDC device flow.
* **`indigo-dc/oidc-agent` & `EOSC-synergy/ssh-oidc` (`motley_cue`):** https://github.com/indigo-dc/oidc-agent and https://github.com/EOSC-synergy/ssh-oidc
  * Standard research CLI/HPC tooling demonstrating `--flow=device` across CILogon, EGI Check-in,
    INDIGO IAM, and WLCG, plus mapping REFEDS assurance levels and `eduperson_entitlement` VOs to
    local Linux accounts.

#### 5. Cross-Vendor Compatibility & Implementation Matrix for `pam_oidc_device`

| Requirement / Behavior | Standard & Vendor Variance | Implementation Rule for `pam_oidc_device` |
| :--- | :--- | :--- |
| **OIDC Discovery validation** | **Entra**, **Okta**, **Auth0**, **Keycloak**, **Google**, **CILogon**, **INDIGO IAM**, **CERN SSO**, and **EGI Check-in** publish `device_authorization_endpoint`; **Globus Auth** does not. | Resolve `device_authorization_endpoint`, `token_endpoint`, `jwks_uri`, and `issuer` via `.well-known/openid-configuration`. Allow manual endpoint overrides in config, and return a clear `PAM_AUTHINFO_UNAVAIL` / config error if `device_authorization_endpoint` is absent. |
| **Verification URI JSON key** | RFC 8628 requires `verification_uri`; **Google Identity** returns `verification_url`. | Parse `verification_uri` first and fall back to `verification_url` if `verification_uri` is missing. |
| **User denial error codes** | RFC 8628 defines `access_denied`; **Microsoft Entra ID** can return `authorization_declined`. | Treat both `access_denied` and `authorization_declined` as immediate terminal authentication failures (`PAM_AUTH_ERR`). |
| **Polling interval & backoff** | RFC 8628 defaults to `5s` if `interval` is omitted and mandates adding `+5s` on `slow_down`. | Honor server-returned `interval` (default `5s`), permanently increment the session interval by `+5s` upon receiving `slow_down`, and apply exponential backoff on transient network/5xx errors. |
| **Client authentication mode** | **Entra ID**, **Okta**, **Auth0**, and **Google** expect public native clients without a secret (some reject secrets on device flow); **Keycloak**, **PingAM**, **CILogon**, **CERN SSO**, and **INDIGO IAM** support both public and confidential clients. | Default to public client mode (`client_id` in form body), with optional `client_secret` support (`client_secret_basic` or `client_secret_post`) for centrally provisioned confidential clients. |
| **POSIX username claim mapping** | Commercial IdPs often use `email` or `preferred_username`, whereas academic IdPs frequently issue opaque `sub` URIs (`http://cilogon.org/serverA/users/...`) alongside `eppn` or `eduperson_unique_id`. | Support configurable `username_attribute` lookup (`eppn`, `eduperson_unique_id`, `preferred_username`, `email`, `sub`) with optional `@domain` stripping or local mapfile/regex translation, and block `root` logins by default. |
| **VO / Group & MFA gating** | Research clusters authorize by Virtual Organization (`eduperson_entitlement`, `wlcg.groups`, `cern_roles`) and REFEDS MFA (`acr` = `https://refeds.org/profile/mfa`). | Support optional claim-matching rules (required group/entitlement values and `acr` MFA assertions) and optional `acr_values` / `audience` request parameters before returning `PAM_SUCCESS`. |
| **PAM & OpenSSH UX** | `sshd` requires `KbdInteractiveAuthentication yes` (`ChallengeResponseAuthentication yes`) and `UsePAM yes` to display prompts. | Emit `verification_uri` and `user_code` (plus an optional ASCII QR code from `verification_uri_complete` when enabled) via `PAM_TEXT_INFO` in the PAM conversation function before entering the token polling loop. |

---

## 10. Specialized Review Workflows (Audit Passes)

When performing comprehensive reviews, pull-request audits, or pre-release verification on the
`pam_oidc_device` repository, execute the appropriate structured pass(es) below. Each pass
states **when to run** it and provides an **agent review prompt** with focus areas and the
expected deliverable.

### 10.1 Security & Defensive Engineering Audit Pass

**When to run:** analyzing C source files (`src/`), headers (`include/`), or security-critical
configuration parsing for vulnerability vectors and defensive coding flaws.

> **Agent review prompt:** Act as a Senior Security Engineer and C Systems Security Expert.
> Analyze the codebase for security vulnerabilities, edge-case flaws, and defensive hardening
> gaps across the following domains:
>
> 1. **Memory hygiene & buffer safety:** Verify that sensitive tokens, client secrets, and JSON
>    trees are zeroed via volatile memory writes (`secure_memzero`, `secure_zero_json_tree`)
>    across **all** exit paths (including `return`, `goto cleanup`, and error branches). Enumerate
>    every `free()` / `json_object_put()` release of a sensitive or provider-parsed value and
>    manually confirm the paired scrub: the lexical gate (`make check-scrub`) only recognizes
>    bare-identifier, `*handle`, and `&handle` argument forms — releases through array indexing
>    or temporaries, and allowlisted non-sensitive trees (`JSON_PII_ALLOWLIST`), are out of its
>    scope. Audit stack and heap bounds checking: inspect `snprintf`, `memcpy`, `realloc`, and
>    fixed-capacity form field arrays (`DEVICE_FORM_MAX_FIELDS`, `TOKEN_FORM_MAX_FIELDS`) for
>    integer wrap-around or truncation risks.
> 2. **POSIX & system hardening:** Validate file-descriptor and race-condition defenses during
>    file loading (`load_config`). Confirm strict usage of `O_NOFOLLOW` and `O_CLOEXEC`, root
>    ownership assertions (`uid == 0`), and restrictive file-permission enforcement
>    (`0600` / `0640`).
> 3. **Terminal safety & injection defenses:** Verify that all provider-supplied data (URLs,
>    user codes, initial message prompt templates, QR block characters) is sanitized before
>    terminal display to prevent ANSI escape-sequence or control-character injection
>    (`is_safe_terminal_string`, `is_safe_rendered_prompt`).
> 4. **Network & transport security:** Ensure `http_request` strictly enforces TLS 1.2+ minimum
>    protocol versions and mandatory peer/host certificate verification. Confirm request
>    timeouts and monotonic polling clocks (`CLOCK_MONOTONIC`) prevent unbounded blocking.
>
> Organize findings by severity (**Critical, High, Medium, Low, Informational**). For each
> finding, provide file path, function name, flaw description, root-cause analysis, and a
> recommended code patch.

### 10.2 RFC Protocol & Standards Compliance Audit Pass

**When to run:** verifying strict adherence to the IETF standards governing authentication,
token formats, and parameter encodings.

> **Agent review prompt:** Act as a Standards & Identity Protocol Architect. Review the
> repository against the official specifications for OpenID Connect and OAuth 2.0 — RFC 8628
> (Device Authorization Grant), RFC 7636 (PKCE), RFC 7519 (JWT), RFC 4648 §5 (unpadded
> Base64URL encoding), and RFC 3986 (URI generic syntax & percent-encoding). Evaluate
> compliance against these criteria:
>
> 1. **Device flow (RFC 8628):** Verify handling of `authorization_pending`, `slow_down`,
>    transient HTTP status codes (429/5xx), and polling-interval backoff calculations. Confirm
>    mandatory provider response fields are validated before consumption.
> 2. **PKCE (RFC 7636):** Validate CSPRNG code-verifier generation
>    (`pkce_generate_code_verifier`) for entropy, byte length, and URL-safe character set.
>    Confirm SHA-256 S256 challenge derivation (`pkce_compute_s256_challenge`) aligns with
>    specification test vectors.
> 3. **JWT metadata (RFC 7519):** Inspect `verify_token_metadata` for `exp`, `nbf`, `iss`, and
>    `aud` claim validation. Confirm NumericDate claims handle integer and fractional JSON
>    numeric types while rejecting stringified or malformed types.
> 4. **Encoding strictness (RFC 4648 §5):** Ensure Base64URL decoding rejects non-alphabet
>    characters (standard Base64 `+`, `/`, embedded whitespace, or misplaced `=` padding).
>
> Report all specification non-compliance items, ambiguous parameter handling, or edge-case
> protocol deviations with file paths, line references, and RFC section citations.

### 10.3 Build Systems, Packaging & Automation Audit Pass

**When to run:** inspecting the Makefile, packaging specs, git attributes,
or GitHub Actions CI workflows.

> **Agent review prompt:** Act as a Principal DevOps & Infrastructure Engineer. Audit the build
> configurations (`Makefile`), packaging scripts (`packaging/`), and CI/CD
> pipelines (`.github/workflows/*.yml`). Focus analysis on:
>
> 1. **Compiler flags & hardening:** Verify essential C security flags are enforced (`-Wall`,
>    `-Wextra`, `-Werror`, `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-fPIE/-pie`,
>    `-Wformat-security`, `-z relro`, `-z now`). Confirm clean separation between Debug and
>    Release build configurations.
> 2. **CI/CD security & least privilege:** Audit GitHub Actions workflows for third-party action
>    SHA pinning, explicit minimal `permissions:` scopes, and safe handling of context variables
>    in shell scripts to prevent command injection.
> 3. **Sanitizers & dynamic analysis:** Ensure dynamic testing tools (ASan, UBSan, LSan, CMocka)
>    and static analyzers (`clang-tidy`, `cppcheck`) are cleanly integrated into automated test
>    targets.
> 4. **Packaging & distribution:** Confirm RPM/Debian packaging specs correctly handle module
>    installation paths (`/lib64/security`), binary permissions, and release-tarball exclusion
>    patterns (`export-ignore` in `.gitattributes`).
>
> Deliver concrete recommendations to optimize build reproducibility, pipeline security, and
> packaging integrity.

### 10.4 Code Quality, Maintainability & Documentation Audit Pass

**When to run:** evaluating long-term maintainability, cyclomatic complexity, unit test
coverage, and documentation accuracy.

> **Agent review prompt:** Act as a Lead C Developer and Technical Writer. Review the codebase
> for architectural cleanliness, code quality, unit test coverage, and documentation accuracy.
> Examine the following areas:
>
> 1. **Code structure & maintainability:** Identify functions with high cyclomatic complexity,
>    inconsistent error-handling return codes, redundant helper functions, or missing Doxygen
>    function headers.
> 2. **Documentation accuracy:** Verify that `README.md`, the `docs/` guides, and inline comments
>    accurately reflect the actual C implementation, syslog levels, and configuration parameters
>    line-by-line.
>    **Accessibility (WCAG 2.1 AA):** confirm every image has meaningful alt text, heading
>    structure is unbroken, no information is conveyed by color alone, every ASCII-art
>    diagram carries a preceding prose figure description, long guides begin with a
>    Table of Contents, link labels are descriptive and context-unique (no bare-URL
>    labels, no repeated unanchored labels), and prose uses words rather than symbols
>    (no `≠`, no inline `→`) (§8) — and that no
>    `pam_sm_authenticate()` failure path is log-only: every one must deliver a
>    user-visible plain-text notice via `notify_user_failure()`.
> 3. **Test suite coverage:** Evaluate the CMocka unit tests in `tests/test_suite.c`. Identify
>    untested edge cases (null inputs, memory allocation failures, malformed JSON structures,
>    invalid regex rules, network transport errors). Confirm test isolation and weak-symbol
>    mocking reliability.
>
> Provide structural refactoring suggestions, documentation corrections, and specific test cases
> to improve repository coverage and readability.
