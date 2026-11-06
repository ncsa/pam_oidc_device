# AGENTS.md — pam_oidc_device: AI Agent Context & Rules

> **Purpose.** This file is the single, *tool-agnostic* source of truth for all AI/GenAI coding
> agents (Copilot, Cline, Cursor, Roo, …) working on `pam_oidc_device`. It consolidates the former
> `.airules` and `.github/ai-instructions/system-context.md`. Machine-oriented memory of prior AI
> work (decisions, gotchas, verification status) is kept separately in
> [`.agents/memory.md`](.agents/memory.md) and must be read before starting significant work.

---

## 1. Project Overview & Architecture

- **Project Identity:** `pam_oidc_device` (v0.1.0, see `include/metadata.h`) is a Linux Pluggable
  Authentication Module (PAM) written in C.
- **Core Purpose:** Implements out-of-band user authentication via the OAuth 2.0 Device
  Authorization Grant (RFC 8628) and OpenID Connect (OIDC).
- **Maintainer & License:** Maintained by NCSA CyberInfrastructure under the MIT License.
- **Primary Subsystems:**
  - `src/pam_module.c`: Primary PAM entry points (`pam_sm_authenticate`, `pam_sm_setcred`) and the
    monotonic polling orchestrator.
  - `src/config.c`: Configuration file parsing, strict POSIX filesystem safety, and regex setup.
  - `src/http.c`: Thread-safe cURL HTTP transport layer and level-filtered syslog audit logging
    (`pam_oauth_log`).
  - `src/identity.c`: POSIX extended-regex identity-claim extraction and group/role authorization
    checks.
  - `src/jwt.c`: Local Base64URL parsing and claims-only JWT claim inspection (`exp`, `nbf`, `iss`,
    `aud`) via OpenSSL — **does not verify the JWT signature**.
  - `include/metadata.h`: Single source of truth for module metadata and identity macros.

---

## 2. Tech Stack & Build Dependencies

- **Language:** Modern C (compiled with `-D_GNU_SOURCE`; C99/C11 standards).
- **Required Libraries:**
  - `libpam` (PAM extension framework)
  - `libcurl` (HTTPS network client)
  - `json-c` (JSON payload parsing)
  - `libcrypto` / OpenSSL (Base64URL decoding and cryptographic routines)
  - `cmocka` / `libcmocka-devel` (unit-testing suite)

---

## 3. Mandatory Verification & Autonomous Loop

When completing **any** code modification, refactoring, or bug fix, execute this validation loop
sequentially and **never commit or push until it passes**. The lint/static-analysis commands must
match `.github/workflows/lint.yml` **verbatim** — do not "improve" the file scope (never drop
`tests/*.c` from clang-format, never add `tests/*.c` to clang-tidy) or the local result stops
predicting CI.

1. **Pre-commit gate (enable once per clone):** point git at the repo hooks so every `git commit`
   runs the lint gate automatically:
   ```bash
   git config core.hooksPath .githooks
   ```
   `.githooks/pre-commit` invokes `scripts/lint.sh` (clang-format + clang-tidy + cppcheck +
   flawfinder, CI-mirrored). Tools that aren't installed — or that can't compile the translation
   units here (e.g. no PAM headers on macOS) — are skipped with a notice, so the gate never
   dead-ends a commit. Bypass only in a genuine emergency with `git commit --no-verify`.

2. **Format Code** (fix, then verify against the exact CI scope):
   ```bash
   clang-format -i src/*.c include/*.h tests/*.c
   clang-format --dry-run --Werror src/*.c include/*.h tests/*.c
   ```
   The second line is the *failing* check CI runs — it must report no diff.

3. **Run clang-tidy (mirror CI exactly)**:
   ```bash
   clang-tidy src/*.c -- -Iinclude -D_GNU_SOURCE
   ```
   CI gates clang-tidy to `src/*.c`; `include/` headers are still analyzed via `.clang-tidy`'s
   `HeaderFilterRegex: 'include/.*'`, and `tests/*.c` is intentionally *not* clang-tidy-gated in CI
   (covered by the compiler + tests). With `WarningsAsErrors: '*'`, **any** diagnostic in user
   code is a hard error. Do not suppress findings or disable checks to make the gate pass — fix
   the underlying code instead.

4. **Run cppcheck (mirror CI)**:
   ```bash
   cppcheck --enable=all --suppress=missingIncludeSystem --suppress=unusedFunction \
            --suppress=constParameterCallback --error-exitcode=1 --std=c99 -I include/ src/
   ```

5. **Run flawfinder (mirror CI)**:
   ```bash
   flawfinder --minlevel=3 --error-level=3 src/ include/
   ```

   **Shortcut:** `make lint` runs steps 1–4 in one shot (single source of truth: `scripts/lint.sh`).

6. **Sanitizer Build & Test (the CI-enforced gate is `make test-sanitize CC=clang`):**
   - `make test-sanitize` — **builds AND runs** the CMocka suite under ASan +
     UBSan + LSan (recompiling the module with sanitizer flags). This is the
     *only* sanitizer job CI enforces: the `sanitize-test` job in
     `.github/workflows/build.yml` runs `make test-sanitize CC=clang`. It is
     the gate that actually *detects* heap overflow/underflow, use-after-free,
     undefined behavior, and memory leaks; known intentional third-party
     process-lifetime allocations (libcurl global state) are documented in
     `tests/lsan.supp`.
   - `make sanitize` — compile-only smoke check under the same instrumentation.
     **Not a CI gate** — no CI job runs it, and it is subsumed by
     `make test-sanitize`, which compiles the module with identical flags.
     Run it only as an optional fast pre-check.
   ```bash
   make test-sanitize CC=clang
   ```

7. **Run Unit Tests (CI runs the suite under *both* compilers):**
   The `compile-matrix` job in `.github/workflows/build.yml` executes the
   CMocka suite (non-sanitized baseline) under both `gcc` and `clang`:
   ```bash
   make test CC=gcc
   make test CC=clang
   ```

8. **Verify Compiler Warnings (both compilers, as in CI's `compile-matrix`):**
   Ensure the normal build completes with zero warnings under the full
   `CFLAGS` (`-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Wformat-security`),
   since CI builds the module with *both* compilers:
   ```bash
   make clean && make CC=gcc
   make clean && make CC=clang
   ```

9. **RPM Package Build (CI-enforced on EL8/EL9/EL10, on every push/PR to `main`):**
   The `rpm-build` job in `.github/workflows/build.yml` runs `make rpm` inside
   Rocky Linux 8/9/10 containers (then installs the produced RPM and verifies
   `/lib64/security/pam_oidc_device.so` and `/etc/pam_oidc_device.conf`), so
   packaging is part of the normal CI gate, not only "packaging work."
   `make rpm` needs the `rpmbuild` toolchain (EL/dnf hosts):
   ```bash
   make rpm
   ```

Do not mark a task as completed unless every gate CI enforces exits cleanly with code `0`:
`make lint` (clang-format/clang-tidy/cppcheck/flawfinder — mirrors `lint.yml`),
`make CC=gcc` + `make test CC=gcc` and `make CC=clang` + `make test CC=clang`
(the `compile-matrix` job), `make test-sanitize CC=clang` (the `sanitize-test`
job), and `make rpm` on EL8/EL9/EL10 (the `rpm-build` job). `make sanitize` is
*not* a CI gate and must not be reported as one.

### Non-Linux (macOS / Windows) Hosts

The loop above assumes a **Linux PAM host**. `libpam` has no Homebrew/MacPorts/Windows package, and
`include/pam_oidc_device.h` pulls in `<security/pam_*.h>`, so the native `make` / `make sanitize` /
`make test` / `clang-tidy` gates do **not** run on macOS. Do **not** treat a failing native build on
macOS as a code defect. Instead:
- Run the gates in a **Linux container that mirrors CI** (`ubuntu:24.04` +
  `libpam0g-dev libcurl4-openssl-dev libjson-c-dev libcmocka-dev libssl-dev clang clang-tidy`);
  see the exact command below.
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
The `rpm-build` gate cannot be mirrored in that Ubuntu container — it requires
an EL image (e.g. `rockylinux:9` with `rpm-build`, `pam-devel`, …, as in
`build.yml`) — or simply run it in CI.

### Lightweight checks that DO work on macOS (no PAM needed)
- **Pre-commit gate (recommended):** `git config core.hooksPath .githooks`; `.githooks/pre-commit`
  then runs `scripts/lint.sh` on every commit — clang-format runs locally while clang-tidy/cppcheck/
  flawfinder are skipped with a notice when their tools or headers are unavailable (e.g. macOS).
- **Formatting:** `brew install clang-format`, then
  `clang-format -i src/*.c include/*.h tests/*.c` and verify with the exact CI check
  `clang-format --dry-run --Werror src/*.c include/*.h tests/*.c`.
- **Isolated compile-check of PAM-independent logic** (e.g. JWT `exp`/`nbf` arithmetic, base64url
  helpers, `is_safe_*` string validation): copy the target function into a small harness with stub
  PAM/json-c declarations and compile it under the project's exact warning flags
  (`-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Wformat-security`) to catch
  type/warning/format errors early.
- **Validate test fixtures with Python:** when a new CMocka test adds base64url JWT payloads, decode
  them to confirm they map to the intended JSON before relying on CI:
  ```bash
  python3 - <<'PY'
  import base64, json
  def b64url_dec(seg):
      return json.loads(base64.urlsafe_b64decode(seg + '=' * (-len(seg) % 4)))
  # <paste the base64url payload segments from your new test here>
  print(b64url_dec("eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC90ZW5hbnQvIn0"))
  PY
  ```

### The quality bar is unchanged
A native macOS build is **not** a substitute for the Linux gates. A task is only complete when
`make lint`, the gcc+clang build/test matrix, `make test-sanitize CC=clang`, and the EL8/EL9/EL10
`make rpm` job — i.e. the full CI pipeline — pass in a **Linux** environment.

---

## 4. Strict Code & Security Guardrails

### Memory Scrubbing
- **NEVER** scrub sensitive buffers (`client_secret`, `device_code`, `access_token`, and the
  app-owned `Authorization` header buffer) with standard `memset()`.
- **ALWAYS** use `secure_memzero()` or `explicit_bzero()` to prevent optimizing-compiler dead-code
  elimination of the zero-fill loop.
- Scrub json-c-parsed credential/PII strings by zeroing every string leaf before
  `json_object_put()` (`secure_zero_json_tree`); libcurl's internal `Authorization` header copy
  cannot be securely zero-filled via the public cURL API (it is reclaimed by the allocator on
  `curl_slist_free_all()`).

### Filesystem & I/O Hardening
- Configuration loading logic must use `O_NOFOLLOW | O_CLOEXEC` flags on `open()` calls (the config
  path must also be a regular file, `S_ISREG`, owned by root `st_uid == 0`).
- Permissions must be restricted to `0600` or `0640` owned by `root:root` (`st_gid == 0`).
- Dynamic terminal inputs must be validated to reject ANSI escape sequences and C0/C1 control
  characters: provider URLs via `is_valid_https_url` and user codes via `is_safe_user_code`; the
  prompt template is confined to the root-owned, permission-restricted config file, and the fully
  rendered prompt is validated line-by-line by `is_safe_terminal_string` inside
  `render_prompt_message()` (newlines permitted; all other bytes must be printable ASCII).

### Terminal & Transport Protection
- Enforce strict HTTPS URL schemes for all OIDC endpoints (`is_valid_https_url`).
- Ensure cURL global state is initialized thread-safely via `pthread_once`.

### Timing & Timeouts
- Use `CLOCK_MONOTONIC` and `clock_nanosleep` for all polling intervals and deadlines. Do not use
  wall-clock `time()` for relative timeouts.

---

## 5. Protocol & External Specifications

- **OAuth 2.0 Device Authorization Grant** — [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628):
  - **Grant type:** Must strictly use `urn:ietf:params:oauth:grant-type:device_code` when querying
    the token endpoint.
  - **Polling & backoff:** Standard polling interval defaults to 5s (`MIN_POLL_INTERVAL`); treat
    that as a floor. If the provider returns `error: "slow_down"`, increase the interval by +5s per
    RFC 8628 §3.5.
  - **Non-retryable errors:** Only `authorization_pending` and `slow_down` allow loop
    continuation; all other well-formed `4xx` OAuth `error` payloads must break polling
    immediately. Treat `429`/`5xx` (including empty, `{}`, or HTML proxy bodies) as transient and
    retry with backoff *within* the device-authorization deadline.
- **OAuth 2.0 Token Introspection** — [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)
  (`introspection_endpoint` is accepted-but-unused; a load-time notice is emitted).
- **Base64URL Encoding** — [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648)
- **Project Guidelines:** Consult `CONTRIBUTING.md` and `README.md`.

---

## 6. Terminal Execution & Safety Rules

- **Prohibited System Commands:** Do NOT install system-wide PAM modules (`make install`), modify
  `/etc/pam.d/`, or touch system `/etc/` configurations directly without explicit user
  authorization.
- **Isolated Testing:** Perform all test execution strictly within the repository workspace using
  `make test` and the `tests/runner` binaries.
- **Destructive Commands:** Do NOT run `rm -rf` on paths outside `build/` or `rpmbuild/`.

---

## 7. LLM Memory Log (`.agents/memory.md`)

[`.agents/memory.md`](.agents/memory.md) is an accumulating, *machine-oriented* memory of
AI-assisted work on this repo — **not** a user-facing changelog (that is `CHANGELOG.md`).
- **Read it first:** before starting a significant task, read `.agents/memory.md` (and this file)
  to recover prior context, decisions, and gotchas.
- **Update it strategically:** after completing a *significant* AI-assisted change (a feature, a
  refactor, a non-trivial bug fix, or a notable environment/CI decision), append a new entry to
  its **Interaction Log** (newest first) using the entry format defined at the top of that file,
  and promote any durable, reusable takeaway into its **Standing Invariants** section.
- **Do NOT:** log trivial / format-only edits, or duplicate what `CHANGELOG.md` already records for
  end users.
- Every entry must state **verification status** explicitly — what was verified locally vs. what
  still requires the Linux gates / CI.

---

## 8. Contributor Guidelines & Pull-Request Quality Bar

- Ensure the GitHub Actions build and static-analysis pipelines pass completely.
- Commit messages should clearly describe the rationale behind the change.
- Code **must** compile cleanly under
  `-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Wformat-security -O2 -g` with zero
  warnings.
- `clang-tidy` must run clean across `src/*.c` using `-- -Iinclude -D_GNU_SOURCE` (exactly
  matching the CI `clang-tidy` job in `.github/workflows/lint.yml`), honoring the `.clang-tidy`
  config where `WarningsAsErrors: '*'` turns any user-code diagnostic into a hard error.
- All existing and new tests in `tests/test_suite.c` must pass.
- Wiping of sensitive memory buffers must use `secure_memzero()` or `explicit_bzero()`.
- Always run build/test commands in quiet mode (e.g., `make -s`, `pytest --tb=short`).
- Do not run commands that emit over 50 lines of output unless requested.


---

## 9. Core Security & Hardening Best Practices

* **Extend Device Flow with PKCE (RFC 7636):** Although RFC 8628 originally treated device codes as sufficient proof, modern identity providers (IdPs) recommend or support pairing the Device Grant with Proof Key for Code Exchange (PKCE). Generate a high-entropy `code_verifier` on the C side, send `code_challenge` in the initial `/device/authorization` request, and pass `code_verifier` during token polling to prevent device code replay or interception attacks.
* **Strict Local-to-Remote User Identity Binding:** Do not grant authorization solely because the token exchange succeeded. Validate the returned identity (e.g., verifying the `sub`, `preferred_username`, or custom claim from an OIDC `/userinfo` endpoint or decoded JWT) against the local Linux system user returned by `pam_get_user()`. Explicitly disable or restrict `root` authentication unless mapped through a strict local alias file.
* **Mitigate Out-of-Band Device Code Phishing:** RFC 8628 flows are vulnerable to phishing, where an attacker triggers a flow and sends the `user_code` to a victim. Ensure the PAM module outputs clear context via `PAM_TEXT_INFO` (e.g., specifying host IP, system identifier, and requested scope) so the user verifies what they are authorizing on their secondary device.
* **Enforce TLS 1.2+ & Strict Certificate Validation:** When using libraries like `libcurl` for HTTP polling in C, explicitly set `CURLOPT_SSL_VERIFYPEER = 1L`, `CURLOPT_SSL_VERIFYHOST = 2L`, and enforce minimum TLS 1.2/1.3 versions. Never allow disabling certificate validation via module options.
* **Token Lifetime & In-Memory Cleanup:** Treat access and refresh tokens as ephemeral in-memory secrets. Use `explicit_bzero()` or `memset_s()` to zero out memory buffers holding client secrets, device codes, or tokens immediately after use or before `pam_sm_authenticate()` exits.

---

## 10. Key C & PAM Implementation "Gotchas"

1. **Process Boundary & Memory Leak Accumulation:** PAM modules execute in the address space of the caller (`sshd`, `sudo`, `login`). Any leaked memory or open file descriptors persist for the lifetime of the host process. Ensure all HTTP client handles (e.g., `curl_easy_cleanup`), JSON parsers (e.g., `json_object_put`), and dynamic strings are freed on all execution paths.
2. **Signal Handling & Interruptible Polling:** If a user cancels an SSH session (or sends `SIGINT`/`SIGTERM`), standard network calls can hang. Make sure your HTTP polling loop respects signal interruptions, breaks gracefully, cleans up resources, and returns `PAM_AUTH_ERR` or `PAM_AUTHINFO_UNAVAIL`.
3. **Polling Interval & Backoff Enforcement:** Implement strict compliance with the authorization server's `interval` response. If the server responds with an error payload containing `slow_down`, RFC 8628 requires increasing the polling interval by at least 5 seconds. Failing to do so can trigger rate-limiting or DDoS defenses on the server side.
4. **Session Timeouts vs. PAM Timeouts:** PAM authentication blocks execution. Long polling timeouts (e.g., waiting 15 minutes for `expires_in`) can trigger SSH `LoginGraceTime` or `systemd-pam` module timeouts. Configure a conservative maximum timeout on the PAM module side (e.g., 60–120 seconds) independent of the server's maximum code expiration.
5. **Reentrancy and Thread Safety:** If building with `libcurl`, call `curl_global_init()` properly or rely on static module initialization. Ensure thread-safe calls when parsing JSON responses or evaluating crypto primitives.

---

## 11. Key Documentation & Implementation References

* **[RFC 8628 Official Specification](https://datatracker.ietf.org/doc/html/rfc8628):** The foundational IETF standard for the OAuth 2.0 Device Authorization Grant.
* **[IETF OAuth 2.0 Security Best Current Practice (BCP)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics):** The latest guidance on threat models, client isolation, token handling, and transport security.
* **[Authlete Device Flow Technical Deep-Dive](https://developers.authlete.com/protocols-and-flows/advanced-flows/oauth-2-0-device-authorization-grant-device-flow):** Detailed protocol mechanics, parameter breakdown, and implementation state diagrams.
* **[Okta Threat Research: Device Code Phishing](https://www.okta.com/blog/threat-intelligence/device-code-phishing--it-s-phishing-with-dynamite/):** Analysis of real-world exploitation vectors against RFC 8628 flows and mitigation strategies.
* **[Ping Identity: Device Authorization Grant with PKCE](https://docs.pingidentity.com/pingoneaic/am-oauth2/oauth2-device-flow-pkce.html):** Guide on extending RFC 8628 with PKCE parameters (`code_challenge` / `code_verifier`) for strengthened device flow security.
* **[Nithe14/pam_oauth2_device (GitHub)](https://github.com/Nithe14/pam_oauth2_device):** An example implementation of a Linux PAM module utilizing the OAuth 2.0 Device Authorization Grant.