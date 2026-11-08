# Project LLM Memory Log

> **Purpose.** This file is an accumulating, *machine-oriented* memory of AI-assisted work on
> `pam_oidc_device`. It lets LLM / GenAI tools (Copilot, Cline, Cursor, …) recover prior context,
> decisions, and gotchas without re-deriving them. It is **not** a user-facing release log — that
> is `CHANGELOG.md`.
>
> **How to use it.**
> 1. **Read it first.** Before starting any significant task, read this file (and
>    `AGENTS.md` / `.agents/context.md`) to recover prior context, decisions, and known gotchas.
> 2. **Update it strategically.** After completing a *significant* piece of AI-assisted work — a
>    feature, a refactor, a non-trivial bug fix, or a notable environment/CI decision — append a new
>    entry to the **Interaction Log** (newest first) and fold any durable, reusable takeaway into
>    **Standing Invariants**.
> 3. **Do NOT** log trivial / format-only edits, and do NOT duplicate what `CHANGELOG.md` already
>    records for end users. This log is for *machine memory*: decisions, rationale, gotchas,
>    verification status, and follow-ups.
>
> **Entry format.** One `###` entry per significant session: `### YYYY-MM-DD — <short title>`,
> followed by bullets: **Task**, **Decisions & Rationale**, **Gotchas & Lessons**, **Verification**
> (state explicitly what was verified locally vs. what still requires the Linux gates/CI), and
> **Follow-ups / Open Items**. Keep entries dense and factual.

---

## Standing Invariants (curated, always-true)

- **Linux PAM only.** This is a Linux PAM module; `libpam` has no Homebrew/MacPorts/Windows package
  and `include/pam_oidc_device.h` pulls in `<security/pam_*.h>`. A failing *native* macOS build is an
  **environment limitation, not a code defect** — do NOT change code to make the macOS build pass.
  Authoritative gates run on Linux (CI or a `ubuntu:24.04` container mirroring CI; see
  `AGENTS.md` §3 — Non-Linux Hosts).
- **CI-enforced gate set, in order (see `AGENTS.md` §3, aligned with `lint.yml` + `build.yml`):**
  `make lint` (clang-format → clang-tidy `src/*.c` → cppcheck → flawfinder, all CI-mirrored) →
  build + CMocka suite under **both** compilers (`make CC=gcc && make test CC=gcc`,
  `make CC=clang && make test CC=clang` — the `compile-matrix` job) →
  `make test-sanitize CC=clang` (the `sanitize-test` job). `make sanitize` (compile-only) is
  **NOT** a CI gate — no CI job runs it; never report it as a passed gate. CI additionally
  enforces `make rpm` on EL8/EL9/EL10 (`rpm-build` job) on every push/PR to `main`.
  `.clang-tidy` has `WarningsAsErrors: '*'` and `HeaderFilterRegex: 'include/.*'`; `tests/*.c` is
  not clang-tidy-gated in CI. Do not mark a task complete until these pass **on Linux**.
- **Never suppress clang-tidy checks** to make a gate pass — fix the underlying code. The single
  justified `misc-no-recursion` NOLINT is on the intentionally-recursive `secure_zero_json_tree()`.
- **Memory scrubbing:** never `memset()` sensitive buffers (`client_secret`, `device_code`,
  `access_token`, app-owned `Authorization` header). Use `secure_memzero()` / `explicit_bzero()`.
  Zero json-c string leaves via `secure_zero_json_tree()` before `json_object_put()`. libcurl's
  internal `Authorization` header copy cannot be securely zero-filled through the public cURL API.
- **`pam_user` buffer ownership:** the string returned by `pam_get_user()` is owned and freed by
  PAM — the module must NOT free it. (History had a leak↔double-free back-and-forth; the invariant
  is that PAM owns these buffers.)
- **RFC 8628 polling invariants:** only `authorization_pending` and `slow_down` keep the loop alive;
  any other well-formed `4xx` OAuth `error` aborts immediately. Treat `429`/`5xx` (including empty,
  `{}`, or HTML proxy bodies) as transient and retry with backoff *within* the device-authorization
  deadline. Use `CLOCK_MONOTONIC` + `clock_nanosleep`; never wall-clock `time()` for deadlines.
- **Test-binary curl shadowing:** `tests/test_suite.c` defines weak overrides of
  `curl_easy_setopt`/`curl_easy_perform` (TLS-options test) — the test binary therefore never
  performs real HTTP transfers; no test may rely on real curl transport. (`url_encode_param`
  uses `curl_easy_escape`, which is NOT overridden.) Because naming the `curl_easy_setopt`
  override would collide with libcurl's `typecheck-gcc.h` argument-checking macro under real
  GCC, the test TU starts with `#define CURL_DISABLE_TYPECHECK` — keep that define *before*
  the project-header include, and keep the test TU free of direct `curl_easy_setopt` calls.
- **Documentation honesty:** local JWT inspection is **claims-only** (`exp`, `nbf`, `iss`, `aud`) —
  no signature verification, no replay protection; enforce token authenticity via the provider's
  UserInfo endpoint. `jwks_url` and `introspection_endpoint` are accepted-but-unused (load-time
  notice). Do not overclaim "zero-trust" / "replay protection."
- **Config schema:** `[access]` is now the *single* section for all access control (`allow_users`,
  `deny_users`, `allow_groups`, `deny_groups`, `enforce_groups`, `group_claim_field`). Deny lists
  take precedence; local user lists are enforced before any provider contact. Legacy
  `[group]`/`[groups]`/`[roles]` sections and the `verify_group`/`group_field`/`required_group`/
  `verify_jwt` keys are removed.
- **EL8 pthread linking:** the Makefile links `-lpthread` explicitly (in `LIBS`). On EL8
  (glibc < 2.34) libpthread is a separate library and `src/http.c`'s `pthread_once` makes it
  required for the `tests/runner` link; on EL9+/Debian/macOS `-lpthread` is a harmless no-op.
  Do not remove it when the only CI matrix entries are EL9/EL10 — an EL8 `make test` (RPM
  `%check`) will fail with `undefined reference to symbol 'pthread_once@@GLIBC_2.2.5'`.
- **Config-parsing seam:** `parse_config_file(FILE*, config_t*, pam_handle_t*)` (src/config.c,
  declared in the public header) is the pure parsing counterpart of `load_config()` — line loop,
  section handling, `parse_config_kv` dispatch, `regcomp`, and mandatory-field checks. It does not
  `fclose` (caller owns the stream), does not apply defaults, and zeroes `cfg` via
  `secure_memzero` on failure. Unit tests drive it with `fmemopen` + the `init_config_defaults()`
  helper in `tests/test_suite.c`. Key ownership is section-strict: `verify_jwt_claims`,
  `clock_skew_leeway`, `require_exp_claim`, `use_pkce` are `[oauth]` keys; `case_sensitive` is a `[claim]`
  key; `[runtime]` only accepts `max_poll_seconds` and `loglevel`.
- **Terminal output defense-in-depth:** `render_prompt_message()` validates the fully rendered
  prompt line-by-line via `is_safe_terminal_string` (newlines permitted; all other bytes must be
  printable ASCII; lines longer than `MAX_INIT_MSG_LEN` fail closed) and returns -1 on
  rejection — so `init_message` templates are limited to printable ASCII + escaped `\n` (tabs no
  longer render). Raw `is_safe_terminal_string` still rejects `\n`; never apply it to a whole
  multi-line string. Client authentication is form-body only (`client_secret_post`, RFC 6749
  s2.3.1) — `client_secret_basic` (HTTP Basic) / `client_secret_jwt` / `private_key_jwt` are not
  supported; keep this documented in the `client_secret` header doc, `pam_sm_authenticate`
  comments, README, and CHANGELOG.

---

## Interaction Log (newest first)

### 2026-11-07 — Review remediation: A1–A5 + B1–B4 + C1 (discovery_probe_pkce tests)
- **Task:** Implement the follow-up fixes from the code/docs review: A1 (`http_request` left `resp` uninitialized on early-exit paths), A2 (`req_timeout_ms` could be 0/negative at the deadline boundary; cURL treats `CURLOPT_TIMEOUT_MS=0` as "no timeout"), A3 (locale-dependent `isalnum()` in `is_safe_user_code`), A4 (`user_resp` scrub omitted the terminating NUL), A5 (device/token form-field key/value arrays sized exactly at capacity; a sixth parameter would silently overflow the stack arrays), B1–B4 (README missing `openssl-devel`; CHANGELOG self-contradiction on `is_safe_terminal_string`; CONTRIBUTING gate loop drifted from `AGENTS.md` §3; README missing PKCE feature bullet), C1 (no tests for `discovery_probe_pkce`).
- **Decisions & Rationale:**
  - **A1:** moved `memset(resp, 0, sizeof(http_response_t))` to the TOP of `http_request()` (right after arg validation, before global-init/handle/setopt failure paths) and documented the zero-init contract on the `resp` `@param`; also zero-init `resp` locally in `discovery_probe_pkce` (`http_response_t resp = {0};`) as belt-and-suspenders. This closes the UB on the fail-safe path itself (probe read/freed a garbage `body`).
  - **A2:** at the poll-loop deadline math, `if (remain_ms <= 0L) break;` — the loop-top monotonic check is ns-precise but the whole-second difference can be 0 at the boundary; breaking is stricter than clamping and never fires a request past the RFC 8628 deadline.
  - **C1 fake transport:** extended the test binary's weak-override seam — new weak `curl_easy_getinfo` (returns `g_fake_curl_status_code` for `CURLINFO_RESPONSE_CODE`), `curl_easy_perform` now returns `g_fake_curl_perform_rc` and invokes the WRITEFUNCTION/WRITEDATA pair captured by the weak `curl_easy_setopt` with `g_fake_curl_body`. No real transfers ever occur; `reset_fake_curl_transport()` isolates state. 5 new tests: non-200/no-status fail-safe, cURL-error fail-safe, non-JSON/scalar-document fail-safe, three-way support matrix (S256+dev-ep → 1; S256-only → 0; no-S256 → 0), NULL-arg rejection.
  - **A3:** byte-wise ASCII ranges replace `isalnum()` in `is_safe_user_code()` (matches the other terminal-safety helpers; locale can no longer widen the accepted set).
  - **A5:** added `DEVICE_FORM_MAX_FIELDS`/`TOKEN_FORM_MAX_FIELDS` (both 5, with a comment documenting exactly which params fill each table) and a `static int form_field_append(keys, vals, *count, capacity, key, val)` helper in `pam_module.c` that returns -1 when the table is full. All `d_keys/d_vals` and `t_keys/t_vals` appends in `pam_sm_authenticate()` now go through it; a non-zero accumulated append rc logs an error and returns `PAM_BUF_ERR` at `goto cleanup` instead of silently overflowing. The `static` helper is unreachable from `tests/test_suite.c` (linked against module objects), so it was verified with an isolated strict-flag harness rather than a CMocka test.
- **Gotchas & Lessons:**
  - `tests/test_suite.c` previously had only two curl overrides (setopt/perform); `resp.status_code` in tests came from the REAL `curl_easy_getinfo` on a no-transfer handle (i.e. 0). Any test asserting 200 behavior now needs the new `g_fake_curl_status_code` seam. `CURL_DISABLE_TYPECHECK` at the top of that TU must stay (typecheck-gcc.h macro collision under real GCC) and the TU must still never *call* `curl_easy_setopt`/`curl_easy_getinfo` directly.
  - Context summaries from prior sessions can carry stale/hallucinated code quotes (this session's summary quoted a `pkce_code_verifier[5]` array that does not exist; current code already uses `PKCE_VERIFIER_LEN + 1`). Always re-verify against the tree before editing.
- **Verification:**
  - LOCAL (macOS): `make lint` green (clang-format `--dry-run --Werror` at exact CI scope; clang-tidy/cppcheck/flawfinder skipped with notices — no PAM headers/tools); isolated strict-flag harnesses (gcc + clang, `-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Wformat-security -O2 -g`, zero warnings) compiled the verbatim new fake-transport section, the new `is_safe_user_code`, and the new `form_field_append()` (fill-to-capacity, overflow rejection, repeat-overflow, and empty-table cases — all passing). No base64url fixtures were added (plain JSON strings only).
  - NOT RUN: `make CC=gcc/clang` + `make test`, `make test-sanitize CC=clang`, `make rpm` (no libpam/cmocka or container runtime on this host). STILL REQUIRED: full Linux/CI gate loop before merge.
- **Follow-ups / Open Items:**
  - Push `wglick/review` (or open a PR) to run `lint.yml` + `build.yml` (compile-matrix, sanitize-test, rpm-build) in CI.

### 2026-11-07 — PKCE auto-detection via provider discovery metadata + provider-support docs
- **Task:** Document how to determine device-flow PKCE support per provider; set `use_pkce` in the example configs; add a live discovery check that gates/enables PKCE and logs a suggestion.
- **Decisions & Rationale:**
  - **Research (verified live 2026-11):** No standard OIDC/OAuth discovery parameter advertises
    device-flow PKCE. `code_challenge_methods_supported` (present on CILogon, ABSENT from
    Microsoft's v2.0 `/.well-known/openid-configuration`) describes the auth-code flow only →
    treated as a heuristic hint, documented as such. Keycloak's device flow supports PKCE
    (issue keycloak/keycloak#13244, mid-2022). Entra ID's device-code reference does not
    document `code_challenge`. Unregistered-client probes against MS/CILogon are inconclusive
    (client validated before parameters) — the definitive test needs a *registered* test
    client; documented that gotcha in examples/README.md.
  - **`use_pkce` is now tri-state:** 0 off (default), 1 on, 2 "auto" (parsed by new
    `parse_pkce_mode()` in `src/config.c` next to `parse_bool`). New optional `[oauth]` key
    `discovery_endpoint[512]` (HTTPS-validated like the other endpoints; `seen`-flag
    duplicate detection). Load-time validation: `use_pkce = auto` without
    `discovery_endpoint` → config load fails (fail fast). Load-time advisories: explicit
    `true` logs a one-time "confirm provider support" INFO; `discovery_endpoint` set with
    non-auto `use_pkce` logs "has no effect" INFO.
  - **Probe:** `discovery_probe_pkce()` in `src/http.c` (kept the Makefile `OBJS` untouched
    by reusing http.c rather than a new TU): GET, 5000 ms cap, via the existing
    `http_request()` (TLS-verified, HTTPS-only); decision = enable PKCE iff
    `discovery_json_advertises_s256()` (pure helper, exported for tests; exact case-sensitive
    "S256" string match inside a string array) AND a `device_authorization_endpoint` string
    exists. Any transport/HTTP/JSON failure → -1, fail-safe off; discovery outage can never
    block logins. Every decision logged with rationale (failures at LOGLEVEL_ERROR threshold /
    LOG_WARNING; decisions at LOGLEVEL_INFO).
  - **Flow wiring (`src/pam_module.c`):** `int pkce_active = cfg.use_pkce;` resolved after
    `verify_user_access()` (denied accounts never trigger a probe) and before PKCE material
    generation; the three former `if (cfg.use_pkce)` sites now use `pkce_active`. Also fixed
    the macOS-flagged sign-conversion at the token-length read:
    `(size_t)json_object_get_string_len(j_acc)`.
  - **Examples/docs:** `keycloak.conf` sets `use_pkce = true`; `entra_id.conf` and
    `cilogon.conf` keep `#use_pkce = false` with verify-first comments; `examples/README.md`
    gained "Does Your Provider Support PKCE with the Device Flow?" (why discovery can't
    answer it, vendor-docs + live test-client curl probe procedure, `auto` semantics,
    per-archetype recommendation table) plus a new metadata-mapping table row. Threat-model
    §7 and the shipped `config/pam_oidc_device.conf` comments updated; CHANGELOG [Unreleased]
    gained a Features entry.
- **Gotchas & Lessons:** `json_object_get_string_len()` returns `int` — cast explicitly when
  assigning to `size_t` under `-Wconversion`. Discovery probes must be fail-safe-off: an
  IdP metadata outage mid-login must degrade to plain device flow, never `PAM_AUTH_ERR`.
  Web research here: duckduckgo/bing scrape endpoints are bot-gated; direct vendor doc URLs +
  live `curl` of real discovery documents + GitHub API searches are the reliable path.
- **Verification:** clang-format clean locally; all 6 modules compile warning-free under the
  strict flag set + `-fsanitize=undefined` via the /tmp/pam_san PAM-stub harness; full CMocka
  suite passes under UBSan, **40/40 (5 new tests: pkce_auto, auto_requires_discovery,
  invalid_discovery_endpoint, duplicate_discovery_endpoint, discovery_json_advertises_s256)**,
  zero diagnostics. NOT yet verified: Linux CI gates (make lint incl. clang-tidy/cppcheck/
  flawfinder, gcc+clang build/test matrix, `make test-sanitize CC=clang`, `make rpm` EL8/9/10)
  — macOS can't run them; push and let CI run.
- **Follow-ups / Open Items:** none for this feature; consider a discovery fetch
  timeout/latency knob if 5 s ever proves too aggressive for air-gapped-ish networks.

### 2026-11-07 — F-3: PKCE (RFC 7636) device-flow extension (config-gated)
- **Task:** Implement F-3 from the threat-model review: extend the RFC 8628 device flow with
  PKCE S256 — config-gated, CSPRNG verifier, scrub on cleanup.
- **Decisions & Rationale:**
  - **Opt-in config gate:** `use_pkce` boolean in the `[oauth]` section (default `false`,
    `parse_bool` + `seen.use_pkce` duplicate detection; `load_config` default block sets 0).
    Opt-in (not opt-out) because providers without device-flow PKCE support will reject the
    device-authorization request, so flipping the default would break existing deployments.
  - **New translation unit `src/pkce.c`:** `pkce_generate_code_verifier()` (48 bytes from
    OpenSSL `RAND_bytes()` -> 64-char unpadded Base64URL, within RFC 7636 s4.2's 43-128 bound;
    raw CSPRNG stack buffer `secure_memzero`'d before return) and
    `pkce_compute_s256_challenge()` (EVP SHA-256 -> 43-char unpadded Base64URL). Shared static
    `base64url_encode_nopad()` helper (standard 3-octet grouping, URL-safe alphabet, no `=`
    padding). Both exported via the public header so the test binary can drive them.
  - **Flow integration (`pam_module.c`):** when `cfg.use_pkce`, step 3a generates the pair
    before the device-authorization POST; `code_challenge` + `code_challenge_method=S256`
    appended to the device POST (`d_keys[5]`), `code_verifier` appended to the token POST
    (`t_keys[5]`). Verifier is never displayed, not in the verification URI, never logged.
    Failure to generate -> `PAM_SERVICE_ERR` + `goto cleanup`.
  - **Secret disposal:** `code_verifier[65]` / `code_challenge[44]` zeroed at declaration and
    `secure_memzero`'d unconditionally at `cleanup` (next to `device_code`); their encoded
    copies die with the already-scrubbed `postfields`/`token_postfields`.
  - **Makefile:** `src/pkce.o` added to `OBJS`; `src/pkce.c` added to the `sanitize` and
    `test-sanitize` source lists (three hardcoded lists — keep them in sync when adding files).
- **Gotchas & Lessons:**
  - RFC 7636 Appendix B known vector now anchors `test_pkce_s256_challenge` (verifier
    `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` ->
    challenge `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM`); cross-checked with Python
    `hashlib`/`base64.urlsafe_b64encode` before trusting it.
  - `tests/test_suite.c` `init_config_defaults()` mirrors `load_config()`'s default block —
    add new int defaults to *both* when they are non-zero.
- **Verification:** clang-format gate clean (exact CI scope). PAM-independent PKCE logic
  compile-checked + executed in an isolated harness under the project's strict warning flags
  (verifier length/alphabet/uniqueness, RFC vector, fail-closed paths all pass). NOT yet run:
  full Linux gates (lint, gcc+clang build/test matrix, `make test-sanitize CC=clang`, rpm)
  — no Docker/PAM headers locally; CI is required.
- **Follow-ups / Open Items:** push the branch and monitor `compile-matrix` +
  `sanitize-test`; on CI green, mark F-3 closed in `docs/threat-model.md` if the review
  process tracks per-finding status there.

### 2026-11-07 — Fix gcc CI parse error in test_suite.c weak curl override
- **Task:** `make test CC=gcc` failed on ubuntu-latest with `error: expected identifier or '('
  before '__extension__'` at `tests/test_suite.c:45` (the weak `curl_easy_setopt` override).
- **Root cause:** libcurl's `<curl/curl.h>` (8.x) includes `typecheck-gcc.h` when compiled
  with a *real* GCC >= 4.3, which `#define`s `curl_easy_setopt`/`curl_easy_getinfo`/
  `curl_multi_setopt`/`curl_share_setopt` as variadic argument type-checking macros built
  from `__extension__` statement-expressions. Naming our weak override therefore expands
  the macro → parse error. Clang masquerades as GCC 4.2 (`__GNUC_MINOR__ < 3`), so the guard
  is false and only the gcc CI job hit it. The stubs predate F-2 (added in `38dcb2f`), so the
  gcc compile-matrix job had been failing since that commit.
- **Fix:** `#define CURL_DISABLE_TYPECHECK` at the top of `tests/test_suite.c` (before the
  project header that pulls in `curl.h`) — the explicit opt-out in curl.h's own guard.
  Safe: the macros are a compile-time argument check only, and the test TU never calls
  `curl_easy_setopt()` directly (only *names* the weak stubs). No `#undef` juggling needed;
  the real function declarations from `<curl/easy.h>` are untouched.
- **Verification:** (local, macOS — no PAM headers, no Docker): clang-format gate clean on the
  CI scope; isolated harness compiled against the *real* curl 8.5.0 headers (Ubuntu 24.04's
  libcurl) under the project's strict warning flags — with and without the define — and
  executed: weak interposition still captures the TLS setopt values, exit 0. Negative control
  reproduced the exact `expected identifier or '('` parse error when the typecheck-style macro
  is active. Still requires: full Linux gates in CI (`make lint`, gcc+clang build/test matrix,
  `make test-sanitize CC=clang`, `make rpm` EL8/9/10).
- **Follow-ups:** push the branch and watch the `compile-matrix` gcc job.

### 2026-11-07 — Security remediations F-2, F-6, F-7, F-8
- **Task:** Implement four security remediations from the threat-model review: F-2 (root
  default-deny), F-6 (EINTR during poll no longer silently resumes), F-7 (documented no-op
  `pam_sm_setcred` rationale), F-8 (full `timeval` deadline comparison).
- **Decisions & Rationale:**
  - F-2: `int allow_root` (0 default) added to `oauth_config_t` next to `enforce_groups`;
    parsed in the `[access]` section of `config.c` via `parse_bool` (accepts true/false,
    yes/no, on/off, 1/0, case-insensitive) with duplicate-key detection (`seen.allow_root`).
    The root gate in `verify_user_access()` runs after the `deny_users` check and *before*
    the `allow_users` check, so listing "root" in `allow_users` alone never grants access —
    root requires explicit `allow_root = true`. Uses `strcmp(pam_user, "root") == 0` rather
    than uid lookup because PAM passes the account name string. `load_config` zeroes the
    struct with `memset`, so the default-deny needs no extra initialization.
  - F-8: `timespec_before()` helper (sec-then-nsec lexicographic compare) replaced both
    `now.tv_sec >= deadline.tv_sec` comparisons in the poll loop.
  - F-6: `clock_nanosleep` `EINTR` now logs at ERROR, cleans up, and returns `PAM_ABORT`
    (`goto cleanup`) — a signal during auth means the caller was interrupted; silently
    resuming could keep blocking longer than the PAM/SSH grace window.
- **Gotchas & Lessons:**
  - `docs/threat-model.md` lists the same four findings (F-2/F-6/F-7/F-8) — keep
    `CHANGELOG.md`/docs in sync when closing them.
  - In `test_verify_user_access`, each block mutates a shared `cfg`; always `memset` a block
    to a clean state before asserting — the new root-allowed block left `allow_root=1` set
    for the subsequent deny_users block and had to be fixed.
- **Verification:** `clang-format -i` + `clang-format --dry-run --Werror src/*.c include/*.h
  tests/*.c` pass locally on macOS (clean, exit 0). Full C gates (lint, gcc+clang build/test
  matrix, `make test-sanitize CC=clang`, rpm) still required on a Linux host/CI.
- **Follow-ups / Open Items:** Run the Linux container gate (AGENTS.md §3) or push for CI
  before merge; confirm no existing deployments relied on root via `allow_users`
  (behavior change, documented under `[Unreleased]` in `CHANGELOG.md`).

### 2026-11-07 — Security-review remediations F-1/F-4/F-5 (TLS enforcement, strict Base64URL, PII log redaction)
- **Task:** Implement three security-review remediations: F-1 add explicit TLS options to
  `http_request()`; F-4 strictly validate the Base64URL alphabet in `base64url_decode()`;
  F-5 redact PII from the DEBUG-level UserInfo log in `pam_sm_authenticate()`.
- **Decisions & Rationale:**
  - **F-1:** `CHECK_SETOPT(CURLOPT_SSL_VERIFYPEER, 1L)`, `CHECK_SETOPT(CURLOPT_SSL_VERIFYHOST, 2L)`,
    and `CHECK_SETOPT(CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2)` (guarded by
    `LIBCURL_VERSION_NUM >= 0x072000`) — defense in depth on top of the HTTPS-only
    `CURLOPT_PROTOCOLS(_STR)` restriction.
  - **F-4:** `base64url_decode()` now rejects any byte outside `[A-Za-z0-9_-]` and any `'='`
    that is not part of a contiguous 1–2 char trailing pad (trailing-pad start is scanned
    first, then a single pass validates the rest). Fail-closed before OpenSSL BIO, which
    historically tolerated such input.
  - **F-5:** DEBUG now logs only the payload byte size and the configured claim-field name;
    the raw UserInfo body is emitted only at `LOGLEVEL_VERBOSE` (troubleshooting level).
  - **F-1 test without a real transfer:** weak definitions of `curl_easy_setopt` /
    `curl_easy_perform` in `tests/test_suite.c` — the executable's own symbols shadow
    libcurl's at dynamic-link time. All setopt calls no-op with `CURLE_OK`; the mock
    captures only the three TLS options, which the new
    `test_http_request_enforces_tls_options` asserts.
- **Gotchas & Lessons:** base64 *of* '+' or '/' is not a literal '+'/'/' in the encoded
  output (`"b/c"` encodes to `Yi9j`); negative test fixtures must use synthetic segments
  containing the literal chars (e.g. `"AAA+AAA"`). cmocka `mock_function` was avoided for
  external-library symbols (uncertain mechanism); a plain `__attribute__((weak))` override
  is deterministic and works on Mach-O (verified locally) — expected to hold on ELF/CI,
  unverified.
- **Verification:** clang-format clean (exact CI scope); `make lint` passed on macOS
  (clang-tidy/cppcheck/flawfinder skipped — headers/tools unavailable on this host);
  isolated strict-flags compile-check + functional run of the new `jwt.c` validation loop
  (all accept/reject cases OK); weak-override shadowing demonstrated against a fake
  dylib. **NOT yet run: full Linux gates (gcc+clang build+test matrix,
  `make test-sanitize CC=clang`, rpm) — no Docker/PAM headers locally; CI is required.**
- **Follow-ups / Open Items:** resolved since — F-2 and F-6/F-8 landed in
  "Security remediations F-2, F-6, F-7, F-8" (same day), F-3 (PKCE, opt-in `use_pkce`)
  landed in "F-3: PKCE (RFC 7636) device-flow extension (config-gated)". No F-items open.

### 2026-11-05 — D2: align AGENTS.md §3 "required gates" with what CI actually runs
- **Task:** AGENTS.md §3 listed gates CI does not run (`make sanitize` presented as a mandatory
  "complementary gate") and under-stated enforced ones (gcc+clang build/test matrix,
  `make test-sanitize CC=clang` specifically, `make rpm` on EL8/9/10 on *every* push/PR). Rewrote
  §3 steps 6–9, both quality-bar paragraphs, and the "mirror CI" container block to name the
  CI-enforced set verbatim; `make sanitize` is now explicitly documented as optional/not-a-CI-gate.
  Also fixed the stale `build.yml` comment claiming "the compile-only `make sanitize` used in the
  matrix" (no such matrix usage exists).
- **Decisions & Rationale:** §3 must list only gates CI enforces, so agents never report a
  non-gate as passed (or a real gate as skipped). The container block now mirrors
  `compile-matrix` (gcc+clang build+test), the `clang-tidy` gate from `lint.yml`, and
  `sanitize-test` (`make test-sanitize CC=clang`); a note states `rpm-build` needs an EL image.
- **Gotchas & Lessons:** `.agents/context.md` is a byte-identical mirror of `AGENTS.md` — after any
  AGENTS.md edit, re-sync it with `cp AGENTS.md .agents/context.md`.
- **Verification:** docs-only change; no C sources touched, so no Linux build/test gates required.
  Verified §3 line-by-line against `.github/workflows/lint.yml`, `.github/workflows/build.yml`, and
  the `Makefile` targets (`CC ?= gcc`, `test`/`test-sanitize` honor `$(CC)`), and confirmed
  `.agents/context.md` was re-synced byte-identical to `AGENTS.md`.
- **Follow-ups / Open Items:** none.

### 2026-11-05 — S2: wire `is_safe_terminal_string` into rendered-prompt check; S3: document `client_secret_basic` limitation
- **Task:** Close the documented gap that `is_safe_terminal_string` was not applied to the rendered prompt (S2, chosen over "mark reserved"); document the supported OAuth client-authentication method and the `client_secret_basic` limitation (S3).
- **Decisions & Rationale:** A naive whole-string `is_safe_terminal_string` check would fail legitimate prompts: rendered prompts contain real `'\n'` bytes, and that function rejects anything `< 32`. So a static `is_safe_rendered_prompt()` (src/pam_module.c) splits on newlines and requires every NUL-terminated line to pass `is_safe_terminal_string` (empty lines OK; lines longer than `MAX_INIT_MSG_LEN` fail closed). It is applied to the final output of BOTH `render_prompt_message()` branches (default template and custom template), failing with -1. Behavior change: C0/C1 bytes in `init_message` templates, provider URLs, or user codes now abort authentication; tabs in templates no longer render. S3: documented that `client_id`/`client_secret` are form-body only (RFC 6749 s2.3.1 `client_secret_post`) — `client_secret_basic`/`client_secret_jwt`/`private_key_jwt` unsupported — in the `client_secret` header doc, both form-field build sites in `pam_sm_authenticate`, README Security section, and CHANGELOG [Unreleased].
- **Gotchas & Lessons:** `.agents/context.md` is a mirror of root `AGENTS.md` and gets auto-synced after editing AGENTS.md (mtime changed without an explicit edit) — don't double-edit it. `read_files` intermittently returns `[outdated]` for `.agents/memory.md`; extract ranges via `sed > /tmp/file` and read that instead. Multi-line editor anchors on memory.md failed even when od-verified — prefer single-line anchors there.
- **Verification:** LOCAL (macOS) only — isolated harness: awk-extracted the REAL `is_safe_terminal_string` (config.c) + `is_safe_rendered_prompt`/`render_prompt_message` (pam_module.c) and compiled with the project's exact strict flags (`-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Wformat-security -O2 -g`), zero warnings; all 10 assertion groups PASSED (regression rendering, truncation, default template, ESC-in-template/url/code, tab, C1 byte, NULLs, `is_safe_terminal_string` semantics preserved). `clang-format -i` + `clang-format --dry-run --Werror` clean at the exact CI scope. NOT RUN: `make`, `clang-tidy`, `cppcheck`, `flawfinder`, `make test`, `make test-sanitize` (no libpam/cmocka on this host). STILL REQUIRED: Linux gates / CI.
- **Follow-ups / Open Items:** none.

### 2026-11-05 — Extract `parse_config_file()` from `load_config()` + 15 CMocka config-parsing tests
- **Task:** Make config-file parsing unit-testable without a root-owned on-disk file: extract the stream-parsing logic out of `load_config()` into a new public `parse_config_file(FILE *fp, config_t *cfg, pam_handle_t *pamh)` (declared in `include/pam_oidc_device.h`), and add 15 CMocka tests in `tests/test_suite.c` that drive it via `fmemopen`.
- **Decisions & Rationale:** `parse_config_file` owns everything from `fdopen` onward: the `fgets` loop (overlong-line rejection + drain, `trim_whitespace`, blank/`#` skip, `[section]` header handling, key-before-section and malformed-entry rejection), `parse_config_kv` dispatch, the `regcomp` check on `claim_regex`, and the mandatory-field check (`client_id` + 3 endpoints). `load_config` keeps steps 1–5 (defaults, `O_NOFOLLOW|O_CLOEXEC` open, `S_ISREG`, root uid, 0600/0640 + root gid) plus `fdopen`/`fclose` and the path-inclusive success log. The parse function does NOT `fclose` (caller owns the stream) and still securely zeroes `cfg` on failure, matching prior behavior. A `FILE*` seam (not a string) lets tests use `fmemopen` (available on Linux under the Makefile's `-D_GNU_SOURCE`). Defaults are NOT applied inside `parse_config_file` — tests seed them via the `init_config_defaults()` helper, mirroring `load_config`'s step 1.
- **Gotchas & Lessons:** config keys are section-strict: `verify_jwt_claims`/`clock_skew_leeway`/`require_exp_claim` live in `[oauth]` (NOT `[runtime]`), and `case_sensitive` lives in `[claim]` (NOT `[access]`) — both misplacements were caught by the running harness, not the compiler. `is_valid_https_url` rejects `#` and whitespace, so a URL value with a fragment is invalid, while non-URL values (e.g. `client_id`) keep `#` as data. All `pam_oauth_log` calls are `if (pamh)`-guarded, so a NULL handle produces zero output; to debug parse failures locally, pass a non-NULL fake handle plus a printing `pam_oauth_log` stub.
- **Verification:** LOCAL (macOS) only — `src/config.c` compiles with ZERO warnings under the full strict flags against stub PAM/json-c headers; all 15 new tests compiled against the real `config.c` in an isolated harness and PASSED (rc=0); `clang-format --dry-run --Werror` clean at the exact CI scope. NOT RUN: `make`, `clang-tidy`, `cppcheck`, `flawfinder`, `make test`, `make test-sanitize` (no libpam/cmocka on this host, no docker). STILL REQUIRED: Linux gates / CI for the full CMocka suite and lint pipeline.
- **Follow-ups / Open Items:** none; the `FILE*` seam is reusable for future tests (e.g. the `ferror` path, which `fmemopen` cannot easily trigger).

### 2026-11-05 — L1: poll token endpoint immediately on first iteration (remove leading interval latency)
- **Task:** Remove the one-interval of latency before the first token poll. Previously the `while (1)` loop slept for `interval` seconds on the *first* iteration before issuing any token request; now the first poll is issued immediately, and only subsequent polls wait the (possibly adjusted) interval.
- **Decisions & Rationale:** RFC 8628 §3.4 `interval` bounds the spacing *between* polling requests ("MUST NOT poll more frequently than the configured interval"); it does not mandate a leading delay before the first request — so polling immediately is compliant and saves ~5s (default interval) of time-to-first-token. Implemented with a `first_poll` flag gating the leading `next_poll`/deadline/`clock_nanosleep` block; the post-sleep `now >= device_deadline` guard (every iteration) and the pre-sleep `next_poll >= device_deadline` guard (subsequent iterations only) are preserved. Side benefit: when `expires_in < interval` the old code made *zero* polls; now the first poll is always attempted. Backoff (`429`/`5xx`/transient cURL) and `slow_down` still adjust the interval, which only affects subsequent polls.
- **Gotchas & Lessons:** a dedicated timing regression test would require extracting the monolithic polling loop out of `pam_sm_authenticate` with an injectable monotonic clock + `http_request` stub; out of scope for this change, so no new CMocka test was added.
- **Verification:** LOCAL (macOS) only — `clang-format --dry-run --Werror` clean; loop logic reviewed by hand. NOT run: `make`/`clang-tidy`/`cppcheck`/`flawfinder`/`make test`/`make test-sanitize` (no `libpam` on macOS). STILL REQUIRED: Linux gates / CI (`ubuntu:24.04` container or GitHub Actions) to confirm compile-clean under the full `CFLAGS` and all static-analysis gates.
- **Follow-ups / Open Items:** optional future refactor to extract the polling loop into a testable helper (injectable monotonic clock + `http_request`) to add a regression test asserting the first poll has no leading sleep.

### 2026-11-05 — Fix EL8 RPM `%check` failure: link `-lpthread` explicitly
- **Task:** After folding EL8 into the `build.yml` RPM matrix (replacing `rpm-el8.yml`), the
  `rpm-build (Rocky 8)` job failed in `%check`: `make test` could not link `tests/runner` —
  `src/http.o: undefined reference to symbol 'pthread_once@@GLIBC_2.2.5'` (`DSO missing from
  command line`).
- **Decisions & Rationale:** Added `-lpthread` to the shared `LIBS` variable in the Makefile so
  every link target (`.so`, `test`, `test-sanitize`) records the pthread dependency. EL8 (glibc
  2.28) still ships libpthread separately; pthread merged into libc at glibc 2.34 (EL9+), which is
  why the EL9/EL10 matrix entries passed. Spec file left untouched — with the `.so` NEEDED
  entry, rpm auto-detects the `libpthread` requirement on EL8 only, which is correct.
- **Gotchas & Lessons:** cross-distro matrix entries can expose glibc-version-dependent link
  requirements that newer distros hide; prefer explicit `-lpthread` over conditional logic.
- **Verification:** local macOS only — `make -n test` shows `-lpthread` in the link line,
  `./scripts/lint.sh` OK (clang-tidy/cppcheck/flawfinder skipped on macOS, covered by CI).
  **Not yet verified on Linux**; committed `c10114f` and pushed to
  `origin/wglick/initial_working_version` — awaiting the GitHub Actions `rpm-build (Rocky 8)`
  job plus the EL9/EL10 jobs (regression check that `-lpthread` is a no-op there).
- **Follow-ups / Open Items:** monitor CI; if green, merge the branch into `main`.

### 2026-11-05 — Add `make test-sanitize` (run CMocka under ASan/UBSan/LSan) + CI `sanitize-test` job
- **Task:** Make the "no memory bugs" claim real and CI-enforced: add a `make test-sanitize` target
  that builds AND runs the CMocka suite under ASan/UBSan/LSan, a dedicated `sanitize-test` CI job,
  and a documented LSan suppression for intentional libcurl global-state retention.
- **Decisions & Rationale:** `test-sanitize` recompiles the 5 `src/*.c` + `tests/test_suite.c` fresh
  under `SAN_FLAGS` (does NOT reuse `$(OBJS)`) so the module code itself is instrumented; it uses the
  strict CFLAGS subset the plain `test` target already proves warning-clean (`-Wall -Wextra -g`) plus
  sanitizer flags to avoid `-Wconversion`/`-Wformat` noise from sanitizer intrinsics. Runtime uses
  `ASAN_OPTIONS=detect_leaks=1` + `LSAN_OPTIONS=suppressions=tests/lsan.supp` + `UBSAN_OPTIONS=halt_on_error=1`
  (default is print-and-continue, which would not fail the build). CI runs it with `clang` for
  first-class ASan/UBSan/LSan support. `tests/lsan.supp` suppresses libcurl global state: `src/http.c`
  calls `curl_global_init` once via `pthread_once` and intentionally NEVER calls
  `curl_global_cleanup` (correct for a long-lived PAM host inside sshd); the suppression is anchored
  on real symbols (`init_curl_global_impl`, `oauth_http_global_init`, `curl_global_init`, `Curl_init`).
- **Gotchas & Lessons:** the pre-existing `sanitize` target is compile-only; `test-sanitize` is the
  complementary *execution* gate — both coexist. `$(TEST_SRC)` is NOT defined in this Makefile (the
  `test` target hardcodes `tests/test_suite.c`); using `$(TEST_SRC)` expanded to empty and was caught
  via `make -n`. libcurl global state is a well-known LSan false positive in any executable that
  calls `curl_global_init` without cleanup — document + suppress, do NOT "fix" the code (adding
  `curl_global_cleanup` would break the production PAM host). **CI-confirmed gotcha:** leak
  suppressions MUST go in `LSAN_OPTIONS=suppressions=...`, NOT `ASAN_OPTIONS` — ASan's parser only
  accepts `interceptor_*` / `odr_violation` types and hard-fails with "failed to parse suppressions"
  on any `leak:` line; the first CI `sanitize-test` run failed exactly this way and was fixed by
  moving the file to `LSAN_OPTIONS`.
- **Verification:** LOCAL (macOS) only — `make test-sanitize --dry-run` confirms the target parses and
  emits the correct cc → run → cleanup sequence; `build.yml` YAML validated (jobs: compile-matrix,
  sanitize-test, rpm-build); suppression anchors confirmed against the real `src/http.c` symbols; no
  `curl_global_cleanup` exists. NOT run: no docker/podman available and no `libpam` on macOS, so the
  actual gate could not be executed locally. First CI `sanitize-test` run FAILED on the ASan/LSan
  suppressions parse error (see Gotchas) — now fixed by moving to `LSAN_OPTIONS`; the corrected
  command shape was re-confirmed locally via `make test-sanitize --dry-run`. STILL REQUIRED: re-run
  `make test-sanitize` in CI / the `ubuntu:24.04` container to confirm green and catch any residual
  OpenSSL global-state leak (see Follow-ups).
- **Follow-ups / Open Items:** run the gate in CI / Linux container; if OpenSSL reports process-lifetime
  global state on the first run, add a documented `leak:OPENSSL`/`leak:CRYPTO` line to
  `tests/lsan.supp`; confirm the CI `sanitize-test` job is green before merging.

### 2026-11-04 — Local lint gate + pre-commit hook to catch clang-format/clang-tidy before commit
- **Task:** Stop clang-format/clang-tidy (and cppcheck/flawfinder) findings reaching CI.
- **Decisions & Rationale:** The rules' local loop did not mirror CI: clang-format used
  `clang-format -i src/*.c include/*.h` (auto-fix, never fails, and omits `tests/*.c`), while CI
  runs `clang-format --dry-run --Werror src/*.c include/*.h tests/*.c`; clang-tidy ran on
  `src/*.c include/*.h tests/*.c` but CI runs only `src/*.c` (headers via `HeaderFilterRegex`, tests
  not clang-tidy-gated); cppcheck/flawfinder were absent from the rules; and no pre-commit hook
  existed. Added `scripts/lint.sh` (single source of truth: runs the 4 CI lint commands verbatim,
  each guarded so missing tools / non-compiling hosts skip with a notice), a `make lint` target, and
  `.githooks/pre-commit` (enable via `git config core.hooksPath .githooks`). Rewrote `.airules` §2 to
  mirror CI exactly; synced `system-context.md` §6 and `CONTRIBUTING.md`.
- **Gotchas & Lessons:** macOS ships a *stub* `security/pam_appl.h`, so a trivial `#include` probe
  false-positives; the clang-tidy gate must instead syntax-check a real TU (`src/config.c`), which
  fails on macOS (no `json-c`) and so correctly skips clang-tidy there instead of flooding with
  false errors and blocking every commit.
- **Verification:** `scripts/lint.sh` / `make lint` run clean on macOS (clang-format passes;
  clang-tidy/cppcheck/flawfinder skip). The real clang-tidy/cppcheck/flawfinder runs plus
  `make test` / `make sanitize` still require the Linux container / CI.
- **Follow-ups / Open Items:** Optionally point `lint.yml` at `scripts/lint.sh` so CI and local share
  one source of truth; enable the hook on any fresh clone.

### 2026-11-04 — Consolidate config schema into a single `[access]` section
- **Task:** Add user & group allow/deny access-control rules, then consolidate the whole access
  schema into one `[access]` section and delete legacy/duplicate keys & sections across source,
  headers, tests, examples, and docs.
- **Decisions & Rationale:** `[access]` now owns `allow_users`/`deny_users`/`allow_groups`/
  `deny_groups`/`enforce_groups`/`group_claim_field`. Removed `[group]`/`[groups]`/`[roles]` and
  `[accounts]`; dropped `verify_group`/`group_field`/`required_group` and the `verify_jwt` alias
  (→ `verify_jwt_claims`). Renamed `verify_group`→`enforce_groups`, `group_field`→`group_claim_field`.
  Deny-over-allow precedence; local user lists are checked before contacting the IdP (limits blast
  radius of a loose `claim_regex`); recommended OpenSSH stack adds `pam_succeed_if.so uid >= 1000`.
- **Gotchas & Lessons:** macOS native gates can't run (no `libpam`). Worked around by building PAM /
  curl / json-c / cmocka **stub headers under `/tmp/stub`** and doing isolated per-TU compile checks
  under the exact CI warning flags, plus validating base64url fixtures with Python — a *local*
  signal, **not** a CI substitute. Also fixed 2 pre-existing dead stores in `src/identity.c` that
  clang-tidy surfaced.
- **Verification:** Isolated compile of all 6 TUs (`src/*.c` + `tests/test_suite.c`), 0 warnings
  under the strict CI flags; `clang-format` + `clang-tidy` clean on the touched files. Full link +
  `make test`/`make sanitize` **still pending** on Linux.
- **Follow-ups / Open Items:** Push the branch → confirm GitHub Actions `build.yml` + `lint.yml`
  pass on `ubuntu-latest` against real `libpam`. (Status: **blocked on Linux CI**.)

### 2026-11-04 — Memory safety & device_code hardening
- **Task:** Zero sensitive json-c-parsed string trees before cleanup; require `user_code` in the
  device-authorization response (remove fallback); satisfy clang-tidy on the scrub helper.
- **Decisions & Rationale:** `secure_zero_json_tree()` recursively zeroes every string leaf that may
  hold credentials/PII before `json_object_put()`. Device-authorization responses must contain
  `user_code` — no silent fallback.
- **Gotchas & Lessons:** clang-tidy `misc-no-recursion` flags the intentionally-recursive scrubber —
  the one justified NOLINT in the codebase.
- **Verification:** clang-tidy clean; full gate loop via CI.
- **Follow-ups / Open Items:** none.

### 2026-11-04 — RFC 8628 polling compliance, JWT numeric dates, honest docs
- **Task:** Handle fractional `exp`/`nbf` NumericDates + add `require_exp_claim`; retry transient
  HTTP errors during polling; warn on unused endpoints; correct overclaimed security docs; document
  macOS/Windows dev workarounds + Docker.
- **Decisions & Rationale:** `429`/`5xx` (incl. empty / `{}` / HTML proxy bodies) are transient →
  retry with backoff within the device-authorization deadline; well-formed `4xx` OAuth `error` still
  aborts per RFC 8628 §3.5. `jwks_url`/`introspection_endpoint` are parsed/validated but unused →
  load-time notice. Documented that JWT checks are claims-only.
- **Gotchas & Lessons:** proxies / load balancers can return `5xx` with empty/HTML bodies during
  polling — do not abort the auth loop on them.
- **Verification:** CI.
- **Follow-ups / Open Items:** actual JWKS signature verification and RFC 7662 introspection remain
  unimplemented (accepted-but-unused keys).

### 2026-11-04 — AI context/rules + PAM & Makefile portability fixes
- **Task:** Add AI instructions/rules/context; fix `pam_user` lifecycle; correct access-token length
  cap; fix `verify_jwt` naming/semantics; make Makefile metadata includes portable; address a
  federated-namespace/"domain not pinned" example issue; point the Entra example `claim_field` at
  `email`.
- **Decisions & Rationale:** `pam_user` buffer is PAM-owned (module must not free it); access-token
  length cap must account for the `Bearer ` prefix; Makefile include paths made portable (early
  macOS-build workaround).
- **Gotchas & Lessons:** a leak↔double-free back-and-forth on `pam_user` settled on "PAM owns these
  buffers"; early native macOS builds were blocked by missing `libpam`.
- **Verification:** portability bits locally; rest via CI.
- **Follow-ups / Open Items:** establish a reliable local verification path on macOS (later solved
  via stub headers + CI).

### 2026-10-30 — Initial implementation of the PAM module (RFC 8628)
- **Task:** Bootstrap `pam_oidc_device` — OAuth 2.0 Device Authorization Grant via RFC 8628.
- **Decisions & Rationale:** section-based config parser (`/etc/pam_oidc_device.conf`) with
  `[oauth]`/`[claim]`/`[group]`/`[prompt]`/`[runtime]` + duplicate-key detection; POSIX ERE claim
  extraction with capture-group support; optional group/role authz; optional local claims-only JWT
  inspection; thread-safe cURL init (`pthread_once`); cmocka tests; RPM packaging (Rocky 9/10);
  GitHub Actions CI; example IdP configs (Keycloak, Microsoft Entra ID, CILogon).
- **Verification:** CI (GCC/Clang matrix; clang-tidy/cppcheck/flawfinder/clang-format; Rocky 9/10 RPM).
- **Follow-ups / Open Items:** none recorded.

---

*New entries go at the top of the Interaction Log. When an entry surfaces a durable, reusable
takeaway, promote it into **Standing Invariants** above.*

