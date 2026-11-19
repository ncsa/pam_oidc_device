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

- **Release version sources & the agent-docs layout.** The canonical module version lives in
  `include/metadata.h` (`PAM_OIDC_VERSION`, which also feeds the User-Agent string). A release bump
  must keep it consistent with `Makefile` (`VERSION ?=`), `packaging/pam_oidc_device.spec`
  (`%global mod_version`), `packaging/gen-changelog.py` (`default_ver`), and `.agents/context.md`.
  The root `AGENTS.md` is a thin *real* file (build/test commands + hard boundaries); `CLAUDE.md`,
  `.github/copilot-instructions.md`, and the `.*rules` files are all *symlinks* to it — edit only
  the root `AGENTS.md`, never a shim. Deep content lives in `.agents/context.md`.
  `CHANGELOG.md` historical entries keep their original version strings (do not
  rewrite past releases).
- **Linux PAM only.** This is a Linux PAM module; `libpam` has no Homebrew/MacPorts/Windows package
  and `include/pam_oidc_device.h` pulls in `<security/pam_*.h>`. A failing *native* macOS build is an
  **environment limitation, not a code defect** — do NOT change code to make the macOS build pass.
  Authoritative gates run on Linux (CI or a `ubuntu:24.04` container mirroring CI; see
  `AGENTS.md` §3 — Non-Linux Hosts).
- **CI-enforced gate set, in order (see `AGENTS.md` §3, aligned with `lint.yml` + `build.yml`):**
  `make lint` (clang-format → clang-tidy `src/*.c` → cppcheck → flawfinder →
  `scripts/check-memory-scrubbing.sh`, all CI-mirrored; the scrub step is the `memory-scrub`
  job) →
  build + CMocka suite under **both** compilers (`make CC=gcc && make test CC=gcc`,
  `make CC=clang && make test CC=clang` — the `compile-matrix` job) →
  `make test-sanitize CC=clang` (the `sanitize-test` job). `make sanitize` (compile-only) is
  **NOT** a CI gate — no CI job runs it; never report it as a passed gate. CI additionally
  enforces the native-distro `distro-build` jobs (`distro-build.yml`: `make rpm` on
  EL8/EL9/EL10 + openSUSE Leap 16.0; `make deb` on Debian 13 + Ubuntu 26.04 LTS) on
  every push/PR to `main`.
  `build.yml` also enforces the `e2e-sandbox` job: `tests/e2e/run_e2e.sh` drives the
  **installed** module through a real PAM stack (`/etc/pam.d/e2e`) against the in-repo HTTPS
  mock OIDC provider (`tests/e2e/mock_oidc.py`, PKCE S256 enforced) — run it locally with
  `make sandbox` (Docker). The mock's self-signed CA must be in the system trust store, and
  the PAM module dir is architecture-specific (never hardcode `/lib/x86_64-linux-gnu`; on
  Apple-Silicon Docker the image is arm64). Linux-PAM status codes are **not** classic PAM
  numbering: `PAM_SERVICE_ERR=3, PAM_PERM_DENIED=6, PAM_AUTH_ERR=7, PAM_ABORT=26,
  PAM_MODULE_UNKNOWN=28`; app-side PAM code includes `<security/pam_appl.h>` (Debian has no
  `pam_ap.h`).
  `.clang-tidy` has `WarningsAsErrors: '*'` and `HeaderFilterRegex: 'include/.*'`; `tests/*.c` is
  not clang-tidy-gated in CI. Do not mark a task complete until these pass **on Linux**.
- **Never suppress clang-tidy checks** to make a gate pass — fix the underlying code. The single
  justified `misc-no-recursion` NOLINT is on the intentionally-recursive `secure_zero_json_tree()`.
- **Memory scrubbing:** never `memset()` sensitive buffers (`client_secret`, `device_code`,
  `access_token`, app-owned `Authorization` header). Use `secure_memzero()` / `explicit_bzero()`.
  Zero json-c string leaves via `secure_zero_json_tree()` before `json_object_put()`. libcurl's
  internal `Authorization` header copy cannot be securely zero-filled through the public cURL API.
   This is mechanically enforced by `scripts/check-memory-scrubbing.sh` (`make check-scrub`;
   `lint.sh` step 5; CI `memory-scrub` job). Its S3 allowlist currently exempts only `doc`
   (http.c OIDC discovery metadata — endpoints/methods only, no tokens/PII); any NEW
   `json_object_put(handle)` without a same-file `secure_zero_json_tree(handle)` FAILS the gate.
- **json-c `*_add()` return convention:** `json_object_object_add()` / `json_object_array_add()`
  (and friends) return **0 on success, -1 on failure** — the *opposite* of the "nonzero = success"
  convention most libc helpers use. To test for failure write `json_object_object_add(...) != 0`;
  NEVER `!json_object_object_add(...)` (that is true on success). The F2 commit's `group_claim_uinfo()`
  test helper had exactly this inversion and failed the whole CMocka suite on Linux (both compilers)
  with `assert_non_null(uinfo)` — no module code is affected (src/ never calls `*_add()`), but it is
  easy to repeat in new tests that build `json_object` trees by hand.
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
- **clang-format version skew (CI = 18.1.x):** CI's `formatting` job installs `clang-format`
  from Ubuntu 24.04 apt → **clang-format 18.1.x**; this host has MacPorts 19.1.7. The two can
  *oppositely* disagree on the same line — e.g. anonymous function-pointer type-ids inside
  `va_arg(args, size_t (*)(…))` (18 wants `size_t(*)(`, 19 wants `size_t (*(`). Keep such
  type-ids out of the clang-format CI scope (`src/*.c include/*.h tests/*.c`) — use named
  typedefs (see `test_write_cb` in `tests/test_suite.c`) — and when in doubt, verify with a
  pinned 18.1.8 binary (`python3 -m venv /tmp/cf18 && /tmp/cf18/bin/pip install
  clang-format==18.1.8`) in addition to the local one.
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

- **Vendored third-party C lives in `third_party/`, never in `src/`/`include/`:** CI
  clang-tidy gates `src/*.c` (and cppcheck/flawfinder `src/`) with `WarningsAsErrors: '*'`;
  unmodified third-party code there will fail the gate. The Makefile needs a matching
  pattern rule for `third_party/.../*.o` and the rpm tarball file list must include
  `third_party` (see the `third_party/qrcodegen/` precedent, 2026-11-08).

- **Vendored code carries provenance + a drift gate:** each `third_party/` payload keeps
  machine-readable pins + local SHA-256 (`vendor-provenance.txt`), a human `AUTHORS`
  (upstream, pin commits, license, re-vendoring procedure), and a minimal
  `local-deviations.patch` (the ONLY semantic deviations from upstream; everything else
  is clang-format). A scheduled audit workflow (`vendor-audit.yml` → `scripts/check_*.sh`)
  verifies local integrity, token-normalized equivalence vs. pinned upstream + patch, and
  fails when upstream advances past the pin. Drift primitive: token-normalize (blank
  string/char literals, strip comments, delete all whitespace) — immune to clang-format
  version skew (local 19 vs CI 18) and whitespace churn.

- **Prompt flushing over OpenSSH keyboard-interactive:** OpenSSH buffers PAM_TEXT_INFO
  (the sign-in URL / QR / user code) and only renders it to the client when a subsequent
  PAM_PROMPT_* forces a USERINFO round-trip. The module therefore polls immediately by
  default and only issues a best-effort `PAM_PROMPT_ECHO_ON` "Press [Enter]" flush prompt
  when `[prompt] require_keypress = true` (that round-trip flushes the prompt AND acts as a
  sync barrier; the keystroke is ignored). The earlier in-place PAM_TEXT_INFO repaint /
  `[prompt] show_countdown` feature was removed (2026-11-09) because a live countdown cannot
  be reliably updated on an SSH keyboard-interactive terminal.
- **Never name a local function after a PAM API symbol** (`pam_prompt`, `pam_get_user`,
  `pam_get_authtok`, …): libpam exports those names, so a same-named static helper in
  `pam_module.c` collides with / silently shadows the real PAM API — the helper stops calling
  PAM. Call the native PAM functions directly (the 2026-11-08 hybrid-flush work removed such a
  static `pam_prompt`).
- **RPM tarball packages the working tree:** `make rpm`'s source tarball includes stale
  `src/*.o` left by earlier local/CI builds; a newer `.o` than its `.c` makes rpmbuild
  `%build` skip recompilation and `%check` link the wrong-toolchain objects (symptom:
  `undefined reference to '__isoc23_strtol'` + DWARF FORM 0x25 errors on EL9 aarch64).
  Run `make clean` (and `rm -rf rpmbuild`) before mirroring the rpm gate locally.
- **Third-party licensing:** every `third_party/<name>/` must carry license text (a
  LICENSE/COPYING file or the upstream in-source license header), an `AUTHORS`/`NOTICE`
  attribution, and a `vendor-provenance.txt` pin; root `THIRD_PARTY_NOTICES.md` must declare
  every RPM-spec `Requires:` runtime dependency; any copyleft (GPL/LGPL/AGPL) text in
  `third_party/` fails the gate. Enforced by `scripts/check-licenses.sh` (`make check-licenses`;
  CI `license-audit.yml` → `license-compliance` job), the GitHub dependency-graph audit
  (`scripts/audit-dependency-graph.py`; `dependency-graph-audit` job — no-op until GitHub
  indexes a recognized manifest; the `dependencyGraph` GraphQL field is feature-gated per
  account, so the job falls back to the REST `dependencies` endpoint on the schema-level
  "Field 'dependencyGraph' doesn't exist" error, and a REST 404 — the current state, since
  all dependency-graph REST endpoints 404 even for public repos and this repo is private —
  is a clean INFO no-op; the auditor accepts both payload shapes, REST has no license data),
  and the `vendor-audit.yml` drift gate. The notices file is
  shipped in the RPM source tarball.
- **`dpkg-shlibdeps` (dpkg >= 1.17; trixie/resolute ship 1.22) is a source-build tool with
  two traps.** (1) It does not print a bare dependency list: without `-O` it writes to
  `debian/substvars` in the cwd (stdout empty); with `-O` it prints substvars lines —
  `shlibs:Depends: <deps>` and, because `libc6` is `Essential:yes` on Debian/Ubuntu,
  `shlibs:Pre-Depends: libc6 (>= ...)`. (2) It unconditionally loads `debian/control` from
  the cwd (`Dpkg::Control::Info->new()` with no args → `error 'cannot read debian/control'`
  otherwise) and needs a parseable `Build-Depends` in the source stanza — so it cannot be
  pointed at a .so from an arbitrary directory. `packaging/build-deb.sh` therefore builds a
  scratch source tree (`mktemp -d` + minimal `debian/control` with `Source:` +
  `Build-Depends: dpkg-dev`), runs `dpkg-shlibdeps -O <abs .so path>` from that cwd, strips
  the `shlibs:(Pre-)?Depends:` prefixes (extended-regex sed — BSD/macOS sed lacks `\?` in
  BRE, so the script uses `sed -nE`), merges both fields into the single control-file
  `Depends:` line, and captures stderr to a mktemp file that is printed on failure.

## Interaction Log (newest first)

### 2026-11-18 — Review finding M-3: document the claims-only / no-JWKS trust model for operators
- **Task:** Address review finding 5 (M-3) — document clearly for operators in `SECURITY.md`/threat-model that JWT handling is **claims-only** and the signature is intentionally NOT verified, that there is **no JWKS signature path**, and that offline ID-token consumption would make this High severity.
- **Decisions & Rationale:** Trust for the returned token rests entirely on (1) enforced HTTPS/TLS 1.2+ transport and (2) the provider's UserInfo endpoint — the module's single authoritative validity/signature checkpoint. `verify_token_metadata()` and `jwt_extract_claim_string()` (`src/jwt.c`) are claims-only inspectors; no local signature verification. `jwks_url`/`introspection_endpoint` are parsed+HTTPS-validated but **unused** (load-time notice). If a deployment ever consumes ID-token claims directly/offline, this escalates to **High** and requires a JWKS/RFC 7517 signature path (module does not provide it). Kept the documented-jargon aligned with the standing invariant: do NOT overclaim "zero-trust"/"replay protection."
- **Gotchas & Lessons:** `docs/threat-model.md` §5 already had a "Cryptographic Boundary" NOTE and `docs/jwt-validation.md` a claims-only WARNING, but neither stated the NO-JWKS fact explicitly nor the offline-ID-token severity escalation — added explicit operator callouts (`[!IMPORTANT]` trust model, `[!CAUTION]` escalation) to both, plus a dedicated M-3 bullet in `SECURITY.md`. Reused the existing `[!NOTE]`/`[!IMPORTANT]` admonition style already present in both docs.
- **Verification:** Docs-only change (no build/test needed). `git diff` limited to `SECURITY.md`, `docs/threat-model.md`, `docs/jwt-validation.md`, `.agents/memory.md`. Anchored the `#5-...` anchor link to the exact existing heading slug in threat-model TOC.
- **Follow-ups / Open Items:** JWKS signature verification and RFC 7662 introspection remain unimplemented (accepted-but-unused keys) — a future High-severity item if offline ID-token-trust is ever adopted.

### 2026-11-18 — USER_NOTICE_* PIC-link fix + full Linux-gate re-confirmation at 73 tests + workflow least-privilege/SHA-pinning audit
- **Task:** (a) Fix CI `-Werror` link failures (`R_X86_64_PC32` relocation after the M-2
  `message.c` extraction) by converting the 4 exported `const char *const USER_NOTICE_*`
  globals in `src/message.c` into `#define` string-literal macros in `src/device_flow.h`;
  (b) address review finding #3 — re-run the full Linux gate set since the in-tree test count
  is now 73 vs. the previously recorded 61; (c) run a dedicated CI least-privilege /
  SHA-pinning audit of `.github/workflows/`.
- **Decisions & Rationale:** Root cause of the link failure: a shared-object (PIC) build that
  references exported data symbols (`USER_NOTICE_*`) across TUs emits `R_X86_64_PC32`
  relocations, which `ld.bfd` rejects (`relocation ... can not be used when making a shared
  object`); toolchain-dependent (container GCC 13 did not reproduce — CI's GCC did). Fix is
  attribute-free and works on all toolchains: the macros inline the string literal at each call
  site, eliminating the cross-TU data reference entirely. Option (b) re-confirms: the local
  container runs are green at **73/73 CMocka** under gcc and clang (`-Werror` zero-warning),
  73/73 under `make test-sanitize CC=clang` (ASan/UBSan/LSan), `make lint` full
  (clang-format/clang-tidy/cppcheck/flawfinder/check-scrub) clean, and `make sandbox` e2e
  **9/9 scenarios green**. Option (c): every `uses:` across all 5 workflows is SHA-pinned to
  actions/checkout commit `3d3c42e5…90b1` — API-verified as exactly the commit that tag
  `v7.0.1` points at ("prep v7.0.1 release (#2531)") — and all workflows set a top-level
  `permissions: contents: read` with no job-level grants, no `id-token`, no elevation
  (license-audit's `GITHUB_TOKEN` use is a read-only dependency-graph query). Audit: NO
  action-version or least-privilege changes required.
- **Gotchas & Lessons:** (1) The reviewer's "last recorded green run = 61/61" was stale —
  memory.md's newest dated gate entry was older than the 61→73 test growth, and the actual
  container re-runs during this work were NOT recorded in `.agents/memory.md`, so a reviewer
  reading only the log correctly concluded "unconfirmed at 73" and flagged a re-run. Lesson:
  end every session that runs Linux gates in the container with a fresh Interaction Log entry
  stating the current CMocka count, so the log never lags the tree. (2) `make sandbox` runs
  the host's Docker (not docker-in-docker) and does NOT need the separate CI-mirror container;
  it is a real installed-module PAM-stack e2e vs the in-repo HTTPS mock provider.
- **Verification.** PASSING — full CI-mirror `ubuntu:24.04` container + host Docker: gcc &
  clang `-Werror` builds zero-warning, **73/73** under both compilers, **73/73** under
  `make test-sanitize CC=clang` (ASan/UBSan/LSan), `make lint` clean, `make check-scrub`
  clean, and `make sandbox` **9/9** e2e scenarios. No public API (include/) or packaging
  touched — internal-only reorg (`src/device_flow.h` macros + `src/message.c` comment).
- **Follow-ups / Open Items.** Push to trigger real CI runners (Compile & Test, e2e-sandbox,
  all 6 distro-build legs) to independently confirm; `make fuzz` remains the only gate not yet
  exercised. This entry supersedes the stale 61/61 record for gate-status purposes.
### 2026-11-17 — Low-priority review batch: Base64 padding fix + 4 regression tests + docs/Makefile/.gitattributes
- **Task:** Close 7 low-priority code-review findings: reject excess Base64 padding in
  `base64url_decode()` (OpenSSL's lenient `BIO_f_base64` decodes 1-mod-4 segments into garbage);
  threat-model callout that the JWT-sub/UserInfo-sub consistency check requires
  `verify_jwt_claims = true` (off by default); `EXTRA_CFLAGS ?=` in Makefile; drop stale
  `REVIEW.md` `.gitattributes` line; document the `strlen`→int cast + TLS-1.2 version guard in
  `src/http.c`; add 4 regression tests.
- **Decisions & Rationale:** padding check computes `total_pad = (in_len - pad_start) +
  (padded_len - in_len)` and fails closed on `> 2` (RFC 4648 §3.5). New tests:
  `test_jwt_base64url_excess_padding_rejected`, `test_http_request_proxy_routing` (weak
  `curl_easy_setopt` captures `CURLOPT_PROXY`: `""` when unset — env-var override defense — and
  verbatim when configured), `test_http_request_response_size_cap` (fake `curl_easy_perform`
  feeds the body through the module's write callback; exactly-256 KiB accepted, +1 byte
  rejected; `http_request` return value intentionally unasserted on the reject case because the
  fake transport still reports `CURLE_OK`), `test_pam_oauth_log_line_dropped_marker`
  (`vsnprintf` encoding error via `(wchar_t)-1` `%lc` on glibc; 9000-char arg exercises the
  8192-byte truncation path; live `pam_start` handle needed since `pam_oauth_log` early-returns
  on NULL). CHANGELOG gained the `[Unreleased]` section.
- **Gotchas & Lessons:** this CMocka has **no** `assert_ptr_null`/`assert_ptr_not_null` — use
  `assert_null`/`assert_non_null`. `make clean` runs `rm -rf build/`, so keep scratch scripts
  and logs OUTSIDE the repo (used `/tmp/pam_verify.sh` + `/tmp/pam_verify.log`). On the arm64
  Docker host, `make test-sanitize CC=clang` additionally needs `libclang-rt-18-dev` (ASan
  runtime) beyond the usual dev packages; x86_64 CI doesn't.
- **Verification:** all gates green in `ubuntu:24.04` container (arm64): `make` gcc and clang
  with `EXTRA_CFLAGS=-Werror` (zero-warning), `make test` gcc + clang (66/66),
  `make test-sanitize CC=clang` (66/66 under ASan+UBSan+LSan), `make lint` with all five
  checks active (clang-format/clang-tidy/cppcheck/flawfinder/memory-scrub, no skips),
  `make check-licenses`. Working tree: only the 7 intended files modified.
- **Follow-ups / Open Items:** none; the `pam_oauth_log` escape-buffer malloc-failure branch
  remains intentionally untested (requires a failing malloc).

### 2026-11-17 — Default prompt gains a leading blank line when `[qr] enabled = false`
- **Task:** User: the first prompt line "gets lost" on a live SSH host — it shares the banner/prompt line (`(bglick@cc-login-test3...) Sign in via browser:`). Request: start the default prompt with a leading blank line when `[qr] enabled = false`.
- **Decisions & Rationale:** `render_prompt_message()` default branch now prepends `"\n"` via `const char *lead = cfg->qr_enabled ? "" : "\n";` + a leading `%s` in BOTH snprintf formats (direct-link and plain-URL branches). Config-driven and deterministic: `prompt_buf` is rendered before the QR block is emitted (Step 4b), and the rendered result still passes the line-by-line `is_safe_rendered_prompt()` check (a leading empty line is safe). When the QR code is enabled the leading blank line stays omitted — the QR block's bottom vertical quiet zone already separates art from the "Sign in via browser:" line. Edge case (QR enabled but rendering fails → no leading blank line) accepted: rare, non-fatal debug-logged path, back to the prior display.
- **Gotchas & Lessons:** (a) PAM keyboard-interactive clients print PAM_TEXT_INFO without a leading newline, so the FIRST rendered line lands on the host-banner line — any future first-line prompt reword must keep the leading `\n` when QR is off. (b) `test_prompt_rendering`: all six default-case expectations re-pinned with a leading `"\n"`; NEW pin `def_qr_cfg` (fresh config, `qr_enabled = 1`) asserts the NO-leading-newline output so both branches stay pinned; the escape-rejection tests below still use the shared `def_cfg` (QR off) and are unaffected. (c) Wording now quoted in: shipped-config `[prompt]` comment, `docs/getting-started.md` [prompt] sample (both show the leading blank line + note), CHANGELOG 0.3.4 prompt bullet. Examples' `[prompt]` blocks do NOT quote the rendered layout → untouched; e2e conf uses a custom `init_message` → untouched.
- **Verification:** PASSED — the `run_commands` wrapper recovered mid-session: local `clang-format --dry-run --Werror src/*.c include/*.h tests/*.c` clean (it flagged one bin-packing nit in the new `def_qr_cfg` call — fixed), `make check-scrub` OK, and the ubuntu:24.04 Docker CI-mirror gate: gcc zero-warning build + 62/62 CMocka, clang zero-warning build + 62/62 CMocka, clang-tidy clean, `make test-sanitize CC=clang` 62/62 → `CI_MIRROR_GATE_ALL_PASS`. Remaining: push + GitHub CI, then `v0.3.4` tag (user authority).
### 2026-11-17 — Sign-in prompt rebased: new default layout + compact expiry units + shipped config/examples on built-in default
- **Task:** User: "rebase the default prompts to be more user friendly" with an explicit mock layout (direct link up top, `Manual entry: <url>  |  Code: <code>` line, blank line, `Waiting for approval (expires in 2m; auto-completes on sign-in).`). Scope confirmed by user: rebase built-in default AND shipped config + examples; compact expiry units ("15m"/"2m"/"1h").
- **Decisions & Rationale:** (a) `format_expiry_seconds()` now renders compact units: `45s` (<60s), `Nm` (rounded-up minutes <1h), `Nh [Mm]` (>=1h, total-minutes round-up preserved). Used by BOTH the default status clause and the `{expiry}` token, so custom templates get compact units too. (b) Built-in default in `render_prompt_message()`: with a distinct `url_complete` → "Sign in via browser:\n  <url_complete>\n\nManual entry: <url>  |  Code: <code>\nWaiting for approval<clause>\n"; else "Sign in via browser:\n  URL:  <url>\n  Code: <code>\n\nWaiting for approval<clause>\n". Clause: show_expiry && known window → " (expires in 15m; auto-completes on sign-in)."; show_expiry off OR unknown window → "; auto-completes on sign-in." — the auto-completes note is now ALWAYS present. `status_clause[64]` (was `expiry_clause[48]` — the clause grew: "(expires in 1h 59m; auto-completes on sign-in)." fits). (c) Shipped `config/pam_oidc_device.conf` + all three `examples/*.conf` now leave `init_message` UNSET (commented-out sample + full placeholder docs in its place) so they render the new built-in layout — the conditional direct-link/manual-entry structure is NOT expressible in a single template: `{url_complete}` falls back to `{url}` when absent (duplicate-URL line) and `{expiry}` → "(; auto-completes...)" when unknown. `tests/e2e/pam_oidc_device.e2e.conf` kept its `[E2E Sandbox]` custom template deliberately (exercises the custom-template path end-to-end). (d) `Press [Enter] to begin...` stays the separate `PAM_PROMPT_ECHO_ON` flush prompt (Step 4c) — NOT embedded in the PAM_TEXT_INFO (would double-print; the round-trip is what flushes the text to OpenSSH keyboard-interactive).
- **Gotchas & Lessons:** (a) The deliberate blank line between the sign-in block and status line reverses the 2026-11-10 "no internal blank line" compactness decision — the user's new mock wins; the QR bottom quiet zone still separates art from the header line. (b) Wording now quoted in: `include/pam_oidc_device.h` show_expiry field doc, `docs/getting-started.md` [prompt] sample (now shows the full rendered default), shipped-config show_expiry comment, CHANGELOG 0.3.4 `### Changed`. Grep targets for future prompt-wording changes: "Sign in via browser", "Manual entry:", "auto-completes on sign-in", "expires in". (c) The `run_commands` wrapper intermittently broke mid-session (whole JSON array executed as one literal string, `[cmd]: command not found`) — retry or use the editor/search tools; it may self-recover.
- **Verification:** PENDING at log time: local `clang-format --dry-run --Werror` (src/tests/include), then the ubuntu:24.04 CI-mirror container gate (gcc & clang zero-warning builds, CMocka suite incl. re-pinned `test_prompt_rendering` expectations, clang-tidy, ASan/UBSan/LSan). `test_prompt_rendering` pins all four default cases (direct/plain × expiry on/off/unknown) + `{expiry}` 900s→"15m", 3600s→"1h", 0→empty.
- **Follow-ups / Open Items:** None. (The v0.3.4 release-tag task from the audit context is still open pending user confirmation.)

### 2026-11-17 — Third independent review: full removal of in-prompt host display (F1) + PAM_RHOST corrections
- **Task:** Address two findings: (F1, HIGH residual) the hostname in the prompt reaches the
  ssh *initiator* (the attacker in device-code phishing), not the approving victim — the
  reviewer directed that the host-display prompt options be removed *entirely*, with the
  guidance changed to descriptive per-host OAuth client names and source-network limits;
  (LOW docs) "PAM exposes no peer-address API" is factually wrong — sshd sets `PAM_RHOST`,
  readable via `pam_get_item(PAM_RHOST)`; threat-model §8/§9, the prompt code comment, and
  the v0.3.3 changelog all relied on the opposite claim.
- **Decisions & Rationale:** Full removal: `config_t.show_host`, `[prompt] show_host` parsing
  (a config containing the key now fails to load as an unknown key — fail-closed), the
  `{host}` template token, the built-in default's host clause (wording reverts to
  "Waiting for your approval; ..."), the `host` parameter of `render_prompt_message()`
  (public-header signature), `sanitize_host_for_display()` + `PAM_OAUTH_HOST_DISPLAY_MAX`,
  and the `gethostname()` block in `pam_sm_authenticate()` (`<unistd.h>` no longer needed in
  pam_module.c). All shipped templates (config/, examples/{keycloak,entra_id,cilogon}.conf,
  tests/e2e conf) demoted to host-free wording. A template still referencing `{host}` now
  renders the literal text (consistent with existing unknown-token behavior) — documented in
  the CHANGELOG upgrade note. PAM_RHOST correction: the source *is* identifiable; the real
  in-module scope boundary for per-source rate limiting is process isolation (each PAM
  invocation is a separate sshd worker with no shared state) — restated in threat-model
  §8/§9, getting-started §4, the code comment, and a [Unreleased] Documentation erratum
  (the v0.3.3 entry is historical and was not rewritten, per the standing invariant). New §8
  guidance: register one descriptive OAuth client per host/cluster (e.g. "ssh:db-prod-3") so
  the IdP's *approval page* — the only surface the victim reads — names the machine; limit
  device-flow sign-ins by source network; privileged accounts get a second factor on the
  approval session + alerts on new source addresses. Caveat documented: on console logins
  PAM_RHOST is the local host name — identifying context, not a trusted input.
- **Gotchas & Lessons:** The v0.3.3 prompt-based mitigation repeated the same audience flaw
  as the original 0.3.2 "show client context in the prompt" recommendation: anything
  rendered into the ssh terminal is read by the *attacker* in this attack. Before adding
  user-facing mitigation for an attack where the attacker holds a terminal session, ask who
  actually reads the output. Also: bulk C-test rewrites (many call-signature + expected-string
  edits with subtle indentation) are more reliable as a count-asserted Python `str.replace`
  script than many hand-matched editor calls; the heredoc `python3 -` form mangled multi-line
  literals, so write the script to a file instead.
- **Verification:** All gates green in the CI-mirror `ubuntu:24.04` container: gcc &
  clang zero-warning builds, 62/62 CMocka tests under both compilers (63 minus the
  removed `test_sanitize_host_for_display`), `clang-tidy` clean, `make test-sanitize
  CC=clang` (ASan/UBSan/LSan) 62/62, `make lint` (clang-format → clang-tidy → cppcheck →
  flawfinder → scrub) OK, local `make check-scrub` OK, `bash -n` on the e2e script OK.
  `make sandbox` (e2e-sandbox CI job) not re-run locally: the harness asserts no prompt
  text (verified by grep) and the conf change is wording-only; CI will confirm.
- **Follow-ups / Open Items:** Close F1 + the PAM_RHOST finding externally (alongside the
  three prior findings from the second review session).
### 2026-11-17 — Second independent review: log-escaper silent drop, e2e trap residue, non-ASCII hostname lockout
- **Task:** Address three review findings: (1) `pam_oauth_log()` dropped a log line silently
  when its escape buffer allocation failed; (2) the e2e EXIT trap never removed the
  `conf.uidrange.{orig,tmp}` config copies (0700 workdir kept credential-bearing copies);
  (3) a hostname containing non-ASCII bytes made the rendered-prompt safety check reject the
  prompt, failing *every* login while `show_host` was on (the default).
- **Decisions & Rationale:** (1) No-silent-drop discipline: on `vsnprintf` failure or
  `malloc` failure, scrub the rendered `line` buffer and emit a static
  "pam_oidc_device: log line dropped (...)" marker via `pam_syslog` — the audit trail
  records that a line was attempted; the untrusted content is withheld. (2) Trap now removes
  both backup pairs (`conf.uid0.*` + `conf.uidrange.*`). (3) The hostname is *display-only
  context, not an authorization input* (set by root on the host; per-login attacker control
  is not a threat) — so it is sanitized at the source instead of failing closed: new
  `sanitize_host_for_display()` (`src/pam_module.c`, declared in the public header following
  the established test-export pattern) keeps only printable ASCII, caps at
  `PAM_OAUTH_HOST_DISPLAY_MAX` (64), and `pam_sm_authenticate()` falls back to `(unknown)`
  when nothing printable remains. The fail-closed `is_safe_rendered_prompt()` check is
  retained as defense-in-depth for the template, provider URL(s), and user code — the
  existing test asserting raw non-printable hostnames still fail `render_prompt_message()`
  was kept, with its comment updated.
- **Gotchas & Lessons:** fail-closed is appropriate for *attacker-influenced* prompt content
  (template/URL/code) but wrong for *local display-only* data (hostname): the safety
  invariant (no unsafe bytes reach the terminal) can be met by sanitizing at the source.
  Test-exported helpers are declared in `include/pam_oidc_device.h` (same as
  `is_safe_terminal_string`, `render_prompt_message`) — no separate test shim.
- **Verification:** `make check-scrub` + e2e `bash -n` pass locally (macOS); full
  gcc/clang build+test, clang-tidy, sanitizer, and `make lint` gates running in the
  `ubuntu:24.04` CI-mirror container (see follow-up). New `test_sanitize_host_for_display`
  (ASCII passthrough, UTF-8/control-byte drop, 64-char cap, tight-dst cap, NULL/zero-cap
  inputs) registered after `test_prompt_rendering`.
- **Follow-ups / Open Items:** confirm container gate run green; docs updated (threat-model
  §1, getting-started + conf `show_host` comments, CHANGELOG [Unreleased] "Fixed").


### 2026-11-17 — Independent review: fail-closed uid guards + HTTPS-only `[oauth] proxy` + upgrade notes
- **Task:** Address two independent-review MEDIUM findings: (1) uid-0 / system-UID
  guards skipped when `getpwnam_r()` errors; (2) upgrade from ≤0.3.2 breaks on
  required `claim_regex`, default-deny UIDs 0–999, and disabled env-var proxies.
- **Decisions & Rationale:** (1) Implemented as a three-state lookup in
  `verify_user_access()` (`PWNAM_FOUND`/`PWNAM_NOT_FOUND`/`PWNAM_ERROR`):
  not-found still skips both gates (a name with no local account cannot hold a
  local uid; the user lists decide), while a lookup *error* (ERANGE,
  NSS/LDAP outage) is refused fail-closed by each active gate with an
  actionable log line naming the errno and the config key that disables the
  gate. The reviewer's finding was taken against the committed baseline (HEAD)
  — the working tree already carries the fix; re-verified after clang-format.
  (2) The explicit proxy mitigation is the new `[oauth] proxy` key:
  HTTPS-only (validated by `is_valid_https_url`, which also rejects embedded
  userinfo — no proxy credentials), parsed in `load_config()` with
  duplicate-key rejection, threaded through `http_request()` and
  `discovery_probe_pkce()` (all four call sites in `pam_module.c`, 11 test
  call sites); when unset, `CURLOPT_PROXY` is set to `""` so libcurl never
  falls back to the caller's `*_proxy` env vars. Added "### Upgrade notes
  (from ≤ 0.3.2)" to `CHANGELOG.md` [Unreleased] covering all three breakers
  (all three shipped in 0.3.3; the proxy key is the new mitigation), plus a
  commented `proxy` sample in `config/pam_oidc_device.conf` and the
  `[oauth]` row of the getting-started config table.
- **Gotchas & Lessons:** `PWNAM_ERROR` cannot be induced deterministically in
  the CMocka harness (needs a real NSS/DB outage or ERANGE), so that branch is
  code-reviewed only; the `PWNAM_NOT_FOUND` branch *is* unit-tested (unknown
  name → uid gates skip, lists decide). A sed bulk-edit of the 11 test call
  sites once clobbered a doc comment (missing `/**` opener) — caught by the
  gcc test build (`stray '@' in the program`); recovered via `git checkout` +
  targeted editor edits. `init_config_defaults()` needed no change: it
  `memset`s to zero first, matching `load_config()`, so `proxy` defaults to
  `""` in both.
- **Verification:** PASSED in `ubuntu:24.04` CI-mirror container: gcc + clang
  builds zero-warning; 62/62 CMocka tests under both compilers (was 58/58;
  +1 proxy test + pre-existing adds); `clang-tidy src/*.c -- -Iinclude
  -D_GNU_SOURCE` clean; `clang-format --dry-run --Werror` clean (one
  in-container `clang-format -i` pass on wrap-width fixes); `make
  test-sanitize CC=clang` (ASan/UBSan/LSan) 62/62; macOS-native `make
  check-scrub` + `check-licenses` clean.
- **Follow-ups / Open Items:** none — both findings closed; changes uncommitted
  (8 files: CHANGELOG, config, header, 4 src, test_suite).

### 2026-11-17 — `discovery_probe_pkce()` provider-JSON scrub gap closed (comprehensive review finding)
- **Task.** Comprehensive review flagged the one Low finding: `discovery_probe_pkce()` (src/http.c)
  released the provider-parsed discovery document with bare `json_object_put()` on two exit paths
  (non-object doc branch and the success path), deviating from the module-wide
  `secure_zero_json_tree()`-before-`json_object_put()` discipline.
- **Decision & Rationale.** Added `secure_zero_json_tree(doc)` before both `json_object_put(doc)`
  calls so provider-controlled string elements cannot survive in freed json-c memory. The gap was
  invisible to `check-scrub` S3, whose pairing pattern only catches scrub+put in the contexts the
  other parse sites use — a reminder that a mechanical gate passing does not prove the convention
  holds everywhere.
- **Verification.** PASSING — full CI-mirror `ubuntu:24.04` container re-run green: 61/61 CMocka
  under gcc, 61/61 under clang, 61/61 under `make test-sanitize CC=clang` (ASan/UBSan/LSan), and
  `make lint` (clang-format/clang-tidy/cppcheck/check-scrub) all pass; zero warnings.
- **Follow-ups / Open Items.** Commit `95ef42d` pushed to `wglick/improvements3`; remote
  GitHub Actions gates pending. Optional hardening: extend `scripts/check-memory-scrubbing.sh`
  S3 to catch unpaired `json_object_put()` on provider-parsed trees in any context.

### 2026-11-17 — `test_verify_user_access` made distribution-agnostic (distro-build CI failures)
### 2026-11-17 — `test_verify_user_access` made distribution-agnostic (distro-build CI failures)
- **Task.** `make test` failed on the `distro-build` images (Rocky 8/9/10, openSUSE Leap 16.0) because `test_verify_user_access` asserted on conventional system accounts that differ per distro (`sync` uid 4 missing on openSUSE; `daemon` is uid 2 on RHEL, uid 1 on Debian; no uid-1..999 non-root accounts at all on openSUSE).
- **Decisions & Rationale.** The test now splits into deterministic and dynamic parts. Deterministic: `root` (the module hardcodes the name→uid-0 resolution) covers uid-0 denial even with `allow_users = "root"` and the `allow_root = true` exemption — guaranteed on every platform. Dynamic: new file-static helper `find_system_range_account()` (tests/test_suite.c) parses `/etc/passwd` directly (third colon-delimited field = uid; picks the first account with uid 1..999) and every non-root in-range assertion (range-gate denial, raising `system_uid_min` above its uid, guard-off, inverted-range inactive) runs only when such an account exists — vacuously skipped on openSUSE by design. Parsed `/etc/passwd` instead of `getpwent_r`/`setgrent` because those APIs need `_GNU_SOURCE`, which the test target is not compiled with (first dynamic attempt failed the EL builds with implicit-declaration errors under `-Werror`).
- **Gotchas & Lessons.** (a) `verify_user_access()` has TWO gates: a uid-0 gate (denies `root` unless `allow_root`, runs BEFORE the range gate) and the `[system_uid_min..system_uid_max]` range gate — root therefore can never exercise range-boundary behavior, only a non-root in-range account can. (b) `allow_users` is a separate gate that runs AFTER both uid gates; when a test block reuses a `cfg` where `allow_users` was set to "root", it must be cleared (`cfg.allow_users[0] = '\0'`) before non-root assertions — this was the cause of the second round of Rocky failures at the "raise system_uid_min" assert. (c) Containerized gate runs that share one mounted repo directory stomp on each other's `build/` (parallel `make clean`); run each distro job against its own `cp -R` copy. (d) openSUSE's `opensuse/leap:16.0` image is aarch64-only on this host; `zypper` 404s on the first `libjson-c-devel` mirror and retries — expected, not a failure.
- **Verification.** PASSING — all five CI-mirrored container runs green (61/61 CMocka under both gcc and clang): `rockylinux:8`, `rockylinux:9`, `rockylinux:10`, `opensuse/leap:16.0` (each: deps + build + test, the distro-build job steps) and `ubuntu:24.04` full gate (lint → gcc/clang build+test → clang-tidy → `make test-sanitize CC=clang` ASan/UBSan/LSan clean → `check-scrub` → flawfinder no-hits → `clang-format --dry-run --Werror`).
- **Follow-ups / Open Items.** None — commit the `tests/test_suite.c` change with the F8-F11 work.

### 2026-11-17 — review findings F8/F9/F10/F11 (log escaping, slist scrub, proxy, required claim_regex)
- **Task.** Address four LOW review findings: (F8) untrusted text reaches syslog unescaped;
  (F9) libcurl's `curl_slist` copy of the Authorization header freed but not scrubbed;
  (F10) `*_proxy` env vars honored inside setuid programs; (F11) permissive `^(.*)$` claim
  default + internally inconsistent shipped config.
- **Decisions & Rationale.**
  - F8 fixed at the *choke point*: `pam_oauth_log()` (src/http.c) now vsnprintfs the formatted
    line, escapes non-printable-ASCII bytes (`\n`→`\\n`, `\r`→`\\r`, `\t`→`\\t`, else `\xHH`),
    and calls `pam_vsyslog(pamh, priority, "%s", escaped)` with a literal format. All module
    logging funnels through this one wrapper (verified: no direct `pam_vsyslog` elsewhere in
    src/), so escaping trusted text is a no-op and every untrusted value is covered. 8192-byte
    line cap (`PAM_OAUTH_LOG_LINE_LEN`); both buffers `secure_memzero`d (heap one before
    `free`) to satisfy the scrub gate.
  - F9: `scrub_and_free_slist()` static helper in src/http.c walks the slist and
    `secure_memzero`s each entry's `data` before `curl_slist_free_all()`. Chosen over
    `CURLOPT_XOAUTH2_BEARER` because the token would still live in curl's own setopt copy.
    All six `curl_slist_free_all(headers)` call sites in `http_request()` now use the helper.
  - F10: `CHECK_SETOPT(CURLOPT_PROXY, "")` in `http_request()` — empty string is libcurl's
    documented way to explicitly disable the proxy and overrides the `*_proxy` env fallback.
  - F11: `claim_regex` is now REQUIRED. Check lives in `parse_config_file()` (right before
    `regcomp`): `strlen(cfg->claim_regex) == 0` → error + `secure_memzero(cfg)` + -1. Removed
    the `"^(.*)$"` default from `load_config()` step 1 (and from the test helper
    `init_config_defaults`). Rejected value is logged as
    `claim_regex must be explicitly set in the [claim] section`.
  - F11 consistency fix: `preferred_username` is normally a bare local username, so the
    shipped config (`config/pam_oidc_device.conf`), `docs/getting-started.md` quick start, and
    `docs/access-control.md` complete example now use `claim_regex = ^([a-zA-Z0-9._-]+)$`
    (matches `examples/keycloak.conf`), with the domain-pinned e-mail pattern
    `^([^@]+)@example[.]edu$` documented as the alternative for e-mail-shaped claims. The
    `examples/*.conf` templates (eppn/email domain-pinned; preferred_username bare) were left
    unchanged — they were already consistent.
- **Gotchas & Lessons.**
  - Making a key required cascades into *every* parse test fixture that asserts
    `parse_config_file(...) == 0`: minimal_valid, long_access_list, whitespace_and_comments,
    pkce_auto, jwt_claims_requires_binding (all four fixtures, including the -1 ones — keep
    them focused on their own branch), and the `QR_TEST_BASE_CONF` macro. Only 7 tests assert
    parse success; add `[claim]\nclaim_regex = ...\n` to any new success fixture.
  - The claim_regex line in a fixture must sit under `[claim]` (or after a `[claim]` header),
    not under `[oauth]` — `parse_config_kv` rejects keys in the wrong section.
  - New test: `test_parse_config_file_claim_regex_required` (missing → -1 + scrub;
    explicitly empty `claim_regex = ` → -1 + scrub).
- **Verification.** VERIFIED in a `ubuntu:24.04` CI-mirror container: gcc and clang builds
  zero-warning, 61/61 CMocka tests under gcc, clang, and ASan/UBSan/LSan (`make test-sanitize`),
  `clang-tidy` clean, `make check-scrub` OK, `make lint` OK (clang-format auto-fixed
  continuation-line alignment in the CHECK_SETOPT macro and two jwt test fixtures), and
  `make sandbox` e2e 9/9 scenarios (e2e config already sets claim_regex explicitly, so the
  new requirement does not break it).
- **CI follow-up fixes (after first green container run, GitHub Actions reported 3 new
  failures; all fixed and re-verified in the same container: full gate green incl.
  `flawfinder --minlevel=3 --error-level=3` — "No hits found" with 2 suppressed):**
  - *clang-tidy `readability-math-missing-parentheses`* (newer clang-tidy in CI than
    ubuntu:24.04's 18, which missed it): `len * 4U + 1U` now written `(len * 4U) + 1U` in
    `pam_oauth_log()` (malloc + secure_memzero).
  - *Flawfinder level-4 `vsnprintf` format hit* in `pam_oauth_log()`: suppressed same-line
    (`// flawfinder: ignore`) — false positive: every caller passes a compile-time literal
    `fmt`; untrusted bytes flow only as argument values and vsnprintf enforces the bound.
  - *SUSE e2e test failure `test_verify_user_access`*: the uid-range assertions used
    account `"sync"` (uid 4), which does not exist on openSUSE — `getpwnam_r` misses so
    `uid_known` stays 0 and the gate permits. Replaced with `"daemon"` (uid 1, POSIX
    account present on all supported platforms) and adjusted the range-narrowing branch to
    raise `system_uid_min` above 1 instead of lowering `system_uid_max` below 4.
- **Follow-ups / Open Items.** No version bump performed ("ask first" boundary). Uncommitted
  work under the `0.3.3` CHANGELOG heading; note `src/jwt.c` still carries unrelated
  pre-existing uncommitted changes from an earlier session — scope commits accordingly.

### 2026-11-17 — system-account UID-range guard (`deny_system_uids`, new [access] keys)
- **Task:** User request: like the uid-0/root guard, add an optional system-account UID guard — default ON, configurable range; default range uids 0-999.
- **Decisions & Rationale:** New `[access]` keys: `deny_system_uids` (bool, default `true`), `system_uid_min` (int, default `0`), `system_uid_max` (int, default `999`) — inclusive bounds, `parse_int_range(val, 0, INT_MAX)` per key, and a fail-closed cross-field check in `parse_config_file()` rejecting `system_uid_min > system_uid_max` (mirrors the `verify_jwt_claims`/issuer/audience up-front rejection; secure_memzero + -1 on failure). Guard lives in `verify_user_access()` **after** the uid-0 gate and **before** `allow_users`: resolves the uid (`root`→0 shortcut reusing the name-based convention, else `getpwnam_r` 4096 stack buffer — established F3 pattern) and refuses in-range uids regardless of `allow_users` (uid-not-name, same semantics as the uid-0 gate). Deliberate: an explicit `allow_root = true` **exempts uid-0 accounts from this second gate only** — without the exemption the default 0-999 range would silently neuter `allow_root`. A name resolving to no local account is NOT refused (IdP-first flows; same deviation rationale as F3). Inverted ranges are treated as inactive defensively in the gate (load rejects them). e2e: new scenario 7/9 `system-uid-denied` (account `sync`, uid 4, conventional on all supported distros) mirrors the toor scenario's masking-gate trick (temporarily strip `allow_users` via `sudo tee`/redirect so only the uid-range gate can block it; scenarios renumbered 9 total). Unit: `init_config_defaults()` kept in sync (1/0/999); `test_verify_user_access` blocks for default-deny/absent-name pass/allow_users-can't-grant/range-narrow/disable/inverted-inactive/allow_root-exemption. No version bump (ask-first).
- **Gotchas & Lessons:** (1) The e2e fixture `deny_users = daemon` — do **not** use `daemon` for the new scenario (ambiguous attribution); `sync` (uid 4) is clean. (2) Tests `memset(&cfg,0)` build configs, so "default true" lives in `load_config()` step 1, not the zeroed struct — any new default-true gate needs its defaults explicit in test blocks that exercise it (and in `init_config_defaults()` for parse tests). (3) `daemon` is uid 1 on Ubuntu but uid 2 on RHEL — distro-dependent uids are test hazards; `sync`=4 is stable.
- **Verification:** PASSED — local `clang-format -i` on the four C files (headers: doxygen comment alignment in `config_t` needed rewrap; plain `clang-format <files>` prints to stdout, must pass `-i`); `make check-scrub` green. ubuntu:24.04 CI-mirror container (arm64 docker, same recipe as F7): clang + gcc builds zero-warning, **60/60** CMocka under gcc and clang (new `test_parse_config_file_system_uid_range_invalid`), `make test-sanitize CC=clang` ASan+UBSan+LSan clean, `make lint` clean, clang-tidy 0 warnings. `make sandbox`: **9/9** e2e scenarios, new scenario 7/9 `system-uid-denied` → PAM rc 6 (`PAM_PERM_DENIED`) as expected; also updated stale "7-scenario harness" counts in `.agents/context.md` and `.agents/skills/run-e2e/SKILL.md` → 9.



### 2026-11-17 — claim values logged below VERBOSE (F7, review finding, CONFIRMED IN CODE)
- **Task:** Address F7: raw provider claim values reached syslog below the VERBOSE level — `verify_claim()` logged the raw claim value at DEBUG on regex non-match and the extracted identity at DEBUG (match) / ERROR (mismatch); `verify_token_metadata()` logged the received `iss` at ERROR on mismatch and the full received `aud` JSON (`json_object_to_json_string`) at ERROR — while the function's own comment (identity.c:119) says raw values are VERBOSE-only.
- **Decisions & Rationale:** Per the finding's fix ("Below VERBOSE, log claim names and lengths, never values"): (a) identity.c regex-non-match DEBUG line → `(length %zu)` of `raw_claim`; (b) identity.c match-verified DEBUG + mismatch ERROR lines → `(length %zu)` of the extracted identity (reusing the in-scope `extracted_len`; the match-verified DEBUG line wasn't cited in the finding but had the same defect class, so it was fixed too); (c) jwt.c iss-mismatch ERROR → keep configured expected value (admin config, not provider data), log received value length (guarded: only string-typed `iss` yields a length, else 0); (d) jwt.c aud-mismatch ERROR → keep expected, log `strlen(json_object_to_json_string(j_aud))` (handles both string and array forms, NULL-safe). No VERBOSE-gated value logs were *added* — the existing `verify_claim()` VERBOSE line already covers the raw value; jwt iss/aud have none and none was mandated. `pam_user` values in access/group logs left as-is (module-wide convention; not provider claim data). No behavior/return-value/scrub changes; subsequent `secure_zero_json_tree()`/`json_object_put()` paths untouched.
- **Gotchas & Lessons:** The `pam_oauth_log(pamh, cfg_level, msg_level, ...)` wrapper emits when `cfg_level >= msg_level`, so a `LOGLEVEL_VERBOSE` message is VERBOSE-only — that is how the "values only at VERBOSE" policy is expressed in this codebase (see the `verify_claim()` entry log). The finding's cited line numbers (jwt.c:309/368) predate F6's line shifts; grep for the message text, not the number.
- **Verification:** local clang-format clean (one rewrap in identity.c); CI-mirror ubuntu:24.04 container: clang + gcc builds zero-warning, 59/59 CMocka under both compilers, ASan+UBSan+LSan run clean, `make lint` clean, CI clang-tidy gate clean; `make sandbox` e2e all 8 scenarios passed (scenarios 2 & 7 exercise the new identity/jwt mismatch log lines live). Container-gotcha: the gate needs `libcurl4-openssl-dev` (curl/curl.h) and a `/usr/local/bin/clang` → `clang-17` symlink because `make test` hardcodes `CC=clang` internally; `set -e` + `/dev/null`-redirected `make` lines can swallow build failures — log build output to a file.

### 2026-11-17 — every token-phase failure reported as "sign-in code expired" (F12, review finding, REPRODUCED)
- **Task:** Address F12: any `poll_for_access_token()` failure other than a user abort (token_type mismatch, oversized token, fatal network error, provider denial, ...) showed the single USER_NOTICE_EXPIRED text, so a user whose sign-in was declined was told the code had expired.
- **Decisions & Rationale:** Distinguish internal reasons from the polling phase: new `token_phase_t` enum (`TOKEN_PHASE_EXPIRED` / `TOKEN_PHASE_DENIED` / `TOKEN_PHASE_UNAVAILABLE`) + `*phase` out-param on `poll_for_access_token()`, defaulted to UNAVAILABLE at entry and set only at the expired-code sites (the three deadline/`remain_ms<=0` loop breaks) and the definitive-4xx site (`expired_token` → EXPIRED, `access_denied` → DENIED; all other definitive errors stay UNAVAILABLE). `pam_sm_authenticate()` maps: DENIED → new `USER_NOTICE_NOT_APPROVED` ("Sign-in was declined..."), EXPIRED → existing `USER_NOTICE_EXPIRED`, else → existing `USER_NOTICE_SERVICE`. PAM status codes, audit logs, and the no-notice-on-PAM_ABORT behavior all unchanged — only which user-visible notice is shown. e2e: `run_case` gained an optional 5th arg (expected notice substring, grep -qF against the case's `.out`, which already captures every `PAM_TEXT_INFO` the driver prints); scenarios 3 (`provider-denied`) and 7 (`code-expired`) now assert the exact notice. Docs: getting-started "User-Visible Failure Notices" rewritten to describe the outcome-matched notices.
- **Gotchas & Lessons:** The `USER_NOTICE_*` constants block already existed with an EXPIRED notice; the bug was only in the caller's single-branch mapping. Notice strings must stay printable-ASCII (stated invariant in the constants' doc comment) and "intentionally generic" about *which security control* — but naming the provider outcome (declined vs expired vs service-unavailable) is exactly what the finding asked for and leaks no local control detail.
- **Verification:** In progress at log time: `clang-format --dry-run --Werror` clean, `bash -n` clean, `make check-scrub` OK, `gen-changelog.py` parses the new 0.3.3 `### Changed` bullet. Running: ubuntu:24.04 CI-mirror gate (gcc/clang builds + CMocka + clang-tidy + ASan/UBSan/LSan) and `make sandbox` (asserts the new notices end-to-end in the declined and expired scenarios).

### 2026-11-16 — JWT exp/nbf checks accepted NaN (F6, review finding, REPRODUCED)
- **Task:** Address F6: json-c parses the non-standard `NaN`/`Infinity` literals as json_type_double, and all NaN comparisons are false, so `"exp": NaN` (or `nbf`) bypassed the expiry/not-yet-valid checks in `verify_token_metadata()`.
- **Decisions & Rationale:** `src/jwt.c`: added `#include <math.h>` (isfinite compiles to a builtin, no `-lm` needed in the Makefile LIBS). After the existing int/double type dispatch, `exp_val` and `nbf_val` are rejected via `!isfinite(...)` with a distinct audit-log line ("non-finite 'exp'/'nbf' claim"), scrubbed+`json_object_put` on the way out (fail-closed, matching every sibling branch). Step 3/4 doc comments updated to state the finiteness requirement. Tests: new CMocka case `test_jwt_non_finite_claims_rejected` (fixtures: exp=NaN, exp=Infinity, nbf=NaN → -1; finite far-future exp control → 0), registered right after `test_jwt_numeric_date_and_exp_policy`. Base64url fixtures generated via Python (`eyJ...IiwiZXhwIjpOYU59`-style payloads). No Makefile link change.
- **Gotchas & Lessons:** (a) The editor's first include edit failed because I used `#include "pam_oidc_device.h"` — the real line is `#include "../include/pam_oidc_device.h"`; verify exact text before constructing old_text. (b) read_files returned "[outdated]" for src/jwt.c this session; fall back to `sed -n` when that happens.
- **Verification:** PASSED — ubuntu:24.04 CI-mirror gate: gcc & clang builds zero-warning, 59/59 CMocka tests under gcc, clang, and ASan/UBSan/LSan, clang-tidy clean. New `test_jwt_non_finite_claims_rejected` OK in all three runs. Local: `clang-format --dry-run --Werror` clean; `make check-scrub` exit 0; regenerated `%changelog` exactly 6 valid `*` headers, 0 stray. Working tree cleaned.

### 2026-11-16 — provider rate-limit exhaustion via connection loops (F5, review finding, DESIGN, documented)
- **Task:** Address F5: every SSH connection for an allowed username sends a device-authorization request to the provider *before* user input; a connection loop can exhaust the provider's rate limit for this client and lock out real users.
- **Decisions & Rationale:** Documented rather than in-module code. The finding offered "document sshd tuning, or add a local per-source rate limit" — the code option is not implementable in this layer: PAM exposes no peer-address API (already established in the §8/show_host work), so per-source limiting in the module is impossible, and a host-wide limiter would need cross-process state shared by concurrent sshd workers (out of PAM scope) plus a new config key ("ask first" boundary). sshd enforces per-source pre-auth throttling and is the correct layer: `PerSourcePenalties` (OpenSSH ≥ 9.7), `MaxStartups`, `MaxAuthTries`, `LoginGraceTime`. Changes: (a) `docs/getting-started.md` §4 new "Protecting the Provider from Connection Bursts" subsection with a recommended drop-in + `sshd -T` verification command; (b) `docs/threat-model.md` new "Provider Rate-Limit Exhaustion (Self-DoS)" matrix row + new §9 (attack, in-module scope boundary, control table, drop-in, monitoring) + TOC entry; (c) CHANGELOG 0.3.3 `### Documentation` bullet. No code changes. Confirmed `verify_user_access()` runs before `request_device_authorization()` (pre-flight), so a narrow `allow_users`/`AllowUsers` caps provider contact.
- **Gotchas & Lessons:** When a finding offers "document X or implement Y", check whether the code is even implementable in the layer — here PAM's missing peer-address API was already established in-repo; re-deriving that constraint per finding wastes cycles, so cite it.
- **Verification:** Docs-only change — no build/test gates needed. Regenerated `%changelog` via `packaging/gen-changelog.py`: still exactly 6 valid `*` entry-header lines, 0 stray `*`-leading lines (the F4-era generator bug stayed fixed for the new bullet's wraps).

### 2026-11-17 — token_type compared case-sensitively (F4, review finding, REPRODUCED)
- **Task:** Address review finding F4: `strcmp(ttype, "Bearer")` in the token-response handling broke compliant providers sending lowercase "bearer" (RFC 6749 §5.1 says the value is case-insensitive; docker repro showed "Bearer"→0, "bearer"→PAM_AUTH_ERR).
- **Decisions & Rationale:** `src/pam_module.c` (~line 899): `strcmp` → `strcasecmp`; comment updated to cite the RFC's case-insensitivity. No new `<strings.h>` include — repo convention: `src/config.c` already uses `strcasecmp` with just `<string.h>` (glibc declares it under `_GNU_SOURCE`) and passes every gate; keep includes minimal/consistent. Fail-closed semantics for missing/foreign token types unchanged. Added a 0.3.3 `### Fixed` changelog bullet (newest-first position).
- **Gotchas & Lessons:** None new. Note the finding cited `src/pam_module.c:787` — the actual code was at ~line 897 (file shifted since the finding was written); always grep for the code, not the cited line.
- **Verification:** PASSED — `clang-format --Werror` clean; regenerated `%changelog` exactly 6 valid `*` headers, 0 stray. ubuntu:24.04 CI-mirror gate: gcc & clang zero-warning, 58/58 tests under gcc/clang/ASan-UBSan-LSan, clang-tidy clean. rockylinux:8 full `make rpm` loop (incl. spec %check) built + installed the RPM and passed the layout check.

### 2026-11-17 — `[prompt] show_expiry` default flipped false → true
- **Task:** User: "I think the show_expiry should default to true." (explicit schema-default change; user is authority per AGENTS.md "ask first" boundary.)
- **Decisions & Rationale:** The built-in default template's trailing status line now carries "(expires in …)" by default whenever the provider advertises `expires_in` — honest, useful time-boxing for the approver; opt-out via `show_expiry = false`. Semantics unchanged: the flag still only affects the BUILT-IN default template; `{expiry}` in any custom `init_message` is independent of it. Shipped `config/pam_oidc_device.conf` and all `examples/*.conf` use CUSTOM `init_message`s without `{expiry}`, so no shipped deployment's prompt changes — only deployments relying on the built-in default. Changes: `src/config.c` default `0` → `1` (+ comment); `include/pam_oidc_device.h` field doc ("1 (default) adds …; 0 hides it"); `src/pam_module.c` doc comments (3 places); tests: minimal-valid config default assert `0` → `1`, full-sections line flipped to `show_expiry = false` → assert `0` (both bool parse directions stay pinned; no new test function — sibling keys already pin `parse_bool` true/false); render-test comment "(default)" dropped (flag is explicit there, not a config default). Shipped config + getting-started.md commented sample became `#show_expiry = false` (opt-out) with "Set to false to hide" wording; CHANGELOG 0.3.3 bullet rewritten: default `true`, and the old "default prompt wording is unchanged" claim replaced with "the only out-of-the-box wording change is the built-in default template."
- **Gotchas & Lessons:** (a) When a config default flips, grep for the STATED default in prose, not just the code: doc comments in 3 C files, 2 config examples, docs, and CHANGELOG all asserted the old default. (b) The editor tool's displayed indentation in read_files output is NOT reliable for exact-match edits in this repo — verify indented comment blocks with `python3 -c "print(repr(open(...).readlines()[n:m]))"` before constructing old_text; two edits failed on 1-space indent mismatches (9 vs 10, 5 vs 6 spaces). (c) Two containers mounting the same in-tree-build source dir in parallel RACE on `src/*.o`/`build/` — run distro gate containers strictly sequentially.
- **Verification:** PASSED — ubuntu:24.04 CI-mirror gate: gcc & clang builds zero-warning, 58/58 CMocka tests under gcc, clang, and ASan/UBSan/LSan, clang-tidy clean. rockylinux:8 full `make rpm` loop (incl. spec %check) built `pam_oidc_device-0.3.3-1.el8.aarch64.rpm`, installed, and passed the `/lib64/security` + `/etc` layout check. Local: `clang-format --dry-run --Werror` clean; regenerated `%changelog` still exactly 6 valid `*`-entry-header lines. NOTE: first container run FAILED because `tests/test_suite.c`'s `init_config_defaults()` helper (line ~1433, "Keep in sync with load_config() defaults") did not mirror the new `cfg->show_expiry = 1;` default — the config-parse default actually lives in `load_config()` (config.c ~line 964), and the test helper is a second, independent copy. Any future default change must be mirrored in BOTH places.

### 2026-11-17 — CI EL8 RPM failure: `gen-changelog.py` emitted `*`-leading body lines into `%changelog`
- **Task:** Fix CI job "EL8: Rocky Linux 8 (RPM)" — `rpmbuild` died with `error: bad date in %changelog: which machine* the sign-in belongs to — the one piece of context a user can use` during `make rpm`.
- **Root cause:** `packaging/gen-changelog.py` collected changelog items with `stripped.startswith('-') or stripped.startswith('*')` on the STRIPPED line — so indented wrapped-continuation lines of a bullet (e.g. `  *which machine* the sign-in belongs to …`, an inline-emphasis wrap in the new 0.3.3 "Security hardening" bullet; also `**device-code phishing**…` and `**uid 0, …**` wraps) became `%changelog` lines starting with `*`. rpmbuild parses ANY `*`-leading `%changelog` line as a new entry header and demands a valid `Day Mon DD YYYY` date there → "bad date". Latent since the generator was written; first triggered by the 0.3.3 bullets (earlier sections only ever had column-0 `-` bullets whose wraps didn't start with `*`).
- **Fix (generator, not the prose):** item collector now (a) only accepts bullets at column 0 (`line.startswith('- ')` / `'* '`, first char not whitespace — indented lines are prose continuations), and (b) normalizes every emitted item to `- …` so no generated `%changelog` line can ever begin with `*`, even if a future CHANGELOG section uses `*` bullets. CHANGELOG.md prose untouched (the wrapped `*which machine*` line is correct Markdown).
- **Gotchas & Lessons:** Any generator that feeds text to an rpm `%changelog` must remember rpmbuild's header grammar: `*`-leading line == entry header == must carry a parseable date. When editing CHANGELOG.md, re-run `python3 packaging/gen-changelog.py` and eyeball the output (or run `make rpm` in a rockylinux container) before pushing — the RPM gate is the only consumer. Also note the distro CI job (`distro-build.yml`) does the full loop: build → `make rpm` → `dnf install` the RPM → layout check; mirror it in `rockylinux/rockylinux:8` (dnf-utils + powertools + gcc/pam-devel/libcurl-devel/json-c-devel/openssl-devel/libcmocka-devel/rpm-build — spec `%check` runs the CMocka suite).
- **Verification:** PASSING — `rockylinux/rockylinux:8` container re-run of the exact CI loop: `make rpm` (rpmbuild -ba incl. spec `%check`) succeeded, `pam_oidc_device-0.3.3-1.el8.aarch64` installed via dnf, `/lib64/security/pam_oidc_device.so` + `/etc/pam_oidc_device.conf` present (`EL8_GATES_PASSED`). Local: regenerated changelog machine-checked — 6 entries, all 6 `*`-leading lines match the valid entry-header grammar, all item lines `-`-leading, zero stray `*` lines.

### 2026-11-17 — Trailing status line reworded: "on <host>" → "to sign in to <host>"
- **Task:** User called out that "Waiting for your approval **on** <host>; ..." is inaccurate: the approval is not performed *on* that machine — the sign-in request is *for* that machine.
- **Decisions & Rationale:** New canonical wording: "Waiting for your approval **to sign in to** <host>; this session completes automatically once you sign in." The approval is *for the purpose of signing in to* the named host. Applied to: (a) the built-in default template — `host_clause` format in `render_prompt_message()` changed from `" on %s"` to `" to sign in to %s"` (buffer grown 264 → 280: 15-char prefix + 255-char max hostname + NUL); (b) every shipped `init_message` (`config/pam_oidc_device.conf`, `examples/{cilogon,entra_id,keycloak}.conf`, `tests/e2e/pam_oidc_device.e2e.conf` — the e2e line keeps its article-less "Waiting for approval to sign in to {host}"); (c) all quoted wording in docs (`docs/getting-started.md`, `docs/threat-model.md` §8, `include/pam_oidc_device.h` field docs, shipped-config comments, CHANGELOG 0.3.3 bullet — revised in place since 0.3.3 is unreleased); (d) `test_prompt_rendering` expected strings. The `{host}` template token semantics are UNCHANGED (still the bare hostname — presentation glue lives in template text). Left alone: README.md's "approval on the second device" (different, accurate context) and memory.md historical entries.
- **Gotchas & Lessons:** Wording-length changes break the clang-format line-wrapping of test expected-strings: `sed` the wording first, then `clang-format -i tests/test_suite.c`, then the `--dry-run --Werror` check — the round-1 formatted layout is stale once strings grow.
- **Verification:** PASSING — CI-mirrored ubuntu:24.04 container re-run: gcc+clang builds 0 warnings, 58/58 CMocka (incl. updated `test_prompt_rendering` expectations), clang-tidy clean, ASan/UBSan/LSan clean (`ALL_GATES_PASSED`). Local: `make check-scrub` OK, `clang-format --dry-run --Werror` clean.

### 2026-11-17 — Device-code approval window in the prompt: `[prompt] show_expiry` + `{expiry}` token
- **Task:** User follow-up on the demoted host status line: the trailing line should also be able to show how long the user has to complete the approval ("Waiting for your approval; ..."), optionally — only displayed if a `[prompt]` config option is set and/or a prompt placeholder is present.
- **Decisions & Rationale:** New `[prompt] show_expiry` boolean, **default `false`** (opt-in — new information, unlike `show_host` which was already shown). `true`: built-in default template gains the clause → "Waiting for your approval on <host> (expires in 15 minutes); ...". New `{expiry}` template placeholder in ANY `init_message`: expands to a human-readable duration via new static `format_expiry_seconds()` in pam_module.c ("45 seconds" < 1 min; whole minutes rounded up < 1 h; "N hour(s) [M minute(s)]" ≥ 1 h; round-up happens on TOTAL minutes first so 7199 s → "2 hours", never "1 hour 60 minutes"); unknown window (0) → empty string (same convention as `{host}` off). OR-semantics per user request: `show_expiry` alone (default template) or `{expiry}` alone (any template) is enough. Value shown = `dev.expires_in` — the provider's `expires_in` clamped by `[runtime] max_poll_seconds`, i.e. the module's effective wait window (documented as such; honest, conservative). `render_prompt_message()` gained an `int expires_in` parameter (public-header signature change; `pam_sm_authenticate` passes `dev.expires_in` — prompt renders in Step 4, after `request_device_authorization` in Step 3). Default-template rendering refactored: the 4 host-branch snprintfs collapsed into 2 (direct/plain URL) + optional `host_clause[264]` (" on <host>") + `expiry_clause[48]` (" (expires in <X>)") composed into the trailing line — host-off/expiry-off combinations render byte-identical to the pre-change wording. No shipped template/example carries `{expiry}` (opt-in), so default prompt is unchanged. Related history: the live in-place `show_countdown` MM:SS timer was built 2026-11-08 and deliberately removed 2026-11-09 (inter-poll repaint noise) — this is the static one-shot successor, not a resurrection.
- **Gotchas & Lessons:** (a) 14 `render_prompt_message` call sites in test_prompt_rendering needed the new arg — updated with a /tmp Python regex helper (pattern anchored on the `"BCD-123"[...]` code arg + known buffer identifiers; assert count == 14), then `clang-format -i tests/test_suite.c` to normalize (file was format-clean before, so diff stays scoped). (b) `format_expiry_seconds` rounds up on total minutes, not per-unit — naive `expires_in/3600` + `ceil(%3600)` produced "1 hour 60 minutes" at 7199 s.
- **Verification:** PENDING the CI-mirrored ubuntu:24.04 container run. New CMocka coverage in `test_prompt_rendering`: default template with show_expiry on (900 s → "(expires in 15 minutes)", direct form), 45 s → "(expires in 45 seconds)" (plain form), unknown window (0) with flag on → no clause, flag off with 900 s → no clause (opt-in regression); `{expiry}` token: 900 → "15 minutes", 3600 → "1 hour", 0 → "Approval window: \n" (empty expansion). Config tests: `show_expiry` default 0 in `test_parse_config_file_minimal_valid`; `show_expiry = true` → 1 in `test_parse_config_file_full_sections`. Docs: shipped config `[prompt]` placeholder list + commented `#show_expiry = true`, getting-started.md placeholder list + option doc, CHANGELOG [0.3.3] Added bullet.

### 2026-11-17 — Host display UX follow-up: demoted to trailing status line + gated behind `[prompt] show_host`
- **Task:** User follow-up on commit `5c039d4` (the `Host:` credential-line): (a) demote the host display into the trailing status line ("Waiting for your approval on <host>; ...") so the credential block keeps its original two lines; (b) gate the display behind a config key so deployments can opt out.
- **Decisions & Rationale:** New `[prompt] show_host` boolean, **default `true`** ("opt out" semantics). `true`: built-in default template names the host in the trailing status line; `{host}` expands to the hostname. `false`: built-in default reverts to the exact pre-`5c039d4` host-free wording; `{host}` expands to an **empty string**; `gethostname()` is not called at all (empty `host_disp`). `{host}` = bare hostname (or empty) — predictable placeholder semantics; presentation glue (" on ") lives in the template text. All shipped templates (`config/pam_oidc_device.conf`, `examples/{cilogon,entra_id,keycloak}.conf`, `tests/e2e/pam_oidc_device.e2e.conf`) demoted to the "on {host}" status-line form; caveat documented: with `show_host = false` a custom template's "on {host}" renders "on ;" — opt-out deployments should drop the clause or clear `init_message` (the built-in default adapts automatically).
- **Gotchas & Lessons:** (a) Test configs are built with `memset(&cfg, 0, ...)` → `show_host` is 0 unless set explicitly: every existing `render_prompt_message` call site expecting host output needed `cfg.show_host = 1` (re-grep all call sites). `init_config_defaults()` in test_suite.c mirrors load_config defaults — keep both in sync when adding keys. (b) Terminal output in this environment escapes backslashes (`\` shown as `\\`), making C-literal `\n` vs `\\n` diagnosis from displayed output unreliable — probe with `hex(ord(c))` character codes instead of eyeballing reprs. (c) Editor-tool JSON escaping + C file bytes + shell heredocs layer up; for backslash-laden text (C string literals like `"show_host = false\n"`) a backslash-free Python helper using `chr(92)` is the reliable route.
- **Verification:** PENDING the CI-mirrored ubuntu:24.04 container run (gcc+clang builds, CMocka, clang-tidy, sanitize). New CMocka coverage: default-template host-on/host-off (direct + plain URL forms), `{host}` on/off substitution, non-printable hostname accepted when host is gated off, `show_host` parse (false→0) + default-preserved (1) in config tests.

### 2026-11-17 — F1 review finding: device-code phishing corrected in threat model; target host now shown in prompt (`{host}`)
- **Task:** Address review finding F1 (HIGH): `docs/threat-model.md:75` credited PKCE with defeating a "code-phishing relay", but device-code *phishing* (attacker initiates the flow from the victim's host, social-engineers approval) is not stopped — the attacker holds the `code_verifier` and the identity really is the victim's.
- **Decisions & Rationale:** Two-part fix. (1) **Docs (the core ask):** threat matrix — dropped "code-phishing relay" from the "Device Code Interception / Replay" row and added a scope-boundary note that PKCE only stops an *interceptor* who was not the flow's initiator; added a new **High** "Device-Code Phishing (Social Engineering)" row documented as a **residual risk**; new deep-dive §8 (attack walkthrough, why PKCE/identity checks can't stop it, mitigations: host in prompt, prefer IdPs whose approval page shows client context, network restrictions / second factor for privileged accounts, user awareness, residual-risk WARNING callout); TOC entry; out-of-scope item 4 (approver vigilance & provider approval pages). (2) **Code mitigation:** `render_prompt_message()` gained a `host` parameter (public-header signature change — user instruction explicitly requested the prompt change) + a `{host}` `init_message` placeholder; default template shows `Host: <hostname>`; `pam_sm_authenticate()` resolves it via `gethostname()` (256-byte stack buffer; failure → logged + "(unknown)" — host bytes still pass the `is_safe_rendered_prompt()` fail-closed check). All shipped `init_message` templates (`config/pam_oidc_device.conf`, `examples/{cilogon,entra_id,keycloak}.conf`, `tests/e2e/pam_oidc_device.e2e.conf`) carry the host line — remember from 2026-11-10 gotcha that deployments with `init_message` set do NOT get the built-in default. **Connecting-client IP is NOT shown:** PAM exposes no peer-address API; documented honestly instead (threat model §8 + CHANGELOG).
- **Gotchas & Lessons:** (a) The CMocka `test_prompt_rendering` had one 6-arg call site (the ESC-in-URL assert) that the harness caught — when changing a function signature, re-grep every call site for arg count, not just visual match. (b) `docs/threat-model.md` TOC sub-items use **2-space** indent, and the §1 placeholder list contains a literal double-backslash `\\n` (markdown-escaped) — both caused editor anchor misses; byte-level checks (python repr) before re-anchoring. (c) Long heredoc commands from this environment get corrupted in transit — write helper .py files with the editor tool and run `python3 /tmp/x.py` instead.
- **Verification:** LOCAL (macOS) only — isolated harness (awk-extracted real `is_safe_terminal_string` (config.c) + `is_safe_rendered_prompt`/`render_prompt_message` (pam_module.c)) compiled and ran CLEAN under strict flags (`-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Wformat-security -O2`) on **clang, clang+ASan/UBSan, and gcc**: ALL PASS (11 assertion groups incl. `{host}` substitution, both default-template shapes with `Host: testhost`, non-printable-hostname rejection, NULL-host rejection, truncation). `clang-format --dry-run --Werror` clean on all 3 touched C/H files (ran `clang-format -i tests/test_suite.c` once); `make check-scrub` green. NOT RUN: `make`/`make test`/clang-tidy/cppcheck/`test-sanitize`/e2e (no libpam on this host). STILL REQUIRED: Linux gates / CI (compile-matrix gcc+clang, full CMocka incl. updated `test_prompt_rendering`, e2e sandbox — prompt text not asserted there, so the new host line is safe).

### 2026-11-17 — CI green-up: e2e uid0-alias conf backup EACCES (non-root shell redirection) + EL8 dnf best-candidate failure
- **Task:** Two CI failures on the uid-0 `allow_root` guard commit: (1) `e2e-sandbox` — `run_e2e.sh:190: /tmp/pam_oidc_device_e2e/conf.uid0.orig: Permission denied` after scenario 6/8; (2) `distro-build` EL8 — dnf `cannot install the best candidate ... nothing provides libgcc >= 8.5.0-31.el8_10 needed by gcc-8.5.0-31.el8_10`.
- **Root cause 1 (regression in the new uid0-alias scenario):** CI runs `./tests/e2e/run_e2e.sh` as a non-root user with passwordless sudo, so `$SUDO cp "$CONF" "$WORKDIR/conf.uid0.orig"` created a **root:root 0600** backup (cp-as-root copies the source's 0600 mode from `/etc/pam_oidc_device.conf`). The follow-up restore `$SUDO tee "$CONF" < "$WORKDIR/conf.uid0.orig"` fails because the **input redirection is opened by the non-root shell itself**, not by sudo → EACCES. General rule: in this script any file a later *local* redirection must read must be created via a local redirection (`$SUDO cat <rootfile> > local`), never via `$SUDO cp`.
- **Fix 1:** `tests/e2e/run_e2e.sh` scenario 6 now writes the backup with `$SUDO cat "$CONF" > "$WORKDIR/conf.uid0.orig"` + `chmod 600` (live configs may hold client credentials), and the EXIT trap now also `rm -f` the `conf.uid0.{orig,tmp}` files so a mid-flight abort does not leave a config copy (possibly with secrets) in the workdir.
- **Root cause 2 (upstream mirror skew, not our code):** Rocky 8 AppStream published `gcc-8.5.0-31.el8_10` without its matching `libgcc`/`libgomp` packages on the mirrors dnf was reading.
- **Fix 2:** `.github/workflows/distro-build.yml` EL8 install step now falls back to `dnf install -y --nobest ...` (same package list) when the best-candidate resolve fails, allowing an older resolvable gcc. Scoped to EL8 only; EL9/EL10 paths untouched.
- **Verification:** `bash -n tests/e2e/run_e2e.sh` clean; workflow YAML parses (`python3 -c yaml.safe_load`). **NOT yet verified on Linux** — both fixes need the CI `e2e-sandbox` and `EL8: Rocky Linux 8 (RPM)` jobs to go green (or an ubuntu:24.04 container run of `run_e2e.sh` for the script fix; the EL8 mirror issue is only reproducible against the affected mirrors).
- **Follow-ups / Open Items:** If EL8 keeps flapping on the broken candidate, consider pinning `gcc` to a resolvable version instead of `--nobest`. `shellcheck` is not in the local macOS toolchain; CI lint does not gate `.sh` files beyond `make lint` (no shellcheck step confirmed in `lint.yml` at edit time).

### 2026-11-17 — F2 regression test was itself buggy: inverted `json_object_object_add` check
- **Task:** The F2 commit ("fail-closed deny-only group policy") still failed Linux CI under both gcc and clang: `test_verify_group_membership_deny_only_fail_closed` → `assert_non_null(uinfo)` at `tests/test_suite.c:1248` (F2) / the allow-only mixed-array step. Reproduced locally in `ubuntu:24.04` Docker (clang 18, json-c 0.17, cmocka 1.1.7) — **deterministic, not a compiler quirk**.
- **Root cause (the whole rabbit hole):** the F2 test helper `group_claim_uinfo()` did `if (!j_claim || !json_object_object_add(uinfo, "groups", j_claim)) { put; return NULL; }`. But json-c's `json_object_object_add()` returns **0 on success, -1 on failure**, so `!json_object_object_add(...)` is true **exactly on success** → the helper freed the tree and returned NULL on the success path, and returned the tree on the failure path. `assert_non_null(uinfo)` then failed on every Linux build. Confirmed by: (a) a standalone probe (`json_object_object_add` on a fresh object prints `rc=0` on success), (b) gcc's disassembly of the helper matching the source logic (`cmp w0,#0; b.ne` into the put/NULL block on rc==0), and (c) an LD_PRELOAD shim showing `object_add#1 … -> rc=0` yet the test still failing.
- **Fix:** `tests/test_suite.c` `group_claim_uinfo()` now checks `json_object_object_add(...) != 0`. **No module code changed** — production (`src/`) never calls `json_object_object_add()`. CHANGELOG `[Unreleased]` gained a Testing entry.
- **Gotchas & Lessons:**
  1. **json-c `json_object_object_add` (and the `_add` family) return 0-on-success / -1-on-failure** — the opposite of the "nonzero = success" convention most libc helpers use. Never write `!json_object_object_add(...)` to mean "did it fail"; write `... != 0`.
  2. This bug was **invisible in the local macOS harness** because (a) the full CMocka suite can't build without Linux PAM headers, and (b) the isolated ASan/UBSan harness verified the *production* `verify_group_membership()` gate (byte-identical copy), not the test *helper* that feeds it. A helper bug only shows up when the real suite runs against a real json-c on Linux.
  3. **Reproduction recipe on macOS (no PAM):** `docker run --rm -v <repo>:/work -w /work ubuntu:24.04` after `apt-get install -y clang gcc make libpam0g-dev libcurl4-openssl-dev libjson-c-dev libcmocka-dev libssl-dev`; then `make test CC=clang EXTRA_CFLAGS=-Werror`. A persistent dev image (`pam-dev`) with those + gdb avoids re-running apt each time.
  4. Debugging dead-ends that looked plausible but were NOT the cause: clang miscompile (disproved — gcc shows the same logic), GOT/PLT slot corruption & `_dl_fixup` re-binding (red herring; slots read correctly at failure), ASan/UBSan/valgrind (all clean — because there is no memory error; it's a pure logic inversion in the helper), a "flaky"/layout-dependent failure (it's deterministic).
  5. `readelf -r`/`objdump -d` on the test binary confirmed the helper goes through the PLT and that json-c links dynamically (`libjson-c.so.5`); a `strdup`/malloc OOM theory was also wrong — `object_add` returned 0.
- **Verification (Linux, `ubuntu:24.04` Docker):** `make test CC=clang EXTRA_CFLAGS=-Werror` → 58/58 PASS; `make test CC=gcc EXTRA_CFLAGS=-Werror` → 58/58 PASS; `make test-sanitize CC=clang EXTRA_CFLAGS=-Werror` (ASan+UBSan+LSan) → 58/58 PASS; `make lint` → OK; `make check-scrub` → OK. Verified on both the F2 tree and HEAD (F3).
- **Follow-ups / Open Items:** Commit the one-line test fix; Docker e2e (`make sandbox`) re-run to confirm all 8 scenarios (incl. `uid0-alias-denied` + F2 repro claims) still pass; then version bump to 0.3.3 and tag.

### 2026-11-16 — F3 security fix: `allow_root` guard now targets uid 0, not the name "root"
- **Task:** Fix a HIGH-severity bypass (reproduced in Docker): `allow_root = false` refused only the account literally named `root`; an alternative uid-0 account (`toor` via `useradd -o -u 0`, or any site-specific admin alias) authenticated fine.
- **Changes:** `src/identity.c` `verify_user_access()`: the root gate now runs when `!cfg->allow_root`; it denies on name `root` **or** on `getpwnam_r(pam_user, ...)` resolving to `pw_uid == 0`. Added `#include <pwd.h>`. New e2e scenario `uid0-alias-denied` (Dockerfile creates `toor` with `-o -u 0`; run_e2e.sh idempotently creates it too, now 8 scenarios; the scenario temporarily strips `allow_users` from the fixture config via `sudo tee` so ONLY the uid-0 gate can block `toor` — see gotchas). Unit test pins the not-found path (a >32-char impossible login name passes the uid gate; still blockable via `deny_users`). Docs updated: `docs/access-control.md` (param table + Root Default-Deny rule), `docs/threat-model.md` (gate-1 table + bullet), `docs/testing.md` (scenario table, PAM-rc table, checklist), `config/pam_oidc_device.conf` comment, `include/pam_oidc_device.h` (config field + `verify_user_access` doc). CHANGELOG `[Unreleased]`/`### Fixed` entry added.
- **Decisions & Rationale:** Deliberate deviation from the reviewer's suggested `if (getpwnam_r(...) != 0 || !res) return 0;`: a name that resolves to **no** local account is NOT refused by this gate. Rationale: the module supports PAM flows where the local account does not yet exist (IdP-first), so fail-closing on "not in /etc/passwd" would turn gate 1 into a "local account must exist" requirement — a much broader regression than F3. Local uid-0 accounts are *always* in the account database (shadow(5) holds hashes; entries live in /etc/passwd or an NSS source getpwnam_r consults), so deny-on-confirmed-uid-0 plus the name-based `root` check fully closes the bypass; an NSS lookup failure only leaves the name check in place, which is out of scope under the threat model's untampered-host assumption.
- **Gotchas & Lessons:** (1) `getpwnam_r` returns 0 on success with `*result` possibly NULL (not found) and ERANGE on a too-small buffer — test `ret == 0 && res != NULL && res->pw_uid == 0`. (2) A 4096-byte `pw_buf` stack buffer in a PAM module is fine (established pattern; PAM runs in the service process). (3) CMocka tests can't deterministically create a second uid-0 user (CI runs unprivileged) — pin uid-0 alias behavior in the e2e sandbox instead; the unit test instead pins the fail-open-on-not-found semantics with a name longer than Linux's 32-char login limit (guaranteed absent). (4) `useradd -o -u 0 toor` needs `-o` (non-unique uid) and works in the fresh ubuntu:24.04 image where root owns uid 0. (5) **Masking gate:** the e2e fixture sets `allow_users = alice,bob`, which alone would already refuse `toor` — a new scenario that doesn't neutralize the allow list can't distinguish the uid-0 fix from an allow-list miss (both give rc 6). Fix: scenario 6/8 temporarily strips `allow_users` from the live config (`sudo tee` preserves the root:root 0600 inode; a plain `> $CONF` redirect runs as the invoking user and fails on a 0600 root-owned file), then restores it. Pre-fix the scenario yields PAM_AUTH_ERR (7, claim mismatch) instead of 6 — regression pinned.
- **Verification:** LOCAL (macOS) only — `clang-format --dry-run --Werror` clean on `src/identity.c`, `tests/test_suite.c`, `include/pam_oidc_device.h`; `make check-scrub` green; `packaging/gen-changelog.py` still parses; `bash -n tests/e2e/run_e2e.sh` clean; an isolated harness with the post-fix gate logic copied verbatim compiled zero-warning under the strict flag set (gcc) and passed all behavior asserts incl. ASan+UBSan (uid-0 alias deny, root-name deny, allow_root=true pass, not-found pass, deny_users still win). NOT RUN: `make`/`make test`/`test-sanitize`/clang-tidy/cppcheck/e2e-sandbox (no PAM headers on this host). STILL REQUIRED: Linux gates / CI.
- **Follow-ups / Open Items:** Linux CI confirmation (unit + e2e `uid0-alias-denied`); ship with the next version bump (0.3.3) alongside the F2 group-claim fix.

### 2026-11-16 — F2 security fix: deny-only group policy fail-closed on unusable claims
- **Task:** Fix a HIGH-severity bypass (reproduced in Docker): with `deny_groups` set and `allow_groups` empty, a groups claim that is missing, JSON `null`, of a wrong type (e.g. `123`), or a comma-delimited string >255 bytes (the fixed `char val_copy[256]` scratch buffer made `copy_checked` fail and the split silently skipped) all returned "allowed".
- **Changes:** `src/identity.c` `verify_group_membership()` is now fail-closed whenever any group policy is active: missing/invalid UserInfo JSON → 0; claim absent or JSON `null` (json-c returns a NULL pointer for null) → 0; claim neither array nor string → 0; array containing a non-string element → 0 when `deny_active` (allow-only still skips such elements — behavior preserved); comma-delimited strings are split in place on a `malloc(strlen+1)` heap copy instead of the 256-byte stack buffer, and `malloc`/copy failure → 0 (frees on all paths). New CMocka test `test_verify_group_membership_deny_only_fail_closed` (+ `group_claim_uinfo` helper) covers all five bypass shapes, a 300-byte claim with the denied token leading and at byte 260 (past the old cap), and a long clean claim (no spurious deny). Docs updated: `docs/access-control.md` §2 rule 5 (Fail-Closed on Unusable Claims) and `docs/threat-model.md` Figure 2 gate-4 reject column. `CHANGELOG.md` gained a new `## [Unreleased]` / `### Fixed` security entry (0.3.2 is already tagged).
- **Decisions & Rationale:** Fail-closed applies to *all* active policies, not just deny-only: if membership cannot be established, treat it as a non-match (deny for allow-only, deny for deny-only). The allow-list behavior for non-string array elements is deliberately unchanged to avoid a second behavior break. The whole-string fast-path (`group_value_denied(val)` before splitting) is untouched.
- **Gotchas & Lessons:** (1) json-c maps a JSON `null` value to a `NULL` pointer, so `json_object_object_get_ex(...) || !j_group` conflates "absent" and "null" — that conflation is now safe (both deny) but was the latent bypass. (2) `strtok_r` needs a mutable copy sized to the full input; the old 256-byte cap was invisible because `copy_checked` returns a code nobody treated as fatal. (3) Banned `strcpy`/`strcat` even in test code — build long claims with `memset`/`memcpy`. (4) A test that builds a `json_object` just to serialize it must `json_object_put()` the intermediate or LSan flags it.
- **Verification:** LOCAL (macOS) only — `clang-format --dry-run --Werror` clean on `src/identity.c` + `tests/test_suite.c`; `make check-scrub` green; `packaging/gen-changelog.py` still parses and emits a valid `0.3.2-1` RPM entry; an isolated harness with the post-fix split loop copied verbatim compiled zero-warning under the full strict flag set (gcc; clang binary built OK but macOS ASan runtime hung — environment) and all 10 behavior asserts passed, including under gcc ASan+UBSan. NOT RUN: `make`/`make test`/`test-sanitize`/clang-tidy/cppcheck/e2e-sandbox (no PAM headers on this host). STILL REQUIRED: Linux gates / CI.
- **Follow-ups / Open Items:** Linux CI confirmation of the new CMocka test; Docker e2e re-run of the original repro (`DENY_GROUPS=contractors` with the 371-byte string, `123`, and `null` claims — all must now deny); ship with the next version bump (0.3.3).

### 2026-11-16 — `make fuzz` container one-liner: preseed tzdata (Chicago) + noninteractive
- **Task:** The suggested `docker run` one-liners (Makefile `fuzz-preflight` guidance +
  `tests/fuzz/README.md`) hung on tzdata's interactive "Please select the time zone" prompt.
- **Changes:** Both now pass `-e DEBIAN_FRONTEND=noninteractive -e TZ=America/Chicago` and preseed
  debconf **before** `apt-get` (`tzdata tzdata/Areas select America` +
  `tzdata tzdata/Zones/America select Chicago` via `debconf-set-selections`). The Makefile now
  prints the command as a single `printf '%s\n' "…"` line (one-liner; no backslash-continuation
  echoes).
- **Gotchas & Lessons:** (1) In make recipe lines, `\$PWD` is corrupted — make expands the
  undefined variable `$P`, leaving a stray backslash (`\WD`). Use `\$$PWD` (→ shell `\$` →
  literal `$PWD`) or `$$PWD` inside single quotes. (2) Multi-line guidance via
  `echo '…\'' / \\` continuations is a quoting trap across dash vs bash-as-sh echo semantics —
  prefer `printf '%s\n'`. (3) `debconf-set-selections` ships in the base `ubuntu:24.04` image,
  so preseeding works before any `apt-get install`.
- **Verification:** Both the preflight-printed one-liner and the README block were executed verbatim
  in a fresh `ubuntu:24.04` container — no prompts, `Current default time zone: 'America/Chicago'`,
  all six fuzz harnesses PASS (`FUZZ_MAX_TIME=5`).

### 2026-11-15 — Added opt-in libFuzzer harnesses + `make fuzz` (tests/fuzz/)
- **Task:** Add "loose" crash/UB/leak fuzzing as an opt-in `make fuzz` target, without touching `make lint` or any CI workflow.
- **Changes:** New `tests/fuzz/` with six libFuzzer harnesses — `fuzz_config` (`parse_config_file` via `fmemopen`), `fuzz_jwt_extract` (`jwt_extract_claim_string`), `fuzz_token_meta` (`verify_token_metadata`), `fuzz_string_validators` (`is_valid_https_url`/`is_safe_terminal_string`/`is_safe_user_code`/`copy_checked`/`parse_loglevel`), `fuzz_verify_claim` (`verify_claim`; regex *subject* only, pattern held fixed), `fuzz_pkce` (`pkce_compute_s256_challenge`) — a hand-picked seed corpus under `tests/fuzz/seed/<target>/`, a `tests/fuzz/README.md`, and a Makefile `fuzz`/`fuzz-build` block plus a `fuzz-preflight` gate that fails fast with per-platform install guidance (clang missing / dev headers missing / non-Linux host → container one-liner).
- **Decisions & Rationale:** Kept it fully opt-in and out of lint: `make lint`/pre-commit globs are `src/*.c include/*.h tests/*.c` (non-recursive), so `tests/fuzz/*.c` is never lint-checked or CI-gated. Each harness re-instruments the full module source set under `-fsanitize=fuzzer,address,undefined,leak -fno-omit-frame-pointer` (the `test-sanitize` sanitizer set + libFuzzer) and drives one leaf function; the PAM handle is `NULL` (proven safe by the CMocka suite). Fuzzing the regex *subject* (not the *pattern*) keeps `verify_claim` deterministic and crash-focused. Seeds are **copied** (never mutated) into `build/fuzz/corpus_<t>/`; crash reproducers land in `build/fuzz/` (git-ignored).
- **Gotchas & Lessons:** (1) libFuzzer's duration flag is `-max_total_time=N`, **not** `-max_time` (the latter is silently ignored → unbounded run; caught when a pass kept climbing past the tool's 300 s window and had to be `docker kill`ed). (2) GNU `cp` needs `-R` to copy a directory's contents (`cp -fR tests/fuzz/seed/<t>/. build/fuzz/corpus_<t>/`); plain `cp -f .../.` fails silently on Linux, so seeds never loaded (libFuzzer reported "0 files found" until fixed, then "2 files found"). (3) On Linux the PAM headers live under `security/` (`security/pam_modules.h`/`security/pam_ext.h`), **not** `pam/pam.h` (the macOS/HP-UX layout) — so the `fuzz-preflight` probe includes the module's own `pam_oidc_device.h` + `openssl/evp.h` and links `$(LIBS)`, rather than guessing individual headers.
- **Verification:** In the `ubuntu:24.04` CI-mirror container (clang 18.1.3): `make fuzz-build` compiles all six with **zero warnings** (`-Wall -Wextra`); `make fuzz FUZZ_MAX_TIME=10` loads the seed corpus for every target and reports all six **PASS — crash/UB/leak-free** (up to ~1.8 M execs on the string/pkce targets). Baseline is clean. `make clean` wipes `build/fuzz/`; no C/packaging/CI behavior change.
- **Follow-up:** Optional longer runs (`make fuzz FUZZ_MAX_TIME=3600`); extend to `verify_group_membership` (json array/string claims) and the cURL callbacks if a PAM-independent harness is wanted; a standalone (non-CI-gating) `fuzz.yml` workflow if continuous fuzzing is desired.

### 2026-11-15 — Accessibility polish: plain-word symbols, link labels, TOC consistency
- **Task:** Second accessibility audit pass (WCAG 2.4.4/2.4.5 + plain-language prose).
- **Changes:** (1) `≠` → "does not match" (testing.md status table); all inline `→`
  arrows in *prose* replaced with explicit words ("results in", "maps to", "shows",
  "the result is") across `docs/testing.md`, `docs/threat-model.md` (Figure 2
  caption now reads "next, …; and finally, …"), `docs/access-control.md`, and
  `examples/README.md`. Arrows inside code fences / ASCII diagrams untouched.
  (2) Bare-URL link label fixed (README footer → "[NCSA website]").
  (3) Every repeated link label made context-unique (README ×2, getting-started ×5,
  threat-model ×4). (4) `## Table of Contents` added to the four long guides lacking
  one (`getting-started`, `testing`, `jwt-validation`, `access-control`) in the
  threat-model format; anchors verified against GitHub's slug algorithm with a
  Python check (all valid, incl. the tricky `#6-enterprise-linux--authselect`,
  `#1-local-account-filtering-allow_users--deny_users` double-hyphen slugs).
- **Standing invariants:** `.agents/context.md` §8 now requires TOC-on-long-guides,
  descriptive context-unique link labels, and words-not-symbols in prose; §10.4
  audit prompt extended accordingly. CHANGELOG `[Unreleased]` → Fixed.
- **Gotchas & Lessons:** macOS `security/pam_ext.h` declares `pam_prompt`'s handle
  **non-const** — a `const pam_handle_t *` helper signature breaks the clang build
  under `-Werror` (gcc/tests pass silently); keep helper signatures
  `pam_handle_t *`. The flaky terminal corrupts long multi-line heredocs — use the
  editor tool to create script files, not `cat > file <<EOF`.
- **Verification:** docs-only round (no C changes since the last green gate).
  Grep sweep: zero `≠`, zero prose `→` (fence-external), zero bare-URL labels,
  zero duplicate link labels; TOC-anchor checker passes on all five long guides.
- **Figures 1 & 2 → tables:** both fixed-width box diagrams in
  `threat-model.md` are now tables (Figure 1: zones + relationships;
  Figure 2: five pre-flight gates with reject/continue conditions, incl.
  the fail-closed UserInfo failure the old art omitted). Refined rule of
  thumb: *any diagram whose branches all exit to the same terminal state is
  a linear early-exit pipeline — table it*; keep ASCII art (with prose
  caption) only for branches that re-converge into *different* later steps.
  Mermaid was rejected: GitHub renders it, but as raw SVG with weak
  screen-reader semantics, and it's a GitHub-only extension in plain-MD docs.
  The old art also wrapped illegibly on GitHub mobile (~77 chars wide).
- **Post-review accuracy fix (code-verified vs `src/identity.c`):** the first
  table pass carried two factual slips: gate 4 said "local NSS group
  memberships" (the codebase contains zero NSS calls — `verify_group_membership()`
  matches UserInfo *claim* values against allow/deny lists), and gate 1
  omitted the default `root` denial (`allow_root = true` opt-in). Lesson: when
  converting or keeping figures, audit them against the implementation — do not
  transcribe from the old art or adjacent prose. Also de-duplicated Figure 1
  (security properties stated once, in the relationships table; zone rows list
  contents only; added `*Zones:*` / `*Trust relationships:*` lead-ins).

### 2026-11-15 — Full accessibility review (WCAG 2.1 AA): user-visible failure notices + docs fixes
- **Task:** Repo-wide accessibility review of terminal UI/UX + documentation. Confirmed
  earlier fixes hold: badge alt text, threat-model figure captions, every code fence
  language-tagged, ASCII art only in `docs/threat-model.md` (captioned), all tables have
  header rows, no color-only cues, no stray LaTeX.
- **Decisions & Rationale:** Core UI/UX gap found: *every* failure path in
  `pam_sm_authenticate()` was log-only — users saw an unexplained "permission denied"
  (WCAG 3.3.1 *Error Identification*). Added `notify_user_failure()` (static, best-effort
  `pam_prompt()`/`PAM_TEXT_INFO`) plus three static, deliberately-generic notices
  (`USER_NOTICE_SERVICE` / `USER_NOTICE_DENIED` / `USER_NOTICE_EXPIRED`) at 14 failure
  sites. No notice on `PAM_ABORT` (user-initiated Ctrl-C) or when the conversation
  itself fails. Wording never reveals *which* control denied the attempt — details
  stay in the syslog audit trail.
- **Gotchas & Lessons:** Ubuntu's `security/pam_ext.h` declares
  `pam_prompt(pam_handle_t *pamh, ...)` **non-const** — a `const pam_handle_t *` helper
  signature breaks the clang build under `-Werror`
  (`-Wincompatible-pointer-types-discards-qualifiers`); the gcc build/tests pass silently.
  OpenSSH keyboard-interactive buffers `PAM_TEXT_INFO` until a prompt round-trip, so
  post-Enter notices may not display on every SSH client — documented as best-effort
  (local console always shows them) in code comment, README `## Accessibility`, and
  getting-started §7.
- **Docs touched:** README (Accessibility bullet + new §7 link), getting-started §7
  (new *User-Visible Failure Notices* subsection), `examples/README.md` (literal
  `$\rightarrow$` → `→`), CHANGELOG `[Unreleased]`, `.agents/context.md` §8 + §10.4
  (standing invariant: "no failure path is log-only" + audit checklist item).
- **Verification:** `ubuntu:24.04` Docker gate (§3.3) **PASSED end-to-end**: gcc +
  clang builds (zero-warning), CMocka 57/57 under both compilers, `clang-tidy` gate
  clean, `make test-sanitize CC=clang` (ASan/UBSan/LSan) 57/57. (First run caught
  the const-qualifier bug on the clang build; fixed and re-verified.)
  `make check-scrub` + `make check-licenses` pass on macOS.
- **Follow-ups / Open Items:** Optional one-line "out of scope" note in README
  Accessibility section (IdP web pages where the code is approved are not this
  project's content).

### 2026-11-15 — Accessibility alignment: docs + terminal UX to WCAG 2.1 AA (§508 / IL + US federal policy)

- **Task:** Make repository documentation and the documented terminal UX
  conform to State of Illinois and US federal accessibility policy.
- **Decisions & Rationale:** Three overlapping mandates govern NCSA/UIUC
  public-facing docs and all converge on **WCAG 2.1 Level AA** — IITAA 2.1
  (30 ILCS 587), ADA Title II (28 CFR Part 35, effective April 2026), and
  Rehabilitation Act § 508 (29 U.S.C. § 794d, via 36 CFR Part 1194) — so no
  code change was needed — the terminal UX already satisfies the key criteria
  (verified in `src/pam_module.c`: text prompt always carries URL + code, QR
  is off-by-default and strictly supplemental, Enter/Ctrl-C keyboard control,
  no time-limited interaction the user cannot cancel). Changes: README gained
  an `## Accessibility` section (documentation conformance + terminal UX +
  supplemental-QR note + issue-reporting path); README badge alt text made
  meaningful (WCAG 1.1.1); `docs/getting-started.md` §4 gained an
  "Accessible by default" NOTE (text-first prompt, no color-only cues,
  `style = ascii` fallback, Enter/Ctrl-C).
- **Gotchas & Lessons:** prompt-template placeholders in docs are
  `{url}`/`{url_complete}`/`{code}` (NOT `{verification_uri}`/`{user_code}`)
  — same-session finding, same fix direction: docs must track
  `render_prompt_message()` in `src/pam_module.c`.
- **Verification:** docs-only; all claims spot-checked against source
  (`pam_module.c` Steps 4/4b/5, EINTR → `PAM_ABORT`). No build gates affected.
- **Follow-ups / Open Items:** independent review flagged the un-described
  ASCII art in `docs/threat-model.md` — fixed by adding "**Figure N — …**"
  prose descriptions (text alternatives, WCAG 1.1.1) before both figures;
  durable rule recorded in `.agents/context.md` (§5.2 WCAG 2.1 AA spec entry,
  §8 documentation quality bar, §10.4 audit checklist item).

### 2026-11-15 — Docs audit: polling-timing contradiction fixed repo-wide (README + getting-started)

- **Task:** User-driven review of `README.md` (polling-timing contradiction, dangling `If`
  clause, typos, line-wrap style) followed by a repo-wide sweep for the same
  polling-timing misrepresentation in other docs.
- **Decisions & Rationale:** Verified against `src/pam_module.c` Steps 4/4c/5: the module
  displays the sign-in prompt (Steps 4/4b), blocks on the mandatory `PAM_PROMPT_ECHO_ON`
  "Press [Enter] to begin..." (Step 4c), and only then polls — first poll immediate, no
  leading sleep. Docs corrected to that behavior:
  - `README.md`: "Standard RFC 8628 Flow" bullet no longer claims polling starts *before*
    Enter; the Enter step + OpenSSH `PAM_TEXT_INFO` flush rationale moved into "How It
    Works" step 2; two mini-paragraph bullets tightened; hard-wrapped sections unwrapped
    to the file's unwrapped majority style; Step-4 `required`-vs-`sufficient` warning
    rewritten with a main clause; sample config gained a commented `client_secret`.
  - `docs/getting-started.md` §4 NOTE: "pressing Enter does not start polling (that has
    already begun)" was the same wrong-side claim — rewritten: polling begins *after*
    Enter (first poll immediate); the true statement that the provider `expires_in`
    clock runs from device-code issuance (before Enter) is kept. Also fixed the
    misquoted prompt text ("Press ENTER to continue" → "Press [Enter] to begin...").
  - `docs/testing.md` §3.2: added the Enter pause to the flow summary.
- **Gotchas & Lessons:** The earlier note in this file ("polls immediately by default,
  best-effort Enter flush only when `require_keypress = true`") is **SUPERSEDED** — since
  v0.2.0 the confirmation is mandatory (CHANGELOG [0.2.0]) and polling begins only after
  Enter. `CHANGELOG.md` [0.1.0] "first poll immediate after prompt shown" is historical
  and was intentionally left as-is (standing invariant: never rewrite past releases); the
  [0.2.0] entry already supersedes it. `docs/threat-model.md`, `examples/README.md`,
  `SECURITY.md`, `CONTRIBUTING.md`, `.agents/context.md` checked clean — no
  when-polling-starts claims.
- **Verification:** Markdown-only changes (no build impact). Grep-verified: no residual
  "even before you press Enter" / "that has already begun" / "Press ENTER to continue"
  claims; README wrapping uniform; QR-fallback note appears exactly once. No code
  touched, so the Linux gates/CI status of the tree is unchanged.
- **Follow-ups / Open Items:** None.


### 2026-11-15 — Lower-level review findings (I-1…Q-2/T-2/B-1): dispositions recorded, no code change
- **Task:** Address the Info/Nit findings from the follow-up review: I-1 (claims-only local JWT),
  I-2 (unscrubbed `doc` release in `discovery_probe_pkce`), I-3 (`expires_in` fallback), Q-2
  (`discovery_probe_pkce` in the public header), T-2 (L-1-class gaps invisible to lint + sanitizers),
  B-1 (in-tree `.o` files).
- **Decisions & Rationale:** I-1/I-2/I-3 confirmed as documented-by-design / allowlisted
  (`JSON_PII_ALLOWLIST='doc'`, `check-memory-scrubbing.sh:117`) / defensive-with-clamp — accepted
  as-is, no change. B-1: objects are git-ignored; keep `make clean` habitual before packaging/audit.
  T-2's regex mitigation was already landed in the P2 S3 extension (verified: negative/positive
  self-tests + full ubuntu:24.04 gate green); the remaining mitigation — a standing code-review
  checklist item — was added to `.agents/context.md` §10.1 item 1 (enumerate every
  `free()`/`json_object_put()` release site and manually confirm the paired scrub; note the gate's
  bare-identifier/`*`/`&`-only scope). Q-2 is the only item with a real decision: `discovery_probe_pkce`
  is a genuine cross-TU internal helper (defined `src/http.c:208`, called from production
  `src/pam_module.c:1003` and by the test suite via the public header), not merely a testability export;
  moving it out of `include/pam_oidc_device.h` is an "ask first" boundary — deferred to user decision.
- **Gotchas & Lessons:** A "testability export" finding may understate the coupling — always grep
  for production call sites before treating a non-static symbol as test-only.
- **Verification:** docs-only delta; no build/test impact.
- **Follow-ups / Open Items:** None — Q-2 resolved by user decision: keep the declaration in the
  public header (consistent with the single-public-header pattern for all shared internal helpers;
  finding rated "awareness only").

### 2026-11-15 — Review remediation: L-1/L-2 scrub + S3 gate extension, T-1 backoff unit tests, Q-1 no-local-teardown markers
- **Task:** Implement the comprehensive-review recommendations (P2 L-1/L-2, P3 D-1/T-1/Q-1).
- **Decisions & Rationale:**
  - Both `poll_for_access_token()` re-parse sites now run `secure_zero_json_tree(*tok_json)`
    before `json_object_put(*tok_json)` (the prior tree is provably a 4xx
    `authorization_pending`/`slow_down` error tree — a 2xx always exits the loop — but
    scrub-before-release now holds on every release path), with a comment at each site making
    the (non-sensitive) nature of the prior tree auditable (D-1).
  - `scripts/check-memory-scrubbing.sh` S3 handle regex extended to
    `json_object_put\([*&]?handle\)` so pointer/dereference forms are gated; documented in the
    script header + known-limitations (out of scope: array indexing / temporaries).
  - Poll-interval backoff math extracted into exported helpers `poll_interval_after_slow_down()`
    / `poll_interval_after_transient()` (both call sites in the poll loop — HTTP 429/5xx AND
    transient cURL errors use the doubling helper). Prototypes live **only in
    `tests/test_suite.c`** (test-only externs, deliberately NOT added to
    `include/pam_oidc_device.h` to leave the public header untouched — the "ask first"
    boundary). New CMocka cases: `is_retryable_token_http_status()` matrix + backoff
    +5/double/clamp-at-120 math.
  - Q-1: doc blocks of `request_device_authorization()` / `poll_for_access_token()` now carry an
    explicit "NO local teardown — do not introduce function-local allocations" marker.
- **Gotchas & Lessons:** the poll loop has TWO doubling sites (HTTP 429/5xx branch and the
  transient-cURL-error branch), not one — grep before assuming; multi-line editor anchors in
  this file must match 16-space loop indentation exactly.
- **Verification:** `make check-scrub` clean locally (plus a negative/positive
  self-test of the new S3 dereference handling); ubuntu:24.04 container
  (§3.3 recipe): gcc + clang builds zero-warning, CMocka suite green
  (57 cases incl. the 2 new ones, run under gcc, clang, and ASan/UBSan/LSan),
  clang-tidy gate clean — all `GATES_ALL_GREEN`.
- **Follow-ups / Open Items:** none.

### 2026-11-15 — Restructured AI-agent docs: thin root `AGENTS.md` + canonical `.agents/` layout
- **Task:** Reorganize the AI-coding-agent instruction files to match the emerging cross-tool
  `AGENTS.md` standard: a thin, canonical root `AGENTS.md` (commands + hard boundaries up top)
  with thin symlinks for every tool, and deeper content under `.agents/`.
- **Decisions & Rationale:**
  - Root `AGENTS.md` was a *symlink* to the 651-line `.agents/context.md`; it is now a **real,
    thin (~150-line) file** leading with copy-paste build/verify commands and three-tier
    boundaries (Always / Ask first / Never). Deep architecture, protocol gotchas, reference, and
    audit-pass prompts stay in `.agents/context.md` (its § numbering is preserved so the `§X`
    references scattered across the repo remain valid).
  - Every tool entry point is now a **symlink** to the thin root `AGENTS.md` (more reliable than
    `@import` shims — the content is literally present at each path): `CLAUDE.md`, `.clinerules`,
    `.cursorrules`, `.roorules`, `.windsurfrules`, and `.github/copilot-instructions.md` (the
    latter was previously a 34 KB full *duplicate* of the doc — now a symlink, removing a
    maintenance trap).
  - Added `.agents/plans/` (feature plans / cross-tool handoffs) and `.agents/skills/`
    (agentskills.io-standard reusable workflows), each with a README.
  - Repointed the stale `AGENTS.md §X` external references (in `Makefile`, `CONTRIBUTING.md`,
    `docs/developer/review.md`, `scripts/check-memory-scrubbing.sh`, `.github/workflows/lint.yml`)
    to `.agents/context.md §X`.
  - Added `.agents/memory.local.md` to `.gitignore` (personal LLM scratchpad companion to
    `memory.md`).
- **Gotchas & Lessons:**
  - `AGENTS.md`'s `.gitattributes` already marks it `linguist-vendored` + `export-ignore`, so the
    new real file inherits the correct packaging/exclusion behavior — no `.gitattributes` change
    needed.
  - The `context.md` header previously claimed *it* was `AGENTS.md` and the symlink target;
    reworded so it self-describes as the deep companion the shims point readers to.
- **Verification:** All edits verified by re-grep — no stray `AGENTS.md §X` references remain in
  code/scripts/CI; `readlink` confirms every tool shim resolves to the root `AGENTS.md` (and
  `ai-instructions/*` to the `.agents/` docs). Docs- and config-only change: no C code touched, so
  the build/test/lint/sanitizer gates are unaffected. Still need to push + confirm in CI
  (docs-only; expect no job changes).
- **Follow-ups / Open Items:**
  - `.agents/skills/` now populated with 8 skills: `security-audit`, `protocol-compliance-audit`,
    `build-packaging-audit`, `code-quality-audit` (ported from `context.md` §10.1–10.4),
    `release-bump`, `sanitizer-audit`, `add-c-module`, and `run-e2e`.
  - If the repo grows, add nested `AGENTS.md` files under `src/`/`tests/` that *add* constraints
    (never contradict root).

### 2026-11-14 — Landed review fixes M1 + L1–L3 + I1–I3 (v0.3.1 tree, uncommitted)
- **Task:** Implement all seven findings from the 2026-11-14 comprehensive review — M1 (iss/aud silently skipped), L1 (provider-interval hard-fail), L2 (no JWT-`sub` vs UserInfo-`sub` check), L3 (unscrubbed `prompt_buf`), I1–I3 (informational) — code + tests + docs, then run the complete §3 gate matrix including the six-distro `distro-build` legs.
- **Decisions & Rationale:** **M1** — `parse_config_file()` (config.c) now *rejects* `verify_jwt_claims=true` with empty `issuer`/`audience` at load time (error log + `secure_memzero(cfg)` + `-1`), stronger than the review's "load-time warning": silently skipping iss/aud leaves claims-only inspection bound solely to "userinfo accepts this token". **L1** — provider `interval > MAX_SUPPORTED_POLL_INTERVAL` (120 s) now *clamps* with a warning instead of hard-failing (RFC 8628 §3.5 only forbids polling *faster*). **L2** — new `jwt_extract_claim_string()` (jwt.c, declared in the public header): same strict 3-segment / RFC 4648 §5 / object-payload validation as `verify_token_metadata()`, claims-only; `pam_sm_authenticate` extracts the access token's `sub` into stack `jwt_sub[JWT_SUB_CLAIM_MAX=256]` (local #define in pam_module.c) and compares with the UserInfo `sub`: missing `sub` on either side is skipped with a log (providers differ), present-but-mismatched or malformed fails closed (`PAM_AUTH_ERR`, "token substitution suspected"). **L3** — `prompt_buf` and `jwt_sub` scrubbed via `secure_memzero` on all exit paths; `scripts/check-memory-scrubbing.sh` `S2_ANCHORS` extended with `prompt_buf jwt_sub`. **I1** — pkce.c comment documents the 48-byte verifier draw as modulo-bias-free by construction (multiple of 3 → exact 6-bit Base64URL groups, full 384-bit entropy, no rejection sampling). **I2** — default `max_poll_seconds` 300 → 120 (PAM-safe ceiling) in `load_config()` + sample config with rationale. **I3** — VERBOSE full-UserInfo payload logging documented as by-design (docs/jwt-validation.md).
- **Gotchas & Lessons:** (1) cppcheck cannot model the `json_object_object_foreachC` macro loop — a `counter < N` comparison seeded to 0 is flagged "always false" (it folds the incremented counter to 0); fix by *decrementing* an opaque budget (`names_left`, seeded from `json_object_object_length()` with a range check, cap 32) instead of incrementing a counter. (2) `json_object_object_length()` returns `int` on EL8/EL9 json-c (0.13/0.14) but `size_t` on newer — seed via `const long claims_raw = (long)json_object_object_length(uinfo_json);` + explicit range check: exempt from `-Wconversion` *and* keeps the value opaque to cppcheck. (3) The EL8/EL9 distro gates are the only gates that catch (2) — the ubuntu:24.04 suite does not; any change touching json-c API usage needs the six-distro run. (4) clang-tidy required renaming the new `jwt_extract_claim_string` param `jwt_str` → `token` (header + source in lockstep); the pre-existing `jwt_str` in `verify_token_metadata` was never flagged. (5) First distro run failed EL8/EL9 on `-Wconversion` from (2) — fix → re-run the ubuntu:24.04 gate suite *and* sandbox before relaunching the distro matrix.
- **Verification:** ALL LOCAL, in Linux containers (macOS host), all green: ubuntu:24.04 suite — `make lint` (clang-format/clang-tidy/cppcheck/flawfinder/check-scrub), `make CC=gcc && make test CC=gcc`, `make CC=clang && make test CC=clang`, `make test-sanitize CC=clang`, `make check-licenses` → ALL_GATES_PASSED (re-run green after the final cast fix; `.gates.log` removed on success); `make -s sandbox` → SANDBOX_PASSED; six-distro matrix via a `distro-build.yml`-mirroring harness (`EXTRA_CFLAGS=-Werror` build + CMocka + rpm/deb build + package install + on-disk verification of `/lib64/security/pam_oidc_device.so` + `/etc/pam_oidc_device.conf`): **EL8 PASS, EL9 PASS, EL10 PASS, SUSE16 PASS, DEB13 PASS, UBU2604 PASS**. Nothing left for CI to prove beyond re-confirmation on push.
- **Follow-ups / Open Items:** Commit the 14-file working tree (src/{config,jwt,pam_module,pkce}.c, include/pam_oidc_device.h, tests/test_suite.c, scripts/check-memory-scrubbing.sh, config/pam_oidc_device.conf, CHANGELOG.md, README.md, docs/getting-started.md, docs/jwt-validation.md, docs/testing.md, .agents/memory.md); CI re-validates on push.

### 2026-11-14 — Comprehensive full-repo code review pass (read-only, v0.3.1 @ 597f618)
- **Task:** Deliver the comprehensive code-review report covering all of `src/`, `include/`, and the `Makefile` with file:line findings. Read-only — no code changes requested or made.
- **Decisions & Rationale (findings of record):** 1 **Medium** — `iss`/`aud` checks silently skipped when `issuer`/`audience` are unset (jwt.c:298, 312): with claims-only JWT inspection the default config binds identity solely to "IdP userinfo accepts this Bearer token", a real risk on multi-audience IdPs (token minted for another client); recommend a load-time warning when `verify_jwt_claims=true` and either is empty. 3 **Low** — provider `interval > MAX_SUPPORTED_POLL_INTERVAL` (120 s) hard-fails instead of clamping (RFC 8628 §3.5 only forbids polling *faster*; pam_module.c:503-509); no JWT-`sub` vs UserInfo-claim consistency check (pam_module.c:1090-1097); stack `prompt_buf` (holds user_code + URIs) not scrubbed at exit while every comparable buffer is (pam_module.c:979, cleanup 1122-1174). 3 **Info** — PKCE verifier `%66` mapping has modulo bias (immaterial at 64 chars, ≥387 bits); default `max_poll_seconds=300` exceeds AGENTS §5.3.4's own 60–120 s guidance; VERBOSE logs the full UserInfo payload by design (pam_module.c:1087-1088).
- **Gotchas & Lessons:** Verified NOT findings: `aud_cfg_copy[256]` cannot truncate (`cfg->audience` is `char[256]`, header line 190 — the jwt.c:318 failure branch is unreachable defensive code); CI *does* mechanically enforce `-Werror` (`EXTRA_CFLAGS=-Werror` in compile-matrix + sanitizer jobs, CHANGELOG "Mechanically enforced zero-warning bar"); redirects are disabled (`CURLOPT_FOLLOWLOCATION 0L`, http.c:401). `case_sensitive` defaults to 1 (exact match) and `allow_root` to 0 (deny) — both correct; do not "fix". The prompt is a *stack* buffer, so the scrub gate's free()-based lexical check cannot cover it.
- **Verification:** LOCAL (macOS): `make check-scrub`, `make check-licenses`, and `clang-format --dry-run --Werror src/*.c include/*.h tests/*.c` (exact CI scope) all green; working tree clean at 597f618 (v0.3.1). No code changed → Linux gates/CI unaffected.
- **Follow-ups / Open Items:** if any of M1/L1–L3 are adopted, they require the full §3.1 Linux gate loop (make lint, gcc+clang matrix, test-sanitize, sandbox, distro builds).

### 2026-11-12 — EL8/EL9 `make EXTRA_CFLAGS=-Werror` build fixes: `JSON_ARRAY_IDX` → `size_t`, qrcodegen per-TU flags, cppcheck `--enable` scope
- **Task:** Three CI jobs red: `Distro / EL8`, `Distro / EL9` (both failed in `make EXTRA_CFLAGS=-Werror` AND `make rpm`), and `Lint / cppcheck`. Root-caused each; applied minimal correct fixes. (Distinct from the earlier same-day 739d094 commit, which fixed `.clang-tidy`/`src/qr.c`/spec + the cppcheck `staticFunction` suppress.)
- **Decisions & Rationale:**
  - **`JSON_ARRAY_IDX` sign-conversion (EL8/EL9 `make -Werror`):** failed first at `src/http.c:184`. The header's version-conditional shim (`#if ... JSON_C_MINOR_VERSION >= 17 ... (i) #else ((int)(i)) #endif`) was wrong: it narrowed the index to `int` on pre-0.17, but json-c's `json_object_array_get_idx()` takes a `size_t` index on **every** supported release. Probed the real installed headers via Docker: EL8 json-c **0.13.1** → `size_t idx`, EL9 0.14 → `size_t`, Ubuntu 24.04/26.04 0.17/0.18 → `size_t`, EL10 0.18 → `size_t`. (The old `JSON_C_MAJOR_VERSION > 0 || MINOR >= 17` gate is also effectively dead on `0.x`.) Replaced the shim with a single `#define JSON_ARRAY_IDX(i) ((size_t)(i))` in `include/pam_oidc_device.h` — a no-op at all 4 call sites (each already `for (size_t i = ...)`) and correct on all platforms.
  - **qrcodegen `-Wconversion` under `-Werror` on EL8 GCC 8 (the *next* failure after the header fix):** `third_party/qrcodegen/qrcodegen.c:784` (`int ret` → `uint8_t` write in `setModuleBounded`) trips `-Wconversion`. Vendored code is SHA256-pinned by `scripts/check_qrcodegen_upstream.sh` (drift audit), so it must stay pristine. Fixed in `Makefile`: the `third_party/qrcodegen/%.o` rule now uses a dedicated `QR_CFLAGS = -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Wextra -fPIE -O2 -g` (hardening + basic warnings, but NOT `-Wconversion`/`-Wpedantic`/`-Wshadow`/`-Wformat=2`/`-Werror`/`$(EXTRA_CFLAGS)`). Project `src/*.c`/`include/*.h` unchanged and still held to the full strict bar.
  - **cppcheck `--enable=all` → 4 defect severities:** newer cppcheck (2.13) emits **information-level** report lines (`checkersReport`, `normalCheckLevelMaxBranches`) that `--error-exitcode=1` treats as hard failures (exit 1 despite "0 errors"). Changed all 5 `--enable=all` sites (`.github/workflows/lint.yml`; `scripts/lint.sh` note + invocation; `.agents/context.md` §3.1) to `--enable=warning --enable=style --enable=performance --enable=portability`. `error` severity is always checked regardless; only `information`/`debug` drop out.
- **Gotchas & Lessons:**
  - `-Werror` distro builds surface **sequential** failures — fix one, rebuild, find the next (EL8: `JSON_ARRAY_IDX` → then qrcodegen.c:784). Don't stop at the first.
  - "cppcheck reports 0 errors but exits 1" = information/debug report lines tripping `--error-exitcode=1`; scope `--enable`, don't disable the check.
  - When a json-c API's param type is version-sensitive, **probe the installed header** (`grep` the `json_object.h` after `dnf/rpm` install) rather than trusting a remembered version boundary — the old "int before 0.17" assumption was simply wrong.
  - Vendored code is drift-pinned: work *around* it (per-TU flags), never edit the file.
- **Verification (all in CI-mirror Docker containers; native macOS build is an environment limitation, §3.3):**
  - `make check-scrub` → OK (also ran natively on macOS).
  - **EL8** (`rockylinux:8`, GCC 8, json-c 0.13.1): `make EXTRA_CFLAGS=-Werror` BUILD_EXIT=0; `make test EXTRA_CFLAGS=-Werror` 52/52 PASSED TEST_EXIT=0; `make rpm` → `pam_oidc_device-0.3.0-1.el8.aarch64.rpm` RPM_EXIT=0; docker-exit=0.
  - **EL9** (`rockylinux:9`, GCC 11, json-c 0.14): same three steps exit 0, 52/52 PASSED, `.el9` RPM built.
  - **Full `make lint`** in `ubuntu:24.04` (clang 18.1.3, cppcheck 2.13): clang-format `--dry-run --Werror` clean; clang-tidy `Suppressed 53327 (53326 non-user, 1 NOLINT)` = 0 user-code diagnostics; cppcheck (new flags) 7/7 clean exit 0; flawfinder level-3+ = 0; scrub OK; `LINT_GATE_EXIT=0`.
  - Not yet run locally: `compile-matrix` clang leg + `test-sanitize CC=clang` on ubuntu (header/Makefile changes are C-standard, clang-tidy-verified, and gcc-proven on EL8/EL9). CI confirms.
- **Follow-ups / Open Items:** Commit (`include/pam_oidc_device.h`, `Makefile`, `.github/workflows/lint.yml`, `scripts/lint.sh`, `.agents/context.md` + this memory entry) and push to `wglick/more_improvements`; confirm `Distro / EL8`, `Distro / EL9`, and `Lint / cppcheck` turn green, and that `compile-matrix` (clang) + `sanitize-test` stay green.

### 2026-11-12 — Unblocked CI after EL consolidation: `_FORTIFY_SOURCE` 3→2, cppcheck `staticFunction`, clang-tidy pins
- **Task:** After the `distro-build` consolidation commit (64f7c08), several CI jobs went red: `Static Analysis (clang-tidy)`, `Static Analysis (cppcheck)`, and `EL8/EL9: Rocky Linux (RPM)`. Needed to separate failures caused by that commit from latent toolchain drift, and restore green.
- **Decisions & Rationale:** Root-caused and applied the minimal correct fix for each. (1) **EL8/9/10 build — genuinely caused by the consolidation:** the new distro-build step builds with `make EXTRA_CFLAGS=-Werror`, but the old `rpm-build` job only ran `make rpm` (bare, no `-Werror`). glibc on EL8/EL9 (2.28/2.34) does not support `_FORTIFY_SOURCE=3` and emits `#warning _FORTIFY_SOURCE > 2 is treated like 2`, which `-Werror` makes fatal. Fixed at the source: `Makefile` `-D_FORTIFY_SOURCE=3` → `=2` (maximum universally-supported level and the flag §10.3 already documents; warning-free on every distro), plus the matching comment in `packaging/pam_oidc_device.spec`. (2) **cppcheck `staticFunction` — toolchain-version drift:** newer cppcheck on `ubuntu-latest` now reports 5 functions (`parse_config_file`, `discovery_json_advertises_s256`, `render_prompt_message`, `qr_encode_uri`, `qr_render_matrix`) as "should be static". All are declared in `include/pam_oidc_device.h` and called by `tests/test_suite.c`, so they CANNOT be `static` (would break the header decl + test link). Added `--suppress=staticFunction` to all 3 cppcheck mirrors (`.github/workflows/lint.yml`, `scripts/lint.sh`, `.agents/context.md` §3.1 step 4) — same heuristic family as the already-suppressed `unusedFunction`. (3) **clang-tidy — all 4 errors on code untouched by recent commits, so also a runner clang-tidy version bump:** `readability-math-missing-parentheses` on `QR_MAX_SIZE` (fixed the code — parenthesized `((QR_MAX_VERSION * 4) + 17)` in both `QR_MAX_SIZE`/`QR_LINE_BUF_MAX`, semantics unchanged: 97/874); `readability-function-size` on the large `http_request` orchestrator and `clang-analyzer-security.ArrayBound` ×2 (false positives on the canonical `isspace((unsigned char)x)` in `trim_whitespace` and on `calloc(n+1)` NUL-termination in `base64url_decode` — both provably in bounds) are disabled in `.clang-tidy` with an explanatory comment, consistent with the existing `-readability-*` / `-clang-analyzer-security.insecureAPI.*` disable list.
- **Gotchas & Lessons:** The clang-tidy + cppcheck reds were NOT caused by the recent C/CI changes — the flagged lines (config.c:193, http.c:285, jwt.c:127, qr.c:166) predate them. Treat "CI suddenly red on unchanged code" as runner toolchain drift, not a regression in your diff. `clang-analyzer-security.ArrayBound` is a genuine false-positive source on glibc `ctype` (128-entry `__ctype_b` model) and on `calloc`; `readability-function-size` is a subjective style metric. Disabling a specific FP-prone/subjective check (or adding a `--suppress=` for a heuristic that cannot see header-declared/test-used functions) is the honest fix — do NOT rewrite correct, safe code to appease a buggy analyzer.
- **Verification status:** LOCAL + LINUX-CONTAINER (ubuntu:24.04 via Docker) — (a) all 4 touched YAML files re-parse (PyYAML); (b) `clang-format --dry-run --Werror src/*.c include/*.h tests/*.c` clean; (c) `make check-scrub` and `make check-licenses` green; (d) qr.c macro values verified unchanged (97/874); (e) **full CI-mirror gate run in `ubuntu:24.04` Docker: `clang-tidy src/*.c -- -Iinclude -D_GNU_SOURCE` (clang-tidy 18.1.3) → 0 user-code errors; `cppcheck` (2.13.0) → exit 0 (`Unmatched suppression: staticFunction` info-level only — the 5 CI findings did not reproduce because 2.13.0 is older than the CI runner's cppcheck); `make EXTRA_CFLAGS=-Werror` + `make test` under gcc AND clang → 52/52 tests pass both; `make test-sanitize CC=clang` (ASan+UBSan+LSan) → clean. So the 4 clang-tidy errors are DEFINITIVELY fixed.** STILL REQUIRED (CI only): `make EXTRA_CFLAGS=-Werror` on **EL8/EL9/EL10** (the Ubuntu 24.04 gate uses glibc 2.39 which silently honors `_FORTIFY_SOURCE=3`, so it does not exercise the EL8/9 glibc-2.28/2.34 path that triggered the regression — `=2` sidesteps it but only CI can confirm); the cppcheck `staticFunction` suppression against the CI runner's newer cppcheck; `distro-build` EL8/EL9/EL10 legs; `e2e-sandbox`; `make rpm` / `make deb`; `license-audit`.
- **Follow-ups / Open Items:** Confirm the `clang-tidy` + `cppcheck` jobs and the six `distro-build` legs all turn green on the next push/PR. If a future clang-tidy/cppcheck bump surfaces NEW checks on unchanged code, apply the same pattern (code fix for style; targeted disable/suppress for false positives) rather than widening the gates.

### 2026-11-12 — Consolidated all native-distro package builds into `distro-build.yml`
- **Task:** EL8/EL9/EL10 RPM builds lived in the `rpm-build` job of `.github/workflows/build.yml` while the SUSE/Debian/Ubuntu builds lived in `.github/workflows/distro-build.yml`. Operator wanted every distro package build co-located in one workflow (the distro-build one).
- **Decisions & Rationale:** Folded EL8/EL9/EL10 (Rocky Linux, `make rpm`) into the single `distro-build` matrix in `distro-build.yml`, alongside the existing SUSE (RPM) + Debian 13 / Ubuntu 26.04 (DEB) entries. Each entry carries `label`/`image`/`pkg`/`install`/`verify`; the EL `verify` mirrors the SUSE verify shape (`set -euo pipefail`, `find ... | head -1`, `[ -n ]` guard) but installs via `dnf install -y` (not `zypper --no-gpg-checks`). `dnf config-manager` needs `dnf-utils` (EL8) / `dnf-plugins-core` (EL9+) plus the extra-products repo enabled first: `powertools` on EL8, `crb` on EL9/EL10. Deleted the `rpm-build` job from `build.yml`, which now holds only the non-distro gates (compile-matrix, sanitize-test, qr-scan-audit, e2e-sandbox). Updated every doc that asserted the EL gate lives in `build.yml`: `.agents/context.md` (§3.1 step 10, §3.2, §3.3), this file's Standing Invariants, `docs/packaging.md`, and `CONTRIBUTING.md`. No C or packaging-content change — pure CI reorganization.
- **Gotchas & Lessons:** (1) Never run a `perl -i -pe` substitution through a shell whose script text contains backticks — bash treats them as command substitution and will actually execute the `make rpm`/`make deb`/`make clean` targets referenced in the docs (that ran in-repo `make clean`/`make rpm`/`make deb`, all gitignored/failed-harmless on macOS, but it is not safe against `/etc`). Use the editor tool, or a quoted `<<'PY'`/`<<'EOF'` heredoc, for anything containing backticks. (2) The `memory.md` bullets use a 2-space continuation indent, not 3 — the editor match failed twice on the wrong indent.
- **Verification status:** LOCAL (macOS) — both workflow files re-parsed cleanly with PyYAML (`build.yml` jobs = compile-matrix/sanitize-test/qr-scan-audit/e2e-sandbox; `distro-build.yml` jobs = distro-build); all doc cross-references updated. NOT RUN / STILL REQUIRED: the actual EL `make rpm` + install + on-disk checks on EL8/9/10 and the SUSE/Debian/Ubuntu legs via the CI `distro-build` jobs (no rpmbuild/dpkg toolchain locally). No source-code or packaging-content change, so this edit does not by itself require re-running the lint/compile/test/sanitize gates, but CI re-validates everything on push/PR.
- **Follow-ups / Open Items:** Confirm the six `distro-build` matrix legs (EL8/EL9/EL10, SUSE Leap 16.0, Debian 13, Ubuntu 26.04) turn green on the next push/PR to `main`.

### 2026-11-12 — Expanded `[access]` list fields 256→2048 (fixes "Failed to parse key 'deny_users'")
- **Task:** Operator hit `pam_oidc_device(sshd:auth): Failed to parse key 'deny_users' at line 28` followed by `error: PAM: Error in service module`. Their `deny_users` value was 574 chars but the fields are `char deny_users[256]`.
- **Decisions & Rationale:** Root cause: `copy_checked()` in `parse_config_kv` caps a value at `sizeof(cfg->deny_users)` = 255, so any list >255 chars fails load → `load_config()` returns `PAM_AUTH_ERR`. Expanded all four `[access]` list fields (`allow_users`/`deny_users`/`allow_groups`/`deny_groups`) to a new `ACCESS_LIST_LEN 2048` macro (`include/pam_oidc_device.h`). CRITICAL lockstep change: `identity.c list_contains()` scratch buffer went `char buf[256]` → `char buf[ACCESS_LIST_LEN]` — otherwise a longer list would parse but fail to match at runtime (fail-open on a *deny* list is worse than the parse error). Also `config.c parse_config_file()` line buffer `MAX_INIT_MSG_LEN+128` (1152) → `ACCESS_LIST_LEN+128` (2176) so a valid ~2 KB list line is not misreported as "Overlong line". Added CMocka regression test `test_parse_config_file_long_access_list` (589-char `deny_users` round-trips into the field) and registered it in the config suite.
- **Gotchas & Lessons:** The three bounds (struct field, `list_contains` scratch buffer, `fgets` line buffer) are the SAME logical cap and MUST be raised together — the struct field is the one the error message points at, but the scratch buffer is where a silent fail-open lurks. A ~574-char operator deny list ≈ most of `/etc/passwd` service accounts; 255 was too small for production. The 600-char `test_parse_config_file_overlong_line` still passes for a DIFFERENT reason (no `[section]`/`=` → key-before-section reject), not the buffer cap.
- **Verification status:** LOCAL (macOS) only — `clang-format --dry-run --Werror` clean at the exact CI scope; `make check-scrub` green; an isolated harness (verbatim `list_contains` + the new test's value-generation) compiled AND ran CLEAN under the full strict flags under BOTH clang and gcc, all behavior asserts pass (589-char parse + member match, non-member reject, over-long reject). NOT RUN: `make`/`make test`/clang-tidy/cppcheck/flawfinder/`test-sanitize` (no PAM headers / no docker on this host). STILL REQUIRED: Linux gates / CI (compile-matrix gcc+clang, sanitize, e2e-sandbox, rpm/deb, license-audit).
- **Follow-ups / Open Items:** Run the Linux container gate (AGENTS.md §3.3) or push for CI before merge. CHANGELOG note added under `[Unreleased]` / `### Fixed`.

### 2026-11-12 — Regression fix: remove `-pie` from `LDFLAGS` (shared-library link broke on modern binutils)
- **Task:** The `-pie` addition from the previous entry broke every link:
  CI `Debian 13 (DEB)` (and any job linking the module) failed with
  `/usr/lib/.../Scrt1.o: in function '_start': undefined reference to 'main'`.
- **Root cause:** `-pie` is an *executable* link flag. Even with `-shared`,
  modern gcc/binutils (Ubuntu gcc 14) pull in the executable CRT start file
  `Scrt1.o`, whose `_start` references `main` — absent in a shared library.
  A `-fPIC`/`-fPIE` object set plus `-shared` already yields a fully
  position-independent DSO; `-pie` at the `.so` link is redundant and
  actively harmful. (Audit `-fPIE/-pie` flags only make sense for the
  *executable* targets — e.g. `tests/e2e/pam_driver`, built with its own
  flags, untouched.)
- **Fix:** `LDFLAGS` back to `-Wl,-z,relro,-Wl,-z,now`; `-fPIE` kept in
  `CFLAGS` (compile-time, harmless, proven by the object-compilation
  steps that passed in CI). Makefile comment documents why no `-pie`.
- **Standing invariant:** never add link-time `-pie` to the module's
  `LDFLAGS`; the only link-time hardening flags are the `-z relro`/`-z now`
  pair.
- **Verification:** ubuntu:24.04 Docker container mirroring CI — all pass:
  gcc + clang builds with `EXTRA_CFLAGS=-Werror`, CMocka suite under both
  compilers, `clang-tidy` gate, `make test-sanitize CC=clang`, and `make deb`
  (the previously failing link/packaging step). The first container run
  (before this fix landed in the mounted Makefile) reproduced the CI error
  verbatim, confirming the root cause. EL rpm jobs still confirmed via CI.

### 2026-11-12 — Post-review fixes: 0.3.0 version sync, `-fPIE/-pie`, `token_type` + silent-2xx observability, DEB `Homepage`, device-lifetime docs
- **Task:** Implement the recommendations from the comprehensive §10 audit:
  (1) fix the post-0.3.0-bump version drift at three sync points;
  (2) add `-fPIE`/`-pie` to the Makefile; (3) optional polish — silent-2xx
  token-branch log, `token_type` handling, DEB `Homepage:` field,
  getting-started note on device-code lifetime.
- **Changes:** `packaging/pam_oidc_device.spec` fallback `mod_version`
  0.2.0 → 0.3.0 (the `make rpm` path always passes `--define mod_version`;
  this only affects bare `rpmbuild` invocations);
  `packaging/gen-changelog.py` `default_ver` → 0.3.0; `.agents/context.md`
  §1 → v0.3.0. Makefile: `-fPIE` appended to `CFLAGS`, `-pie` to `LDFLAGS`
  (compile-time intent; the `-pie` link flag turned out to be wrong for a
  shared-library link — see the regression-fix entry above). `src/pam_module.c`
  `poll_for_access_token`: (a) RFC 6749 s5.1 — a present-but-foreign
  `token_type` (anything other than `"Bearer"`) now fails closed with
  `PAM_AUTH_ERR`; a missing field is DEBUG-logged and tolerated (some
  providers omit it; the e2e mock already emits `"token_type": "Bearer"`,
  so no e2e expectation changed); (b) new LOG_DEBUG line when a 2xx token
  response carries no usable `access_token` (non-object body, non-string
  `access_token`, or empty string), replacing the previously silent loop
  `break`. `packaging/build-deb.sh`: `Homepage:` field added to the DEB
  control stanza. `docs/getting-started.md` §4: NOTE that the provider's
  `expires_in` clock starts at the code request — before the ENTER prompt —
  and that `max_poll_seconds` caps the polling window.
- **Verification status:** local (macOS) only: no sensitive-buffer or
  `Requires:` surface touched, so the memory-scrub and license gates are
  unaffected. **NOT run — requires the Linux gates:** clang-format /
  clang-tidy / cppcheck (the `src/pam_module.c` edit), gcc+clang builds +
  tests, `make test-sanitize CC=clang`, e2e sandbox, rpm/deb — the CI
  compile-matrix / sanitize / e2e-sandbox / distro-build jobs are the
  confirmation.

### 2026-11-12 — Documentation restructure: end-user journey organization
- **Task:** Rebase root-level `*.md`, `docs/`, and `examples/` so the initial
  focus is an end user implementing from scratch (why → getting started →
  early testing → advanced configuration → security → contributing), while
  keeping deeper technical content available but not up front; keep using
  standard GitHub-expected file placement.
- **Decisions & Rationale:**
  - `README.md` rewritten as a hub: pre-release warning now links to
    `docs/developer/review.md`; new "How It Works" plain-English 4-step
    section added after the intro; quickstart trimmed and points to the new
    `docs/getting-started.md` and `docs/packaging.md`; "Detailed
    Documentation & Deep Dives" table replaced with an "I want to…" journey
    table; the ~60-line "Building & Binary Packaging (RPM & DEB)" section
    removed (moved verbatim to `docs/packaging.md`).
  - New `docs/getting-started.md` absorbs the deleted `docs/pam-ssh-setup.md`
    (sshd directives, stack order, required-vs-sufficient warning, uid>=1000
    guard, authselect options, loglevel table) plus prerequisites, per-distro
    source install, and the full sample config (config section → reference
    table). `docs/pam-ssh-setup.md` deleted.
  - New `docs/packaging.md` = README packaging section (unchanged content;
    user confirmed packaging artifacts/scope stay untouched — RPM spec, DEB
    script, sdist list NOT modified).
  - `REVIEW.md` → `docs/developer/review.md`; its §4 stale CMake/ctest
    instructions corrected to `make` / `make test` (project is Make-only, no
    CMakeLists.txt), `test_suite.c` → `tests/test_suite.c`.
  - `docs/testing.md` §6 roadmap extracted to `docs/developer/roadmap.md`;
    all `docs/pam-ssh-setup.md` references updated to `docs/getting-started.md`
    with new section numbers (§1–2→§2–3, §1→§4, §2→§5); See-also updated.
  - `docs/threat-model.md`: two `pam-ssh-setup.md` links → `getting-started.md`.
  - `.agents/context.md`: repo-layout + "Root docs" + §9 project-documents
    lists updated; §10.3 audit prompt no longer references CMake/CMakeLists;
    §10.4 doc-accuracy prompt references `docs/` instead of `REVIEW.md`.
  - `CHANGELOG.md` [Unreleased] Changed entry added for the restructure.
- **Gotchas & Lessons:**
  - Shell heredocs in this environment can silently fail to execute (observed
    a python heredoc "run" that never ran and a `cat -A` macOS failure);
    prefer the editor tool for file surgery, and re-grep to confirm each edit
    landed before moving on.
  - `THIRD_PARTY_NOTICES.md` must stay at repo root (CI `check-licenses.sh`
    check L1 enforces it); `README.md` "Third-Party Components & Licenses"
    section heading kept verbatim so its anchor link from the notices file
    stays valid.
- **Verification:** All edits verified by re-grep — no remaining references to
  `REVIEW.md`, `docs/pam-ssh-setup.md`, `CMakeLists`, or the removed README
  anchor `#building--binary-packaging-rpm--deb` anywhere in the repo; all
  markdown links in `README.md`, `docs/`, `examples/`, `SECURITY.md` resolve
  to existing files; `git status` shows only the intended
  add/delete/modify set. No C code touched, so no build/test/lint gates are
  affected; CI gates unaffected by docs-only changes.
- **Follow-ups / Open Items:**
  - `CODE_OF_CONDUCT.md` intentionally not created (needs an organizational
    policy decision, out of scope here).
  - Packages currently ship only root docs (spec `%doc README.md
    CHANGELOG.md SECURITY.md`, same for DEB docdir); user opted to leave
    packaging untouched — revisit if we want `docs/`/`examples/` shipped.
  - Push + verify in CI (docs-only; expect no job changes).

### 2026-11-12 — Fixed `e2e-sandbox` CI job: run_e2e.sh non-root privilege bugs
- **Task:** The `e2e-sandbox` job in `build.yml` (new in ba9568d, never previously green)
  aborted with `/etc/pam_oidc_device.conf exists but does not point at the sandbox mock;
  refusing to overwrite` even though the job had pre-staged the e2e fixture.
- **Root cause (two bugs, both only outside the Docker sandbox):** the CI job runs the
  harness as the unprivileged `runner` user; `make sandbox` runs it as root, so neither
  bug ever showed there.
  1. The config-reuse check ran `grep` on `/etc/pam_oidc_device.conf` **without** `$SUDO`,
     but the file is `root:root 0600` — permission-denied, masked by `2>/dev/null`,
     misreported as "does not point at the sandbox mock".
  2. `WORKDIR` was created `root:root 0700` (`$SUDO install -d`), yet the scenario file,
     TLS key/cert, driver binary, mock log, and per-case `.out` files are all written
     later **without** root — every one of them would have been the next failure.
- **Fix (commit 5368a6b):** `tests/e2e/run_e2e.sh` — (a) `$SUDO grep` for the mock-URL
  check; (b) workdir is now created owned by the invoking user (`install -d -m 0700`
  without sudo), with `$SUDO chown -R "$(id -u):$(id -g)"` takeover of any pre-existing
  root-owned workdir (idempotent across root/non-root reruns). Root-mode (Docker)
  behavior is byte-for-byte unchanged (no-ops).
- **Gotchas & Lessons:**
  - Any script that mixes `$SUDO` system writes with plain-user I/O must keep the
    user-I/O area (workdir) user-owned; audit every `>` redirection and `openssl`/`cc`
    output path for ownership, not just the obviously-root operations.
  - `2>/dev/null` on a check grep converts "cannot read" into "content mismatch" —
    distinguish the two when the file has restrictive permissions.
- **Verification:** `bash -n` clean; `grep -q "127.0.0.1:8443"` confirmed to match the
  fixture; root-mode paths re-audited (no-op `chown 0:0`, `SUDO=""`). **Still requires
  CI:** the full 7-scenario run can only happen on the Linux `e2e-sandbox` job.

### 2026-11-11 — Fixed `make deb` CI failure: dpkg-shlibdeps output format (Debian 13 + Ubuntu 26.04 jobs)
- **Task:** Both DEB jobs in `distro-build.yml` failed at `make deb` with
  "dpkg-shlibdeps produced no dependencies" even though the module .so built fine.
- **Root cause:** On dpkg >= 1.17 (trixie/resolute ship 1.22) `dpkg-shlibdeps` prints
  **nothing** to stdout without `-O` (it writes a `debian/substvars` file in the cwd —
  confirmed in the 1.22.22 source: `scripts/dpkg-shlibdeps.pl`,
  `my $varlistfile = 'debian/substvars'`). With `-O` the stdout lines are substvars-formatted
  (`shlibs:Depends: ...`), and `libc6` lands in `shlibs:Pre-Depends` (Essential:yes). The
  original `grep -v '^dpkg-shlibdeps'` filter matched a non-existent bare-list format;
  `2>/dev/null` also hid all diagnostics.
- **Fix:** `build-deb.sh` now uses `dpkg-shlibdeps -O`, `sed -nE` prefix strip, merges
  Pre-Depends+Depends, and keeps stderr for failure diagnostics.
- **Gotchas & Lessons:**
  - Verify dpkg tooling behavior against the actual distro's source (downloaded
    `dpkg_1.22.22.tar.xz` from deb.debian.org; git.dpkg.org and salsa are bot-walled).
  - macOS BSD sed lacks `\?` in BRE — use `sed -E` in repo scripts for portability.
  - The SUSE RPM job was unaffected (rpmbuild has its own shlibdeps handling).
- **Verification:** Local: `bash -n` clean; sed pipeline validated against simulated
  dpkg 1.22 output (merged Pre-Depends+Depends, single-field, and no-match cases);
  `make check-scrub` + `make check-licenses` pass. Still requires CI: the real
  `make deb` on Debian 13 / Ubuntu 26.04 in `distro-build.yml`.
- **Follow-up (second CI round):** the `-O` fix was not enough — CI then failed with
  `dpkg-shlibdeps: error: cannot read debian/control: No such file or directory`. Second
  source check (`Dpkg::Control::Info` in the 1.22.22 tarball,
  `scripts/Dpkg/Control/Info.pm` + `dpkg-shlibdeps.pl` line 168):
  `Dpkg::Control::Info->new()` is called **unconditionally** and with no args it loads
  `debian/control` from the cwd, and lines 212–216 require a parseable
  `Build-Depends`/`Build-Depends-Arch` in the source stanza. Fix: `build-deb.sh` now
  creates a scratch source tree (`mktemp -d` + minimal `debian/control` with
  `Source:` + `Build-Depends: dpkg-dev`, EXIT-trap cleanup) and runs
  `dpkg-shlibdeps -O <abs .so path>` from that cwd. Validated against a fake
  1.22-behavior `dpkg-shlibdeps` on macOS (old cwd → reproduces the exact CI error;
  new scratch tree → clean merged `SHLIB`).
- **Follow-up (third CI round, same day):** scratch tree alone was still not enough —
  CI then failed `dpkg-shlibdeps produced no dependencies` with **exit 0, empty stdout
  AND empty stderr** (contradicts a 1.22.22 source walk that says deps must be
  generated). New root-cause clue found in 1.22.22/1.23.7 source:
  `Dpkg::Path::get_pkg_root_dir()` walks the **analyzed binary's ancestor dirs** for a
  `DEBIAN/` subdir, and `dpkg-shlibdeps.pl my_find_library()` searches those package
  trees first. The .so lived under `build/deb/...`, whose sibling `build/deb/DEBIAN/`
  (our hand-rolled control) made the **staging dir** the "package root" — an
  unsupported non-source-tree invocation (also explains why CI showed none of the
  usual stderr warnings). Note: dpkg 1.23.7 (Ubuntu 26.04 "resolute") is
  behaviorally identical to 1.22.22 for this code path (diffed `dpkg-shlibdeps.pl`,
  `Dpkg/Path.pm`, `SymbolFile.pm` — only style changes); trixie symbols files DO
  populate the `deps` list from the section header (`libcurl.so.4 libcurl4t64
  #MINVER#`), so the symbols-branch empty-deps theory was disproven with a real
  trixie `libcurl4t64` .deb.
  - **Fix attempt 2:** stage the .so at its final install path *inside* FAKESRC
    (`$FAKESRC/lib/<multiarch>/security/<name>.so`, copied via `install`), run
    `dpkg-shlibdeps -O` against that copy — canonical `dh_shlibdeps`-style usage
    (binary under the package build root; `guess_pkg_root_dir` then resolves
    cleanly and the bogus package-tree search disappears).
  - A `deb_debug_dump()` (**TEMP-DEBUG**, must be removed) was added to both
    failure branches: dpkg version, raw stdout/stderr of `dpkg-shlibdeps -O`,
    `-v -v` re-run, `objdump -p` NEEDED lines, FAKESRC tree. Keep until a green
    round, then delete the function + its two call sites.
- **Resolution (fourth CI round, same day):** the TEMP-DEBUG dump proved the
  FAKESRC staging fix works — dpkg 1.22.22 resolved every NEEDED library and
  printed `shlibs:Depends=libc6 (>= 2.38), libcurl4t64 (>= 7.16.2),
  libjson-c5 (>= 0.15), libpam0g (>= 0.99.7.1), libssl3t64 (>= 3.0.0)`.
  The real last bug: dpkg-shlibdeps `-O` emits the **substvars file format
  `name=value`** (equals sign), not the man-page-style `shlibs:Depends: `
  colon form the sed filter expected — so the filter matched nothing on a
  perfectly good run. Fixed with `sed -nE
  's/^shlibs:(Pre-)?Depends[:=][[:space:]]*//p'` (accepts both separators)
  and the TEMP-DEBUG block was removed (commit 06813b5). The full causal
  chain, for posterity: (1) no `-O` flag → nothing on stdout (and the
  original filter expected a bare list) — fixed with `dpkg-shlibdeps -O` +
  sed prefix strip; (2) unconditional `debian/control` load from the cwd —
  fixed by the FAKESRC scratch source tree; (3) `get_pkg_root_dir`
  ancestor walk + staging-dir `DEBIAN/` — fixed by staging the .so inside
  FAKESRC; (4) `=` vs `:` substvars separator — fixed by the `[:=]` filter.
  Note: on trixie dpkg 1.22.22, `libc6` lands in `shlibs:Depends`, not
  `shlibs:Pre-Depends` (the merge still handles both).
- **Verification:** `bash -n` clean; capture pipeline validated locally
  against a fake `dpkg-shlibdeps` reproducing the exact observed 1.22.22
  output; `make check-scrub` + `make check-licenses` pass. The remaining
  proof is the next `distro-build` CI round on Debian 13 + Ubuntu 26.04
  (Ubuntu's dpkg 1.23.7 emits the same substvars format — diffed
  `dpkg-shlibdeps.pl`; the dual-separator filter hedges either way). Local
  Linux hosts are unavailable on this Mac — CI is the only live test bed.
- **Follow-up (fifth CI round, same day):** the shlibdeps fix worked and
  `make deb` then reached `dpkg-deb --build`, which failed with
  `package name has characters that aren't lowercase alphanums or '-+.'`
  — Debian package names **cannot contain underscores** (this was simply
  the next pre-existing bug masked by the earlier failure). Fixed
  (commit 8a6125e): `build-deb.sh` now derives `DEBNAME="${NAME//_/-}"`
  (`pam-oidc-device`) and uses it for the `Package:` field, the
  `/usr/share/doc/` dir, and the output filename
  (`build/pam-oidc-device_<ver>_<arch>.deb`); in-package files keep the
  underscore module name (`pam_oidc_device.so`, `/etc/pam_oidc_device.conf`).
  `.github/workflows/distro-build.yml` find-globs and the README install
  examples updated to the new filename. Divergence from the RPM name
  (`pam_oidc_device`) is intentional and documented — RPM allows
  underscores. Remaining proof: next `distro-build` round; any later
  failure will come from `dpkg-deb --build` staging or `dpkg -i`
  verification, not from dependency derivation.
- **Follow-up (SUSE rpm, same day):** the `SUSE: openSUSE Leap 16.0`
  job failed in `%build` with `ld: cannot find %{build_ldflags}`. The
  spec's long-standing `%build` line
  `make CFLAGS="%{build_cflags}" LDFLAGS="%{build_ldflags} ..."` mixes
  distro macros with project flags: on Leap 16.0 `build_cflags` IS
  defined (expanded to SUSE optflags + fortify/protector/unwind) but
  `build_ldflags` is UNDEFINED, and rpmbuild leaves undefined `%{...}`
  as literal text — the literal reached the link line. Fixed
  (commit d4a2c4c): `%build` is now a bare `make` using the Makefile's
  own default flag bar (`-fstack-protector-strong -D_FORTIFY_SOURCE=3
  -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2
  -Wformat-security -fPIE -O2 -g`, `LDFLAGS=-Wl,-z,relro,-z,now`; no
  `-pie` — see the 2026-11-12 `-pie` regression entry below) —
  distro-independent, stronger than SUSE's `build_cflags`, and
  identical to what the DEB path builds with. The strict warning set
  was already proven on Leap's gcc 15 by the workflow's earlier
  zero-warning build step. Also eliminates any macro-availability risk
  on EL8/9/10 `rpm-build` (same spec). Verify-step consistency
  re-checked: `_libdir=/lib64` on SUSE x86_64 matches
  `ls /lib64/security/...`; RPM name glob unaffected.
- **Follow-up (SUSE verify step, same day):** the bare-`make` `%build`
  fix worked — the RPM built AND `%check` (make test) passed; the job
  then failed at verify: `zypper install` rejected the locally-built
  RPM with `Signature verification failed [6-File is unsigned]` —
  zypper enforces GPG checks by default and CI builds unsigned packages
  (no signing key in the container). Fixed (commit 86dc766): the SUSE
  verify step now runs
  `zypper --non-interactive --no-gpg-checks install "$MAIN_RPM"`. The
  EL rpm-build job (`dnf install -y <local .rpm>`) is unaffected — dnf
  does not block unsigned local installs. YAML re-validated locally.
  Remaining proof: next SUSE round — if it passes verify's
  `ls /lib64/security/... /etc/pam_oidc_device.conf`, the whole
  distro-build matrix (SUSE + Debian 13 + Ubuntu 26.04) is done.

### 2026-11-11 — SUSE / Debian / Ubuntu packaging support + `distro-build.yml` CI workflow
- **Task:** Make Makefile/packaging support SUSE (RPM), Debian, and Ubuntu (DEB); add CI jobs
  building on the latest LTS of each family.
- **Decisions & Rationale:**
  - Spec gained an `%if 0%{?suse_version}` branch in
    `packaging/pam_oidc_device.spec`. **Verified SUSE binary names via rpmfind.net
    (`system=opensuse`), filtered to 15.6/16.0-era release tags (`150600.*`, `160000.*`):**
    build-time `pam-devel`, `libcurl-devel`, `libjson-c-devel`, `libopenssl-devel`,
    `libcmocka-devel` (SUSE uses `libcmocka-devel`, *not* `cmocka-devel`; `json-c-devel` is an
    old Tumbleweed name — modern SUSE is `libjson-c-devel`; openssl devel is
    `libopenssl-devel`); runtime `pam`, `libcurl4`, `libjson-c5`, `openssl`.
  - **No new C code** — packaging/CI/docs only, so the §4 security guardrails and all C gates
    are unaffected.
  - `make deb` = `packaging/build-deb.sh`: hand-crafted `.deb` via `dpkg-deb`
    (`--root-owner-group`, no fakeroot needed) + `dpkg-shlibdeps` for distro-correct
    `Depends` (handles `libcurl4t64`/`libssl3t64`-style t64 renames without hardcoding);
    module staged to `/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)/security` (same path the
    e2e harness uses — Debian/Ubuntu libpam's module dir); `/etc/pam_oidc_device.conf` is a
    `0600` conffile; Maintainer matches `MODULE_MAINTAINER` in `include/metadata.h`.
  - New `.github/workflows/distro-build.yml` (push/PR to `main`, `contents: read`,
    concurrency-cancel, SHA-pinned checkout): matrix of **opensuse/leap:16.0** (SUSE RPM),
    **debian:13**, **ubuntu:26.04** (both DEB); each job = install deps →
    `make EXTRA_CFLAGS=-Werror` → `make test EXTRA_CFLAGS=-Werror` → `make rpm|deb` →
    install the artifact → `ls` the installed layout.
  - `scripts/check-licenses.sh` L4 now collects **all** `Requires:` lines (EL + SUSE branches,
    `awk 'tolower($1)=="requires:"'` + `sort -u`) instead of the first one;
    `THIRD_PARTY_NOTICES.md` declares the per-distro names so L4 passes for `libcurl4` /
    `libjson-c5` / `openssl` etc.
  - Distro "latest LTS" pins (as of 2026-11): openSUSE Leap **16.0** (SUSE family), Debian
    **13** (trixie), Ubuntu **26.04** LTS ("resolute"). Verified tag existence: Docker Hub
    registry manifest API (Hub's `tags/` API returns 404 even for valid tags — a known quirk;
    query `registry-1.docker.io/v2/<repo>/manifests/<tag>` with a bearer token instead).
    `libcmocka-dev` on Ubuntu 26.04 lives in **universe** (enabled by default in ubuntu images;
    verified via `archive.ubuntu.com/dists/resolute/universe/.../Packages.xz`).
- **Gotchas & Lessons:** SUSE naming traps — cmocka devel is `libcmocka-devel` on SUSE too;
  json-c devel is `libjson-c-devel` (not EL's `json-c-devel`) on 15.6/16.0; openssl devel is
  `libopenssl-devel`; runtime libs are `libcurl4`/`libjson-c5`/`openssl` (no `-libs` suffix).
  From this dev host, SUSE/OBS endpoints are unreachable (api.opensuse.org wants auth,
  build.opensuse.org 403, ftp.opensuse.org times out) — rpmfind.net search (`system=opensuse`)
  is a working fallback for SUSE package-name verification.
- **Verification:** local (macOS): `bash -n packaging/build-deb.sh`, YAML parse of
  `distro-build.yml` + `build-deb.sh` control-file heredoc logic, `make -n deb` recipe
  expansion, `make check-scrub`, `make check-licenses` (L4 now exercises the SUSE branch
  names), README/CONTRIBUTING/context/memory docs updated. **NOT yet verified:** actual
  `make rpm` on openSUSE 16.0, `make deb` on Debian 13 / Ubuntu 26.04, and the CI install
  steps — these first run in the pushed `distro-build` jobs (docker pull is broken on this
  host, so no local container verification was possible).
- **Follow-ups / Open Items:** If the first `distro-build` run shows a zypper "package not
  found" for a SUSE name (the workflow probes candidates on failure), fix the name in the
  spec's SUSE branch + the README quickstart. Consider adding `make deb` to a release
  automation / multi-arch (arm64) matrix later.

### 2026-11-11 — Fixed license-audit `dependency-graph-audit` CI hard-fail (feature-gated GraphQL field)
- **Task:** The `dependency-graph-audit` job in `license-audit.yml` failed with
  `gh: Field 'dependencyGraph' doesn't exist on type 'Repository'`.
- **Root cause:** `Repository.dependencyGraph` is a per-account **feature-gated** GraphQL
  field. On accounts without the supply-chain dependency-graph feature the field is simply
  absent from the served schema, so `gh api graphql` fails at *validation time* (schema-level
  error, before execution). Not fixable by token, permissions, or retries.
- **Decisions & Rationale:**
  - Workflow: tolerate **only** that exact schema error (grep on stderr) and try the REST
    `GET /repos/{owner}/{repo}/dependencies`; a REST **404** (the initial fix assumed a
    deterministic `[]` — wrong: the first CI run failed with `gh: Not Found (HTTP 404)`).
    Investigation: the repo is **private** (repo metadata 404 unauthenticated), and *every*
    dependency-graph REST shape (`/dependencies`, `/dependency-graph/{packages,dependencies,
    license-summary,package-ecosystem-summary,services}` ± beta media types) also 404s for
    **public** repos (torvalds/linux) — these endpoints are not publicly served today. So:
    REST 404 = "no dependency-graph data available" → record `[]` for a clean INFO no-op
    (safe: `GITHUB_REPOSITORY` is always a real repo in CI, so 404 can't mean
    misconfiguration); every other query failure still hard-fails the job. `set -e` dropped
    from that step in favor of the explicit if/elif/else.
  - `scripts/audit-dependency-graph.py` now classifies payloads: GraphQL
    `data.repository.dependencyGraph.packagesV2.nodes` → full license-allowlist audit
    (unchanged semantics); REST top-level array → names cross-checked against
    `THIRD_PARTY_NOTICES.md`, licenses reported `unknown` with an explicit NOTE (no failure
    invented from missing data); feature-gated `errors[]` payload → INFO no-op; REST error
    objects (`{"message": ...}`), malformed JSON, and other GraphQL errors still fail.
  - Docs synced: `THIRD_PARTY_NOTICES.md` gate table, `.agents/context.md` §3.1 step 11,
    `CHANGELOG.md` [Unreleased] Fixes.
- **Verification status:** locally verified on macOS with Python fixtures — 10 payload
  scenarios pass (feature-gated error, empty graph, allowed package, off-allowlist GPL
  package, unknown GraphQL error, REST empty, REST populated with undeclared-name WARN,
  REST error object, malformed JSON, missing file); the workflow's *exact* run block
  (extracted from the YAML, so it can't drift) was simulated with a fake `gh` across all
  five branches (ok / gated→REST-ok / gated→REST-404→no-op / gated→REST-500→hard fail /
  unexpected GraphQL error → hard fail) and the workflow YAML re-parsed. Live API probes:
  repo metadata 404 unauthenticated (private repo); all dependency-graph REST shapes 404
  even for public repos. **Still requires CI:** the `license-audit` jobs have not run
  remotely with the 404-handling fix.
- **Follow-ups / Open Items:** confirm `dependency-graph-audit` is green on the next push
  (expect two INFO lines + "no indexed packages"); if GitHub ever serves the dependency-graph
  data for this account/repo (feature enabled / repo made public / manifest indexed), the
  audit activates automatically — GraphQL with license data if the schema field appears,
  otherwise the REST name cross-check.

### 2026-11-11 — Pre-production testing guide + one-command e2e sandbox (tests/e2e)
- **Task:** Document how users test/audit the module before production (pamtester usage,
  optional one-command Docker sandbox with mock OIDC, "what else" recommendations), and
  integrate the sandbox into the automated test framework.
- **Decisions & Rationale:**
  - New `tests/e2e/`: `mock_oidc.py` (Python 3 stdlib, HTTPS via self-signed cert trusted via
    the system CA store; scenario file selects per device-code request; **enforces PKCE S256
    for real** — stores code_challenge, rejects token polls whose code_verifier does not
    re-derive to it; issues alg=none JWTs so `verify_jwt_claims` runs), `pam_driver.c`
    (deterministic PAM driver: classical `pam_conv` multi-message conv, prints
    PAM_TEXT_INFO/PAM_ERROR_MSG, auto-answers the module's "Press [Enter]" prompt, exits with
    the PAM retval), `pam_oidc_device.e2e.conf` (use_pkce=true, verify_jwt_claims=true,
    issuer/audience pinned to https://127.0.0.1:8443), `pam.d-e2e` (`auth requisite
    pam_oidc_device.so` under throwaway service `e2e`), `run_e2e.sh` (7 asserted scenarios:
    success / claim-mismatch / provider-denied / slow_down-backoff / root-denied / code-expired
    / fail-closed 0644 config), `Dockerfile` (ubuntu:24.04, production-style install).
  - `Makefile`: `make sandbox` (build+run, headless) and `make sandbox-shell`; CI: new
    `e2e-sandbox` job in `build.yml` (same harness, no docker-in-docker; PAM module dir
    computed architecture-aware via `dpkg-architecture` — **/lib64/security on EL,
    /lib/<multiarch>/security on Debian/Ubuntu**).
  - `docs/testing.md` — full guide: test layers, sandbox, `pamtester` setup + PAM
    return-code table + 7-case negative matrix + real-ssh gold standard, real-IdP trial
    checklist, pre-production audit/rollback checklist, roadmap (config-check CLI, sshd e2e,
    authselect template, provider matrix, more scenarios, fuzzing).
  - **Why not drive automation with `pamtester` itself:** its source could not be located in
    the linux-pam trees (it ships as its own tiny distro package, e.g. Debian `pamtester
    0.1.2`), so its conversation handling of the module's Enter prompt is unverifiable;
    `pam_driver.c` is the deterministic substitute (pamtester remains the documented manual
    tool, with a NOTE about the prompt caveat).
- **Gotchas & Lessons:**
  - Debian/Ubuntu `libpam0g-dev` provides `security/pam_appl.h` + `pam_ext/pam_modules.h` but
    **no `pam_ap.h`** — app-side PAM code must include `pam_appl.h` (EL has both).
  - `pam_start()` takes `const struct pam_conv *` (a struct whose `.conv` is the classical
    `(int num_messages, const struct pam_message **, struct pam_response **, void *)` fn) —
    not a bare conv pointer; `pam_response` field is `resp` (not `resp_msg`).
  - **Linux-PAM status numbers are NOT classic PAM v1 numbering**: on Linux-PAM
    `PAM_SERVICE_ERR=3, PAM_PERM_DENIED=6, PAM_AUTH_ERR=7, PAM_AUTHINFO_UNAVAIL=9,
    PAM_ABORT=26, PAM_MODULE_UNKNOWN=28` (classic PAM has AUTH_ERR=1, PERM_DENIED=7,
    SERVICE_ERR=12, ...). Verify against `/usr/include/security/_pam_types.h` before
    hardcoding expectations; `pam_strerror` prints the name either way.
  - Docker images on Apple Silicon are arm64: a module installed to
    `/lib/x86_64-linux-gnu/security` is **PAM_MODULE_UNKNOWN** to an arm64 PAM — compute the
    PAM dir, don't hardcode it.
  - When the e2e run fell back to `/etc/pam.d/other` → `common-auth` (pam_unix hidden
    "Password:" prompt, every case PAM_AUTH_ERR), the cause was a missing
    `/etc/pam.d/e2e` install line lost during a split editor write — always grep the script
    after multi-chunk file creation.
  - `run_e2e.sh` refuses to overwrite an existing `/etc/pam_oidc_device.conf` that doesn't
    point at the sandbox mock; `make install` installs the stock sample config if absent — so
    both the Dockerfile and the CI job pre-stage the e2e fixture *before* `make install`.
- **Verification:** `make sandbox` green end-to-end on this host (Docker 29.9.3, arm64
  Ubuntu 24.04 container): all 7 scenarios pass, mock log shows full device→token→userinfo
  flow with `pkce=yes` on every issue; manual in-container runs confirmed root→6 and
  0644-config→3 with the expected log lines. `bash -n`, `python3 -m py_compile` clean.
  **Still requires CI:** the new `e2e-sandbox` job has not run remotely; C code in `src/`
  unchanged so the existing gcc/clang/lint/sanitize gates are unaffected.
- **Follow-ups / Open Items:** push and confirm `e2e-sandbox` is green in CI; watch
  `pamtester` behavior on hosts (doc NOTE covers the Enter-prompt caveat); roadmap items in
  docs/testing.md §6 (config-check CLI, sshd-in-container e2e, authselect template, provider
  matrix, PAM_ABORT/group/PKCE-auto scenarios, config-parser fuzzing).

### 2026-11-11 — Third-party notices + license-compliance automation (license-audit)
- **Task:** Add root `THIRD_PARTY_NOTICES.md` (detailed) + compact README section, and automate
  license compliance in CI (local mechanical gate + GitHub dependency-graph audit).
- **Decisions & Rationale:**
  - Licenses verified against upstream before writing: Nayuki qrcodegen MIT (in-source header);
    Linux-PAM = 3-clause BSD-style notice, "ALTERNATIVELY ... GNU GPL" per upstream COPYING;
    cURL = the "curl license" (MIT-style permission notice); json-c = MIT (COPYING: Haszlakiewicz
    + Metaparadigm); OpenSSL = Apache-2.0 (3.x, repo badge + README; historical: dual); CMocka =
    Apache-2.0 per cmocka.org (1.x distro releases: 3-clause BSD) — build-only, never shipped.
  - `scripts/check-licenses.sh` layers: L1 notices present; L2 per-component license text +
    attribution + provenance; L3 copyleft rejection; L4 spec `Requires:` cross-declaration.
    L2's license-text patterns *include* copyleft headers, so a GPL component fails at L3
    (the correct layer), not L2.
  - `scripts/audit-dependency-graph.py` audits `gh api graphql` `packagesV2` output against a
    permissive allowlist: empty graph → INFO + exit 0; undeclared package → WARN only;
    off-allowlist license or GraphQL `errors[]` → exit 1. Auto-activates when a manifest
    (CMakeLists.txt, package.json, ...) is ever added.
  - New `license-audit.yml` (push/PR main + monthly 08:00 UTC + dispatch; `contents: read`;
    SHA-pinned checkout v7.0.1; concurrency group); `make check-licenses` target; RPM source
    tarball now includes `THIRD_PARTY_NOTICES.md`.
- **Gotchas & Lessons:** spec `Requires:` values are comma-separated — first L4 attempt parsed
  `pam,` and failed; normalize with `tr ',' ' '`. macOS `cat -A` doesn't exist (use `cat -v`).
  Editor `new_text` > ~6000 chars is rejected — write the notices file in 3 inserts.
- **Verification:** `make check-licenses` green locally; negative tests all reverted cleanly —
  L1 (file moved away) / L2 (bare component) / L3 (GPL header now fails at L3, not L2) / L4
  (json-c scrubbed from notices) each fail with exit 1; python audit exercised on mock
  empty/GPL/GraphQL-error payloads (exits 0/1/1). No C code changed, so build/lint/test gates
  are unaffected. **Still requires CI:** the new `license-audit.yml` jobs have not run remotely.
- **Follow-ups / Open Items:** push the branch and confirm both `license-audit` jobs are green
  in CI (the GraphQL field shape — `dependencyGraph.packagesV2` — was written from the current
  schema; watch the first remote run).

### 2026-11-11 — Memory-scrub inspection gate + jwt.c ID-token payload PII scrub fix
- **Task:** User asked to set up Makefile + GitHub Actions to run on every push: (1) static analysis (cppcheck/flawfinder/clang-tidy), (2) ASan/UBSan test builds, (3) memory-management inspection verifying secrets/buffers/state are explicitly zeroed before free/return.
- **Decisions & Rationale:**
  - Items (1) and (2) already existed and were left untouched: `make lint` (clang-format/clang-tidy/cppcheck/flawfinder, all CI-mirrored in `lint.yml`) and the `sanitize-test` job (`make test-sanitize CC=clang`, ASan+UBSan+LSan, builds AND runs the CMocka suite). Do not duplicate these gates.
  - Item (3) was new: `scripts/check-memory-scrubbing.sh` — pure bash/grep (no PAM headers, no toolchain; runs identically on macOS and CI). S1: every `free()` of a sensitive heap buffer (`postfields`, `token_postfields`, `access_token`, `payload_b64`, `payload_json_str`, `resp->body`) requires a same-file `secure_memzero()`/`explicit_bzero()` scrub with first-scrub ordered before first-free. S2: plain `memset()` of a sensitive anchor (incl. `code_verifier`, `code_challenge`, `client_secret`, `device_code`, `cfg`, `dev`) is only tolerated when a secure scrub of the same anchor also exists in the file (top-of-function init-zeroing is kept; memset-as-only-zeroing fails). S3: every `json_object_put(X)` requires same-file `secure_zero_json_tree(X)`; only allowlisted handle is `doc` (http.c discovery metadata, no secrets/PII).
  - Wiring: `Makefile` `check-scrub` target (+ `.PHONY`); `lint.sh` step 5 (so `make lint` and `.githooks/pre-commit` run it — no hook change needed, only a comment fix); new `memory-scrub` job appended to `lint.yml` (runs on `push: [main]` + `pull_request`, `permissions: contents: read` inherited); context.md §3.1 renumbered (new step 6, loop now 1–10; `make lint` shortcut now "steps 1–5"); §3.2 + §4.1 + §3.3 updated.
  - **Real §4.1 gap the gate caught:** `src/jwt.c` released the provider-parsed ID-token payload via `json_object_put(payload_json)` at 9 sites without scrubbing json-c's private PII string copies (only app-owned `payload_b64`/`payload_json_str` were scrubbed). Fix: `secure_zero_json_tree()` de-staticed (pam_module.c) and exported via `include/pam_oidc_device.h` (documented); all 9 `jwt.c` sites now scrub before put (bulk perl insertion, verified by grep).
- **Gotchas & Lessons:** ERE gotcha: in `grep -E` an escaped `\(` matches a literal OPEN paren — a stray trailing `\(` in the scrub pattern demanded `secure_memzero(id(` and silently broke S1/S3 detection (every real scrub "missing"). Negative-testing the script requires copying it INTO the fixture tree (`cd "$(dirname "$0")/.."` resolves to the script's own repo, so running it from the real repo by absolute path against a /tmp fixture silently checks the real tree).
- **Verification (all on Linux, ubuntu:24.04 container mirroring CI):** `make check-scrub` ✓; `make lint` ✓ (clang-format + clang-tidy + cppcheck + flawfinder 2.0.19 + memory-scrub); `make CC=gcc EXTRA_CFLAGS=-Werror` + `make test CC=gcc` 51/51 ✓; same for clang ✓; standalone `clang-tidy src/*.c` ✓; `make test-sanitize CC=clang EXTRA_CFLAGS=-Werror` 51/51 ✓ (ALL_GATES_PASSED). Locally (macOS): `make check-scrub` ✓ plus S1/S2/S3 negative tests in a /tmp fixture each fail the gate. NOT run: `make rpm` (EL container only — leave to CI `rpm-build`; the change adds no files to the rpm tarball, and no new packaging surface).
- **Follow-ups / Open Items:** None (S1/S2/S3 are lexical; coarse-path blind spot documented in the script header — sanitizer run + §10.1 audit pass remain the backstop).

### 2026-11-10 — Condensed default text prompt (removed leading blank line + internal blank line)
- **Task:** User reported residual extra whitespace between the rendered QR block and "Complete authentication in your browser:" and wanted the whole SSH session prompt as concise as possible.
- **Decisions & Rationale:** Root cause: the built-in default template in `render_prompt_message()` (src/pam_module.c) began with a leading `\n` AND contained `\n\n` before the "Waiting for your approval..." line; stacked on the QR bottom vertical quiet zone (default 4 modules = 2 blank utf8 lines) that gave ~3 blank lines of gap (0.3.0 had removed only the QR block's *trailing* blank line). Removed the leading `\n` and the internal blank line from BOTH default branches (with/without `url_complete`) — the QR bottom quiet zone still separates art from prompt when the QR is shown. Condensed the shipped `init_message` templates identically in `config/pam_oidc_device.conf` + all three `examples/*.conf`. `test_prompt_rendering` now pins the exact default-template output for both branches (previously only the return code was asserted, so this string change broke nothing).
- **Gotchas & Lessons:** Deployments that SET `init_message` (the shipped config does) do not get the built-in default — the host must adopt the updated template or clear `init_message`; the user's test host was already falling through to the built-in default. `vertical_quiet_zone = 2` remains the config knob to cut the QR blank lines from 2 to 1.
- **Verification:** Docker CI-mirror gate (ubuntu:24.04): `make CC=gcc EXTRA_CFLAGS=-Werror` + 51-test CMocka suite, `make CC=clang EXTRA_CFLAGS=-Werror` + 51-test suite, `clang-tidy src/*.c -- -Iinclude -D_GNU_SOURCE` (clean), `make test-sanitize CC=clang EXTRA_CFLAGS=-Werror` (51/51) — ALL-PASS (`CI_MIRROR_GATE_ALL_PASS`; zbar roundtrip skipped in-container, runs in CI's `qr-scan-audit`). Local: `clang-format --dry-run --Werror src/*.c include/*.h tests/*.c` clean. `make rpm` (EL8/9/10) still requires CI.
- **Follow-ups / Open Items:** Commit on `wglick/review2` stacked after d946d7d; the two blank QR quiet-zone lines are now the only gap between art and prompt (ISO-minimum default, intentional).


### 2026-11-10 — §10.4 follow-up review fixes: -Werror CI enforcement, SHA-pin/permissions/concurrency, `rpm: clean`, dnf install, pam_sm_authenticate phase extraction

- **Task:** Address the follow-up review findings on `wglick/review2`: (1) the zero-warning bar is
  documented but not mechanically enforced; (2) CI workflows lack SHA pinning, `permissions:`, and
  `concurrency:`; (3) `make rpm` packages the working tree (stale-`.o` hazard); (4) `dnf localinstall`
  deprecated, `zbar-tools` unused in compile-matrix/sanitize jobs; (5) `pam_sm_authenticate()` ~600
  lines (extract device-auth-request and poll-loop phases).
- **Decisions & Rationale:**
  - **`EXTRA_CFLAGS` (Makefile):** new appendable variable added to every compile recipe
    (`src/%.o`, `third_party` rule, `sanitize`, `test`, `test-sanitize`); CI passes
    `EXTRA_CFLAGS=-Werror` so any warning fails the build (works because `CFLAGS ?=` can't be
    command-line-extended — command-line assignment replaces it wholesale).
  - **SHA pinning:** resolved `actions/checkout@v7.0.1` → commit
    `3d3c42e5aac5ba805825da76410c181273ba90b1` via the GitHub API (`/repos/actions/checkout/commits/v7.0.1`)
    and pinned all 9 `uses:` (4 build.yml, 4 lint.yml, 1 vendor-audit.yml) with a trailing `# v7.0.1` comment.
  - **Least privilege / cancel groups:** top-level `permissions: contents: read` +
    `concurrency: {group: "${{ github.workflow }}-${{ github.ref }}", cancel-in-progress: true}`
    on all three workflows (no job needs anything beyond content reads; no artifacts are published).
  - **`rpm: clean`:** chosen over `git archive` (which would silently package HEAD instead of the
    working tree a local dev intends to package, and breaks non-git tarball builds).
  - **Phase extraction (pam_module.c):** new static helpers `request_device_authorization()`
    (RFC 8628 §3.1/§3.2 form build → POST → parse/validate → deadline) and `poll_for_access_token()`
    (§3.4/§3.5 form build → poll loop → access token); new `device_auth_t` result struct
    (`DEVICE_CODE_MAX_LEN 2048`) whose URI/user-code members are BORROWED from the caller-owned
    `*dev_json` tree. Pure code motion: identical log messages, return codes, clamping, backoff,
    and the single caller-owned `cleanup` path (helpers never own resources — they write into
    caller storage and return the PAM code). `pam_sm_authenticate()` dropped ~690 → 334 lines.
  - rpm-build `dnf localinstall` → `dnf install`; dropped `zbar-tools` from compile-matrix and
    sanitize-test (kept in `qr-scan-audit`, the only zbarimg consumer).
- **Gotchas & Lessons:**
  - Editor chunking of a large extraction: the helper copy and the original in-function copy are
    textually identical until the `loglevel` vs `active_loglevel` / `->` vs `.` substitutions —
    anchors must include those lines or the edit matches twice.
  - `pam_oauth_log(..., LOGLEVEL_DEBUG, LOG_DEBUG, ...)` has two similar-looking enum args; a
    typo in one silently fails the old_text match — re-read the region instead of retyping.
  - Backgrounded `docker run` subshells from `run_commands` get killed when the call times out —
    relaunch with `nohup ... & disown` and poll the log file.
  - Local clang-format (19.1.7) reflowed 6 spots in the new helper code (comment-column alignment,
    line wrapping) — always re-run `clang-format --dry-run --Werror` after C edits.
- **Verification:** local: `clang-format --dry-run --Werror src/pam_module.c` clean;
  `make -n rpm` runs `clean` first; all 3 workflow YAMLs parse. Docker CI-mirror gate
  (ubuntu:24.04): gcc+clang `make EXTRA_CFLAGS=-Werror`, `make test EXTRA_CFLAGS=-Werror`
  (both compilers), `make test-sanitize CC=clang EXTRA_CFLAGS=-Werror`, `qr_render_check` +
  zbar decode roundtrip — ALL-PASS.
- **Follow-ups / Open Items:** commit on `wglick/review2` (stacked with QR-quiet-zone + §10 fixes,
  awaiting user sign-off); CI EL8/9/10 `rpm-build` matrix + `qr-scan-audit` must stay green on push.

### 2026-11-10 — Configurable QR vertical quiet zone + removed trailing separator blank line

- **Task:** User reported excess vertical whitespace around the terminal QR code (2 blank lines above,
  2 below, plus 1 trailing separator line). User chose a **configurable** vertical quiet zone over a
  hard reduction or a docs-only answer.
- **Decisions & Rationale:**
  - The blank lines are the ISO/IEC 18004 4-module quiet zone (2 text lines/side in the utf8 half-block
    style) — required for reliable scanning, so the default stays 4. New `[qr]` key
    `vertical_quiet_zone` (0–4, `parse_int_range`, default `QR_QUIET_ZONE`) lets operators trade
    scanner robustness for compactness; the **horizontal** quiet zone stays fixed at 4 (it separates
    the symbol from adjacent terminal text).
  - The trailing separator blank line appended by `qr_render_verification_code()` was pure redundancy
    (the bottom quiet zone already separates art from the following prompt) — removed unconditionally;
    the undersized-buffer guard tightened from `strlen(header)+3` to `+2` (only the NUL is reserved now).
  - `qr_render_matrix()` gained a `vquiet` parameter (public-API change; `qr_render_check.c` harness
    updated to pass `QR_QUIET_ZONE` so the CI `qr-scan-audit` art stays ISO-compliant).
  - `art2png.py`: optional `VQUIET` arg; ASCII scale detection switched from the top light border to
    the leading-space run of the first non-blank line (the horizontal quiet zone is always 4×scale at
    any vertical zone — the top-left finder pattern guarantees a dark module right after it); quiet-zone
    guard checks outer `vquiet` rows vertically; shape check is now
    `mod_cols - mod_rows == 2*(QUIET_ZONE - vquiet)` instead of squareness.
  - Roundtrip unit test now decodes BOTH styles at vquiet 4 **and** 2 through zbarimg; matrix test pins
    compact-vquiet expectations for both styles; guard test re-pinned to the new bound.
- **Gotchas & Lessons:**
  - `art2png.py` `main()` argv off-by-one: `python3 art2png.py ART OUT PX VQ` is **5** argv entries
    (len 6 would be a phantom 6th). The old code also silently ignored `argv[3]` unless len==5 — a
    latent bug fixed by `px = int(argv[3]) if len(argv) >= 4 else 3`; len 3 (px defaulted) is now
    accepted, matching the documented usage. Caught only by a synthetic-art functional check —
    the in-repo callers always pass all args, so the unit tests alone missed it.
  - ubuntu:24.04 docker images don't ship `make` — add it to the gate's apt install list.
- **Verification:** CI-mirror docker gate (ubuntu:24.04): gcc/clang builds + 51-test CMocka suites
  (now including the zbar roundtrip at both quiet zones, since zbar-tools is installed in the gate),
  `make test-sanitize CC=clang`, `qr_render_check` harness + zbar decode — see entry follow-up for
  results. Local: `clang-format --dry-run --Werror` clean; `art2png.py` functional check on synthetic
  art (vquiet accept/reject/shape-guard) all PASS.
- **Follow-ups / Open Items:** commit alongside the §10 review fixes on `wglick/review2`; CI
  `qr-scan-audit` and EL8/9/10 rpm matrix must stay green on push.

### 2026-11-10 — Implemented all four §10 audit fixes (PII log, QR underflow, NUL scrub, json-c 0.17 warnings)

- **Task:** Implemented and validated the four findings from the prior §10 audit (see entry below).
- **Decisions & Rationale:**
  - **json-c index compat (fixes the 4 `-Wsign-conversion` warnings):** added a single
    `JSON_ARRAY_IDX()` macro to `include/pam_oidc_device.h` (with `#include
    <json-c/json_c_version.h>`) that expands to the bare index on json-c >= 0.17 (`size_t`
    parameter since 0.17) and to `(int)(i)` on older releases (e.g. EL8's 0.13). Replaced the
    `(int)i` casts at `src/http.c`, `src/identity.c`, `src/jwt.c`, `src/pam_module.c`
    (`json_object_array_get_idx` call sites). Version-detection via `JSON_C_MAJOR/MINOR_VERSION`
    (defined since json-c 0.10; guarded with `defined()` checks for ancient headers).
  - **PII logging:** `verify_claim()` (`src/identity.c`) raw-claim log demoted
    LOGLEVEL_DEBUG → LOGLEVEL_VERBOSE, with a comment referencing the redacted DEBUG receipt in
    `pam_sm_authenticate()`. Chosen over logging lengths/hashes to preserve verbose-level
    debuggability while matching the documented redaction policy.
  - **QR underflow:** `qr_render_verification_code()` (`src/qr.c`) guard now rejects
    `out_len < strlen(QR_HEADER_LINE) + 3` before any `out_len - 2` arithmetic (out_len == 1
    previously underflowed to SIZE_MAX → unbounded snprintf). Test extended with undersized-buffer
    cases (0, 1, 2, header+2, header+3) including a no-write check (`out[0] == 'X'` sentinel).
  - **NUL scrub:** `free_http_response()` (`src/http.c`) now scrubs `resp->size + 1` bytes
    (write_callback guarantees `body[size] == '\0'`), matching the strlen+1 convention.
  - CHANGELOG gained an `[Unreleased]` → `### Fixed` section with all four entries.
- **Gotchas & Lessons:**
  - Background `docker run` via `nohup ... &` from the tool shell gets killed when the command
    exits; use **detached mode** (`docker run -d --name ... bash /ci_gate.sh`) and poll
    `docker logs` instead.
  - clang-format wraps long `#if` conditions (the version-check line exceeded the column limit
    and needed `clang-format -i` before the format gate passed).
  - When grepping gate logs for warnings, exclude make's echoed compile commands — they contain
    `-Wconversion` and false-positive; grep for `warning:` / `sign-conversion` instead.
- **Verification:** Full CI-mirror container gate (ubuntu:24.04) passed end-to-end: gcc and clang
  builds under the full CFLAGS **with zero compiler warnings** (previously 4
  `-Wsign-conversion`), 51/51 CMocka tests both compilers (extended QR test included),
  clang-tidy (`WarningsAsErrors: '*'`), cppcheck, flawfinder, clang-format dry-run, and
  `make test-sanitize CC=clang`. Local clang-format leg passed after reformatting the header.
  RPM gate not re-run locally (CI covers EL8/9/10; the `(int)` path for EL8's json-c 0.13 is
  compile-time-selected by the macro but not natively compiled here).
- **Follow-ups / Open Items:** none for these fixes; changes are uncommitted on `wglick/review2`
  alongside the audit memory entry — commit (and PR-scope decision: docs-only PR now carries code
  fixes) is left to the maintainer.


### 2026-11-10 — Comprehensive §10 four-pass PR audit (wglick/review2, e6d56c8)

- **Task:** Full §10 audit-pass review (security §10.1 / RFC protocol §10.2 / build-automation §10.3 /
  quality §10.4) of the PR delta (docs-only `context.md` refactor) plus the full codebase snapshot,
  and execution of the CI-mirrored verification gates.
- **Verification:** Full Linux CI-mirror (ubuntu:24.04 container) passed end-to-end: gcc and clang
  builds, 51/51 CMocka tests under both compilers, clang-tidy, cppcheck, flawfinder, clang-format
  18.1.x dry-run, and `make test-sanitize CC=clang` (ASan/UBSan/LSan, executed). RPM gate not re-run
  locally (docs-only delta; `.agents/` is excluded from the rpm tarball) — CI covers it. The TOC
  anchor check (pending from the prior entry) is now done: GitHub-style slugger → 0 broken links;
  structure checks re-confirmed (11 `##` / 15 `###`, no sentinels, no double blanks, single trailing
  newline, symlinks intact).
- **Findings (all pre-existing on main; none introduced by this PR):**
  - **MEDIUM — zero-warning bar violated:** gcc and clang builds under the full CFLAGS emit 4
    `-Wsign-conversion` warnings: `src/http.c:183`, `src/identity.c:359`, `src/jwt.c:333`,
    `src/pam_module.c:193` — all `json_object_array_get_idx(x, (int)i)`. json-c >= 0.17 takes a
    `size_t` index, so the `(int)` cast now *causes* the warning (and removing it would warn on
    EL8's json-c 0.13 `int` parameter) — needs a version-conditional compat cast. CI passes anyway
    because `make` has no `-Werror`, i.e. §3.1 step 8's zero-warning bar is not mechanically
    enforced.
  - **MEDIUM-LOW — PII at debug level:** `verify_claim` (`src/identity.c:114-116`) logs the raw
    claim value at LOGLEVEL_DEBUG, contradicting `pam_module.c` step-8 comment (line 355: full
    payload "only at verbose").
  - **LOW — unsigned underflow:** `qr_render_verification_code` (`src/qr.c:229-231`) computes
    `out_len - 2` after only rejecting `out_len == 0`; `out_len == 1` underflows to SIZE_MAX →
    unbounded snprintf. Unreachable via the production caller (32 KiB `qr_buf`), but the function
    is exported in the public header.
  - **LOW — CI hardening gap vs §10.3's own bar:** all 8 `actions/checkout` uses are tag-pinned
    (`@v7.0.1`), not SHA-pinned; no `permissions:` blocks in any workflow.
  - **Informational:** `base64url_decode` does not pre-reject length ≡ 1 (mod 4) (relies on BIO
    failure); `make rpm` packages the working tree (known invariant — consider a `clean`
    prerequisite); `dnf localinstall` is deprecated in favor of `dnf install`; `zbar-tools` is
    installed but unused in the compile-matrix and sanitize jobs; no `concurrency:` cancel group.
- **Follow-ups / Open Items:** the two MEDIUM findings are the only candidates worth fixing before
  the next release; the rest are optional hardening.


### 2026-11-10 — Restructured `.agents/context.md` (10 numbered sections, deduplicated, tool-agnostic)

- **Task:** Full rebase/refactor of `.agents/context.md` (the canonical file behind the
  `AGENTS.md` and `CLAUDE.md` symlinks) for consistency and cross-tool usefulness.
- **Decisions & Rationale:**
  - Re-numbered to a clean 1–10 scheme with a Contents table (§/title/"read it when") up top;
    the previously un-numbered "Code Audit & Specialized Review Workflows" addendum became §10
    with passes §10.1–§10.4.
  - Deduplicated overlapping content: old §9 (Core Security Best Practices) folded into §4 as
    §4.5 (auth-flow hardening); old §8 clang-tidy/compiler-flag duplicates now cross-reference
    §3.1; old §11 reference links consolidated into §9; output-discipline rules moved from
    contributor guidelines into §6 (Agent Operational Safety Rules).
  - Documented the symlink wiring (`.agents/context.md` ← `AGENTS.md` ← `CLAUDE.md`) in the
    header and added the missing subsystems `src/pkce.c` and `src/qr.c` plus a repository-layout
    map (verified against the actual tree).
  - Unified formatting: `-` bullets only, consistent ~95-col wrapping, single-blank-line
    separation, cleaned stray `>` blanks inside audit blockquotes, exactly one trailing newline.
  - All CI gate commands preserved **verbatim** (clang-format/clang-tidy/cppcheck/flawfinder,
    `make test-sanitize CC=clang`, docker CI-mirror command, Python fixture snippet).
  - Cross-reference audit: this file's historical references to "AGENTS.md §3" (verification
    gates / non-Linux hosts) remain valid — verification is still §3 (§3.3 = non-Linux hosts).
- **Gotchas & Lessons:** large file rewrites must be chunked through the editor tool (<6 KB per
  call) with a `<!-- CONTINUE -->` sentinel; the editor appends extra trailing newlines that
  need a final normalize pass.
- **Verification:** docs-only change — no C code touched, so no build/test gates apply. Verified
  locally on macOS: heading structure (11 `##`, 15 `###`), no leftover sentinels, no double
  blank lines, all verbatim gate commands present (grep spot-check), symlinks resolve to the new
  content, exactly one trailing newline. Rendering/rendered-anchor check pending CI/preview.
- **Follow-ups / Open Items:** none.

### 2026-11-09 — Full re-review (post-0.2.0): no new code defects; fixed one stale "countdown" comment

- **Task:** Thorough code/security/documentation re-review after the 0.2.0 changelog rebase and
  the `require_keypress`-mandatory + on-screen-countdown-removal work.
- **Decisions & Rationale:**
  - Confirmed the `[0.2.0]` CHANGELOG entry is clean (no residual "countdown" references). The
    `.agents/memory.md` historical entries intentionally retain their original "countdown" wording
    (they are the machine log, not user docs — do not rewrite them).
  - Fixed the LAST code-side reference to the removed on-screen expiry countdown: a stale comment
    in `src/pam_module.c` (the `PAM_TEXT_INFO` prompt block, ~line 671) still said "the same
    primitive used for the QR code and the expiry countdown", quoted the old
    `PAM_PROMPT_ECHO_ON "Press Enter to continue"` text, and cited a non-existent "(Step 4d)".
    Rewrote it to describe the mandatory "Press [Enter] to begin..." confirmation (Step 4c).
    Comment-only; no behavior change.
- **Gotchas & Lessons:**
  - When a feature is removed, grep the *entire* tree (not just CHANGELOG) for the old term — the
    countdown wording lived on in a code comment that documented the OpenSSH flush mechanism.
  - Re-verified the standing hardening invariants: `form_field_append()` bounds the 5-field
    device/token tables; PKCE verifier/challenge + `postfields`/`token_postfields` +
    `access_token` + all json-c trees are scrubbed via `secure_memzero`/`secure_zero_json_tree`;
    config load enforces `O_NOFOLLOW|O_CLOEXEC` + `S_ISREG` + uid 0 + 0600/0640(gid 0); TLS 1.2+
    with `SSL_VERIFYPEER`/`SSL_VERIFYHOST`; monotonic-clock polling that aborts on `EINTR`; root
    default-deny. All present and correct.
- **Verification:** LOCAL (macOS): a comment-only edit cannot alter compiler output;
  `clang-format --dry-run --Werror src/*.c include/*.h tests/*.c` green; grep confirms zero
  residual "countdown"/"Step 4d"/"Press Enter to continue" in `src/`/`include/`. NOT RUN (no Linux
  PAM host): gcc+clang build/test matrix, `make test-sanitize CC=clang`, `make rpm` — a comment-only
  edit cannot regress these, but CI still formally gates the branch.
- **Follow-ups / Open Items:**
  - Push `wglick/review` to run the full Linux/CI gate loop (compile-matrix, sanitize-test,
    rpm-build, lint).


### 2026-11-12 — `require_keypress` made mandatory; option removed from config

- **Task:** Remove the `[prompt] require_keypress` config option; the "Press [Enter] to begin..."
  prompt is now always issued before polling starts.
- **Decisions & Rationale:**
  - The OpenSSH keyboard-interactive buffering issue makes `PAM_TEXT_INFO` invisible until a
    subsequent `PAM_PROMPT_*` round-trip. Since the Enter prompt is the *only* reliable flush
    mechanism, it is now unconditional rather than opt-in.
  - Removed the `require_keypress` field from `oidc_device_config_t`, the config parser,
    `init_config_defaults`, the shipped `.conf`, README, CHANGELOG, and all test fixtures.
  - The conditional in `pam_sm_authenticate` is now simply `if (pamh)` — the prompt is issued
    whenever a PAM handle is available.
- **Gotchas & Lessons:**
  - `config/pam_oidc_device.conf` previously had a commented-out `# require_keypress = false`
    line; it has been removed entirely so operators don't see it in `grep`.
  - The CHANGELOG entry for "Unreleased" now reads "Mandatory sign-in confirmation" instead of
    the two previous bullet points.
- **Verification:** No local compilation possible on macOS (PAM headers absent). The changes are
  mechanical: struct field removal, parser branch removal, conditional simplification, and test
  deletion. CI (gcc+clang build, lint, sanitizer) must confirm.
- **Follow-ups / Open Items:**
  - If a future change ever makes `PAM_TEXT_INFO` reliably flush on OpenSSH (e.g., SSH config
    `SendEnv` trick or PAM module re-entry), the keypress could be made optional again.

### 2026-11-09 — Non-blocking polling by default; new `[prompt] require_keypress`; removed on-screen countdown
- **Task:** Make the device-flow prompt non-blocking by default: show the URL/code, then start
  polling immediately (no Enter keypress). Add an optional config to require a keypress before
  polling. Remove the on-screen `show_countdown` timer entirely.
- **Decisions & Rationale:**
  - **Default = poll immediately.** `pam_sm_authenticate()` no longer issues a flush prompt after
    showing the sign-in URL/QR/user-code; it builds the token request and polls at once
    (`first_poll` skips the leading sleep). This replaces the previous "Option C hybrid flush"
    which always issued a best-effort `PAM_PROMPT_ECHO_ON` "Press Enter" prompt.
  - **New `[prompt] require_keypress` boolean (default `false`)** replaces the removed `show_countdown`
    in the config struct/bitfield/parse branch and in `init_config_defaults()`. When `true`, a single
    best-effort `PAM_PROMPT_ECHO_ON` "Press [Enter] to begin..." prompt is issued *before* polling;
    the keystroke is ignored, but the round-trip flushes the buffered PAM_TEXT_INFO to OpenSSH
    keyboard-interactive clients and acts as a sync barrier. A `PAM_ABORT` still cancels; other
    non-success results log and continue.
  - **Removed `show_countdown` everywhere:** `format_time_remaining()` + `render_countdown_line()`
    (and their `pam_sm_authenticate` Step-4c start + inter-poll repaint + trailing `PAM_TEXT_INFO "\n"`
    cleanup), the `COUNTDOWN_TICK_SECONDS` macro, the `countdown_buf/width/shown` locals, and the
    CMocka tests `test_format_time_remaining` / `test_render_countdown_line` /
    `test_parse_config_file_show_countdown`. `expires_in` is KEPT (it still bounds `device_deadline`,
    the monotonic poll deadline, capped by `max_poll_seconds`) — only the on-screen timer was dropped.
    The inter-poll sleep is now a single `clock_nanosleep` of the full `interval` (no slicing).
  - Updated shipped `config/pam_oidc_device.conf`, `README.md` (feature bullet + Quickstart), and
    `CHANGELOG.md` [Unreleased] to match.
- **Gotchas & Lessons:**
  - **CHANGELOG drift:** the [Unreleased] bullets described a "non-blocking" state the actual
    working tree (HEAD `b9de98c`) did NOT have — the blocking flush prompt was still present. Always
    diff against the *actual* source, not the changelog narrative, when planning a change.
  - `test_parse_config_file_full_sections` now asserts `require_keypress = yes` +
    `assert_int_equal(cfg.require_keypress, 1)`; the dedicated
    `test_parse_config_file_require_keypress` mirrors the old countdown test (accepted forms / absent
    default / invalid value / duplicate key).
  - The two removed helpers were PUBLIC (declared in `include/pam_oidc_device.h`, reachable by the
    test TU), so their tests were the only external references; grep `render_countdown_line` /
    `format_time_remaining` / `show_countdown` to confirm no stragglers.
- **Verification:** LOCAL (macOS) only — edits applied to `src/`, `include/`, `tests/`, config + docs.
  Native PAM build not possible on macOS. STILL REQUIRED: Linux gates / CI — `make lint`,
  `make CC=gcc && make test CC=gcc`, `make CC=clang && make test CC=clang`,
  `make test-sanitize CC=clang`, and `make rpm` (EL8/EL9/EL10). Not yet run in a Linux container here.

### 2026-11-08 — Hybrid flush strategy for reliable OpenSSH URL display; removed PAM-API-conflicting `pam_prompt` helper

- **Task:** Make the sign-in URL / QR / user code reliably appear on the terminal over OpenSSH's
  keyboard-interactive PAM (which can buffer `PAM_TEXT_INFO` until a subsequent prompt forces a
  round-trip), and remove a static helper that shadowed the real PAM API.
- **Decisions & Rationale:**
  - Added a single **best-effort `PAM_PROMPT_ECHO_ON` flush prompt** ("Press Enter to continue...")
    in `pam_sm_authenticate()` *after* the QR/URL/user-code (+ optional `[prompt] show_countdown`
    line) and *before* the token-poll loop — `src/pam_module.c` "Step 4d (hybrid flush, Option C)".
    The keystroke is intentionally ignored (the device-code flow is already in progress); polling
    proceeds on any non-`PAM_SUCCESS` result, and only a user `PAM_ABORT` cancels (returns
    `PAM_ABORT`).
  - **Removed the static `pam_prompt()` helper** defined in `pam_module.c`; it shadowed PAM's own
    `pam_prompt` from `security/pam_ap.h`. All call sites now use the native PAM function directly.
- **Gotchas & Lessons:**
  - A local function named after a PAM API symbol (`pam_prompt`, …) **collides with / silently
    shadows the real libpam API** — the "helper" never actually called PAM. Never define local
    functions with PAM API names (see the new Standing Invariant).
  - **clang-format version skew:** CI runs `clang-format` **18.1.3** (apt, `ubuntu:24.04`); a local
    Homebrew `clang-format` (19.x) formats the multi-line `pam_oauth_log(...)` continuation
    differently, so `clang-format --dry-run --Werror` fails on a logically-correct line. Re-format
    with clang-format 18 (see the existing "pinned 18.x" invariant) so the local result predicts CI.
    Only `src/pam_module.c` needed re-flowing (`git diff --stat`).
- **Verification:** Verified in an `ubuntu:24.04` Docker container mirroring CI: `make CC=gcc` and
  `make CC=clang` build clean (zero warnings) with all 54 CMocka tests passing; `make test-sanitize
  CC=clang` passes 54 tests under ASan/UBSan/LSan; `make lint` passes (clang-format 18 clean,
  clang-tidy clean on `src/*.c`, cppcheck clean; flawfinder skipped — not installed). **Still
  requires CI / live:** `make rpm` on EL8/EL9/EL10 (not runnable in the Ubuntu container),
  flawfinder on a host that has it, and a live OpenSSH keyboard-interactive login to confirm the
  flush prompt actually surfaces the URL.
- **Follow-ups:** Live OpenSSH end-to-end test (URL visible for the whole polling window);
  `CHANGELOG.md` [Unreleased] updated this session to document the hybrid flush and reconcile the
  "Non-blocking sign-in prompt" wording.

### 2026-11-08 — Root-caused the persistent "Press [Enter]" prompt; updated shipped config templates

- **Task:** Live SSH logins still showed a "Press [Enter]" prompt and still blocked on the Enter key,
  even though the `src/pam_module.c` Enter-gate had been removed in a prior session.
- **Decisions & Rationale:** The C code was already correct/non-blocking (prompt delivered via
  non-blocking `PAM_TEXT_INFO`; no `PAM_PROMPT_ECHO_ON`/`user_resp`/`pam_get_authtok` remain), so the
  stale prompt was NOT in the source. Two root causes: (1) `render_prompt_message()` only uses the
  built-in default when `cfg.init_message` is empty — every shipped config SETS `init_message`, and
  its templates (`config/pam_oidc_device.conf` + the three `examples/*.conf`) still ended with a
  "Press [Enter] …" line; (2) the deployed host ran a STALE `.so` (old blocking build) — the observed
  text "Press [Enter] after authenticating in your browser…" matched `config/pam_oidc_device.conf`
  line-for-line. Updated all four `init_message` templates to "Waiting for your approval; this session
  completes automatically once you sign in." and noted it in `CHANGELOG.md`.
- **Gotchas & Lessons:** The RPM ships the config as `%config(noreplace)` (spec) and `make install`
  writes the config ONLY when absent (`if [ ! -f … ]` in the Makefile install target). So updating the
  package never clobbers an existing `/etc/pam_oidc_device.conf` (new one lands as `…conf.rpmnew`).
  Any prompt-text change must land in BOTH the `src/pam_module.c` default AND the shipped config
  templates, and on the host requires a `.so` rebuild + manual config replacement.
- **Verification:** Verified locally via `grep` — no `Press [Enter]` in any `.conf`; new wording present
  in all four templates; source free of blocking prompt APIs. Config/doc-only change this session (no
  `src/*.c` touched), so the previously-verified lint/gcc+clang/test-sanitize/RPM gates for the C code
  are unaffected. The on-host fix (rebuild `.so` from current source + replace `/etc/pam_oidc_device.conf`)
  must be done on a Linux/EL host and cannot be verified from this macOS host.
- **Follow-ups / Open Items:** If blocking persists after a `.so` rebuild, the running `.so` is not the
  new build; confirm the host actually picked up the rebuilt module and the updated config.

### 2026-11-09 — v0.2.0 release finalization: version consistency, README/changelog alignment
### 2026-11-09 — v0.2.0 release finalization: version consistency, README/changelog alignment

- **Task:** Finalize the 0.2.0 release: bring every version source to `0.2.0`, align the README
  with the shipped `[prompt]`/`[qr]` features, and close out the changelog.
- **Decisions & Rationale:** Set `Makefile` (`VERSION`), `packaging/pam_oidc_device.spec`
  (`%global mod_version`), `packaging/gen-changelog.py` (`default_ver`), and `.agents/context.md`
  to `0.2.0` to match `include/metadata.h` (already `0.2.0` at `de058fb`), so no two source files
  disagree on the version. Promoted the `CHANGELOG.md` `[unreleased - targeted for 0.2.0]` header to
  `## [0.2.0] - 2026-11-09` (the accumulated unreleased Features/Security/Misc *are* the 0.2.0
  release; the historical `0.1.0` entries were left untouched). README: added Key-Features bullets
  for the QR sign-in and on-screen expiry countdown, added `[prompt]`/`[qr]` to the Quickstart
  config example, and bumped the example RPM filename to `0.2.0`.
- **Gotchas & Lessons:** `AGENTS.md` is a *symlink* to `.agents/context.md`, so a "missing" AGENTS.md
  version line was really already updated via `context.md`. In this environment the file-reader
  tool served **stale pre-`de058fb` snapshots** (it showed `metadata.h` at `0.1.0` and an older
  README/memory.md); ground truth had to come from `git show HEAD:<file>` / `grep` / `sed`. When a
  read and `git` disagree, trust `git`.
- **Verification:** Version-string consistency confirmed by `grep` across all source files and
  `git diff` (each version file is a clean single-line bump). README/config content cross-checked
  against `src/config.c` (`[prompt]`: `init_message`, `show_countdown`; `[qr]`: `enabled`, `style`,
  `block_char`). These are doc/packaging-only changes (no `src/` code touched), so they do not
  themselves require the Linux build/test gates; CI's `lint.yml`/`build.yml` still run on push.
- **Follow-ups / Open Items:** No dedicated `docs/` pages exist yet for QR rendering or the expiry
  countdown (the README documents them in Quickstart `Key Features` + config example instead);
  consider adding `docs/qr-terminal.md` / `docs/prompt-countdown.md` deep-dives and wiring them into
  the "Detailed Documentation" table. Confirm the release date/tag with maintainers.

### 2026-11-08 — RFC 8628 on-screen expiry countdown (`[prompt] show_countdown`)
- **Task:** Feature request: visually show remaining device-code expiry on the SSH
  terminal, optionally configured, updating every few seconds IN PLACE (no new line per
  update) — RFC 8628 encourages client-side countdowns from `expires_in`.
- **Decisions & Rationale:**
  - New `[prompt]` boolean key `show_countdown` (default `false`), parsed via `parse_bool`
    with duplicate-key tracking like every other key.
  - Line format `\rCode expires in MM:SS` (`H:MM:SS` ≥ 1 h), rendered by new public helpers
    `format_time_remaining()` / `render_countdown_line()` in `src/pam_module.c` (public so
    CMocka can reach them — the test TU links the .o's, not the .c). Module-static template
    + local time only → no provider/user data, so no `is_safe_terminal_string` needed.
  - In-place repaint: `\r` prefix + space padding to the first render's width (fixed for the
    session because remaining only decreases and MM:SS↔H:MM:SS can't widen).
  - Refresh cadence: the inter-poll sleep is sliced into `COUNTDOWN_TICK_SECONDS` (5 s)
    `clock_nanosleep` chunks that repaint after each wake; the HTTP poll still happens once
    per provider `interval`, so no extra load. When disabled, it's a single sleep exactly as
    before (chunk == interval).
  - Initial paint right after the main prompt (Step 4c); `PAM_ABORT` on interrupted
    conversation aborts; other display failures are non-fatal (informational line).
  - A single terminating `\n` (PAM_TEXT_INFO) is emitted after the poll loop when the
    countdown was shown, so later PAM messages start on a fresh line.
  - Remaining time is recomputed from the monotonic `device_deadline` (never wall clock);
    clamped to [0, 359999].
- **Gotchas & Lessons:**
  - Trailing-space assertions are a footgun: the test literal must have exactly 2 spaces to
    match width 24 ("\rCode expires in 00:45  ") — first container run failed
    `test_render_countdown_line` because the literal had 3 spaces; verify such lines with
    `od -c`, not by eyeballing.
  - Stale `src/*.o` in the tree were packaged into the local RPM tarball → `%check` linked
    Ubuntu-clang objects under EL9 gcc (`__isoc23_strtol` undefined). `make clean` +
    `rm -rf rpmbuild` before the rpm gate; base-commit worktree proved it environmental.
  - macOS ASan binaries built with the local toolchain hang at startup (ld dylib-version
    mismatch warning) — don't use ASan for local macOS smoke checks; the Linux sanitizer
    gate is authoritative.
- **Verification (all in `ubuntu:24.04` / `rockylinux/rockylinux:9` aarch64 containers
  mirroring CI; native macOS PAM build is not possible):**
  - `make CC=gcc` + `make test CC=gcc` → 54/54 PASS (3 new tests:
    `test_parse_config_file_show_countdown`, `test_format_time_remaining`,
    `test_render_countdown_line`; `test_parse_config_file_full_sections` extended).
  - `make CC=clang` + `make test CC=clang` → 54/54 PASS.
  - `clang-tidy src/*.c -- -Iinclude -D_GNU_SOURCE` clean; `clang-format --dry-run
    --Werror src/*.c include/*.h tests/*.c` clean; cppcheck + flawfinder clean.
  - `make test-sanitize CC=clang` → 54/54 PASS under ASan/UBSan/LSan.
  - EL9 `make rpm` (incl. `%check`) + `dnf localinstall` → `.so` + `.conf` verified.
  - **Still CI-only:** EL8 + EL10 rpm matrix, ubuntu-latest (x86_64) lint/build jobs,
    and real-terminal behavior of the `\r` repaint under an actual sshd session (byte-level
    behavior is unit-tested; PTY rendering itself is not).
- **Follow-ups / Open Items:** nothing blocking. Possible future work: configurable
  countdown refresh period, alternate wording, or a progress-bar style — keep any change
  to the line format in sync with `test_render_countdown_line`.

### 2026-11-08 — CI `zbarimg` PNG rejection → PGM switch; found & fixed vertical-raster truncation bug

### 2026-11-08 — CI `zbarimg` PNG rejection → PGM switch; found & fixed vertical-raster truncation bug
- **Task:** CI (ubuntu-latest, `zbar-tools`) failed `test_qr_scan_roundtrip`:
  `ERROR: Not enough image data … @ error/png.c/MagickPNGErrorHandler` — CI's
  zbarimg reads images through ImageMagick, whose strict PNG decoder rejected
  the hand-rolled PNG. The local macOS "zbarimg" (a zxing-cpp/PIL shim) had
  passed, because **PIL silently zero-pads truncated images** — masking the
  real bug.
- **Decisions & Rationale:** Root cause was NOT the PNG format:
  `tests/qr_scan/art2png.py` expanded pixel columns by `px_per_module` but
  appended **one** pixel row per module row, so the raster carried only
  1/px_per_module of the declared scanline bytes (e.g. 41 of 123 rows at
  scale 3). Fixed by repeating each expanded row `px_per_module` times
  vertically (`pixel_rows.extend([bytes(pixel)] * px_per_module)`). The
  machine-scanned leg now writes **P5 PGM** (`.pgm` out-extension in
  `art2png.py`; trivial header+raw-bytes writer, no zlib/chunk/CRC) instead of
  PNG: it decodes under any zbarimg image backend (ImageMagick's native PGM
  coder or libzbar's built-in PPM/PGM reader). PNG output remains available
  for the human/phone-camera leg. Updated `test_qr_scan_roundtrip`
  (`pgm_path`, `.pgm`) and the `qr-scan-audit` job (PGM decode) to match.
- **Gotchas & Lessons:** A test shim that is *more lenient* than the real
  tool can certify broken output — PIL's zero-padding made a structurally
  truncated image decode "successfully" locally while every strict decoder
  (ImageMagick/libpng, PIL's own strict PPM path) rejects it. When validating
  image rasters, check the full decoded data (size + corner pixels + warnings),
  not just that the payload decodes.
- **Verification:** Locally (macOS): regenerated scale-3 art from the
  non-PAM harness dumps; `art2png.py` now emits byte-exact rasters — PIL
  strict-verify of PGM/PNG with 0 warnings and correct 123×123 dims;
  independent zxing-cpp decode of PGM (UTF-8 + ASCII art) and PNG all return
  the exact URI; clang-format clean (CI scope); workflow YAML parses; py
  syntax OK. The C edits are mechanical (param rename, `.pgm` extension).
  **Still requires Linux/CI:** `make test CC=gcc` / `CC=clang` with
  `zbar-tools` (compile-matrix), `make test-sanitize CC=clang`, and the
  `qr-scan-audit` zbarimg decode — pushed for CI verification.
- **Follow-ups:** Watch `wglick/qr-terminal` CI: `qr-scan-audit` must show
  zbarimg recovering the URI from PGM; manual phone-camera scan of the
  published scale-1 art in the job summary.

### 2026-11-08 — QR vendor provenance + upstream drift audit; independent-scanner decode gate
- **Task:** Implement two follow-up recommendations on `wglick/qr-terminal`: (1) record
  provenance for the vendored Nayuki qrcodegen and add a periodic check against upstream
  so "frozen" never becomes "abandoned"; (2) verify the rendered terminal QR through
  independent scanners (zbarimg in CI; phone camera manually).
- **Decisions & Rationale:**
  - Provenance is triple-locked in `third_party/qrcodegen/`: `vendor-provenance.txt`
    (machine-readable: upstream pins — qrcodegen.c @ 8329a7108fc2… (2024-09-01),
    qrcodegen.h @ f3705873ab6c… (2022-01-08), pinned_at, local SHA-256s, patch name),
    `AUTHORS` (human attribution, MIT, deviation list, re-vendoring procedure), and
    `local-deviations.patch` (the only semantic deviations: `#pragma once`→include
    guard, `QRCODEGEN_TEST` block→`#define testable static`, include order). Verified
    token-equivalence of (pinned upstream + patch) == tree.
  - `scripts/check_qrcodegen_upstream.sh` (gated by new `.github/workflows/vendor-audit.yml`:
    monthly cron 1st 06:00 UTC, workflow_dispatch, PRs touching `third_party/**`):
    (a) local SHA-256 integrity vs. provenance file; (b) fetch upstream AT THE PINS,
    `git apply -p3` the deviation patch (git init in mktemp dir), compare
    token-normalized content; (c) GitHub API freshness — newest commit touching each
    upstream path vs. pin; exit 2 (job failure) when upstream advanced, with the
    since-pin commit list; 403/429 API responses degrade to a warning only.
  - The vendored copy is NOT byte-identical to upstream (clang-formatted at vendor
    time); the earlier "unmodified" commit framing is superseded by the patch +
    token-equivalence mechanism.
  - Scanner gate: `tests/qr_scan/art2png.py` (stdlib-only PNG writer; UTF-8 half-block
    lines each cover 2 module rows with NO vertical repetition, ASCII art lines are
    repeated `scale` times vertically; output pixel scale is a separate
    PX_PER_MODULE arg) and `tests/qr_scan/qr_render_check.c` (production-path harness,
    also prints scale-1 ASCII art to stdout for phone scans). New CMocka
    `test_qr_scan_roundtrip`: renders BOTH styles via qr_render_verification_code at
    scale 3, rasterizes, requires `zbarimg --quiet --raw` to return the exact complete
    URI; skips cleanly when zbarimg/python3 are absent (rpm %check container).
  - `build.yml`: `zbar-tools` added to compile-matrix + sanitize-test apt lines (the
    round trip now runs under gcc, clang, and ASan/UBSan/LSan); new `qr-scan-audit`
    job (gcc + zbar-tools + PAM/curl/json-c headers for the harness build) decodes
    both styles and appends the scale-1 ASCII art to the job step summary for
    phone-camera verification.
  - `packaging/pam_oidc_device.spec` now installs `third_party/qrcodegen/AUTHORS` to
    `%{_docdir}/%{name}/third_party/` and lists it under `%license`.
- **Gotchas & Lessons:**
  - In terminal QR art the TRAILING all-space lines are the bottom quiet zone — do not
    strip trailing blank lines when rasterizing (first attempt dropped the bottom 4
    modules; the quiet-zone guard caught it).
  - art2png detects the renderer's art scale from the quiet-zone width: 4*scale light
    lines (ASCII, vertical repetition) or 4*scale leading spaces on the first glyph
    line (UTF-8, horizontal-only repetition) — then downsamples and enforces a clean
    4-module quiet zone + square grid at module resolution.
  - zbarimg is unavailable on this macOS box (no Homebrew): validate the pipeline with
    zxing-cpp in a throwaway venv (/tmp/qrvenv + PIL + numpy), and exercise the REAL C
    test path (popen/exit-code contract, temp files, header stripping) with a
    `/tmp/fakebin/zbarimg` shim that emulates zbarimg's stdout/exit-code semantics over
    ZXing.
  - Stub-cmocka local builds additionally need `-Wno-string-conversion` (string-literal
    quirk in the stub assert macros) and `-include build/verify/linux_shims.h`
    (clock_nanosleep/TIMER_ABSTIME absent on macOS); both are local-only artifacts.
- **Verification:** LOCAL (macOS, stub-based): drift script passes end-to-end
  (integrity, pinned fetch, token equivalence, freshness) and correctly fails on a
  tampered sandbox copy; both terminal arts rasterize to 123x123 px (41x41 modules)
  and decode to the exact URI under ZXing; all 6 QR CMocka tests pass —
  test_qr_scan_roundtrip SKIPS without zbarimg and PASSES under the ZXing shim;
  `clang-format --dry-run --Werror src/*.c include/*.h tests/*.c` clean; harness +
  test_suite.c compile clean under the full strict warning set; both workflow YAMLs
  parse. STILL REQUIRED on Linux/CI: `make lint`, gcc+clang `make test` (round trip now
  live), `make test-sanitize CC=clang`, EL8/9/10 `make rpm`, plus the new
  `qr-scan-audit` and `vendor-audit` jobs.
- **Follow-ups / Open Items:** push the two new commits to `wglick/qr-terminal`; watch
  the first `qr-scan-audit` + `vendor-audit` runs; optionally scan the published
  scale-1 art with a phone camera for the real-conditions leg.

### 2026-11-08 — Terminal QR rendering wrap-up: stub fidelity, vendored-code placement, gate warnings
- **Task:** Final pass on the QR terminal-rendering branch (`wglick/qr-terminal`): make the
  macOS verification stubs faithful to the real libraries, resolve every remaining
  `-Wconversion`/clang-tidy gate failure in project code, and get the vendored QR encoder
  out of the CI clang-tidy scope.
- **Decisions & Rationale:**
  - Verified real json-c signatures against upstream `json_object.h`/`json_tokener.h`/
    `json_types.h`: read accessors take `const struct json_object *`, **but**
    `json_object_put(struct json_object *)` (returns `int`) and
    `json_object_get_string(struct json_object *)` take **non-const**;
    `json_object_array_get_idx` takes `int`; `get_int`→`int32_t`, `get_int64`→`int64_t`.
    `build/verify/stubs/json-c/json.h` + `stub_runtime.c` now mirror this exactly; all
    module call sites already pass non-const locals, so no const-removal was needed in `src/`.
  - Verified real libcurl: the slist API is `struct curl_slist *` (there is **no**
    `curl_slist` typedef) — the old stub invented one; fixed the stub, module code was right.
  - Moved the vendored Nayuki encoder to `third_party/qrcodegen/{qrcodegen.c,qrcodegen.h}`
    with a local `.clang-tidy` (`Checks: ''`), a new Makefile pattern rule, updated
    `OBJS`/sanitize/test-sanitize source lists, `clean`, and the rpm tarball file list
    (added `third_party`). Reason: CI clang-tidy gates `src/*.c` with
    `WarningsAsErrors: '*'` and the unmodified third-party file produced ~100 findings.
  - `pkce.c`: `B64URL_ALPHABET[64]` → `[65]` (64 chars + NUL) — unterminated-string
    initializer warning.
  - Four `json_object_array_get_idx()` call sites (http.c discovery probe,
    `secure_zero_json_tree`, identity group loop, jwt aud loop) now cast the `size_t`
    loop index to `int` to match the real json-c parameter type under `-Wconversion`.
  - Fixed clang-tidy gate failures in project code: `readability-math-missing-parentheses`
    in `QR_MATRIX_BYTES_MAX` (`include/pam_oidc_device.h`), `QR_LINE_BUF_MAX` and
    `size + 2 * QR_QUIET_ZONE` (`src/qr.c`); `readability-uppercase-literal-suffix`
    (`0x21U`/`0x7EU`) in `src/config.c` + `src/qr.c`.
  - Stub `json_object_object_foreachC` now assigns `iter.key/iter.val` up front (the real
    macro assigns them each iteration) to kill a clang-analyzer uninitialized-value
    false positive on `secure_zero_json_tree`.
  - Stub `cmocka.h` assert macros use a `_cm_norm()` helper (string literals in boolean
    context triggered `-Wstring-conversion`); stub `EVP_DigestInit_ex`/`RAND_bytes`
    signatures match the vendored OpenSSL 1.1-era headers in `build/verify/inc`.
- **Gotchas & Lessons:**
  - `build/verify` stubs are only as good as their fidelity to the *actual* library
    headers — a stub typedef/const mismatch creates phantom warnings (or hides real ones).
    Always diff against upstream headers before trusting a clean stub build.
  - Vendor third-party C under `third_party/`, never in `src/`: the clang-tidy/cpplint
    gates are scoped to `src/*.c` precisely so project code stays strictly linted.
- **Verification:** LOCAL (macOS, stub-based — NOT the Linux gates): all 8 project TUs +
  vendored qrcodegen compile clean under
  `-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Wformat-security -O2 -Werror`;
  `clang-format --dry-run --Werror src/*.c include/*.h tests/*.c` clean; local clang-tidy
  proxy over `src/*.c` (stub includes) reports zero errors; QR-filtered CMocka run passes
  5/5 (config parsing, matrix render, URI encode, verification-code render, UTF-8 golden).
  STILL REQUIRED on Linux: `make lint`, `make CC=gcc`/`make CC=clang` + `make test` for
  both compilers, `make test-sanitize CC=clang`, and the EL8/EL9/EL10 `make rpm` job.
- **Follow-ups / Open Items:** push `wglick/qr-terminal` so the authoritative CI gates run;
  no open code items.

### 2026-11-07 — CI clang-format gate: anonymous fnptr type-id in `va_arg` (version skew fix)
- **Task:** CI `formatting` job failed `clang-format --dry-run --Werror` at `tests/test_suite.c:93`
  (`va_arg(args, size_t (*)(void *, size_t, size_t, void *))` — the C1 fake-transport capture).
- **Decisions & Rationale:** Local clang-format 19.1.7 (MacPorts) *accepts* that line, but CI
  (Ubuntu 24.04 `apt-get install clang-format`) runs **clang-format 18.1.x**, which *rejects* it —
  and the two versions **disagree in opposite directions** on spacing: 18 wants `size_t(*)(`,
  19 wants `size_t (*(`. Reformatting to satisfy one would fail the other, so the code was made
  version-neutral instead: a named typedef `typedef size_t (*test_write_cb)(void *ptr,
  size_t size, size_t nmemb, void *userdata);` (libcurl's `curl_write_callback` signature),
  `g_fake_write_cb` redeclared as `static test_write_cb`, and the capture reduced to
  `va_arg(args, test_write_cb)`. No anonymous function-pointer type-id remains in the CI scope,
  so neither clang-format version has anything to reformat.
- **Gotchas & Lessons:**
  - The local 19.1.7 green check was *false assurance* — local and CI clang-format differ by a
    major version and can disagree on the same line. To reproduce CI exactly, install
    `clang-format==18.1.8` in a throwaway venv (`python3 -m venv /tmp/cf18 && /tmp/cf18/bin/pip
    install clang-format==18.1.8`) and gate with **both** binaries before pushing.
  - Avoid anonymous function-pointer type-ids (in `va_arg`, casts, or declarations) inside the
    clang-format CI scope (`src/*.c include/*.h tests/*.c`); prefer named typedefs.
- **Verification:**
  - LOCAL (macOS): `clang-format --dry-run --Werror src/*.c include/*.h tests/*.c` green under
    **both** 18.1.8 (CI parity) and 19.1.7; `make -s lint` green; isolated strict-flag harness
    (`cc` + `clang`, `-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2
    -Wformat-security -O2 -g`, zero warnings) replicating the `va_arg` capture/invoke round-trip —
    PASS on both.
  - NOT RUN: full CMocka suite / `make test-sanitize CC=clang` / `make rpm` (no libpam/cmocka
    here). The pushed branch must still pass the entire Linux/CI gate loop.
- **Follow-ups / Open Items:**
  - Push `wglick/review` → confirm `lint.yml` `formatting` now passes; remaining gates
    (compile-matrix, sanitize-test, rpm-build) still pending in CI.

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

