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

- **Release version sources & the `AGENTS.md` symlink.** The canonical module version lives in
  `include/metadata.h` (`PAM_OIDC_VERSION`, which also feeds the User-Agent string). A release bump
  must keep it consistent with `Makefile` (`VERSION ?=`), `packaging/pam_oidc_device.spec`
  (`%global mod_version`), `packaging/gen-changelog.py` (`default_ver`), and `.agents/context.md`.
  `AGENTS.md` is a *symlink* to `.agents/context.md`, so editing `context.md` updates both — never
  double-edit. `CHANGELOG.md` historical entries keep their original version strings (do not
  rewrite past releases).
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

## Interaction Log (newest first)

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

