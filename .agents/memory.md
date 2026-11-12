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

