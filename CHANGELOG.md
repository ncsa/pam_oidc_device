# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.7] - 2026-11-23

### Added

- **`group_claim_delimiter` configuration option (`[access]`, `src/config.c`,
  `src/identity.c`):** a single printable ASCII character (default `,`) used to split a
  **string-typed** group claim into individual group/role entries before allow/deny matching.
  JSON array claims are unaffected (each element is one group). This fixes IdPs that emit the
  group list as one delimited string instead of a JSON array — e.g., a semicolon-joined
  `member_of` attribute (`"grp-a;grp-b;grp-c"`) now works with
  `group_claim_field = member_of` + `group_claim_delimiter = ;`; without it the whole string
  was treated as one unmatchable group name. Multi-character and non-printable values are
  rejected at config load.

### Changed

- **Built-in default prompt: dropped the "auto-completes on sign-in" status-line
  clause (`src/message.c`):** the trailing status line of the built-in default
  prompt no longer carries the "auto-completes on sign-in" note — the phrasing was
  ambiguous (browser sign-in vs. terminal sign-in) and redundant with the "Sign in
  via browser" instruction and the "Press [Enter] to begin..." confirmation. The
  status line now reads `Waiting for approval.` (approval window unknown, or
  `show_expiry = false`) or `Waiting for approval (expires in 2m).` (known
  window). `show_expiry` and the `{expiry}` template token semantics are unchanged,
  and custom `init_message` templates are unaffected. The rendered-prompt samples in
  `README.md`, `docs/getting-started.md`, and the shipped `config/pam_oidc_device.conf`,
  plus the `show_expiry` field doc in `include/pam_oidc_device.h`, were updated to
  match.
- **Verbose logging now records provider claim values (`src/identity.c`):** when
  `loglevel = verbose` (maximum troubleshooting level), `verify_userinfo_identity()`
  dumps every claim returned by the UserInfo endpoint (claim name + compact JSON value),
  and `verify_group_membership()` additionally records the `group_claim_field` claim
  immediately before allow/deny evaluation, so operators can see exactly what the provider
  sent when claim matching or `allow_groups`/`deny_groups` unexpectedly matches or
  misses. Logged JSON values are serialized with slashes unescaped, so URL/URN-style
   values are copy-paste safe. Consistent with the PII redaction policy, the dumps are never emitted at
  `debug` or below, untrusted bytes are C-escaped by the central logger, and claim names
  containing non-printable bytes remain withheld.
- **Debug-and-above logging now records the inspected JWT's claims (`src/jwt.c`):** when
  `loglevel = debug` (or `verbose`) and `verify_jwt_claims = true`, `verify_token_metadata()`
  records the token's `iss`, `aud`, `exp`, and `nbf` claims (compact JSON representation, when
  present) before any check runs, so an operator whose `issuer`/`audience` settings do
  not match the provider's token can read the actual values from the log
  (`JWT claim '<name>': <value>`) instead of the length-only mismatch line that routine
  levels emit. These claims are tenant/client/numeric identifiers rather than PII, so the
  value dump is allowed from `debug` upward — one level below the PII-protected UserInfo
  claim dumps, which remain `verbose`-only.

### Fixed

- **JWT audience check now accepts comma-bearing literal audiences (`src/jwt.c`):**
  `verify_token_metadata()` matched the configured `audience` only as a
  comma-separated list, so an audience value that itself contains a comma —
  CILogon's OA4MP identifier
  `cilogon:oa4mp,2012:/client_id/<client-id-md5>`, where the comma is part of the
  versioned namespace, not a delimiter — was fragmented and could never match,
  failing every device-flow sign-in at `verify_jwt_claims = true`. The configured
  value is now matched as a single literal audience (whitespace-trimmed, exact)
  first, falling back to the comma-separated list semantics only when the whole
  value does not match; ordinary multi-audience lists behave exactly as before.
  The PII-safe `Token audience mismatch` log line was also made consistent with
  the `debug`/`verbose` claim dump: for a string `aud` claim it now reports the
  received value's raw length (the same unescaped text the dump prints), instead
  of the JSON-representation length (quotes + escaped slashes), which made the
  two disagree.

## [0.3.6] - 2026-11-19

### Changed

- **Documentation: RFC 8628 introduction, non-SSH generalization, and MFA
  claim clarification (`README.md`, `docs/getting-started.md`,
  `examples/README.md`, `docs/threat-model.md`):** the README now leads
  with an introduction to the OAuth 2.0 Device Authorization Grant —
  what it is, the two-device sign-in shape, and the familiar
  limited-input-client use cases (smart-TV/streaming apps, game
  consoles/IoT devices, headless systems) — and gains a
  "Beyond SSH: Other PAM Services" section (`sudo`/`su`, console and
  display-manager logins, PAM-aware daemons) making the
  interactive-terminal requirement explicit; `docs/getting-started.md`
  mirrors this in §1 and a new "Other PAM Services (Beyond SSH)"
  subsection of §5. "Out-of-band multi-factor authentication (MFA)"
  claims were replaced with "out-of-band sign-in and step-up login",
  plus a note that the module alone does not require a second factor —
  whether a resulting login is multi-factor depends on the surrounding
  PAM stack and on what the identity provider enforces during the
  browser sign-in. No behavior or interface changes.
- **README restructured around the primary value proposition; substantial
  content moved into dedicated guides (`README.md`, new
  `docs/device-flow.md`, `docs/security.md`, `docs/accessibility.md`):**
  the detailed RFC 8628 protocol introduction moved to
  `docs/device-flow.md`; "Security & Credential Handling" and "Accessibility"
  moved to `docs/security.md` and `docs/accessibility.md` (the README keeps
  short summaries plus links); the Third-Party Components section is now a
  short summary pointing at `THIRD_PARTY_NOTICES.md` (which already carries
  the full component table). A new "Use Cases" section states when an
  administrator should deploy the module; the Quickstart is now genuinely
  quick (distro-specific dependency lists, the full annotated config
  including the commented `[qr]` options, and the extended OpenSSH
  hardening moved to the Getting Started guide, which already contained
  them); "How It Works" gains a sequence diagram and a sample terminal
  prompt block; the multi-factor discussion was elevated from a buried note
  to a top-level section; and the terminal QR feature is repositioned as a
  convenience/usability enhancement throughout, never an architectural
  pillar. `docs/getting-started.md`'s accessibility cross-reference now
  targets the new guide. A readability pass followed: the README intro no
  longer re-explains the device flow (that stays in the RFC 8628 section),
  the "How It Works" step list now carries only details the diagram does not
  show, `docs/device-flow.md` gained the table of contents its section count
  requires, and `docs/threat-model.md`'s trust-boundary overview and
  access-control decision flow now render as Mermaid flowcharts above their
  existing reference tables. No behavior or interface changes.
- **Threat Model de-duplication pass (`docs/threat-model.md`):** the
  Device-Code Phishing, Device Code Interception/Replay, and Provider
  Rate-Limit Exhaustion rows of the Threat Matrix were each shrunk from
  multi-paragraph cells to one- or two-sentence summaries with cross
  references, since their full analyses already live in §7/§8/§9; a
  "Key finding" callout now names device-code phishing as the module's top
  residual risk immediately after the introduction, so the headline risk is
  visible on page 1; the "Trust relationships" table under Figure 1 was
  replaced by a one-line pointer because the figure's edge labels already
  state each relationship's protection; the `PAM_RHOST` attribution in §8/§9
  was corrected to "exposed to the PAM service, set by the SSH service";
  and the stopwatch aside in §6's monotonic-clock bullet was trimmed. No
  threat, mitigation, or code-symbol content was lost — only duplication
  removed. No behavior or interface changes.
- **Security disclosure elevated to the top of the security policy
  (`SECURITY.md`):** the "Reporting a Vulnerability" section now leads the
  page (with the table of contents reordered to match) and opens with an
  alert-style callout stating the private-report rule and the contact email,
  so the disclosure path is no longer buried below the security-documentation
  index. No behavior or interface changes.

## [0.3.5] - 2026-11-19

### Fixed

- **Large passwd entries no longer lock out legitimate accounts (`src/identity.c`):** the
  uid lookup in `verify_user_access()` used a fixed 4096-byte stack buffer, so an account
  whose passwd record is larger (LDAP/SSSD entries with long GECOS strings or home paths)
  made `getpwnam_r()` report `ERANGE`; with either uid guard enabled that error failed
  closed, locking the account out entirely. The lookup now starts at
  `sysconf(_SC_GETPW_R_SIZE_MAX)` (4 KiB where the constant is undefined, e.g. glibc)
  and retries `ERANGE` with a doubling heap buffer up to 1 MiB before giving up; a
  persistent backend error still fails closed exactly as before. Pinned by the new
  `test_verify_user_access_large_entry` CMocka test (scripted `getpwnam_r()` override).
- **`no_proxy`/`NO_PROXY` can no longer bypass a configured `[oauth] proxy`
  (`src/http.c`):** `http_request()` only ever cleared `CURLOPT_PROXY`; when a proxy
  was configured, libcurl still consulted the caller's `no_proxy`/`NO_PROXY`
  environment variables (it does so whenever `CURLOPT_NOPROXY` was never set), so a
  PAM caller could steer provider traffic around the admin's egress proxy. Both proxy
  options are now always set explicitly: `CURLOPT_PROXY` to the configured URL (empty
  string when none) and `CURLOPT_NOPROXY` to the empty string, so neither `*_proxy`
  nor `no_proxy`/`NO_PROXY` of a setuid PAM caller is ever honored. The
  `test_http_request_proxy_routing` test now pins both options on every path.
- **Proxy TLS leg is explicitly pinned to certificate validation and TLS >= 1.2
  (`src/http.c`):** a code comment claimed the strict TLS options also applied to
  the proxy connection, but `CURLOPT_SSL_VERIFYPEER`/`SSL_VERIFYHOST`/`SSLVERSION`
  govern only the provider (endpoint) connection — the TLS session libcurl
  negotiates to a configured `[oauth] proxy` is governed by the separate
  `CURLOPT_PROXY_SSL_*` options. Proxy certificate checks default on, so nothing
  was ever unverified, but the TLS 1.2 minimum was not enforced on that leg.
  `http_request()` now explicitly sets `CURLOPT_PROXY_SSL_VERIFYPEER=1`,
  `CURLOPT_PROXY_SSL_VERIFYHOST=2`, and `CURLOPT_PROXY_SSLVERSION` to TLSv1.2 on
  every request, and the comment/doc claims were corrected;
  `test_http_request_proxy_routing` pins all three on the with-proxy and
  without-proxy paths alike.

## [0.3.4] - 2026-11-18

### Fixed
- **`pam_oauth_log()` no longer drops log lines silently**: when the line cannot be
  rendered (`vsnprintf` failure) or the escape buffer cannot be allocated, a static
  "log line dropped (...)" marker is emitted to syslog instead, and the unrendered
  (potentially untrusted) bytes are scrubbed before return — the audit trail records
  that a log line was attempted.
- **E2E suite workdir no longer retains credential-bearing config copies**: the
  `tests/e2e/run_e2e.sh` EXIT trap now removes the `conf.uidrange.{orig,tmp}` config
  copies it leaves in the 0700 workdir alongside the existing `conf.uid0.{orig,tmp}`
  entries — they may mirror a live config holding client credentials.
- **Invalid Base64URL padding is now rejected at decode time (`src/jwt.c`)**:
  `base64url_decode()` previously deferred to OpenSSL's lenient `BIO_f_base64`,
  which would "decode" segments whose total padding exceeds two `=` characters
  (e.g. an unpadded segment whose length is 1 mod 4, which would need three)
  into short binary garbage. The decoder now computes the total pad (existing
  trailing `=` plus the 4-character alignment pad) and rejects anything above
  the RFC 4648 §3.5 maximum of two, failing closed before the JSON parse layer
  is involved.
- **Bearer Authorization header stack buffer is scrubbed on the overflow error
  path (`src/http.c`):** when the Authorization header exceeds the buffer
  capacity, `snprintf` has already copied a (truncated) prefix of the token into
  the stack temporary; that buffer is now `secure_memzero`'d before the error
  return so no partial token survives in process memory. The successfully
  appended (untruncated) `curl_slist` copy was already scrubbed via
  `scrub_and_free_slist()` on every path.

### Removed

- **Target-host display in the sign-in prompt (v0.3.3 device-code phishing mitigation,
  independent-review finding F1):** the prompt is delivered to the party that *ran ssh*
  — the attacker in the phishing attack — while the victim only sees the IdP's approval
  page, so host display there cannot reach the approver and was removed in full:
  the `[prompt] show_host` key (configs that still contain it now fail to load,
  fail-closed, as an unknown key), the `{host}` `init_message` template token
  (templates that reference it now render the literal `{host}` text — drop it),
  the host clause in the built-in default prompt, and the `host` parameter of
  `render_prompt_message()` (the rendered-prompt terminal-safety check is unchanged).
  **Upgrade:** remove `show_host` from `/etc/pam_oidc_device.conf` and drop the
  `to sign in to {host}` clause from any custom `init_message`.
  **Replacement mitigations** (the only surfaces the victim actually reads are the IdP's
  approval page and the victim's own device): register one descriptive OAuth client per
  host or cluster (e.g. "ssh:db-prod-3") so the approval page names the requesting
  machine, and limit device-flow sign-ins by source network. See `docs/threat-model.md` §8.

### Added

- **Outbound HTTPS proxy configuration (`[oauth] proxy`, `src/config.c`, `src/http.c`):**
  provider traffic (device authorization, token polling, UserInfo, and the PKCE
  auto-detection discovery probe) can now be routed through an admin-configured
  proxy via the new `proxy` key. The value must be an `https://` URL validated with
  the same strict rules as the provider endpoints: plain-HTTP proxies are rejected
  (they would carry device codes and tokens in cleartext through a third party),
  authority userinfo is rejected (proxies requiring authentication are not
  supported), and a duplicated key is rejected. The default (absent or empty value)
  routes directly, and the `*_proxy` environment variables remain deliberately
  ignored: when no proxy is configured, `CURLOPT_PROXY` is explicitly set to the
  empty string so libcurl never falls back to the user-controlled environment of a
  setuid PAM caller. Strict TLS validation (certificate + hostname) applies to the
  proxy connection as well.
- **Four new unit tests (`tests/test_suite.c`)**:
  `test_jwt_base64url_excess_padding_rejected` (pins the padding rejection
  end-to-end through `verify_token_metadata()`),
  `test_http_request_proxy_routing` (pins `CURLOPT_PROXY` behavior: empty-string
  proxy clearing so libcurl never honors caller-controlled `*_proxy`
  environment variables, and verbatim routing of a configured proxy),
  `test_http_request_response_size_cap` (pins the 256 KiB
  `MAX_HTTP_RESPONSE_SIZE` cap in `write_callback()`: exactly-at-cap accepted,
  one byte over rejected), and
  `test_pam_oauth_log_line_dropped_marker` (exercises `pam_oauth_log()`'s
  vsnprintf-failure "log line dropped" marker branch and the 8192-byte line
  truncation path; the escape-buffer malloc-failure branch requires a failing
  malloc and remains untested by design).
- **Seven new unit tests for the device-flow scheduling helpers and the log
  escaper (`tests/test_suite.c`; the suite grows 66 → 73):**
  `test_poll_loop_schedule_rules` pins the pure poll-scheduling decision
  (immediate first poll, subsequent polls at now + interval, and expiry once
  the next poll would land at/after the device deadline),
  `test_poll_request_budget_rules` pins the per-request cURL timeout budget
  (whole-second truncation, the 10 s per-request cap, and no request — never
  a zero cURL timeout — once the whole-second remainder runs out),
  `test_request_device_authorization_parses_provider_response` pins the
  RFC 8628 §3.2 response parsing with both clamps observable (a 999 s poll
  interval clamped to `MAX_SUPPORTED_POLL_INTERVAL`, a 99999 s `expires_in`
  clamped to `max_poll_seconds`) and the monotonic deadline computed from the
  clamped window, `test_poll_loop_immediate_token_success`,
  `test_poll_loop_pending_then_deadline_expiry`, and
  `test_poll_loop_maps_provider_error_phases` drive the complete poll loop
  through the fake cURL transport (a token already approved on the first
  poll, `authorization_pending` until the monotonic deadline expires, and
  the expired/denied/unavailable mapping onto the user-visible notices), and
  `test_pam_oauth_log_escapes_untrusted_bytes` pins the escaper itself
  (printable ASCII passes through byte-for-byte with the syslog priority
  intact, while control and high-bit bytes in an untrusted value render as C
  escapes so no raw LF/CR/TAB or C0/C1 byte can forge or garble the syslog
  record).

### Changed

- **Fail-closed uid-0 and system-UID guards on lookup error (`src/identity.c`):**
  `verify_user_access()` now distinguishes three local-account lookup outcomes —
  found, not found, and lookup error (three-state `getpwnam_r()` handling) — instead
  of conflating an error with "no such account". Previously, when the lookup itself
  failed (e.g. `ERANGE`, an NSS/DB outage), the uid-0 gate and the
  `deny_system_uids` range gate were silently skipped, so a broken account database
  could have let an unknown uid (potentially uid 0) through. Not-found semantics are
  unchanged: a name with no local account entry cannot hold a local uid, so the
  guards skip and the `allow_users`/`deny_users` lists still decide. A lookup error
  is now refused fail-closed by each active gate, with a log message that names the
  errno and the config key (`allow_root` / `deny_system_uids`) that would disable the
  gate.
- **User-friendlier sign-in prompt, rebased default wording and layout
  (`src/pam_module.c`):** the built-in default prompt now begins with a leading
  blank line separating it from the terminal banner that shares its first line
  (omitted when `[qr] enabled = true`, where the QR block's quiet zone already
  provides the separation), then the direct link when the provider supplies a
  `verification_uri_complete`, with the plain URL and user code as a one-line
  `Manual entry:` fallback, and a single blank line before the status line:

  ```
  Sign in via browser:
    https://auth.example.edu/oauth2/device/code?user_code=TNQ-7CQ-7QC

  Manual entry: https://auth.example.edu/oauth2/device/code  |  Code: TNQ-7CQ-7QC
  Waiting for approval (expires in 2m; auto-completes on sign-in).
  ```

  When no direct link is available the URL + code are shown as a compact labeled
  block instead of the manual-entry line. The trailing status line is now
  "Waiting for approval …; auto-completes on sign-in." (previously "Waiting for your
  approval …; this session completes automatically once you sign in."), and the
  approval window renders in compact units (`45s`, `15m`, `1h 5m`) instead of spelled
  out ("45 seconds", "15 minutes", "1 hour 5 minutes") — the compact format also
  applies to the `{expiry}` template token. `show_expiry` semantics are unchanged
  (default `true`; off or unknown window drops only the expiry parenthetical). The
  shipped `config/pam_oidc_device.conf` and all `examples/*.conf` now leave
  `init_message` unset so every default installation shows the new layout; existing
  installations keep their custom `init_message` untouched (existing deployments
  adopt the new wording by removing the key or updating the template — the
  placeholder set is unchanged: `{url}`, `{url_complete}`, `{code}`, `{expiry}`).
- **`EXTRA_CFLAGS` is now a conditional assignment (`?=`) in the `Makefile`**,
  so a developer-supplied `EXTRA_CFLAGS` (environment or command line) is
  honored instead of being silently clobbered. CI behavior is unchanged: its
  command-line `EXTRA_CFLAGS=-Werror` still takes precedence over the
  Makefile default.
- **Table-driven configuration parser (`src/config.c`):** the hand-rolled
  per-key `if/else` chain in `parse_config_kv()` was replaced by a declarative
  key-specification table (`config_key_spec_t`: key, section, value kind,
  duplicate-tracking bit, destination offset/size, range bounds, and the
  accepted-but-unused note) walked by a single dispatcher, so every key now
  receives identical unknown-key, wrong-section, duplicate-key, and
  type/range validation from one code path instead of per-key bespoke checks.
  No behavior change: the accepted keys, validation outcomes, and log
  messages are unchanged (and the table's column order is padding-optimal).
- **Device-flow helpers extracted into an internal header (`src/device_flow.h`,
  `src/pam_module.c`):** the per-attempt device-flow types (`device_auth_t`,
  `token_phase_t`, `poll_sched_action_t`) and the prototypes of the RFC 8628
  request/poll helpers (`request_device_authorization()`,
  `poll_for_access_token()`, `poll_loop_schedule()`, `poll_request_budget()`,
  `poll_interval_after_slow_down()`, `poll_interval_after_transient()`) moved
  out of `src/pam_module.c` into a new internal header — the public
  `include/pam_oidc_device.h` is unchanged, and the test suite drives the
  helpers through this header instead of carrying its own test-only
  prototypes. The poll loop was simplified around them:
  `poll_loop_schedule()` is now called unconditionally every iteration (the
  first-poll decision moved inside the helper) with a single monotonic clock
  read at the top of each pass. No behavior change.
- **Sign-in prompt and user-notice delivery extracted into `src/message.c` (review
  finding M-2, modularity):** the templated prompt renderer (`render_prompt_message`),
  the QR/Enter-begin presentation orchestrator (`present_signin_prompt`), the
  plain-text `USER_NOTICE_*` failure strings, and `notify_user_failure()` were moved
  out of `src/pam_module.c` into a focused translation unit (declarations kept in the
  internal `src/device_flow.h`), and the JWT-sub vs UserInfo-sub consistency check
  (`verify_userinfo_identity`) was added to `src/identity.c`. Pure code reorganization
  with no behavior change — the existing unit suite (prompt-safety, expiry-formatting,
  identity, poll-loop) is unchanged and passes under gcc, clang, and the sanitizers.

### Documentation

- **Corrected the "PAM exposes no peer-address API" claim**: sshd sets `PAM_RHOST`,
  which a PAM module can read via `pam_get_item(PAM_RHOST)` (on console logins it
  carries the local host name — identifying context, not a trusted input).
  `docs/threat-model.md` §8–§9, the prompt code comment, and the v0.3.3 changelog
  all relied on the opposite claim; the in-module scope boundary for per-source
  rate limiting is now stated correctly (per-connection PAM invocations share no
  state, so per-source limiting belongs in the SSH layer regardless of PAM_RHOST).
  The device-code phishing guidance now recommends descriptive per-host (or
  per-cluster) OAuth client registration and source-network limits, replacing the
  removed in-prompt host identification.
- **`docs/threat-model.md`** now carries a prominent warning that the JWT-sub
  vs UserInfo-sub token-substitution consistency check runs only when
  `verify_jwt_claims = true`, which is off by default, and recommends enabling
  it (with `issuer`/`audience` configured) wherever token substitution is a
  realistic threat.
- `src/http.c`: documented why the `strlen()` → `int` cast in
  `url_encode_param()` is safe (all inputs are config/response-bounded) and why
  the `LIBCURL_VERSION_NUM >= 7.32` guard around the TLS-1.2 floor is a
  no-op in practice (all supported distros ship libcurl ≥ 7.61).

### Housekeeping

- Removed the stale `REVIEW.md export-ignore` line from `.gitattributes`
  (the file no longer exists).

### Upgrade notes (from < 0.3.4)

Four behavior changes, two shipped in 0.3.3 and two in this release,
can each on its own break an existing deployment after an upgrade. Audit the on-disk
`/etc/pam_oidc_device.conf` before rolling the new module out:

- **`[prompt] show_host` and the `{host}` template token are removed (this
  release).** Configs containing `show_host` fail to load (unknown key) until the
  key is removed, and a custom `init_message` that references `{host}` renders the
  literal `{host}` text. The in-prompt host display reached the ssh initiator, not
  the approving user, so it was removed; replace it with a descriptive per-host
  OAuth client name and source-network limits — see `docs/threat-model.md` §8.
- **`[claim] claim_regex` is now required (0.3.3).** Config loading fails
  closed when the key is missing or empty, so every login through the module
  fails until it is set. Add an explicit `claim_regex`: an anchored username
  character set for a bare `preferred_username` (e.g.
  `claim_regex = ^([a-zA-Z0-9._-]+)$`), or a domain-pinned e-mail pattern
  (e.g. `claim_regex = ^([^@]+)@your[.]domain$`). The historical implicit
  default `^(.*)$` still works when set explicitly, but a loose pattern is
  no longer the out-of-the-box behavior.
- **Local UIDs 0–999 are denied by default (0.3.3).** `deny_system_uids`
  defaults to `true` over the range `0-999`, and the guard applies even to
  accounts listed in `allow_users`. A long-lived service or application
  account whose uid falls in the range must either move the range above it
  (`system_uid_min` / `system_uid_max`) or set `deny_system_uids = false`;
  uid-0 authentication additionally requires `allow_root = true`.
- **The `*_proxy` environment variables are no longer honored (0.3.3); the
  new `[oauth] proxy` key (this release) is the supported replacement.** A
  host that reaches the provider only through an outbound proxy must set
  `proxy = https://...` in the config (HTTPS-only; embedded proxy
  credentials are not supported). With the key absent or empty the module
  connects directly, and the calling user's `*_proxy` environment is
  deliberately never consulted.

## [0.3.3] - 2026-11-17

### Added

- **Security hardening (device-code phishing, `src/pam_module.c`, prompt):** the sign-in
  prompt now names the target host's hostname in its trailing status line
  ("Waiting for your approval to sign in to `<host>`; ...") so the approving user can cross-check
  *which machine* the sign-in belongs to — the one piece of context a user can use
  against the known device-code phishing attack. The display is opt-out via the new
  `[prompt] show_host` key (default `true`; when `false` the host clause is dropped and
  the `{host}` template token expands to an empty string). `render_prompt_message()`
  gained a `host` parameter and a new `{host}` `init_message` template placeholder; the
  default template and every shipped `init_message` (`config/pam_oidc_device.conf`,
  `examples/*.conf`, the e2e sandbox config) carry the host clause in the trailing
  status line. The hostname is rendered through the existing terminal-safety pipeline,
  so a hostname with non-printable bytes fails authentication fail-closed. Note: the
  PAM API exposes no peer address, so the *connecting client's* IP cannot be displayed
  by the module; users should instead correlate the IdP approval page's client context
  with the host shown in the prompt.

- **Prompt approval-window display (`src/pam_module.c`, `src/config.c`):** the trailing
  prompt status line can now tell the user how long they have to complete the
  approval. The new `[prompt] show_expiry` key (default `true`) adds an
  "(expires in 15 minutes)" clause to the built-in default template's trailing
  status line, and every `init_message` template can carry the new `{expiry}`
  placeholder, which expands to the provider's `expires_in` (clamped by
  `[runtime] max_poll_seconds` — the module's effective wait limit) in human units
  ("45 seconds", "15 minutes", "1 hour"); when the provider does not advertise an
  expiry the token expands to an empty string and the default-template clause is
  omitted. `render_prompt_message()` gained an `expires_in` parameter. No shipped
  `init_message` carries the `{expiry}` token, so the only out-of-the-box wording
  change is the built-in default template: when the provider advertises an expiry,
  its trailing status line now carries the clause (`[prompt] show_expiry = false`
  reverts to the previous wording).

- **Security documentation (`docs/threat-model.md`):** the threat model now documents
  **device-code phishing** as a High **residual risk** that PKCE and the identity
  checks do *not* prevent (the attacker initiates the flow from the target host and
  holds the PKCE secret; the identity really is the victim's). The "Device Code
  Interception / Replay" row, which implied PKCE stops a "code-phishing relay", was
  corrected to its actual scope (an *interceptor* who was not the flow's initiator).
  New §8 gives the mitigation guidance: host identification in the prompt, preferring
  providers whose approval page shows client context, and pairing the module with
  network restrictions or a second factor for privileged accounts.

- **System-account UID-range guard (`src/identity.c`, `src/config.c`, `docs/access-control.md`):**
  the new `[access] deny_system_uids` key (default `true`) refuses local accounts whose
  *numeric UID* falls within `[system_uid_min, system_uid_max]` (default `0-999`, the
  conventional system-account range) with `PAM_PERM_DENIED` before any provider contact —
  the same fail-closed, uid-not-name semantics as the existing uid-0/root gate, so
  long-lived application or service accounts holding in-range UIDs can no longer
  authenticate even when listed in `allow_users`. A uid-0 account explicitly permitted
  via `allow_root = true` is exempt from this second gate; names that resolve to no
  local account are not affected. `load_config()` rejects an inverted range
  (`system_uid_min` > `system_uid_max`) and out-of-bounds values at config load. Existing
  `allow_root`, `allow_users`, and `deny_users` behavior is unchanged.

### Changed

- **`[claim] claim_regex` is now required — there is no default**
  (`src/config.c`, `config/pam_oidc_device.conf`, docs): the historical implicit
  default `^(.*)$` mapped *any* provider claim equal to the local username onto
  that account. Config loading now fails closed when `claim_regex` is missing
  or empty (unit test: `test_parse_config_file_claim_regex_required`). The
  shipped sample config and the quick-start / access-control documentation are
  now internally consistent: a bare `preferred_username` is matched with an
  anchored username character set, and the domain-pinning e-mail pattern
  (`^([^@]+)@your[.]domain$`) is documented for domain-pinned claims.
- **All module log output is sanitized before it reaches syslog**
  (`src/http.c`): `pam_oauth_log()` now formats the line, replaces every byte
  outside printable ASCII with a C-style escape (`\n`, `\r`, `\t`, `\xHH`), and
  passes the escaped message to PAM syslog via a literal `"%s"`. PAM
  usernames, provider-supplied claim values, and error strings can no longer
  inject control characters that forge or garble syslog records.
- **Explicit proxy handling in `http_request()` (`src/http.c`):**
  `CURLOPT_PROXY` is now set to an empty string, overriding libcurl's fallback
  to the `*_proxy` environment variables. Under setuid callers (e.g. `su`) that
  environment belongs to the calling user, who could otherwise steer the
  module's HTTPS traffic. No proxy support is provided by design.

- **User-visible failure notices now match the token-phase outcome**
  (`src/pam_module.c`, `tests/e2e/run_e2e.sh`): previously *every* token-polling
  failure (other than a user abort) told the user the sign-in code had expired,
  even when the provider had declined the sign-in or the network path was simply
  broken. `poll_for_access_token()` now classifies its failure outcome via a new
  `token_phase_t` out-parameter, and `pam_sm_authenticate()` maps it to the
  matching notice: an expired code (poll deadline reached, or the provider's
  `expired_token` error) keeps the "sign-in was not approved in time" notice; a
  provider `access_denied` (the sign-in request was declined / never approved)
  gets its own new "sign-in was declined" notice; every other token-phase
  failure (fatal network error, `token_type` mismatch, oversized or unusable
  token, unexpected response status) gets the generic "identity provider service
  is unavailable" notice. No authentication outcome, PAM status code, or log
  detail changed — only which user-visible notice is shown. The e2e suite now
  asserts the exact notice shown in the declined-sign-in and expired-code
  scenarios.

### Fixed

- **Security (memory scrub, `src/http.c`):** the request-header list is now
  scrubbed before `curl_slist_free_all()` in `http_request()`.
  `curl_slist_append()` keeps its own copy of the `Authorization: Bearer
  <token>` header, and that copy previously survived in process memory after
  the request; it is now securely zeroed alongside every other in-module copy
  of the access token.
- **Security (memory scrub, `src/http.c`):** `discovery_probe_pkce()` now
  scrubs the provider-parsed discovery document with `secure_zero_json_tree()`
  before `json_object_put()` on both exit paths (the not-a-JSON-object branch
  and the success path). Provider-controlled JSON string elements can no longer
  survive in freed json-c memory, closing the last spot where a provider-parsed
  tree was released unscrubbed and aligning with the module-wide
  scrub-before-release discipline that every other parse site already followed.
- **Security (PII in logs, `src/identity.c`, `src/jwt.c`):** provider claim
  values no longer appear in log lines emitted below the VERBOSE level,
  matching the module's own PII policy (claim values are VERBOSE-gated).
  `verify_claim()` now logs the raw claim's *length* instead of its value on a
  regex non-match (DEBUG) and the extracted identity's *length* instead of the
  value on both the verified (DEBUG) and mismatch (ERROR) paths; the JWT
  issuer/audience mismatch messages (ERROR) now log the received value's
  *length* instead of the value itself (the configured expectation, which is
  administrator-controlled, is still logged). No authentication outcome,
  return value, or scrubbing behavior changed.

- **Security (JWT claim inspection, `src/jwt.c`):** the local `exp`/`nbf`
  NumericDate checks now reject non-finite values. json-c accepts the
  non-standard `NaN` and `Infinity` literals as `json_type_double`, and every
  comparison with NaN is false — so a token carrying `"exp": NaN` previously
  passed the expiry check unconditionally (and a NaN `nbf` skipped the
  not-yet-valid check). Claims whose value is not finite now fail closed with
  an audit-log entry. Regression coverage: a new CMocka case
  (`test_jwt_non_finite_claims_rejected`) asserts rejection of `NaN` and
  `Infinity` `exp` and `NaN` `nbf`, with a finite far-future `exp` control
  that still passes.

- **Protocol compliance (token endpoint, `src/pam_module.c`):** the token
  response's `token_type` is now compared case-insensitively against "Bearer"
  (`strcasecmp`), as RFC 6749 §5.1 defines the value as case-insensitive. Providers
  and proxies that send lowercase `"bearer"` were previously refused with
  `PAM_AUTH_ERR` (a valid sign-in rejected). Fail-closed behavior for missing or
  foreign token types is unchanged.

- **Security (`verify_group_membership`, `src/identity.c`):** A deny-only group policy
  (`deny_groups` set, `allow_groups` empty) can no longer be bypassed by the *shape* of
  the provider's group/role claim. Previously, a claim that was missing, JSON `null`, of
  an unrecognized type (e.g. numeric), or a comma-delimited string that failed to fit the
  fixed 256-byte scratch buffer (split silently skipped) was treated as "nothing to
  check" and allowed — so anyone in enough groups, or any provider-side change in how
  `groups` is serialized, could bypass a site's deny list (e.g. blocking
  `contractors`). With any group policy active, the check is now fail-closed: missing
  or null claims, unrecognized claim types, non-string array elements (with a deny list
  configured), and allocation/parse failures all refuse access. Comma-delimited string
  claims are now split in place on a heap copy sized to the input instead of a fixed
  256-byte buffer, so arbitrarily long claims are fully matched. Allow-only policies
  keep their previous skip semantics for non-string array elements.

- **Security (`allow_root` guard, `src/identity.c`):** The root guard now protects
  **uid 0, not just the name `root`**. Previously `verify_user_access()` refused only the
  account literally named `root`, so any alternative uid-0 account (e.g. `toor`, or a
  site-specific admin alias created with `useradd -o -u 0`) could authenticate even with
  `allow_root = false`. The gate now resolves the requesting PAM username through
  `getpwnam_r()` and refuses any account whose uid is 0 unless `allow_root = true` is
  explicitly set; the name-based `root` check remains as a first line of defense. A name
  that resolves to no local account cannot be a local uid-0 account (uid-0 accounts
  always exist in the account database), so it is not refused by this gate — only the
  `allow_users`/`deny_users` lists decide it. Regression coverage: a new e2e scenario
  (`uid0-alias-denied`) creates a `toor` uid-0 account in the sandbox and asserts
  `PAM_PERM_DENIED`. The scenario temporarily strips `allow_users` from the sandbox
  config so that only the uid-0 gate can refuse the alias account.

- **Testing (`tests/test_suite.c`):** Fixed an inverted return-value check in the
  `group_claim_uinfo()` CMocka helper introduced with the F2 regression test. The
  helper tested `!json_object_object_add(...)`, but `json_object_object_add()`
  returns `0` on **success** and `-1` on failure — so the "error" path (free the tree,
  return NULL) ran exactly when the add succeeded, and `test_verify_group_membership_deny_only_fail_closed`
  failed on every Linux build (gcc and clang alike) with `assert_non_null(uinfo)`.
  The helper now checks `json_object_object_add(...) != 0`. No module behavior
  changed: production code never calls `json_object_object_add()`, and the bug was
  invisible in the isolated macOS harnesses (which verified the `verify_group_membership()`
  gate logic, not the helper) because the full CMocka suite cannot build without Linux
  PAM headers.

### Documentation

- **sshd rate-limit hardening (`docs/getting-started.md`, `docs/threat-model.md`):**
  documented how to keep connection loops from exhausting the provider-side
  rate limit for this OAuth client. Every SSH connection for an allowed
  username issues a device-code request *before* the user enters anything, so
  a scanner, brute-forcer, or retry loop can lock legitimate users out (429 /
  `slow_down`); because the PAM API exposes no peer address, per-source
  throttling belongs in the SSH layer. Getting Started §4 gains a "Protecting
  the Provider from Connection Bursts" subsection with a recommended drop-in
  (`PerSourcePenalties yes` on OpenSSH ≥ 9.7, `MaxStartups 5:30:100`,
  `MaxAuthTries 3`, `LoginGraceTime 120`) and a `sshd -T` verification
  command, and the threat model gains §9 plus a "Provider Rate-Limit
  Exhaustion (Self-DoS)" matrix row covering the attack, the in-module scope
  boundary, the control table, and monitoring. No module behavior changed.

## [0.3.2] - 2026-11-16

### Added

- **Terminal UX / accessibility:** Failed sign-in attempts now present a plain-text,
  actionable notice in the login terminal (delivered through the PAM conversation,
  `PAM_TEXT_INFO`) — the identity provider service is unavailable, the sign-in code
  expired before approval, or the account was denied — so a failure never ends in an
  unexplained "permission denied" (WCAG 3.3.1 *Error Identification*;
  `notify_user_failure()` in `src/pam_module.c`). Wording is deliberately generic:
  which specific control rejected the attempt remains in the syslog audit trail only.
  Delivery is best-effort (OpenSSH keyboard-interactive clients may buffer
  informational messages until a prompt round-trip; local console logins always
  display the notice). User-initiated cancellation (**Ctrl-C**) produces no notice.
- **Documentation:** `docs/getting-started.md` §7 gains a *User-Visible Failure
  Notices* subsection, and the README `## Accessibility` section now documents the
  failure-feedback guarantee.
- **Testing:** Six opt-in libFuzzer harnesses (`tests/fuzz/`) drive the module's
  pure, input-parsing leaf functions — config parsing, JWT Base64URL/claim
  extraction, JWT token-metadata checks, the terminal/URL string validators, regex
  claim verification, and the PKCE S256 challenge — under ASan+UBSan+LSan (the same
  sanitizer set as `make test-sanitize`). New `make fuzz` / `make fuzz-build`
  targets include a preflight gate with actionable per-platform install guidance
  and a committed seed corpus (`tests/fuzz/seed/`); fuzzing is strictly opt-in and
  runs in no CI workflow. See `tests/fuzz/README.md` for rationale and crash
  triage.

### Fixed

- **Docs:** `examples/README.md` — replaced a raw LaTeX `$\rightarrow$` with a plain
  `→` (GitHub Markdown does not render LaTeX, so the literal source was displayed).
- **Docs (accessibility):** replaced `≠` and inline `→` arrows in prose with explicit
  words ("results in", "maps to", "shows"), gave every link a descriptive, context-unique
  label (no bare-URL link labels, no repeated unanchored link text), and added a
  `## Table of Contents` to the long guides (`getting-started`, `testing`,
  `jwt-validation`, `access-control`) to match `threat-model.md` and `SECURITY.md`
  (WCAG 2.4.4 *Identify Link Purpose* / 2.4.5 *Identify Purpose*).
- **Docs (accessibility):** The two fixed-width box diagrams in
  `docs/threat-model.md` are now rendered as structured tables. Figure 1
  (trust boundary overview) lists the three trust zones and the four trust
  relationships with their protections; Figure 2 (pre-flight
  access-control flow) lists the five evaluation gates with their
  reject/continue conditions — including the UserInfo retrieval failure
  path, which the old art did not show even though the gate is fail-closed.
  The tables keep every relationship and decision the diagrams showed, read
  as proper table semantics by screen readers, and survive narrow/mobile
  rendering where the ~77-char-wide ASCII art wrapped into illegible
  fragments.
- **Docs (accuracy):** `docs/threat-model.md` Figure 2 now matches the
  implementation (verified against `src/identity.c`): gate 4 evaluates the
  provider's group/role claim values (`group_claim_field`, default
  `groups`) against `allow_groups`/`deny_groups` — not local NSS group
  memberships — and states its fail-closed edge cases (enforcement enabled
  with no list rejects; no group policy configured bypasses the gate). Gate 1
  now documents the default `root` denial, which requires an explicit
  `allow_root = true` opt-in. Figure 1's zone rows list contents only, so
  each security property is stated exactly once (in the relationships
  table), and the two adjacent tables carry explicit lead-in labels.
- **Docs (accuracy):** `docs/threat-model.md` re-verified against the C
  implementation and simplified: trust zone 1 now includes the OIDC discovery
  endpoint used by `use_pkce = auto`, the URL-validation bullet clarifies that
  operator-configured endpoints are checked at load time in addition to
  provider-returned verification URIs, and the Figure 2 lead-in now correctly
  describes the access-control gates as running *after* the device-authorization
  token exchange completes.

## [0.3.1] - 2026-11-15

### Added

- **Docs:** Added `.agents/context.md` §9.1 — an OAuth 2.0 Device Authorization Grant
  (RFC 8628) cross-vendor reference covering IETF specs, commercial/enterprise IdPs,
  academic/research federation IdPs, reference PAM implementations, and a cross-vendor
  implementation matrix for `pam_oidc_device`.
- **Poll-loop backoff unit tests:** new CMocka cases pin the transient/retryable
  HTTP status classification (`is_retryable_token_http_status()`) and the
  `slow_down` / transient 429·5xx / cURL-transport-error poll-interval arithmetic
  (`+5 s` and doubling, each clamped at the supported maximum of 120 s), which is
  extracted from the polling loop into the helpers `poll_interval_after_slow_down()`
  and `poll_interval_after_transient()` (`src/pam_module.c`).

### Security

- **Fail-closed JWT `iss`/`aud` checks + load-time binding requirement (config cross-validation):** the claims-only `iss` and `aud` checks in `src/jwt.c` now fail the authentication attempt when `verify_jwt_claims = true` but `issuer` or `audience` is unconfigured (previously the missing check was silently skipped — with no local signature verification this left identity binding to the IdP's UserInfo acceptance alone, which does not distinguish tokens minted for a different client on multi-audience IdPs). Enforced up front: `load_config()` now rejects `verify_jwt_claims = true` unless both `issuer` and `audience` are set (same pattern as the existing PKCE auto-binding check), so the fail-closed token-side branches are a defense-in-depth backstop rather than a reachable normal path.
- **JWT-`sub` vs UserInfo-`sub` consistency check:** when `verify_jwt_claims = true` and the access token carries a `sub` claim, the module now requires it to match the `sub` the provider's UserInfo endpoint returns for the same Bearer token (extracted via a new `jwt_extract_claim_string()` helper). A present-but-mismatched or malformed `sub` aborts with `PAM_AUTH_ERR` (token-substitution suspected); a `sub` absent on either side is skipped with a log line, since providers legitimately differ. Both the extracted token `sub` and the rendered prompt buffer (user code + URIs) are now securely scrubbed (`secure_memzero()`) on every exit path, and `scripts/check-memory-scrubbing.sh` anchors the new sensitive buffers.
- **PII-safe UserInfo logging:** DEBUG/VERBOSE logging of the UserInfo response no longer prints claim *values*. DEBUG logs the response size and the mapped claim field only; VERBOSE additionally lists claim *names* (capped at 32, with non-printable names withheld) so operators can discover the right `claim_regex` without identity data landing in syslog.

### Fixed

- **`[access]` user/group list capacity:** `allow_users`/`deny_users`/`allow_groups`/`deny_groups` are now 2048-byte fields (previously 256). Large production deny lists of local service accounts (commonly >500 bytes, e.g. most of `/etc/passwd`) previously failed config load with `Failed to parse key 'deny_users'` and aborted the login with `PAM_AUTH_ERR`. The matching scratch buffer in `identity.c` (`list_contains`) was raised to the same `ACCESS_LIST_LEN` bound in lockstep, so the longer lists still enforce correctly at runtime instead of silently failing to match.
- **Scrub provider JSON trees on every release path:** the two token-poll re-parse
  sites in `poll_for_access_token()` released the prior `tok_json` tree with a bare
  `json_object_put(*tok_json)`; they now run `secure_zero_json_tree()` first. The
  prior tree can only be a 4xx `authorization_pending`/`slow_down` error response
  (a 2xx response always exits the loop, so no secrets are ever held), but the
  scrub-before-release discipline now holds on every release path.
  `scripts/check-memory-scrubbing.sh` (S3) now also matches
  pointer/dereference forms (`json_object_put(*handle)`), closing the lexical
  blind spot that left those exact release sites invisible to the gate.

### Changed

- **Provider `interval` clamping instead of hard failure:** a device-authorization response with `interval` above the supported maximum (120 s) — or below the RFC 8628 5 s floor — is now clamped into range with a syslog notice instead of aborting the login. RFC 8628 §3.5 only forbids polling *faster* than the server's interval; rejecting an over-long interval made the module incompatible with conservative providers. (E2E-covered via the sandbox; not unit-testable as it lives inside the HTTP-coupled device-request path.)
- **Default `max_poll_seconds` lowered 300 → 120:** the shipped `config/pam_oidc_device.conf` default now matches the project's own PAM-safe guidance (60–120 s): RFC 8628 device-code lifetimes routinely exceed SSH `LoginGraceTime` and systemd PAM timeouts, so the module-side polling window must stay conservative. Existing deployments that explicitly set `max_poll_seconds` are unaffected.
- **AI-agent docs restructure:** the root `AGENTS.md` is now a thin, canonical entry point
  (copy-paste build/verify commands + three-tier boundaries) instead of a symlink to the full
  context doc. Deep architecture, protocol guardrails, and reference/audit material remain in
  `.agents/context.md`; every tool entry point (`CLAUDE.md`, `.github/copilot-instructions.md`,
  `.clinerules`, `.cursorrules`, `.roorules`, `.windsurfrules`) is a symlink to the root
  `AGENTS.md` (the Copilot file was previously a full duplicate and is now a link). Added
  `.agents/plans/` scaffolding and eight `.agents/skills/` (four audit passes ported from
  `.agents/context.md` §10, plus `release-bump`, `sanitizer-audit`, `add-c-module`, and
  `run-e2e`). No module code, build, or packaging behavior changed.

### Documentation

- **PKCE verifier bias note:** `src/pkce.c` now documents why the CSPRNG draw is 48 bytes mapped 6 bits → 1 char (64 divides evenly into 384, no modulo bias; the earlier review's `%66`-style modulo-bias concern is a confirmed false positive for this code).

## [0.3.0] - 2026-11-11

### Added

- **Pre-production testing & audit guide + one-command e2e sandbox:** new `docs/testing.md` documents the full test ladder before production deployment — the automated gates, a new Docker sandbox (`make sandbox` / `make sandbox-shell`, `tests/e2e/Dockerfile` on Ubuntu 24.04) that builds and installs the module exactly like production and drives the *installed* module through a real PAM stack (`/etc/pam.d/e2e`, never `sshd`) against a scenario-driven HTTPS mock OIDC provider (`tests/e2e/mock_oidc.py`, Python 3 stdlib) with a self-signed CA trusted via the system store; `pamtester`-based manual testing (setup, PAM return-code table, 7-case negative-test matrix, plus a deterministic `tests/e2e/pam_driver.c` that answers the module's Enter prompt); a real-IdP trial checklist; and a pre-production audit/rollback checklist. The sandbox exercises the full RFC 8628 loop — device code, **PKCE S256 binding enforced for real by the mock** (S256(verifier) must re-derive the stored challenge), claims-only JWT inspection (`iss`/`aud`/`exp`), UserInfo, claim-to-PAM-user mapping, `slow_down` +5 s backoff, provider denial, code expiry, root denial, and fail-closed mis-permissioned config — as 7 asserted scenarios (`tests/e2e/run_e2e.sh`). A new `e2e-sandbox` CI job in `build.yml` runs the same harness on `ubuntu-latest` (architecture-aware PAM module dir via `dpkg-architecture`).
- **Third-party license notices & automated compliance:** new root-level `THIRD_PARTY_NOTICES.md` records every third-party component (the vendored Project Nayuki QR encoder — MIT, pinned with provenance and local-deviation records; runtime system libraries Linux-PAM, cURL, json-c, OpenSSL; build-only CMocka) with license terms, provenance, and enforcement details, with a compact summary table in `README.md` ("Third-Party Components & Licenses"). A new `license-audit` workflow gates every push/PR to `main` (plus monthly + on demand): its `license-compliance` job runs `scripts/check-licenses.sh` (`make check-licenses`) — notices file present, each `third_party/*/` component carries license text + attribution + provenance pin, no copyleft (GPL/LGPL/AGPL) in `third_party/`, and every RPM-spec `Requires:` runtime dependency declared in the notices file — and its `dependency-graph-audit` job queries the GitHub dependency graph and fails on any indexed package with an off-allowlist license (no-op today for this pure-C project; activates automatically when GitHub indexes a recognized manifest). `THIRD_PARTY_NOTICES.md` is now included in the RPM source tarball.
- **Memory-scrub inspection gate (CI-enforced):** new `scripts/check-memory-scrubbing.sh` (Makefile target `make check-scrub`, step 5 of `make lint` / the pre-commit gate, and a new `memory-scrub` job in `.github/workflows/lint.yml` on every push/PR) lexically enforces the secret-disposal discipline in `src/`: every `free()` of a sensitive buffer (token POST fields, access token, PKCE material, HTTP response body) must be paired with a same-file `secure_memzero()`/`explicit_bzero()` scrub ordered before release, a plain `memset()` is never accepted as the only zeroing of a sensitive buffer, and every `json_object_put()` of a provider-parsed JSON tree must be paired with `secure_zero_json_tree()`.
- **SUSE / Debian / Ubuntu packaging + native-distro CI builds:** the RPM spec (`packaging/pam_oidc_device.spec`) now carries an `%if 0%{?suse_version}` branch selecting SUSE (openSUSE Leap / SLES) binary package names (`pam-devel`, `libcurl-devel`, `libjson-c-devel`, `libopenssl-devel`, `libcmocka-devel` at build time; `pam`, `libcurl4`, `libjson-c5`, `openssl` at runtime), so `make rpm` works unchanged on SUSE. A new `make deb` target (`packaging/build-deb.sh`) hand-crafts a binary `.deb` with `dpkg-deb` + `dpkg-shlibdeps` (no debhelper toolchain): distribution-correct runtime `Depends`, module staged to `/lib/<multiarch>/security`, and `/etc/pam_oidc_device.conf` as a `0600` conffile. A new `distro-build` workflow (`.github/workflows/distro-build.yml`) runs the full loop — zero-warning build, CMocka suite, native package build, install, on-disk layout check — inside containers of the latest LTS releases on every push/PR to `main`: **SUSE openSUSE Leap 16.0** (RPM), **Debian 13** (DEB), **Ubuntu 26.04 LTS** (DEB). `scripts/check-licenses.sh` (L4) now verifies *all* `Requires:` lines (EL + SUSE branches) against `THIRD_PARTY_NOTICES.md`, which documents the per-distribution package names.
- **Configurable QR vertical quiet zone:** new `[qr]` key `vertical_quiet_zone` (0–4, default `4` = the ISO/IEC 18004 4-module minimum) shrinks the blank rows rendered above and below the terminal QR code for a more compact display (e.g. `2` halves the blank lines; the `utf8` style renders two module rows per text line). The horizontal quiet zone always stays at the ISO 4-module minimum since it separates the symbol from surrounding terminal text; values below 4 trade scanner robustness for compactness and remain verified by the independent zbar decode round trip (unit tests) and the CI `qr-scan-audit` job. `tests/qr_scan/art2png.py` gained a matching optional `VQUIET` argument, and its scale detection now uses the leading-space run instead of the top border so compact art rasterizes correctly.

### Changed

- **Documentation restructure (end-user focus):** the repository documentation was reorganized around an end-user journey. `README.md` is now a hub — why the module exists, a plain-English "How It Works" flow, a trimmed quickstart, and a journey-organized documentation map; the previous `docs/pam-ssh-setup.md` and the quickstart details merged into a new `docs/getting-started.md` (prerequisites, install, configuration, OpenSSH, PAM stack, `authselect`, logging); RPM/DEB build instructions moved from the README to a new `docs/packaging.md`; the developer review guide moved from `REVIEW.md` to `docs/developer/review.md` (with its stale CMake build instructions corrected to the project's `Makefile` flow); and the pre-production-testing roadmap moved to `docs/developer/roadmap.md`. No behavior or interface changes.
- **QR prompt compactness:** `qr_render_verification_code()` no longer appends a trailing separator blank line after the rendered art — the bottom quiet zone already separates it from the following text prompt — saving one terminal line at every configuration. `qr_render_matrix()` gained a `vquiet` parameter (breaking API change for direct callers such as test harnesses; `qr_render_verification_code()` reads the setting from the configuration).
- **Condensed default text prompt:** the built-in default prompt template no longer emits a leading blank line before "Complete authentication in your browser:" (the QR block's bottom vertical quiet zone already separates the prompt from the rendered art when the QR code is shown) and no longer emits a blank line between the URL/code block and the trailing "Waiting for your approval..." status line, saving two terminal lines per login. The shipped `init_message` templates in `config/pam_oidc_device.conf` and all three `examples/*.conf` were condensed identically; `test_prompt_rendering` now pins the exact default-template output (with and without a complete verification URI) to prevent regression.
- **`pam_sm_authenticate()` phase extraction:** the device-authorization request/response handling (RFC 8628 §3.1/§3.2) and the token-polling loop (§3.4/§3.5) moved into documented static helpers `request_device_authorization()` and `poll_for_access_token()`, cutting the orchestrator from ~690 to ~330 lines with no behavior change (identical log messages, return codes, clamping, and cleanup/scrubbing, which stays in the single caller-owned `cleanup` path).

### Fixed

- **Dependency-graph audit CI hard-fail on feature-gated accounts:** the `license-audit` workflow's `dependency-graph-audit` job failed with `gh: Field 'dependencyGraph' doesn't exist on type 'Repository'` — GitHub feature-gates the `Repository.dependencyGraph` GraphQL field per account, so on accounts without the supply-chain dependency-graph feature the query fails at *schema validation* (before execution; not a token/permission issue). The job now tolerates only that exact schema-level error and retries via the REST `GET /repos/{owner}/{repo}/dependencies` endpoint; a REST 404 (the endpoints are likewise feature-gated and this repo is private, so no dependency-graph data is served at all — verified: every `/repos/{o}/{r}/dependencies` and `/dependency-graph/*` REST shape returns 404 even for public repos today) is recorded as an empty payload for a clean INFO no-op, while every other query failure still fails the job. `scripts/audit-dependency-graph.py` accepts both payload shapes — the GraphQL `packagesV2` graph (full license-allowlist audit) and the REST array (names cross-checked against `THIRD_PARTY_NOTICES.md`, license reported as "unknown" with no failure invented from missing data).
- **ID-token payload PII scrubbing:** `src/jwt.c` now scrubs the json-c-owned copies of the decoded ID-token claims with `secure_zero_json_tree()` before all nine `json_object_put(payload_json)` release paths (previously only the app-owned decode buffers were scrubbed; json-c releases its private string copies with a plain `free()`). `secure_zero_json_tree()` is now an exported API declared in `include/pam_oidc_device.h` (previously `static` inside `src/pam_module.c`).
- **PII-safe debug logging:** `verify_claim()` no longer logs the raw identity-claim value at DEBUG level; the raw value is now logged only at VERBOSE, consistent with the documented redaction policy (DEBUG-level UserInfo receipts record only the response size and the configured claim field).
- **QR output-buffer guard:** `qr_render_verification_code()` now rejects output buffers too small to hold the instruction header before any `out_len - 2` size arithmetic is performed, eliminating a `size_t` underflow to `SIZE_MAX` when called with a 1-byte buffer (not reachable through the built-in prompt flow, which always passes a 32 KiB buffer).
- **Complete response scrubbing:** `free_http_response()` now scrubs the response body's NUL terminator along with the payload bytes, matching the module's `strlen + 1` scrubbing convention.
- **json-c 0.17 zero-warning builds:** a version-conditional `JSON_ARRAY_IDX()` compatibility macro (public header) selects the array-index parameter type expected by the linked json-c release (`size_t` since json-c 0.17, `int` before), eliminating the four `-Wsign-conversion` warnings emitted on json-c >= 0.17 platforms under the project's full warning set while keeping EL8's json-c 0.13 builds warning-clean.

### CI / Build

- **Mechanically enforced zero-warning bar:** every compile recipe now appends `EXTRA_CFLAGS`, and the CI compile-matrix (gcc + clang) and sanitizer jobs build with `EXTRA_CFLAGS=-Werror`, so any warning fails the build instead of relying on the documented zero-warning convention.
- **Least-privilege, SHA-pinned CI:** all workflows declare `permissions: contents: read` and a `concurrency:` cancel group; all `actions/checkout` uses are SHA-pinned to the v7.0.1 commit (`3d3c42e5aac5ba805825da76410c181273ba90b1`) instead of a mutable tag.
- **Pristine RPM source tarball:** `make rpm` now depends on `clean`, so a prior local build's stale object files (or the module `.so`) can never leak into the packaged source tarball.
- **CI hygiene:** the rpm-build job installs the built package with `dnf install` (the `dnf localinstall` form is deprecated), and `zbar-tools` is no longer installed in jobs that never invoke `zbarimg` (it remains in the `qr-scan-audit` job that decodes the rendered art).

## [0.2.0] - 2026-11-09

### Changed
- **Mandatory sign-in confirmation (always wait for Enter):** `pam_sm_authenticate()` now always issues a `PAM_PROMPT_ECHO_ON` "Press [Enter] to begin..." prompt after displaying the sign-in URL, user code (and optional QR code). Polling begins only after the user presses Enter. This reliably flushes the `PAM_TEXT_INFO` prompt to OpenSSH keyboard-interactive clients (which buffer it until a subsequent prompt triggers a `USERINFO` round-trip) and ensures the user has had time to note the URL and code on a secondary device.

### Documentation
- **User-code format policy:** The README and threat model now state that the RFC 8628 §3.1 character-set, chunking, and ambiguous-character recommendations are identity-provider (server-side) choices, and that the module deliberately displays codes as issued, enforcing terminal-safety filtering only (no rejection or reformatting of vowel/ambiguous-character/un-chunked codes).

### Features
- **Terminal QR code rendering (new `[qr]` section):** Opt-in rendering of the device-flow verification URI as a scannable QR code so that on TTY logins the user can open the sign-in page with a phone camera instead of typing the URL. The code is emitted via `PAM_TEXT_INFO` *before* the text prompt; whenever QR is disabled (`enabled = false`, the default) or rendering fails for any reason — including a URI that exceeds version-20 symbol capacity — the plain text prompt is still displayed, so authentication never depends on the QR code. New `[qr]` keys: `enabled` (default `false`), `style` (`utf8` — compact half-block glyphs U+2580/U+2584/U+2588, fewest lines, default; or `ascii` — one dark-module character per cell for minimal/legacy fonts), `block_char` (single printable ASCII character for the `ascii` style, default `#`), `scale` (1–3 module enlargement, default `1`), `ec_level` (`L`/`M`/`Q`/`H`, default `M`), and `uri` (`complete` — encode `verification_uri_complete` with the user code embedded so nothing is typed on the second device, default, falling back to the plain URI when the provider does not supply a complete one; or `plain` — encode `verification_uri`). Encoding uses a vendored, unmodified copy of the MIT-licensed Nayuki QR Code generator (ISO/IEC 18004) in `third_party/qrcodegen/` — deliberately placed outside `src/` so the CI `clang-tidy` gate lints project code only — with recorded provenance and an upstream-drift audit; a 4-module quiet zone surrounds the symbol and every byte written to the terminal is validated as printable ASCII.
- **PKCE auto-detection via provider discovery metadata:** `use_pkce` now accepts `auto` alongside `true`/`false`, and a new optional `discovery_endpoint` key (`[oauth]`, HTTPS-validated) supplies the provider's OIDC/OAuth discovery URL. In `auto` mode the module fetches that document once per login attempt (5 s cap) and enables PKCE only when the metadata advertises S256 in `code_challenge_methods_supported` *and* advertises a `device_authorization_endpoint`; every transport/HTTP/JSON probe failure fails safe to *no PKCE*, so a discovery outage can never block logins. Every decision is logged with its rationale, and explicit `use_pkce = true` now emits a one-time load-time reminder to confirm provider support. `use_pkce = auto` without `discovery_endpoint` is rejected at config load. `examples/README.md` documents how to determine a provider's device-flow PKCE support (vendor docs, a definitive live test-client probe, and the `auto` heuristic) and recommends `use_pkce` values per archetype (Keycloak: `true`; Entra ID / CILogon: `false` until proven).

### Security
- **Root default-deny:** The `root` account is now denied authentication by default with `PAM_PERM_DENIED`. Set `allow_root = true` in the `[access]` section to explicitly permit root; the check is independent of `allow_users`/`deny_users`, so listing `root` in `allow_users` alone no longer grants root access.
- **Robust polling deadline & interrupt handling:** The poll loop now compares full `timeval` deadlines (sec + nsec) instead of seconds only, and a signaled sleep (`EINTR`) is no longer silently resumed — it logs the interruption, returns `PAM_ABORT`, and aborts the authentication attempt.
- **PKCE device-flow binding:** New optional `use_pkce = true` setting in the `[oauth]` section extends the RFC 8628 device flow with RFC 7636 PKCE: a fresh 64-character Base64URL `code_verifier` is generated from the OpenSSL CSPRNG on each authentication attempt, its S256 `code_challenge` is sent to the device-authorization endpoint, and the verifier is presented at the token endpoint, so a stolen `device_code` alone cannot obtain tokens. Disabled by default (`false`); enable only when the provider supports device-flow PKCE. Verifier/challenge buffers are scrubbed with `secure_memzero()` on every exit path.
- **Security-review remediations:** Transport now enforces strict TLS certificate validation (`CURLOPT_SSL_VERIFYPEER` / `CURLOPT_SSL_VERIFYHOST`) and a TLS >= 1.2 minimum (`CURLOPT_SSLVERSION`); Base64URL decoding strictly validates the RFC 4648 §5 alphabet, rejecting standard-Base64 `+`/`/` characters, embedded whitespace/control bytes, and stray padding; and the DEBUG-level UserInfo audit log is PII-redacted — it records only the response size and the configured claim field, never the raw claim payload.
- **Bounds-checked form-field appending:** The device-authorization and token request bodies are now built through a `form_field_append()` helper that enforces the fixed-capacity stack form-field tables (5 fields each); an oversized parameter set fails safe with `PAM_BUF_ERR` instead of silently overflowing the underlying stack arrays.
- **Memory & robustness fixes:** `http_request()` now zero-initializes the `http_response_t` before any failure path so callers can safely read `status_code`/`size` and release the response on *every* return, not just success; scrubbing of PAM-owned user-response buffers now includes the terminating NUL; the poll loop no longer issues a request whose `CURLOPT_TIMEOUT_MS` would be zero or negative at the deadline boundary (cURL would treat that as "no timeout"); and `is_safe_user_code()` now checks explicit ASCII alphanumeric ranges instead of the locale-dependent `isalnum()`, so the accepted character set cannot vary with the ambient locale.

### Misc
- Module metadata version bumped from `0.1.0` to `0.2.0` (`include/metadata.h`), reflected in the User-Agent string.
- CI: `actions/checkout` bumped to v7.0.1 to resolve the Node 20 deprecation warning.

## [0.1.0] - 2026-11-05

Initial release of `pam_oidc_device`, a native Linux PAM authentication module that
authenticates users through an external OAuth 2.0 / OpenID Connect identity provider using the
[OAuth 2.0 Device Authorization Grant](https://oauth.net/2/device-flow/)
([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)) over HTTPS, then binds the returned
provider identity to the requested local account. It is intended to be composed with other PAM
modules for step-up or multi-factor stacks; it does not independently guarantee MFA.

### Authentication & Workflow
- Native PAM module (`pam_oidc_device.so`) implementing `pam_sm_authenticate` (with a no-op `pam_sm_setcred`).
- Out-of-band RFC 8628 device-authorization flow over HTTPS: request the device/user codes, present the verification prompt, poll the token endpoint, then call the provider UserInfo endpoint with the access token.
- The device-authorization response must include a `user_code`; a missing or non-string `user_code` is rejected up front with an explicit error (no silent `(N/A)` fallback).
- Identity mapping: extracts a configured UserInfo claim (default `claim_field = sub`) and maps it to the local account using a POSIX extended regular expression (`claim_regex`, default `^(.*)$`) with capture-group extraction (`claim_capture_group`, default `1`) and configurable case sensitivity (`case_sensitive`, default `true`).

### Configuration
- Section-based configuration file (`/etc/pam_oidc_device.conf`) with distinct `[oauth]`, `[claim]`, `[access]`, `[prompt]`, and `[runtime]` sections, plus duplicate-key detection.
- Security-restricted config loading: opened with `O_RDONLY | O_NOFOLLOW | O_CLOEXEC`, required to be a regular file (`S_ISREG`), owned by root (`uid 0`), with `0600` or `0640` (`gid 0`) permissions.
- `[oauth]`: `client_id`, `client_secret` (empty for public clients), `device_authorization_endpoint`, `token_endpoint`, `userinfo_endpoint` (all HTTPS-validated), and `scopes` (default `openid`).
- `[claim]`: `claim_field`, `claim_regex`, `claim_capture_group`, and `case_sensitive` (defaults as above).
- `[access]`: `allow_users`/`deny_users` and `allow_groups`/`deny_groups`, `enforce_groups` (default `false`), and `group_claim_field` (default `groups`). Denial lists take precedence over allow lists.
- `[prompt]`: `init_message` template supporting the `{url}`, `{url_complete}`, and `{code}` placeholders and escaped `\n` newlines.
- `[runtime]`: `max_poll_seconds` (device-authorization lifespan, default `300`, range `10`-`3600`) and `loglevel` (`none`/`error`/`info`/`debug`/`verbose`, default `info`).
- `jwks_url` and `introspection_endpoint` are accepted and HTTPS-validated but **not yet used**; setting either emits a load-time notice. JWKS-based signature verification and RFC 7662 token introspection are not performed.

### Identity & Access Controls
- Local account allow/deny lists (`allow_users`/`deny_users`) are enforced **before any provider contact**: a denied account is refused with `PAM_PERM_DENIED` without reaching the identity provider, limiting the blast radius of a loose `claim_regex`.
- Optional group/role authorization evaluates a UserInfo group/role claim (a JSON array or comma-separated string under `group_claim_field`) against `allow_groups`/`deny_groups`, with deny-over-allow precedence; `enforce_groups` can require group authorization even when no lists are configured.

### Local JWT Pre-Check (Claims-Only)
- Optional local JWT inspection (`verify_jwt_claims`, default `false`) Base64URL-decodes the token and checks the `exp`, `nbf`, `iss`, and `aud` claims with a configurable `clock_skew_leeway` (default `60`s, range `0`-`300`) before any downstream network call. In the PAM flow it inspects only the **access token**; the `id_token` is not inspected, since its `aud` audience semantics differ and signature enforcement occurs at the provider's UserInfo endpoint.
- `exp`/`nbf` are enforced as RFC 7519 NumericDate values of either integer or double JSON type; any non-numeric type is rejected as malformed. `require_exp_claim` (default `false`) optionally rejects locally inspected tokens that lack a well-formed `exp`.
- **Claims-only by design:** the JWT cryptographic signature is **not** verified locally and no replay protection is provided; token signature and validity are enforced by the provider's UserInfo endpoint when the bearer token is presented.

### Prompt & Terminal Handling
- Dynamic single-pass prompt template renderer flushed over SSH `keyboard-interactive` sessions via `pam_prompt()`.
- Terminal-injection protection: the prompt template is read only from the root-owned, permission-restricted config file, and the dynamic provider URL(s) and user code are validated before display - `is_valid_https_url` (rejects non-HTTPS schemes, embedded userinfo, and `#` fragments) and `is_safe_user_code` (bounded to 64 characters, restricted character set) - so ANSI escape sequences and C0/C1 control characters cannot be introduced through those fields. `is_safe_terminal_string` is a unit-tested, byte-level validator (newlines allowed; all other bytes must be printable ASCII) that the rendered-prompt check below builds on, line-by-line.
- Defense in depth: the fully rendered prompt is validated before display — `is_safe_terminal_string` is applied line-by-line (newlines permitted, all other bytes must be printable ASCII) to the final text produced by `render_prompt_message()`. ANSI escape sequences or C0/C1 control characters in a custom `init_message` template, a provider URL, or a user code now cause rendering to fail and authentication to abort safely. Custom `init_message` templates are therefore limited to printable ASCII with escaped `\n` newlines.

### Polling & Monotonic Timing
- RFC 8628 polling compliance: only `authorization_pending` and `slow_down` keep the poll loop alive; any other well-formed `4xx` OAuth `error` (or a `4xx` without a parseable error body) aborts authentication.
- The first token-endpoint poll is issued **immediately** after the verification prompt is shown (no leading sleep); only subsequent polls wait the configured interval. This removes one interval of latency (default 5s) from time-to-first-token while remaining RFC 8628-compliant, since the `interval` parameter bounds the spacing *between* polls rather than mandating an initial delay. Backoff and `slow_down` interval adjustments still apply to subsequent polls only.
- Monotonic deadline tracking with `CLOCK_MONOTONIC` and signal-resilient `clock_nanosleep` loops; `slow_down` raises the poll interval by 5s, capped at the 120s maximum supported interval.
- Transient conditions - HTTP `429`/`5xx` (including empty bodies, a JSON `{}` body, or HTML error pages returned by a proxy/load balancer) and transient cURL transport errors - are retried with exponential backoff, capped at the 120s maximum, within the device-authorization deadline.

### Security & Hardening
- Credential scrubbing: `secure_memzero()` (volatile zero-fill rather than plain `memset`, to survive compiler dead-code elimination) is applied to `client_secret`, `device_code`, the access token, the app-owned `Authorization` header buffer, and generated POST form fields.
- json-c credential/PII string trees are zeroed leaf-by-leaf via `secure_zero_json_tree()` before `json_object_put()`, because json-c frees its internal string copies with a plain `free()`.
  - **Limitation:** libcurl retains its own internal copy of the `Authorization` header that cannot be securely zero-filled through the public cURL API.
- HTTPS-only transport is enforced via cURL protocol restrictions; HTTP response bodies are capped at 256 KiB (`MAX_HTTP_RESPONSE_SIZE`); access-token length is bounded (`MAX_ACCESS_TOKEN_LEN`); and form-field buffer growth performs integer-overflow checks.
- Thread-safe cURL global initialization via `pthread_once`.
- Config-descriptor hardening: `O_NOFOLLOW | O_CLOEXEC` on `open()`, `S_ISREG` regular-file check, root ownership (`uid 0`), and strict `0600`/`0640` (`gid 0`) permissions.

### Testing, Packaging & CI
- CMocka unit-test suite (`tests/test_suite.c`) covering URL encoding, loglevel parsing, regex claim mapping and capture groups, case sensitivity, user-code/terminal/URL sanitization, prompt rendering, JWT `exp`/`nbf`/`iss`/`aud` validation, retryable HTTP status handling, and user/group access lists.
- Enterprise Linux RPM build specification (`packaging/pam_oidc_device.spec`) for RHEL / Rocky Linux 9 and 10, with automated spec `%changelog` generation from this file (`packaging/gen-changelog.py`).
- Identity-provider configuration archetypes for Keycloak, Microsoft Entra ID, and CILogon (`examples/`).
- GitHub Actions CI workflows for multi-compiler builds (GCC/Clang), static analysis (`clang-format`, `clang-tidy`, `cppcheck`, `flawfinder`), and Rocky Linux 9/10 package verification.

### OAuth Client Authentication
- Documented limitation: `client_id`/`client_secret` are transmitted as form-encoded request-body parameters (the `client_secret_post` pattern, RFC 6749 §2.3.1). The `client_secret_basic` (HTTP Basic `Authorization`) client-authentication method is not supported, nor are `client_secret_jwt`/`private_key_jwt`; the identity provider must accept body-posted client secrets (the default for most OAuth clients).
