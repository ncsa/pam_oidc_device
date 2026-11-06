# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **Root default-deny (F-2):** The `root` account is now denied authentication by default with `PAM_PERM_DENIED`. Set `allow_root = true` in the `[access]` section to explicitly permit root; the check is independent of `allow_users`/`deny_users`, so listing `root` in `allow_users` alone no longer grants root access.
- **Robust polling deadline & interrupt handling (F-6/F-8):** The poll loop now compares full `timeval` deadlines (sec + nsec) instead of seconds only, and a signaled sleep (`EINTR`) is no longer silently resumed — it logs the interruption, returns `PAM_ABORT`, and aborts the authentication attempt.
- **PKCE device-flow binding (F-3):** New optional `use_pkce = true` setting in the `[oauth]` section extends the RFC 8628 device flow with RFC 7636 PKCE: a fresh 64-character Base64URL `code_verifier` is generated from the OpenSSL CSPRNG on each authentication attempt, its S256 `code_challenge` is sent to the device-authorization endpoint, and the verifier is presented at the token endpoint, so a stolen `device_code` alone cannot obtain tokens. Disabled by default (`false`); enable only when the provider supports device-flow PKCE. Verifier/challenge buffers are scrubbed with `secure_memzero()` on every exit path.

### Features
- **PKCE auto-detection via provider discovery metadata:** `use_pkce` now accepts `auto` alongside `true`/`false`, and a new optional `discovery_endpoint` key (`[oauth]`, HTTPS-validated) supplies the provider's OIDC/OAuth discovery URL. In `auto` mode the module fetches that document once per login attempt (5 s cap) and enables PKCE only when the metadata advertises S256 in `code_challenge_methods_supported` *and* advertises a `device_authorization_endpoint`; every transport/HTTP/JSON probe failure fails safe to *no PKCE*, so a discovery outage can never block logins. Every decision is logged with its rationale, and explicit `use_pkce = true` now emits a one-time load-time reminder to confirm provider support. `use_pkce = auto` without `discovery_endpoint` is rejected at config load. `examples/README.md` documents how to determine a provider's device-flow PKCE support (vendor docs, a definitive live test-client probe, and the `auto` heuristic) and recommends `use_pkce` values per archetype (Keycloak: `true`; Entra ID / CILogon: `false` until proven).

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
- Terminal-injection protection: the prompt template is read only from the root-owned, permission-restricted config file, and the dynamic provider URL(s) and user code are validated before display - `is_valid_https_url` (rejects non-HTTPS schemes, embedded userinfo, and `#` fragments) and `is_safe_user_code` (bounded to 64 characters, restricted character set) - so ANSI escape sequences and C0/C1 control characters cannot be introduced through those fields. `is_safe_terminal_string` is a unit-tested utility available for additional output checks but is not applied to the rendered prompt.
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
