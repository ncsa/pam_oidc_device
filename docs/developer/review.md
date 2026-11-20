# Developer Review Guide (`pam_oidc_device`)

Welcome to the `pam_oidc_device` codebase review. This project implements a Linux Pluggable Authentication Module (PAM) for OpenID Connect (OIDC) and OAuth 2.0 using the Device Authorization Grant (RFC 8628) with optional PKCE support (RFC 7636) and terminal QR code rendering.

---

## 1. Codebase Architecture & File Map

The repository is structured into single-responsibility C source files:

* **`src/pam_module.c`**: Primary PAM ABI hooks (`pam_sm_authenticate`, `pam_sm_setcred` — the whole flow is self-contained in `pam_sm_authenticate()`) and the device-flow orchestrator: bounded form-field arrays built via `form_field_append()`/`build_form_postfields()`, `request_device_authorization()`, the monotonic polling loop `poll_for_access_token()` (with the `poll_interval_after_slow_down()` / `poll_interval_after_transient()` / `poll_request_budget()` scheduling helpers), and `secure_zero_json_tree()`.
* **`src/config.c`**: Strict POSIX configuration file loader (`load_config()`), file descriptor security checks (`O_NOFOLLOW`, `O_CLOEXEC`), permission verifiers (0600/0640 `root:root`), the fixed key-value schema parser (unknown keys are rejected fail-closed), `secure_memzero()`, `copy_checked()`, `is_valid_https_url()`, and the terminal-input validators `is_safe_terminal_string()` / `is_safe_user_code()`.
* **`src/http.c`**: Thread-safe `libcurl` transport wrapper (`http_request()`), TLS 1.2+ enforcement, response-size cap (`write_callback()`), level-filtered syslog audit logger (`pam_oauth_log()`, which C-escapes untrusted bytes so they cannot forge syslog records), the PKCE discovery probe (`discovery_probe_pkce()`), and retry classification (`is_retryable_token_http_status()`).
* **`src/identity.c`**: Identity claim regex extractor (`verify_claim()`), local system account allow/deny filter plus uid-0 (`allow_root`) and system-UID range (`deny_system_uids`) gates with fail-closed lookup-error semantics (`verify_user_access()`), group/role authorization engine (`verify_group_membership()`), and the post-UserInfo identity verifier `verify_userinfo_identity()` (PII-safe audit logging, JWT-`sub` vs UserInfo-`sub` consistency check, then claim + group enforcement).
* **`src/jwt.c`**: Strict Base64URL decoder (rejects over-padded segments per RFC 4648 §3.5) and pre-flight claims-only JWT metadata inspector (`verify_token_metadata()` for `exp`, `nbf`, `iss`, `aud` — no signature verification), plus `jwt_extract_claim_string()` for the `sub`-consistency check.
* **`src/message.c`**: User-facing terminal messaging: `render_prompt_message()` (custom `init_message` template tokens or the built-in default wording), `present_signin_prompt()` (prompt + optional QR block + the `PAM_PROMPT_ECHO_ON` Enter barrier), `notify_user_failure()`, expiry formatting, and `is_safe_rendered_prompt()` (terminal-injection check on the fully rendered prompt).
* **`src/pkce.c`**: RFC 7636 Proof Key for Code Exchange implementation generating high-entropy CSPRNG code verifiers and S256 challenges via OpenSSL.
* **`src/qr.c`**: Terminal QR code generator and renderer (`qr_render_verification_code`) supporting UTF-8 half-blocks and ASCII fallbacks, wrapping the provenance-pinned vendored ISO/IEC 18004 encoder in `third_party/qrcodegen/`.
* **`src/device_flow.h`**: Internal (non-public) header shared by `pam_module.c`, `message.c`, `identity.c`, and the test suite: the `device_auth_t` session state, `token_phase_t` / `poll_sched_action_t` result enums, and the test-exported helper declarations.
* **`include/pam_oidc_device.h`** / **`include/metadata.h`**: Public API types (`config_t`, `loglevel_t`, …) and the single source of truth for module metadata/version macros.
* **`tests/test_suite.c`**: 79-case CMocka unit test suite featuring weak cURL transport overrides, a scripted `getpwnam_r()` override for the uid-gate lookup tests, and end-to-end QR code scanner validation.
* **`tests/qr_scan/`**: Helpers for the QR round-trip test (`qr_render_check.c` renderer harness, `art2png.py` PGM conversion).
* **`tests/e2e/`**: Docker sandbox that installs the module and drives it through a real PAM stack against the scenario-driven HTTPS mock IdP (`run_e2e.sh`, `mock_oidc.py`, `pam_driver.c`).
* **`tests/fuzz/`**: Opt-in clang/libFuzzer crash/UB/leak harnesses over the pure-logic functions (config parsing, claim mapping, JWT extraction/inspection, PKCE, string validators) with a checked-in seed corpus.

---

## 2. Execution Flow Summary

The primary entry point is `pam_sm_authenticate()` in `pam_module.c`. When an authentication attempt occurs, execution flows through the following stages:

1. **Parameter & Config Loading**: Parses PAM command-line arguments and securely loads settings via `load_config()`, validating file permissions and ownership; the config schema is fixed (unknown keys fail to load, fail-closed).
2. **Access Control Check**: Evaluates local user allow/deny lists and the uid-0 (`allow_root`) / system-UID range (`deny_system_uids`) gates in `verify_user_access()` prior to initiating network traffic; a local-account lookup error fails closed rather than skipping the gates.
3. **PKCE & Device Grant Request**: When PKCE is active (`use_pkce = true`, or `auto` and the discovery probe confirms S256), generates a CSPRNG code verifier/challenge in `pkce.c`, then `request_device_authorization()` POSTs to the provider's `device_authorization_endpoint`.
4. **Terminal Prompting**: `present_signin_prompt()` (`src/message.c`) renders sign-in instructions — custom `init_message` template or built-in default wording — and optional terminal QR codes, then presents a `PAM_PROMPT_ECHO_ON` synchronization barrier to flush OpenSSH buffers.
5. **Monotonic Polling Loop**: `poll_for_access_token()` polls `token_endpoint` using `clock_nanosleep(CLOCK_MONOTONIC)` — a monotonic (stopwatch-style) clock that only counts forward and is immune to wall-clock time adjustments — with `poll_interval`/`expires_in` clamps, a per-request cURL timeout budget, and backoff handling for transient errors (HTTP 429/5xx, `slow_down`).
6. **Token Verification**: Performs pre-flight claims-only metadata validation on the access token (`verify_token_metadata()` in `src/jwt.c`) and queries the `userinfo_endpoint`.
7. **Identity & Group Matching**: `verify_userinfo_identity()` cross-checks the JWT `sub` against the UserInfo `sub` (token-substitution defense), validates the identity claim via regex (`verify_claim()`), and enforces group membership policies (`verify_group_membership()`).
8. **Memory Hygiene**: Zeroes all sensitive buffers (`secure_memzero`, `secure_zero_json_tree`) before exiting; access/refresh tokens are zeroed before `pam_sm_authenticate()` returns.

---

## 3. Key Areas for Review Focus

Reviewers are encouraged to scrutinize the following security and reliability domains:

### A. Memory Management & Sensitive Data Hygiene

* **Zeroing Operations**: Verify `secure_memzero()` in `src/config.c` (volatile pointer scrub) and `secure_zero_json_tree()` in `src/pam_module.c` effectively prevent Dead Code Elimination (DCE) when clearing secrets; provider-parsed JSON trees must be scrubbed before `json_object_put()` on every exit path.
* **Fixed Stack Form Buffers**: Inspect `d_keys`/`t_keys` stack arrays and `form_field_append()` in `src/pam_module.c` to confirm bounds enforcement (`DEVICE_FORM_MAX_FIELDS` and `TOKEN_FORM_MAX_FIELDS`) prevents stack overflows.
* **Heap Reallocations**: Review dynamic buffer expansion in `write_callback()` (`src/http.c`), `build_form_postfields()` (`src/pam_module.c`), and the `getpwnam_r()` ERANGE retry loop in `verify_user_access()` (`src/identity.c` — doubling buffer growth with a 1 MiB cap) for integer overflow protections on `size_t` calculations and leak-free cleanup on all error branches.

### B. POSIX Filesystem & Hardening

* **Config Security**: Review `load_config()` in `src/config.c` for symlink race conditions (`O_NOFOLLOW`), file descriptor leaks (`O_CLOEXEC`), root ownership (`uid == 0`), and permission restrictions (`0600` / `0640`).

### C. Terminal Security & Injection Prevention

* **Sanitization Functions**: Scrutinize `is_safe_terminal_string()` / `is_safe_user_code()` (`src/config.c`) and `is_safe_rendered_prompt()` (`src/message.c`) to ensure control characters, ANSI escape sequences, or header injections cannot reach the user terminal — including via custom prompt templates, provider-supplied user codes, and the rendered prompt as a whole.
* **Log & QR Surfaces**: Confirm `pam_oauth_log()` escapes untrusted bytes into syslog records (or emits its "log line dropped" marker and scrubs the unrendered bytes), and that the QR block is rendered only from config-validated URL input.

### D. Cryptography & Protocol Compliance

* **PKCE Implementation**: Review `src/pkce.c` for CSPRNG entropy (`RAND_bytes`), unpadded Base64URL encoding (RFC 4648 §5), and SHA-256 S256 challenge generation (RFC 7636).
* **JWT Claim Inspection**: Confirm `verify_token_metadata()` in `src/jwt.c` safely handles fractional `exp`/`nbf` NumericDate claims, audience array matching, and missing claim policies without performing invalid cryptographic assumptions (it performs no signature verification by design), and that the strict Base64URL decoder rejects segments whose total padding exceeds two `=`.

### E. Transport & Timing Hardening

* **Proxy Environment Bypass**: `http_request()` (`src/http.c`) must keep `CURLOPT_PROXY` and `CURLOPT_NOPROXY` explicitly set on every request so neither `*_proxy` nor `no_proxy`/`NO_PROXY` of a setuid PAM caller can steer traffic or bypass a configured `[oauth] proxy`; proxies must be HTTPS-only, and the proxy TLS leg must be explicitly pinned via `CURLOPT_PROXY_SSL_VERIFYPEER`/`VERIFYHOST` and `CURLOPT_PROXY_SSLVERSION` (TLS >= 1.2) — the provider-connection `CURLOPT_SSL_*` options do not cover the proxy connection.
* **Response & Deadline Bounds**: Confirm the `MAX_HTTP_RESPONSE_SIZE` cap in `write_callback()`, the `poll_interval`/`expires_in` clamps, and `poll_request_budget()`'s whole-second monotonic deadline arithmetic keep the polling loop bounded and free of zero/negative timeouts.

---

## 4. Build, Testing & Verification

### Build & Lint Commands

The project builds with the in-repo `Makefile` (no CMake); CI adds `-Werror`, so keep both compiler builds zero-warning:

```bash
make lint                  # clang-format + clang-tidy + cppcheck + flawfinder + memory-scrub (CI-mirrored)
make clean && make CC=gcc  # gcc build
make clean && make CC=clang# clang build
make check-scrub           # sensitive-buffer scrub discipline
make check-licenses        # third-party / RPM-Requires license audit
```

### Running the CMocka Test Suite

```bash
make test CC=gcc           # CMocka suite under gcc
make test CC=clang         # CMocka suite under clang
make test-sanitize CC=clang# ASan + UBSan + LSan: builds AND runs the suite (the CI sanitizer gate)
```

The test suite in `tests/test_suite.c` uses weak symbol overrides to mock the `libcurl` network transfers without external dependencies, and a scripted `getpwnam_r()` override to drive the uid-gate lookup paths deterministically. If `zbarimg` and `python3` are installed on the system, `test_qr_scan_roundtrip` automatically verifies terminal QR code rendering accuracy against an independent decoder.

### End-to-End & Fuzzing

```bash
make sandbox               # e2e: installed module through a real PAM stack vs the in-repo HTTPS mock IdP (Docker)
make sandbox-shell         # interactive variant of the sandbox
make fuzz                  # opt-in: build + run the clang/libFuzzer harnesses (not part of CI)
```

`make sandbox` exercises the full RFC 8628 loop end-to-end (device code, real PKCE S256 enforcement by the mock, polling, claims-only JWT inspection, UserInfo, claim mapping, `slow_down` backoff, denial/expiry, and fail-closed mis-permissioned config). See `tests/fuzz/README.md` for fuzz-harness rationale and crash triage.

### Packaging

```bash
make rpm                   # EL/SUSE (Rocky 8/9/10, openSUSE Leap 16.0)
make deb                   # Debian 13 / Ubuntu 26.04 LTS
```

---

## Related

* [Security Policy](../../SECURITY.md) — vulnerability disclosure procedure.
* [Testing & Pre-Production Audit Guide](../testing.md) — operator-facing verification ladder.
* [Developer Roadmap](roadmap.md) — planned improvements and open work items.
* [Fuzzing Guide](../../tests/fuzz/README.md) — harness rationale and crash triage.
* `.agents/context.md` §3 — the CI-mirrored verification gates a PR must pass.
