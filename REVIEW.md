# Developer Review Guide (`pam_oidc_device`)

Welcome to the `pam_oidc_device` codebase review. This project implements a Linux Pluggable Authentication Module (PAM) for OpenID Connect (OIDC) and OAuth 2.0 using the Device Authorization Grant (RFC 8628) with optional PKCE support (RFC 7636) and terminal QR code rendering.

---

## 1. Codebase Architecture & File Map

The repository is structured into single-responsibility C source files:

* **`pam_module.c`**: Primary PAM ABI hooks (`pam_sm_authenticate`, `pam_sm_setcred`) and overall authentication workflow orchestrator.


* **`config.c`**: Strict POSIX configuration file loader, file descriptor security checks (`O_NOFOLLOW`, `O_CLOEXEC`), permission verifiers (0600/0640 root:root), and key-value parser.


* **`http.c`**: Thread-safe `libcurl` HTTP transport wrapper (`http_request`), TLS 1.2+ protocol enforcer, discovery endpoint probe (`discovery_probe_pkce`), and syslog logger.


* **`identity.c`**: Identity claim regex extractor (`verify_claim`), local system account allow/deny filter (`verify_user_access`), and group/role authorization engine (`verify_group_membership`).


* **`jwt.c`**: Base64URL decoder and pre-flight JWT metadata claim inspector (`verify_token_metadata` for `exp`, `nbf`, `iss`, `aud`).


* **`pkce.c`**: RFC 7636 Proof Key for Code Exchange implementation generating high-entropy CSPRNG code verifiers and S256 challenges via OpenSSL.


* **`qr.c`**: Terminal QR code generator and renderer (`qr_render_verification_code`) supporting UTF-8 half-blocks and ASCII fallbacks.


* **`test_suite.c`**: CMocka unit test suite featuring mock cURL transport overrides and end-to-end QR code scanner validation.



---

## 2. Execution Flow Summary

The primary entry point is `pam_sm_authenticate()` in `pam_module.c`. When an authentication attempt occurs, execution flows through the following stages:

1. **Parameter & Config Loading**: Parses PAM command-line arguments and securely loads settings via `load_config()`, validating file permissions and ownership.
2. **Access Control Check**: Evaluates local user allow/deny lists in `verify_user_access()` prior to initiating network traffic.
3. **PKCE & Device Grant Request**: Generates a CSPRNG code verifier/challenge (if enabled) in `pkce.c` and POSTs to the provider's `device_authorization_endpoint`.
4. **Terminal Prompting**: Renders sign-in instructions and optional terminal QR codes, presenting a `PAM_PROMPT_ECHO_ON` synchronization barrier to flush OpenSSH buffers.
5. **Monotonic Polling Loop**: Polls `token_endpoint` with `clock_nanosleep(CLOCK_MONOTONIC)` handling transient errors (HTTP 429/5xx, `slow_down`) with backoff.
6. **Token Verification**: Performs pre-flight metadata validation on access tokens (`jwt.c`) and queries the `userinfo_endpoint`.
7. **Identity & Group Matching**: Validates identity claims via regex (`verify_claim()`) and enforces group membership policies (`verify_group_membership()`).
8. **Memory Hygiene**: Zeroes all sensitive buffers (`secure_memzero`, `secure_zero_json_tree`) before exiting.



---

## 3. Key Areas for Review Focus

Reviewers are encouraged to scrutinize the following security and reliability domains:

### A. Memory Management & Sensitive Data Hygiene

* **Zeroing Operations**: Verify `secure_memzero()` in `config.c` (volatile pointer scrub) and `secure_zero_json_tree()` in `pam_module.c` effectively prevent Dead Code Elimination (DCE) when clearing secrets.


* **Fixed Stack Form Buffers**: Inspect `d_keys`/`t_keys` stack arrays and `form_field_append()` in `pam_module.c` to confirm bounds enforcement (`DEVICE_FORM_MAX_FIELDS` and `TOKEN_FORM_MAX_FIELDS`) prevents stack overflows.


* **Heap Reallocations**: Review dynamic buffer expansion in `write_callback()` (`http.c`) and `build_form_postfields()` (`pam_module.c`) for integer overflow protections on `size_t` calculations.



### B. POSIX Filesystem & Hardening

* **Config Security**: Review `load_config()` in `config.c` for symlink race conditions (`O_NOFOLLOW`), file descriptor leaks (`O_CLOEXEC`), root ownership (`uid == 0`), and permission restrictions (`0600` / `0640`).



### C. Terminal Security & Injection Prevention

* **Sanitization Functions**: Scrutinize `is_safe_terminal_string()`, `is_safe_user_code()`, and `is_safe_rendered_prompt()` to ensure control characters, ANSI escape sequences, or header injections cannot reach the user terminal.



### D. Cryptography & Protocol Compliance

* **PKCE Implementation**: Review `pkce.c` for CSPRNG entropy (`RAND_bytes`), unpadded Base64URL encoding (RFC 4648 §5), and SHA-256 S256 challenge generation (RFC 7636).


* **JWT Claim Inspection**: Confirm `verify_token_metadata()` in `jwt.c` safely handles fractional `exp`/`nbf` NumericDate claims, audience array matching, and missing claim policies without performing invalid cryptographic assumptions.



---

## 4. Build, Testing & Verification

### Build Commands

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build

```

### Running the CMocka Test Suite

```bash
ctest --test-dir build --output-on-failure

```

The test suite in `test_suite.c` uses weak symbol overrides to mock `libcurl` network transfers without external dependencies. If `zbarimg` and `python3` are installed on the system, `test_qr_scan_roundtrip` automatically verifies terminal QR code rendering accuracy against an independent decoder.
