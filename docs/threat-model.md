# Threat Model & Security Architecture

`pam_oidc_device` is a Linux Pluggable Authentication Module (PAM) executing inside privileged process spaces (such as OpenSSH `sshd`) to authenticate system users via the [OAuth 2.0 Device Authorization Grant](https://oauth.net/2/device-flow/) ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)). Because authentication modules operate at the primary security boundary of the operating system, this document details the system trust boundaries, threat matrix, defense mechanisms, and implementation specifics.

## Table of Contents

* [Trust Boundaries](#trust-boundaries)
* [Threat Matrix](#threat-matrix)
* [Security Controls & Mitigation Deep Dives](#security-controls--mitigation-deep-dives)
  * [1. Terminal Escape Sequence & Injection Defense](#1-terminal-escape-sequence--injection-defense)
  * [2. Process Memory Hardening & Secret Disposal](#2-process-memory-hardening--secret-disposal)
  * [3. File System & Configuration Permissions Hardening](#3-file-system--configuration-permissions-hardening)
  * [4. Identity Mapping & Pre-Flight Access Control](#4-identity-mapping--pre-flight-access-control)
  * [5. Local JWT Claims Inspection vs. Downstream Signature Enforcement](#5-local-jwt-claims-inspection-vs-downstream-signature-enforcement)
  * [6. HTTP Transport Security & Network Resilience](#6-http-transport-security--network-resilience)
  * [7. PKCE Device-Flow Binding (RFC 7636)](#7-pkce-device-flow-binding-rfc-7636)
* [Out-of-Scope Security Assumptions](#out-of-scope-security-assumptions)

---

## Trust Boundaries

The module operates across three distinct operational boundaries:

```text
 +-------------------------------------------------------------------------+
 |                                LOCAL HOST                               |
 |                                                                         |
 | +---------------------------+    Config & POSIX Access    +----------+  |
 | |  PAM Application Context  |  <----------------------->  | Config   |  |
 | |  (e.g., /usr/sbin/sshd)   |  /etc/pam_oidc_device.conf  | File     |  |
 | +---------------------------+                             +----------+  |
 |              |                                                          |
 +--------------|----------------------------------------------------------+
                | Enforced TLS Transport (HTTPS)
                v
 +-------------------------------------------------------------------------+
 |                         IDENTITY PROVIDER (IdP)                         |
 |                                                                         |
 |  +--------------------+   +-------------------+   +------------------+  |
 |  | Device Auth Endpt  |   |  Token Endpoint   |   | UserInfo Endpt   |  |
 |  +--------------------+   +-------------------+   +------------------+  |
 +-------------------------------------------------------------------------+
                |
                | Out-of-Band Browser Session
                v
 +-------------------------------------------------------------------------+
 |                           USER & CLIENT DEVICE                          |
 |                                                                         |
 |  +--------------------+                           +------------------+  |
 |  |  SSH Terminal      | <-----------------------> | External Web     |  |
 |  |  Prompt            |   User Verification Code  | Browser          |  |
 |  +--------------------+                           +------------------+  |
 +-------------------------------------------------------------------------+

```

### 1. Local Host Integrity (Privileged Kernel & Process Boundary)

* **Assumptions**: The host kernel, file system, `sshd` process space, root account, and system PAM architecture are untampered with and secure.
* **Scope**: Module binary execution, local configuration parsing, process RAM management, and system log emissions (`syslog`).

### 2. Network Transport Boundary (Host-to-IdP)

* **Assumptions**: Identity Provider endpoints (`device_authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`) may exist over untrusted public networks.
* **Scope**: Enforced TLS/HTTPS protocol encryption, TLS host and certificate verification, and payload size restriction.

### 3. Out-of-Band User Authentication Boundary

* **Assumptions**: The user terminal running the SSH session is physically or logically separated from the web browser used to complete OAuth authentication.
* **Scope**: Formatting user prompts, sanitizing user verification codes, display safe output streaming, and polling interval timing.

---

## Threat Matrix

| Risk | Threat Vector | Description | Primary Mitigation | Code Implementation |
| --- | --- | --- | --- | --- |
| **High** | Terminal Injection | Malicious IdP payload or customized prompt template injects ANSI escape sequences into terminal. | Strict printable ASCII character checks and line-by-line validation of rendered user prompt templates. | `is_safe_terminal_string()`, `is_safe_user_code()`, `is_valid_https_url()`, `render_prompt_message()` |
| **High** | Process Memory Leak | Access tokens, client secrets, or sensitive identity claims persist in heap memory after authentication. | Volatile memory zeroing of buffers and deep recursive scrubbing of JSON object trees before deallocation. | `secure_memzero()`, `secure_zero_json_tree()`, `free_http_response()` |
| **High** | Policy Bypass via Local Mapping | Authenticated IdP identity maps to an unauthorized local system account name. | POSIX extended regex claim matching with strict capture groups, case sensitivity controls, and local allow/deny list checks. | `verify_claim()`, `verify_user_access()` |
| **Medium** | Privilege Escalation via Group Claims | IdP user lacking required operational roles gains host machine access. | Evaluation of UserInfo group/role claims against strict allow and deny group lists (deny list takes precedence). | `verify_group_membership()` |
| **Medium** | Config File Manipulation | Low-privileged local user tampers with `/etc/pam_oidc_device.conf` or uses symlink traversal to alter auth logic. | Secure file descriptor opening (`O_NOFOLLOW`, `O_CLOEXEC`), strict file ownership checks (`uid 0`, `gid 0`), and permission validation (`0600`/`0640`). | `load_config()` |
| **Medium** | Token Replay / Token Spoofing | Stale, expired, or wrong-audience access tokens are accepted by the PAM module. | Pre-flight claims inspection (`exp`, `nbf`, `iss`, `aud`) combined with authoritative IdP signature validation at the UserInfo endpoint. | `verify_token_metadata()` |
| **Medium** | Device Code Interception / Replay | An attacker who obtains a live `device_code` (log leakage, network compromise, or a code-phishing relay) completes the token exchange instead of the legitimate user. | Optional PKCE (RFC 7636) S256 binding: a fresh per-attempt CSPRNG `code_verifier` ties the token exchange to the originating device flow, so a stolen `device_code` alone cannot obtain tokens when enabled. | `pkce_generate_code_verifier()`, `pkce_compute_s256_challenge()`, `use_pkce` |
| **Low** | Denial of Service (DoS) via HTTP Buffers | Rogue server sends unbounded HTTP response payloads or redirection loops to exhaust host resources. | Strict HTTPS protocol enforcement, redirection disabling, request timeouts, and fixed response size limits (256 KiB). | `http_request()`, `write_callback()` |

---

## Security Controls & Mitigation Deep Dives

### 1. Terminal Escape Sequence & Injection Defense

Terminal escape sequences (e.g., ANSI control codes) sent to an SSH terminal can manipulate terminal settings, obscure prompt text, or execute unauthorized commands in vulnerable terminal emulators.

* **URL Validation**: Endpoints returned by the identity provider are validated using `is_valid_https_url()`, ensuring they begin strictly with `https://`, contain printable ASCII characters (range 33–126), omit URL fragment hashes, and reject authority userinfo (`user:pass@host`) components.
* **User Code Filtering**: User codes are sanitized by `is_safe_user_code()`, which limits length to 64 bytes and restricts characters exclusively to alphanumeric characters, spaces, hyphens, and underscores.
* **Line-by-Line Prompt Rendering**: Terminal prompts rendered via `render_prompt_message()` replace `{url}`, `{url_complete}`, `{code}`, and newline (`\n`) placeholders. The final rendered prompt is verified by `is_safe_rendered_prompt()`, which splits output on newlines and ensures every line contains strictly printable ASCII characters (range 32–126) via `is_safe_terminal_string()`.

### 2. Process Memory Hardening & Secret Disposal

PAM modules run within the address space of privileged host daemons. Sensitive strings left in heap memory can be exposed through core dumps, memory inspection, or uninitialized buffer reallocations.

* **Volatile Memory Scrubbing**: The module uses `secure_memzero()`, which accesses memory through a `volatile unsigned char *` pointer to prevent optimizing compilers from removing zero-fill operations (Dead Code Elimination).
* **Recursive JSON Tree Scrubbing**: `secure_zero_json_tree()` recursively traverses parsed `json-c` object structures (strings, arrays, and sub-objects) and overwrites internal string bytes with zeroes before calling `json_object_put()`.
* **Lifecycle Cleanup**: Client secrets, OAuth device codes, access tokens, form POST fields, HTTP response buffers, and template buffers are scrubbed immediately after use during module teardown.

### 3. File System & Configuration Permissions Hardening

Configuration files stored at `/etc/pam_oidc_device.conf` contain identity provider settings and security policies.

* **Descriptor-Based Security**: `load_config()` opens configuration files using `open()` with flags `O_RDONLY | O_NOFOLLOW | O_CLOEXEC` to prevent symlink traversal attacks and descriptor leaks to child processes.
* **Regular File & Owner Checks**: `fstat()` verifies the descriptor refers to a regular file (`S_ISREG`) and enforces root owner validation (`st_uid == 0`).
* **Mode Enforcement**: Access modes must strictly be `0600` (read/write by root only) or `0640` (read/write by root, read by group root where `st_gid == 0`). Files with permissive permissions are rejected.

### 4. Identity Mapping & Pre-Flight Access Control

Mapping identity claims from an [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) provider to a local system account requires strict policy verification to prevent unauthorized account access. For configuration options, see [Account & Group Access Control](access-control.md).

```text
Incoming PAM User ("jdoe")
       |
       v
[verify_user_access] ---> Deny List Match? ----------> (YES) ---> REJECT ACCESS
       |                               (NO)
       v
Allow List Configured? ---> (YES) ---> User in List? -> (NO) ---> REJECT ACCESS
       | (NO)                           | (YES)
       +--------------------------------+
       v
Query Provider UserInfo Endpoint
       |
       v
[verify_claim] ---------> Extract Claim via Regex
       |                  Compare with PAM User
       |                  Match Succeeded? -----------> (NO) ---> REJECT ACCESS
       v (YES)
[verify_group_membership] -> Check allow/deny groups
       |                  Group Permitted? ------------> (NO) ---> REJECT ACCESS
       v (YES)
GRANT AUTHENTICATION

```

* **Local Pre-Flight Filtering**: Before initiating network requests to the provider, `verify_user_access()` evaluates the requesting `PAM_USER` against `deny_users` and `allow_users` lists. Denial lists take precedence over allow lists.
* **Regex Claim Extraction**: `verify_claim()` compiles the configured `claim_regex` using [POSIX Extended Regular Expressions](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap09.html) (`REG_EXTENDED`), extracts the specified capture group (`claim_capture_group`), and compares the extracted substring to `PAM_USER`.
* **Deterministic Matching**: Comparison honors `case_sensitive` settings, using `ascii_strcasecmp()` for case-insensitive matching to avoid locale-dependent parsing anomalies.
* **Group Authorization**: `verify_group_membership()` evaluates array or string claims (e.g., `groups` or `roles`) returned by UserInfo against comma-separated `allow_groups` and `deny_groups` settings.

### 5. Local JWT Claims Inspection vs. Downstream Signature Enforcement

When local JWT verification is enabled (`verify_jwt_claims = true`), `verify_token_metadata()` performs pre-flight claim inspection per [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519). For details on configuring issuer and audience checks, see [Local JWT Claim Inspection](jwt-validation.md).

* **Structural Integrity**: Confirms standard 3-part Base64URL JWT structure (`header.payload.signature`).
* **Temporal Validation**: Validates `exp` (Expiration Time) and `nbf` (Not Before) numeric claims against host time (`time(NULL)`), allowing for configurable clock skew (`clock_skew_leeway`).
* **Issuer & Audience Pinning**: Verifies that `iss` matches the configured `issuer` and `aud` matches one or more allowed `audience` entries.

> [!NOTE]
> **Cryptographic Boundary**:
> `verify_token_metadata()` is a pre-flight claims inspector and does **not** perform cryptographic signature checks. Cryptographic signature and token validity enforcement is performed downstream by the identity provider when the access token is presented to the HTTPS `userinfo_endpoint`.

### 6. HTTP Transport Security & Network Resilience

HTTP network interactions managed by `http_request()` enforce security and stability guarantees:

* **Enforced TLS Encryption**: Transport options force HTTPS (`CURLOPT_PROTOCOLS_STR` / `CURLOPT_PROTOCOLS` set to `"https"`). Unencrypted HTTP endpoints are rejected.
* **Redirection Control**: Redirects are disabled (`CURLOPT_FOLLOWLOCATION = 0L`) to prevent credential redirection to unexpected hosts.
* **Payload Bound Enforcement**: Network response payloads are captured via `write_callback()`, which enforces a maximum response size of 256 KiB (`MAX_HTTP_RESPONSE_SIZE`) to mitigate memory allocation attacks.
* **Monotonic Deadline Polling**: Polling loops calculate deadline expirations using the POSIX monotonic clock (`CLOCK_MONOTONIC`) and `clock_nanosleep()`, preventing clock adjustments from affecting authentication timeouts.
* **Transient Error Backoff**: Non-OAuth HTTP errors (e.g., HTTP 429 rate limits, HTTP 5xx server errors, network dropouts) trigger exponential backoff rather than immediate failure, ensuring resilience during temporary provider disturbances.

### 7. PKCE Device-Flow Binding (RFC 7636)

The [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) device flow treats the `device_code` as its sole proof of possession. Modern identity providers pair the device grant with [Proof Key for Code Exchange](https://www.rfc-editor.org/rfc/rfc7636) (RFC 7636) to harden against device-code interception and replay; this module provides that extension as an opt-in.

* **Config Gate**: `use_pkce` in the `[oauth]` section — three states: `false` (default, off), `true` (always on; the provider must support device-flow PKCE or it will reject the device-authorization request, and a load-time advisory reminds operators to confirm support), and `auto` (probe the `discovery_endpoint` metadata document once per attempt and enable PKCE only when it advertises S256 in `code_challenge_methods_supported` *and* a `device_authorization_endpoint`; probe failures fail safe to off). Because no standard discovery field advertises device-flow PKCE specifically, `auto` is a heuristic gate documented as such (see examples/README.md).
* **CSPRNG Verifier**: When enabled, `pkce_generate_code_verifier()` derives a 64-character Base64URL (no padding) `code_verifier` from 48 bytes of OpenSSL `RAND_bytes()` on every authentication attempt, and `pkce_compute_s256_challenge()` computes `BASE64URL(SHA256(ASCII(code_verifier)))` (43 characters) per RFC 7636 §4.2.
* **Flow Binding**: The `code_challenge` and `code_challenge_method=S256` are included in the device-authorization POST; the `code_verifier` itself is included only in the token-endpoint POSTs. The verifier is never displayed on the terminal, embedded in the verification URI, or written to logs.
* **Secret Disposal**: The verifier and challenge stack buffers are scrubbed with `secure_memzero()` at the module's `cleanup` point on every exit path; their URL-encoded copies inside the POST field buffers are scrubbed together with `postfields`/`token_postfields`.

---

## Out-of-Scope Security Assumptions

The following factors fall outside the module's operational scope and must be maintained by system administrators:

1. **Identity Provider Security**: The security, signature integrity, and account lifecycle management of the external OAuth 2.0 / OpenID Connect provider.
2. **Terminal Emulator Integrity**: The safety of the remote user's client terminal software when processing standard printable ASCII characters.
3. **PAM Stack Configuration**: Proper positioning of `pam_oidc_device.so` within system PAM files (e.g., `/etc/pam.d/sshd`) to ensure pre-login checks and environment initializations execute correctly. Refer to the [PAM & OpenSSH Setup Guide](pam-ssh-setup.md) for recommended stack positioning.
