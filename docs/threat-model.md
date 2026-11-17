# Threat Model & Security Architecture

`pam_oidc_device` is a Linux Pluggable Authentication Module (PAM) executing inside privileged process spaces (such as OpenSSH `sshd`) to authenticate system users via the [OAuth 2.0 Device Authorization Grant](https://oauth.net/2/device-flow/) ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)). Because authentication modules operate at the primary security boundary of the operating system, this document details the system trust boundaries, threat matrix, defense mechanisms, and implementation specifics.

> **Security disclosures.** To report a vulnerability in `pam_oidc_device`, follow the [security disclosure procedure](../SECURITY.md).

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
  * [8. Device-Code Phishing — Residual Risk & Hardening](#8-device-code-phishing--residual-risk--hardening)
  * [9. Provider Rate-Limit Exhaustion — Operational Hardening](#9-provider-rate-limit-exhaustion--operational-hardening)
* [Out-of-Scope Security Assumptions](#out-of-scope-security-assumptions)
* [Related Documents](#related-documents)

---

## Trust Boundaries

The module operates across three distinct operational boundaries:

**Figure 1 — Trust boundary overview.** The three trust zones, and the
trust relationships that run within and between them:

*Zones:*

| Zone | Contents |
| --- | --- |
| **Local host** | A PAM application context (e.g., `/usr/sbin/sshd`) and the configuration file `/etc/pam_oidc_device.conf`. |
| **Identity provider (IdP)** | The device-authorization, token, and UserInfo endpoints — plus the OIDC discovery endpoint when `use_pkce = auto`. |
| **User & client device** | The SSH terminal prompt and an external web browser. |

*Trust relationships:*

| Trust relationship | Connects | Protection |
| --- | --- | --- |
| Config & POSIX access | PAM application context to configuration file (within the local host) | Ownership and permission checks (`root:root`, `0600`/`0640`) on a fail-closed open; any deviation aborts authentication |
| Enforced TLS transport | Local host to the IdP's OAuth/OIDC endpoints | HTTPS only, TLS 1.2+, certificate verification enabled (`CURLOPT_SSL_VERIFYPEER=1`, `CURLOPT_SSL_VERIFYHOST=2`) |
| Out-of-band browser session | IdP to the user's browser | A standard authenticated browser session; user credentials are never presented to, or seen by, the module |
| User verification code | SSH terminal to web browser (on the user's own device) | The code is the only material shared between the two; it is never transmitted through the module |

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
| **Medium** | Token Replay / Token Spoofing | Stale, expired, or wrong-audience access tokens are accepted by the PAM module. | Authoritative IdP enforcement when the token is presented to the `userinfo_endpoint`, complemented by a fail-closed `token_type = Bearer` check, opt-in local claims inspection (`exp`, `nbf`, `iss`, `aud`), and a JWT-sub ↔ UserInfo-sub consistency check. | `verify_token_metadata()`, `jwt_extract_claim_string()` |
| **High** | Device-Code Phishing (Social Engineering) | An attacker who already has a session on the target host (stolen or socially engineered access) initiates the device flow *themselves*, copies the verification URL and user code, and persuades the victim to approve it ("IT here, please confirm this sign-in"). The identity check passes because the identity really is the victim's; PKCE provides no protection because the attacker started the flow and holds its `code_verifier`. No technical vulnerability is required — the impact is full account takeover through social engineering. | **Residual risk** — mitigated, not eliminated: the prompt names the target host's hostname in its trailing status line (`[prompt] show_host`, on by default; `{host}` token in custom templates) so the victim can cross-check *which machine* the sign-in belongs to; prefer IdPs whose approval page shows client context; for privileged accounts, pair with network restrictions or a second factor. User vigilance is the final control. See §8. | `render_prompt_message()` (host clause in trailing status line; `show_host`), `docs/threat-model.md` §8 |
| **Medium** | Device Code Interception / Replay | An attacker who *intercepts or recovers* a live `device_code` (log leakage, network compromise, or shoulder-surfing a code the legitimate user is completing) attempts to complete the token exchange instead of the legitimate flow. | Optional PKCE (RFC 7636) S256 binding: a fresh per-attempt CSPRNG `code_verifier` ties the token exchange to the originating device flow, so a stolen `device_code` alone cannot obtain tokens when enabled. **Scope boundary:** PKCE protects only against an *interceptor* who was not the flow's initiator — it does **not** stop device-code phishing, where the attacker is the initiator (row above; see §8). | `pkce_generate_code_verifier()`, `pkce_compute_s256_challenge()`, `use_pkce` |
| **Low** | Denial of Service (DoS) via HTTP Buffers | Rogue server sends unbounded HTTP response payloads or redirection loops to exhaust host resources. | Strict HTTPS protocol enforcement, redirection disabling, request timeouts, and fixed response size limits (256 KiB). | `http_request()`, `write_callback()` |
| **Medium** | Provider Rate-Limit Exhaustion (Self-DoS) | A pre-auth client that loops SSH connections against usernames that pass the local allow/deny pre-flight generates one device-authorization request per connection and can exhaust the OAuth client's provider-side rate limit, locking out legitimate sign-ins (HTTP 429 / `slow_down`). | Per-source pre-auth throttling at the SSH layer (`MaxStartups`, `PerSourcePenalties` on OpenSSH ≥ 9.7, `MaxAuthTries`, `LoginGraceTime`) plus narrow local allow-lists (pre-flight rejection happens before any provider contact). PAM exposes no peer-address API, so in-module per-source limiting is not possible. See §9. | sshd configuration; `verify_user_access()` pre-flight |

---

## Security Controls & Mitigation Deep Dives

### 1. Terminal Escape Sequence & Injection Defense

Terminal escape sequences (e.g., ANSI control codes) sent to an SSH terminal can manipulate terminal settings, obscure prompt text, or execute unauthorized commands in vulnerable terminal emulators.

* **URL Validation**: Verification URIs returned by the identity provider — and, at load time, every operator-configured endpoint — are validated by `is_valid_https_url()`, which requires the `https://` scheme, printable ASCII only (no control bytes), no fragment (`#`), and rejects authority userinfo (`user:pass@host`). Malformed or non-HTTPS URIs are refused before they can reach the terminal.
* **User Code Filtering**: User codes are sanitized by `is_safe_user_code()`, which limits length to 64 bytes and restricts characters exclusively to alphanumeric characters, spaces, hyphens, and underscores.
  * The sanitizer enforces terminal safety only — not code *format*: RFC 8628 §3.1's character-set recommendations (e.g., a consonant-only base-20 set, or omission of visually ambiguous characters such as `0`/`O` and `1`/`l`/`I`) and display chunking (e.g., `WDJB-MJHT`) are server-side choices made by the identity provider when it issues the code.
  * The module therefore deliberately neither rejects nor reformats codes containing vowels, ambiguous glyphs, or un-chunked sequences — rejecting them would break compatibility with providers that do not follow those recommendations.
* **Line-by-Line Prompt Rendering**: Terminal prompts rendered via `render_prompt_message()` replace `{host}`, `{url}`, `{url_complete}`, `{code}`, and newline (`\\n`) placeholders. The `{host}` value (the target host's hostname — gated by `[prompt] show_host`, on by default; when off the token expands to an empty string and the built-in default prompt drops the host clause) gives the approving user a machine-level cross-check against device-code phishing (§8). The final rendered prompt — host bytes included — is verified by `is_safe_rendered_prompt()`, which splits output on newlines and ensures every line contains strictly printable ASCII characters (range 32–126) via `is_safe_terminal_string()`; a hostname containing control or non-ASCII bytes therefore fails authentication fail-closed.

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

Mapping identity claims from an [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) provider to a local system account requires strict policy verification to prevent unauthorized account access. For configuration options, see the [account and group access control guide](access-control.md).

**Figure 2 — Access-control decision flow.** After the device-authorization
token exchange completes, a linear sequence of gates is evaluated using the PAM
username and the provider's UserInfo payload: any failed gate fails closed and
rejects the login, and only a fully passing path reaches
**GRANT AUTHENTICATION** (`PAM_SUCCESS`).

| # | Gate | What is evaluated | Rejects when | Continues when |
| --- | --- | --- | --- | --- |
| 1 | `verify_user_access()` | `deny_users` / `allow_users` on the PAM username; the deny list always takes precedence; any uid-0 account (`root` and alternative uid-0 names) is denied unless `allow_root = true` is set explicitly; when `deny_system_uids = true` (default) any local account whose numeric UID falls in `[system_uid_min, system_uid_max]` (default 0-999) is denied regardless of the lists — a uid-0 account already exempted via `allow_root` is not re-denied by this range gate | The user is listed in `deny_users`; the user is a uid-0 account without an explicit `allow_root = true` opt-in; the user's numeric UID falls within the denied system-UID range; or the user is absent from a configured `allow_users` list | The user passes local account filtering |
| 2 | Provider UserInfo retrieval | `HTTPS GET /userinfo` over the enforced TLS 1.2+ transport | The transport or HTTP request fails — the gate is fail-closed | The claim payload arrives (HTTP 200) |
| 3 | `verify_claim()` | The configured identity claim, extracted from the payload by regex, compared against the PAM username | No configured claim is present, or the extracted value does not match the PAM username | The claim matches the PAM username |
| 4 | `verify_group_membership()` | The group/role values of the configured UserInfo claim (`group_claim_field`, default `groups`) compared against `allow_groups` / `deny_groups`; deny values take precedence | The user holds a group/role listed in `deny_groups`, or holds none that satisfy a configured `allow_groups` list; the gate also rejects when group enforcement is enabled but no list is configured, and — with any group policy active — when the claim is missing, JSON null, of an unrecognized type, or not fully parseable (fail-closed) | Group policy passes, or no group policy is configured (gate bypassed) |
| 5 | — | — | — | **GRANT AUTHENTICATION** — `PAM_SUCCESS` is returned to the PAM stack |

* **Local pre-flight filtering**: `verify_user_access()` (gate 1) runs *before* any provider contact, so a locally-denied account never triggers a device-flow. Deny lists take precedence; uid-0 accounts (`root` and any alternative uid-0 name) are refused unless `allow_root = true`; and, by default (`deny_system_uids = true`), every local account whose numeric UID falls in the configurable system range `[system_uid_min, system_uid_max]` (0-999) is refused — the guard targets the UID, not the name, so service accounts holding in-range UIDs are denied even when listed in `allow_users` (a `pam_succeed_if uid >= 1000` pre-gate in the PAM stack is the complementary control).
* **Regex claim extraction**: `verify_claim()` compiles `claim_regex` with [POSIX extended regular expressions](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap09.html) (`REG_EXTENDED`), extracts capture group `claim_capture_group`, and compares it to the PAM user. Matching honors `case_sensitive`; the case-insensitive path uses a byte-wise `ascii_strcasecmp()` so results never vary with the ambient locale.
* **Group authorization**: `verify_group_membership()` (gate 4) compares the `group_claim_field` value (default `groups`) — a JSON array, a single string, or a comma-separated string — against `allow_groups` / `deny_groups`; deny values take precedence.
* **PII-safe audit logging**: The raw UserInfo payload (which holds personal data) is never written to the system log. At `DEBUG` the module records only the payload size and configured claim field; at `VERBOSE` it additionally lists claim *names* (never values), and a name is withheld if it contains non-printable bytes.

### 5. Local JWT Claims Inspection vs. Downstream Signature Enforcement

When local JWT verification is enabled (`verify_jwt_claims = true`), `verify_token_metadata()` performs pre-flight claim inspection per [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519). For details on configuring issuer and audience checks, see the [local JWT claim inspection guide](jwt-validation.md).

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
* **Monotonic Deadline Polling**: Polling loops calculate deadline expirations using the POSIX monotonic clock (`CLOCK_MONOTONIC`) — a clock that only counts forward like a stopwatch and is unaffected by wall-clock time adjustments — together with `clock_nanosleep()`, preventing clock adjustments from affecting authentication timeouts.
* **Transient Error Backoff**: Non-OAuth HTTP errors (e.g., HTTP 429 rate limits, HTTP 5xx server errors, network dropouts) trigger exponential backoff rather than immediate failure, ensuring resilience during temporary provider disturbances.

### 7. PKCE Device-Flow Binding (RFC 7636)

The [RFC 8628 device flow](https://www.rfc-editor.org/rfc/rfc8628) treats the `device_code` as its sole proof of possession. Modern identity providers pair the device grant with [Proof Key for Code Exchange](https://www.rfc-editor.org/rfc/rfc7636) (RFC 7636) to harden against device-code interception and replay; this module provides that extension as an opt-in.

* **Config Gate**: `use_pkce` in the `[oauth]` section — three states:
  * `false` (default): the device flow runs without PKCE.
  * `true`: always on; the provider must support device-flow PKCE or it will reject the device-authorization request, and a load-time advisory reminds operators to confirm support.
  * `auto`: probe the `discovery_endpoint` metadata document once per attempt and enable PKCE only when it advertises S256 in `code_challenge_methods_supported` *and* a `device_authorization_endpoint`; probe failures fail safe to off.

  Because no standard discovery field advertises device-flow PKCE specifically, `auto` is a heuristic gate documented as such (see examples/README.md).
* **CSPRNG Verifier**: When enabled, `pkce_generate_code_verifier()` derives a 64-character Base64URL (no padding) `code_verifier` from 48 bytes of OpenSSL `RAND_bytes()` on every authentication attempt, and `pkce_compute_s256_challenge()` computes `BASE64URL(SHA256(ASCII(code_verifier)))` (43 characters) per RFC 7636 §4.2.
* **Flow Binding**: The `code_challenge` and `code_challenge_method=S256` are included in the device-authorization POST; the `code_verifier` itself is included only in the token-endpoint POSTs. The verifier is never displayed on the terminal, embedded in the verification URI, or written to logs.
* **Secret Disposal**: The verifier and challenge stack buffers are scrubbed with `secure_memzero()` at the module's `cleanup` point on every exit path; their URL-encoded copies inside the POST field buffers are scrubbed together with `postfields`/`token_postfields`.
  * This scrub-before-release discipline is enforced mechanically on every push/PR by `scripts/check-memory-scrubbing.sh` (CI `memory-scrub` job; `make check-scrub`, part of `make lint`): sensitive heap buffers must be zeroed with `secure_memzero()`/`explicit_bzero()` before `free()` (plain `memset()` is never sufficient on its own), and provider-parsed JSON trees — including the ID-token payload in `src/jwt.c` — must pass through `secure_zero_json_tree()` before `json_object_put()`.

* **Scope Boundary — What PKCE Does *Not* Stop**: PKCE binds the token exchange to the flow's *initiator*. If the attacker was never in possession of a code issued to a legitimate user — i.e., the attacker **started the flow themselves** — they hold the `code_verifier` and PKCE verifies them. Device-code phishing is that case; see §8.

---

### 8. Device-Code Phishing — Residual Risk & Hardening

Device-code phishing is the device grant's known social-engineering attack, and it is a **residual risk** that no technical control in this module can eliminate:

1. The attacker establishes a session on the target host (compromised credentials, a help-desk pretext, an already-malicious account — "I'm IT, I need to verify your sign-in").
2. The attacker triggers the device flow (`ssh victim@host`), copies the verification URL and user code, and persuades the victim to approve it.
3. The victim approves on their own device. The IdP genuinely authenticates the victim's identity — claim mapping, group policy, PKCE, and TLS all pass — and the attacker receives the victim's session.

PKCE does **not** mitigate this: the attacker initiated the flow, so they hold the `code_verifier`; PKCE (see §7) only stops a *receiving* party who merely intercepted or recovered the `device_code`. Likewise, the identity checks (§4) cannot stop it, because the identity really is the victim's.

The module mitigates the *opportunity*, not the social engineering:

* **Host identification in the prompt**: the sign-in prompt names the target host's hostname in its trailing status line (`Waiting for your approval to sign in to <host>; ...`; template token `{host}` in `init_message`; `[prompt] show_host`, on by default — when off, the host clause is dropped and `{host}` expands to an empty string). A victim asked to approve a sign-in for `db-prod-3` should be able to notice when the "IT" pretext describes a different machine and refuse. PAM exposes no peer-address API, so the connecting client's IP cannot be displayed by the module; users should instead correlate whatever source-IP context the IdP's approval page shows.
* **Prefer providers whose approval page shows client context** (registered OAuth client name, device source IP), so the approving device can cross-check the request before confirming.
* **Privileged accounts**: pair the module with compensating controls outside it — network restrictions on which hosts may reach the IdP's device endpoint for that account, a second factor on the approval session, or alerts on device-flow approvals from new source addresses.
* **User awareness**: users should never approve a code they did not initiate from their own terminal session, and should treat "IT is asking you to confirm a sign-in" out-of-band as suspect by default.

> [!WARNING]
> **Residual Risk**: Even with host identification in the prompt, a sufficiently patient attacker who initiates the flow *from the exact machine they are claiming* can still succeed against a cooperative victim. This risk cannot be closed in-module; it is mitigated by the controls above and closed only by operator policy (awareness training, approval-page provider selection, network and identity controls).

---

### 9. Provider Rate-Limit Exhaustion — Operational Hardening

**Threat.** Every SSH connection for a username that passes the module's allow/deny pre-flight check issues one device-authorization request to the provider *before* any user interaction (the request is what carries the sign-in prompt). A source that opens connections in a loop — an SSH scanner, a credential brute-forcer, or a misbehaving client retrying forever — can exhaust the provider-side rate limit for this OAuth client and lock *legitimate* users out of their sign-ins (HTTP 429 responses; `slow_down`-style errors from the provider). The impact is self-inflicted denial of service, plus the risk of the provider flagging the client for abuse.

**Why the module does not mitigate it in-code.** PAM exposes no peer-address API (the same limitation that prevents showing the connecting client's IP in the prompt, §8), so the module cannot rate-limit *per source address*. A host-wide limiter would additionally require cross-process state shared by concurrent `sshd` workers, which is outside PAM module scope. The SSH layer already enforces per-source pre-auth throttling, and that is the correct place for this control:

| Control | Where | Effect |
| --- | --- | --- |
| `MaxStartups` | sshd | Caps *concurrent* unauthenticated sessions (default `10:30:100`: fully accepted up to 10, probabilistic drops above, hard stop at 100). |
| `PerSourcePenalties yes` | sshd (OpenSSH ≥ 9.7) | Progressively penalizes repeated pre-auth connections from the same source address, making a looping source increasingly likely to be dropped. |
| `MaxAuthTries` | sshd | Caps authentication rounds per connection; each round for an allowed username is one potential device-code request. |
| `LoginGraceTime` | sshd | Drops idle pre-auth connections; also bounds hung device flows. |
| `allow_users` / `AllowUsers` | module / sshd | Keep the allow-list narrow: usernames rejected by the pre-flight check never reach the provider. |

Recommended drop-in (`/etc/ssh/sshd_config.d/90-pam-oidc-device.conf`):

```sshd_config
PerSourcePenalties yes
MaxStartups 5:30:100
MaxAuthTries 3
LoginGraceTime 120
```

Verify the effective values with `sudo sshd -T | grep -Ei 'maxstartups|persourcepenalties|maxauthtries|logingracetime'`. The device-code request itself is cheap and disposable (unused codes simply expire), so the operational risk is exhausting the client's rate limit, not user data. Monitor the syslog for device-endpoint errors and the provider's audit console for rate-limit events on this OAuth client.

---

## Out-of-Scope Security Assumptions

The following factors fall outside the module's operational scope and must be maintained by system administrators:

1. **Identity Provider Security**: The security, signature integrity, and account lifecycle management of the external OAuth 2.0 / OpenID Connect provider.
2. **Terminal Emulator Integrity**: The safety of the remote user's client terminal software when processing standard printable ASCII characters.
3. **PAM Stack Configuration**: Proper positioning of `pam_oidc_device.so` within system PAM files (e.g., `/etc/pam.d/sshd`) to ensure pre-login checks and environment initializations execute correctly. Refer to the [Getting Started guide](getting-started.md) for recommended stack positioning.
4. **Approver Vigilance & Provider Approval Pages**: The security of the user's own browser device, and the amount of client context (client name, source IP) the IdP chooses to show on its approval page. The module controls neither; device-code phishing (§8) is mitigated by these out-of-module factors together with host identification in the prompt.

---

## Related Documents

* [Security Policy](../SECURITY.md) — vulnerability disclosure procedure and index to the project's security documentation.
* [Local JWT Claim Inspection](jwt-validation.md) — configuring `verify_jwt_claims`, issuer (`iss`), and audience (`aud`) checks.
* [Account & Group Access Control](access-control.md) — configuring `allow_users`, `deny_users`, `allow_groups`, and `deny_groups`.
* [Getting Started](getting-started.md) — installation, configuration, and recommended PAM stack positioning plus OpenSSH configuration.
* [Identity Provider Integration Examples](../examples/README.md) — complete config templates for Microsoft Entra ID, Okta, Keycloak, Auth0, and CILogon.
