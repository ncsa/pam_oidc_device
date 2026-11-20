# Security & Credential Handling

For the full security analysis — threat matrix, attack vectors, trust boundary mapping, and the
implementation walkthrough — see the [Threat Model & Security Architecture](threat-model.md).
This page collects the day-to-day credential-handling guarantees of the module.

---

## Table of Contents

* [Zero Disk Footprint](#zero-disk-footprint)
* [Volatile Memory Scrubbing](#volatile-memory-scrubbing)
* [Terminal Injection Defense](#terminal-injection-defense)
* [User Code Format](#user-code-format)
* [Client Authentication](#client-authentication)

---

## Zero Disk Footprint

OAuth device codes, tokens, and response bodies are never written to disk or swap files. Provider
secret materials live only in process memory for the lifetime of the authentication attempt.

---

## Volatile Memory Scrubbing

Module-owned secret materials (client secrets, access/refresh tokens, decoded JSON payload
fields) are explicitly zeroed out in process RAM via `secure_memzero` before memory is released —
never left to default allocation reuse.

---

## Terminal Injection Defense

URL endpoints and user verification codes are validated (`is_valid_https_url`,
`is_safe_user_code`) before display, and the fully rendered prompt is validated line-by-line
(`is_safe_terminal_string`, newline-tolerant) before it reaches the user's terminal — preventing
ANSI sequence and control-character injection. Custom `init_message` templates are therefore
limited to printable ASCII with escaped `\n` newlines.

---

## User Code Format

Verification codes are displayed exactly as issued by the identity provider. The RFC 8628 §3.1
recommendations on code character sets (consonant-only base-20 or pure-numeric sets, omission of
visually ambiguous characters) and chunked display formatting are server-side choices, so the module
does not reject or reformat codes to enforce them — it applies terminal-safety filtering only.

---

## Client Authentication

`client_id`/`client_secret` are transmitted as form-encoded request-body parameters (the RFC 6749
§2.3.1 `client_secret_post` pattern). The `client_secret_basic` (HTTP Basic `Authorization`)
client-authentication method is not supported — the identity provider must accept body-posted
client secrets.
