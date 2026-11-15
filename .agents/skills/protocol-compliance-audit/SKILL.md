---
name: protocol-compliance-audit
description: Audit strict IETF/OIDC compliance — RFC 8628 (device flow), RFC 7636 (PKCE), RFC 7519 (JWT claims), RFC 4648 §5 (Base64URL), RFC 3986 (URI). Use when touching the device flow, PKCE, JWT, polling, or encodings.
---

# RFC Protocol & Standards Compliance Audit

Act as a Standards & Identity Protocol Architect. Review the repo against the official
specifications — RFC 8628 (Device Authorization Grant), RFC 7636 (PKCE), RFC 7519 (JWT),
RFC 4648 §5 (unpadded Base64URL), and RFC 3986 (URI generic syntax & percent-encoding):

1. **Device flow (RFC 8628)** — handling of `authorization_pending`, `slow_down`, transient HTTP
   status codes (429/5xx), and polling-interval backoff; mandatory provider response fields
   validated before consumption.
2. **PKCE (RFC 7636)** — CSPRNG code-verifier generation (`pkce_generate_code_verifier`) for
   entropy, byte length, and URL-safe character set; S256 challenge derivation
   (`pkce_compute_s256_challenge`) aligned with specification test vectors.
3. **JWT metadata (RFC 7519)** — `verify_token_metadata` for `exp`, `nbf`, `iss`, and `aud`;
   NumericDate claims accept integer and fractional JSON numerics while rejecting stringified or
   malformed types.
4. **Encoding strictness (RFC 4648 §5)** — Base64URL decoding rejects non-alphabet characters
   (standard Base64 `+`, `/`, embedded whitespace, or misplaced `=` padding).

**Steps:**
1. Cite file path + line + the specific RFC section for every finding.
2. For PKCE/JWT edge cases, decode any new Base64URL test fixtures with Python to confirm the
   intended JSON (helper in `.agents/context.md` §3.3).
3. Report all specification non-compliance, ambiguous parameter handling, or edge-case protocol
   deviations.

See `.agents/context.md` §10.2 (canonical prompt) and §5 (protocol implementation gotchas).
