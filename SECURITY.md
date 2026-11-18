# Security Policy

`pam_oidc_device` is a Linux Pluggable Authentication Module (PAM) that authenticates system users via the [OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628). Security is a priority for this project. This document defines how to report security vulnerabilities and indexes the project's security documentation.

## Table of Contents

* [Security Documentation](#security-documentation)
* [Reporting a Vulnerability](#reporting-a-vulnerability)

---

## Security Documentation

The project's security architecture and threat analysis are documented in:

* [Threat Model & Security Architecture](docs/threat-model.md) — trust boundaries, the threat matrix, and mitigation deep dives (terminal injection defense, process memory scrubbing, configuration hardening, PKCE device-flow binding, and more).
* [Local JWT Claim Inspection](docs/jwt-validation.md) — pre-flight claims-only inspection (`verify_jwt_claims`), issuer pinning, and audience checks.
* **JWT trust model** — the JWT signature is intentionally **NOT** verified. Token trust rests **entirely** on enforced TLS + the provider's UserInfo endpoint, and there is **no JWKS / `jwks_url` signature path** (`jwks_url`/`introspection_endpoint` are accepted-but-unused). Consuming ID-token claims directly (offline, without a fresh UserInfo call) would be **High severity** and require adding signature verification. See the [threat-model §5](docs/threat-model.md#5-local-jwt-claims-inspection-vs-downstream-signature-enforcement) operator callout.
* [Account & Group Access Control](docs/access-control.md) — restricting access via `allow_users`, `deny_users`, and provider group/role claims (`allow_groups`/`deny_groups`).

---

## Reporting a Vulnerability

If you discover a potential security vulnerability, please **do not** open a public GitHub issue or disclose it publicly.

Instead, report your findings via email:

* **Contact Email:** `help@ncsa.illinois.edu`

To help evaluate and address the report, please include as much detail as possible:

1. A description of the issue and its potential security impact.
2. Step-by-step instructions or proof-of-concept code to reproduce the issue.
3. Relevant environment details, affected operating systems, and dependency versions (`libcurl`, `json-c`, `glibc`, etc.).

Reports will be reviewed on a best-effort basis as maintainer resources permit.
