# Provider Configuration Examples & Discovery Guide

This directory contains reference configuration templates and guidance for integrating `pam_oidc_device.so` with identity providers supporting the OAuth 2.0 Device Authorization Grant ([RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)) and OpenID Connect (OIDC).

---

## Configuration Disclaimer & Scope Boundary

The configuration templates provided in this directory serve strictly as technical reference patterns for setting up standard RFC 8628 endpoints and POSIX username regular expression mappings.

* **Vendor Neutrality:** `pam_oidc_device` is designed as a generic, vendor-neutral Linux PAM authentication utility. It is not affiliated with, endorsed by, or officially certified by any commercial or institutional identity provider.
* **Trademarks:** All product names, logos, trademarks, and registered trademarks mentioned in this repository belong to their respective owners.
* **Administrator Responsibility:** System administrators are responsible for verifying endpoint transport security (HTTPS), authorization scopes, and identity claim mappings with their organization's identity team before deploying to production servers.

---

## Discovering Endpoints via OIDC Discovery

Rather than relying on provider-specific vendor documentation, you can discover the exact required endpoints for any compliant OIDC provider using its standard OpenID Connect Discovery metadata document.

Most identity providers publish their metadata at:
```text
https://<your-idp-domain>/.well-known/openid-configuration
```

### Mapping Metadata to `/etc/pam_oidc_device.conf`

Fetch the JSON document (for example, using `curl -s https://auth.example.com/.well-known/openid-configuration | jq`) and map the JSON attributes directly into your configuration file:

| OIDC Discovery JSON Attribute | `pam_oidc_device.conf` Parameter | Notes / Description |
| :--- | :--- | :--- |
| `device_authorization_endpoint` | `device_authorization_endpoint` | Endpoint issuing device and user codes (RFC 8628) |
| `token_endpoint` | `token_endpoint` | Endpoint polled for access token issuance |
| `userinfo_endpoint` | `userinfo_endpoint` | Endpoint queried to retrieve user identity claims |
| `scopes_supported` | `scopes` | Space-separated list of scopes (must include `openid`) |
| `code_challenge_methods_supported` | `use_pkce = auto` (hint only) | Advertises PKCE methods for the **authorization-code** flow; used by the `auto` gate as a heuristic for device-flow PKCE — see below |

---

## Does Your Provider Support PKCE with the Device Flow?

`use_pkce` in the `[oauth]` section extends the RFC 8628 device flow with PKCE (RFC 7636): a fresh
high-entropy `code_verifier` is generated per login, its `S256 code_challenge` is sent to the
device-authorization endpoint, and the verifier is presented at the token endpoint — so a stolen
`device_code` alone cannot obtain tokens.

PKCE is **not** part of RFC 8628, and provider adoption of it for the *device grant* is uneven.
**A provider without device-flow PKCE support rejects the device-authorization request when
`code_challenge` is sent**, which would break every login — so determine your provider's support
before enabling `use_pkce = true` in production.

### Why the discovery document alone cannot answer this

* The standard OIDC/OAuth discovery documents (OIDC Discovery 1.0, RFC 8414, and the
  `device_authorization_endpoint` extension) advertise that the device grant *exists*, but
  **no standard discovery parameter advertises PKCE support for the device grant**.
* `code_challenge_methods_supported` (when present in a discovery document) describes the
  **authorization-code** flow only. It is *not* a reliable signal for the device flow — for
  example, CILogon advertises `["plain", "S256"]` while Microsoft Entra ID's v2.0 discovery
  document omits the field entirely, in neither case stating anything about the device grant.
  (Both documents were verified live against the public endpoints in 2026-11.)

Treat the field as a *hint*, not proof.

### How to determine your provider's support

1. **Vendor documentation.** Search your provider's OAuth 2.0 / OIDC docs for
   "PKCE" + "device code" / "device authorization". As of 2026-11:
   * **Keycloak** — device-flow PKCE is implemented (its issue tracker discusses making it
     optional for PKCE-only clients), so `use_pkce = true` is appropriate.
   * **Microsoft Entra ID** — the v2.0 device-code reference does *not* document
     `code_challenge`; treat as unsupported for the device flow until proven for your tenant.
   * **Okta / Auth0 / CILogon / Google / others** — check the current documentation for your
     tenant/edition; none of them document device-flow PKCE in the reference docs examined.
2. **Live test-client probe (definitive).** Register a throwaway test client in your provider,
   then compare the device-authorization request with and without PKCE:
   ```bash
   # (a) baseline — should return a normal device-code payload
   curl -sS -X POST https://<idp>/device-authorization \
        -d "client_id=<TEST_CLIENT>&scope=openid"

   # (b) with PKCE — a valid S256 code_challenge (43 Base6URL chars, no padding)
   curl -sS -X POST https://<idp>/device-authorization \
        -d "client_id=<TEST_CLIENT>&scope=openid&code_challenge=<CHALLENGE>&code_challenge_method=S256"
   ```
   * **(b) returns the same normal device-code payload** (and, if you complete the flow, polling
     with the matching `code_verifier` succeeds while a wrong/missing verifier is rejected with
     `invalid_grant`) — the provider **supports** PKCE: set `use_pkce = true`.
   * **(b) fails with an error naming `code_challenge` / an unsupported-parameter error** —
     the provider **does not support** PKCE: keep `use_pkce = false`.
   * **Gotcha:** an *unregistered* `client_id` cannot be used for this test — most providers
     validate the client before inspecting the extra parameters and return an
     `unauthorized_client`-style error either way.
3. **`use_pkce = auto` heuristic gate.** With `discovery_endpoint` set (e.g.
   `https://<idp>/.well-known/openid-configuration`), the module fetches the discovery document
   once per login attempt and enables PKCE **only** when it advertises S256 in
   `code_challenge_methods_supported` *and* advertises a `device_authorization_endpoint`.
   Probe failures (network, non-200, bad JSON) fail safe to *no PKCE*, so a discovery outage can
   never block logins. Every decision is logged to syslog with its rationale — e.g.
   `PKCE auto-detection: provider metadata does not advertise S256 PKCE support; continuing
   without PKCE for this attempt` — so you can audit the suggestion. Because of the caveat above,
   `auto` is a conservative gate: it never *breaks* a login to enable PKCE, but a provider that
   supports device-flow PKCE without advertising S256 in discovery will stay on the plain device
   flow until you set `use_pkce = true` manually after step 2.

### Suggested `use_pkce` by provider archetype

| Archetype (`examples/`) | Typical providers | `use_pkce` | Rationale |
| :--- | :--- | :--- | :--- |
| `keycloak.conf` | Keycloak (21+), and similar self-hosted IdPs you control | `true` | Device flow accepts `code_challenge`; you can verify on your own deployment. Set `false` if your Keycloak client has PKCE disabled. |
| `entra_id.conf` | Microsoft Entra ID / Azure AD | `false` (until proven) | Device-code reference does not document PKCE; run the live probe against your tenant first. |
| `cilogon.conf` | CILogon, Globus, ACCESS, other federations | `false` (until proven) | Discovery advertises S256 for the authorization-code flow only; run the live probe first. |

---

## Configuration Archetypes

Instead of maintaining separate files for dozens of individual vendors, this repository provides three core archetype templates representing the primary integration patterns encountered in production:

### 1. Self-Hosted / Internal IdP Pattern
* [keycloak.conf](keycloak.conf)
* **Target Environment:** On-premises or private cloud deployment (e.g., Keycloak, ZITADEL, Ory Hydra).
* **Key Traits:**
  * Uses internal realm or tenant path structures.
  * Demonstrates exact 1:1 local username matching (`preferred_username`).
  * Can be configured with a client secret or as a public client.

### 2. Cloud Enterprise / Public Client Pattern
* [entra_id.conf](entra_id.conf)
* **Target Environment:** Multi-tenant enterprise cloud providers (e.g., Microsoft Entra ID, Okta, Auth0).
* **Key Traits:**
  * Uses public client flows (empty `client_secret`).
  * Demonstrates domain-pinned regular expressions that extract the local POSIX handle only from user principal names (UPNs) or emails belonging to your own tenant (e.g., `jdoe@company.com` maps to `jdoe`; `jdoe@otherdomain.com` does not match).
  * Configures extended polling timeouts for enterprise MFA policies.

### 3. Academic & Research Federation Pattern
* [cilogon.conf](cilogon.conf)
* **Target Environment:** Federated research infrastructures, national labs, and universities (e.g., CILogon, ACCESS, Globus Auth).
* **Key Traits:**
  * Requests institutional claim scopes (e.g., `org.cilogon.userinfo`).
  * Extracts identity claims from institutional attributes (`eppn` / EduPersonPrincipalName).
  * Pins the institutional domain in the claim regex and applies case-insensitive comparison to the extracted local username.

---

## Quick Reference Summary

| Archetype File | Typical IdPs | Default Claim Field | Common Capture Group Regex |
| :--- | :--- | :--- | :--- |
| `keycloak.conf` | Keycloak, ZITADEL, Hydra | `preferred_username` | `^([a-zA-Z0-9._-]+)$` |
| `entra_id.conf` | Entra ID, Okta, Auth0 | `email` | `^([^@]+)@domain[.]com$` |
| `cilogon.conf` | CILogon, Globus, ACCESS | `eppn` or `email` | `^([^@]+)@institution[.]edu$` |
