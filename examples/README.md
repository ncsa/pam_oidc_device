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
  * Demonstrates domain-pinned regular expressions that extract the local POSIX handle only from user principal names (UPNs) or emails belonging to your own tenant (e.g., `jdoe@company.com` $\rightarrow$ `jdoe`; `jdoe@otherdomain.com` does not match).
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
