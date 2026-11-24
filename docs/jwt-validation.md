# Local JWT Claim Inspection (`verify_jwt_claims`)

Local JWT claim inspection is an optional defense-in-depth security feature configured in the `[oauth]` section of `/etc/pam_oidc_device.conf`. 

When enabled (`verify_jwt_claims = true`), the module parses Base64URL-encoded access token payloads locally to validate expiration (`exp`), not-before (`nbf`), issuer (`iss`), and audience (`aud`) claims *before* querying downstream endpoints.

## Table of Contents

* [Important Security Clarification](#important-security-clarification)
* [Configuration Reference](#configuration-reference)
* [Key Benefits of Pre-Flight Inspection](#key-benefits-of-pre-flight-inspection)
* [Provider Setup Guidance](#provider-setup-guidance)
* [NumericDate Handling (RFC 7519)](#numericdate-handling-rfc-7519)
* [Troubleshooting Claim Mismatches](#troubleshooting-claim-mismatches)

---

## Important Security Clarification

> [!WARNING]
> **Claims-only pre-flight inspection — NOT cryptographic signature verification.**
> `verify_jwt_claims` decodes the token payload locally to catch tenant mismatches, audience errors, and expired tokens fast. It does **NOT** verify the cryptographic signature of the token. Full cryptographic signature enforcement is performed downstream when the Bearer token is presented to the provider's UserInfo endpoint.

> [!NOTE]
> **Target token: the access token only.**
> In the PAM flow, `verify_jwt_claims` is invoked only on the **access token** returned from the token endpoint; the **`id_token` is not inspected**. The function is token-type-agnostic in capability, but the device-flow PAM pipeline passes only the access token. The `id_token` is intentionally out of scope because (1) its `aud` semantics differ — an `id_token` audience is the *client* application, whereas the configured `audience` matches the resource/userinfo audience of the access token; (2) some providers omit the `id_token` in the device flow; and (3) signature enforcement for authentication occurs at the provider's UserInfo endpoint, which is driven by the access token.

> [!IMPORTANT]
> **No JWKS / `jwks_url` signature-verification path exists — and the severity escalates if you consume ID-token claims directly.**
> Because this inspection is claims-only, the module holds **no JWKS signature-verification path**: `jwks_url` (and `introspection_endpoint`) are parsed and HTTPS-validated but **unused** — a load-time notice is emitted. Token authenticity and validity are enforced **entirely** by the provider's UserInfo endpoint over enforced TLS; there is no other authority for the returned token.
> If a deployment ever switches from that fresh UserInfo call to consuming the ID token's claims directly (offline trust — skipping UserInfo, or trusting the ID token's embedded claims without a live exchange), this becomes **High severity** (a forged/tampered ID token with acceptable `iss`/`aud`/`sub`/`exp` could authenticate) and a **JWKS / RFC 7517 signature-verification path** would be required before any token claims could be trusted locally. The module does not implement that path today.

---

## Configuration Reference

Add these options under the `[oauth]` section of `/etc/pam_oidc_device.conf`:

```ini
[oauth]
# Enable local Base64URL payload decoding and claim inspection
verify_jwt_claims = true

# Tenant Pinning: Expected token issuer ('iss')
issuer = https://sts.windows.net/00000000-0000-0000-0000-000000000000/

# Audience Check: Expected audience client ID or URI ('aud')
audience = 00000003-0000-0000-c000-000000000000

# Allowed clock skew leeway in seconds (Default: 60)
clock_skew_leeway = 60

# Require presence of 'exp' claim (Default: false)
require_exp_claim = false
```

### Option Parameters

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `verify_jwt_claims` | boolean | `false` | Enables local pre-flight claims parsing (`exp`, `nbf`, `iss`, `aud`). **Requires both `issuer` and `audience` to be configured** (rejected at load time otherwise). |
| `issuer` | string | `""` | Expected issuer string (`iss`). If set, incoming tokens must match exactly. |
| `audience` | string | `""` | Expected audience string or comma-separated list (`aud`). A value containing a comma is matched as one literal audience first (comma-bearing URNs, e.g. CILogon's `cilogon:oa4mp,2012:/client_id/<client-id>`). |
| `clock_skew_leeway` | integer | `60` | Time window leeway (in seconds) permitted during `exp` and `nbf` timestamp validation. |
| `require_exp_claim` | boolean | `false` | When `true`, tokens missing an `exp` claim are rejected immediately. |

> [!IMPORTANT]
> **`issuer` and `audience` are required together with `verify_jwt_claims = true`.**
> With claims-only inspection (no local signature verification), the `iss`/`aud`
> binding is the core defense against tokens minted for a different tenant or
> client. A missing expectation would silently skip the check, so the module
> rejects the configuration at load time and fails closed if the combination
> ever reaches the token check. A token whose `iss` or `aud` claim does not
> match the configured expectation fails the authentication attempt.

---

## Key Benefits of Pre-Flight Inspection

1. **Tenant Pinning (`iss` check):** Ensures logins are restricted strictly to your organization's specific OIDC tenant ID, preventing users from presenting valid tokens issued by foreign or personal tenants.
2. **Audience Restriction (`aud` check):** Confirms the presented token was explicitly minted for your target resource or application audience.
3. **Subject Consistency (`sub` cross-check):** When local inspection is enabled and the access token carries a `sub` claim, it must match the `sub` returned by the provider's UserInfo endpoint — a token-substitution defense on multi-audience IdPs. A missing `sub` on either side is skipped (logged); a present-but-mismatched or malformed `sub` fails the authentication attempt.
4. **Fail-Fast Efficiency:** Immediately rejects expired (`exp`) or premature (`nbf`) tokens locally, eliminating unnecessary TLS socket connections and UserInfo network round-trips.

---

## Provider Setup Guidance

### Microsoft Entra ID (Azure AD)

Entra ID access tokens for Microsoft Graph (`https://graph.microsoft.com/oidc/userinfo`) utilize specific tenant issuer URLs and Graph App ID GUID audiences:

```ini
[oauth]
verify_jwt_claims = true
issuer = https://sts.windows.net/<YOUR-TENANT-ID>/
audience = 00000003-0000-0000-c000-000000000000
clock_skew_leeway = 60
```

> [!TIP]
> You can specify multiple acceptable audiences using a comma-separated list:
> `audience = 00000003-0000-0000-c000-000000000000, https://graph.microsoft.com, <YOUR-CLIENT-ID>`

> [!NOTE]
> The comma acts as the list separator **only when the whole configured value
> does not match the token's `aud` claim exactly**. Audience URNs that
> themselves contain a comma — most notably CILogon's OA4MP identifier
> (`cilogon:oa4mp,2012:/client_id/<client-id-md5>`) — are therefore simply
> configured as a single value: `audience = cilogon:oa4mp,2012:/client_id/<client-id-md5>`.

### Standard OIDC Providers (Okta, Keycloak, Auth0)

```ini
[oauth]
verify_jwt_claims = true
issuer = https://auth.example.com/oauth2/default
audience = https://api.example.com
clock_skew_leeway = 30
```

---

## NumericDate Handling (RFC 7519)

Per RFC 7519 §2, `exp` and `nbf` claims are **NumericDate** values (seconds since UNIX epoch) and may be formatted as either integers or floating-point numbers:

* Both integer timestamps (e.g., `1735689600`) and double/fractional timestamps (e.g., `1735689600.5`) are fully supported and evaluated.
* Non-numeric types (e.g., string timestamps) are rejected as malformed claims.

---

## Troubleshooting Claim Mismatches

If local JWT validation fails:

1. Enable debug-level logging by setting `loglevel = debug` (or `verbose`) in `/etc/pam_oidc_device.conf`.
2. Inspect syslog output:
   ```bash
   sudo journalctl -f -u sshd | grep pam_oidc_device
   ```
   At `debug` (or `verbose`), the token's `iss`, `aud`, `exp`, and `nbf` claims (when present) are
   recorded as `JWT claim '<name>': <value>` lines before any check runs — use them to
   copy the correct `issuer`/`audience` values into your configuration.
3. Common mismatch log messages and fixes:
   * **`verify_jwt_claims = true requires both issuer and audience to be configured`** — Add both `issuer` and `audience` to the `[oauth]` section, or disable `verify_jwt_claims`.
   * **`JWT issuer (iss) check required but no issuer is configured`** / **`JWT audience (aud) check required but no audience is configured`** — Same fix as above (normally caught at load time).
   * **`Token issuer mismatch (expected: '...', received value length: N)`** — The log shows the expected value and only the length of what the token carried. At `debug` or `verbose`, the `JWT claim 'iss'` line above carries the actual received value — copy it into your `issuer` setting.
   * **`Token audience mismatch (expected: '...', received value length: N)`** — Same: at `debug` or `verbose`, the `JWT claim 'aud'` line carries the actual received audience (a string or a JSON array); copy the matching entry into your `audience` setting. N is the received value's length — for a string audience, the length of that exact value; for a JSON array audience, the length of its compact JSON representation.
   * **`JWT subject does not match UserInfo subject ... (token substitution suspected)`** — The access token's `sub` claim differs from the `sub` the provider's UserInfo endpoint returned for the same Bearer token. If this is unexpected, contact your identity provider administrator; do not disable the check to work around it.
   * **`Invalid token structure: missing header/payload delimiter`** — The IdP returned an opaque access token instead of a 3-part JWT. Set `verify_jwt_claims = false`.