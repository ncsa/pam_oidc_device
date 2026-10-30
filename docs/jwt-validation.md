# Local JWT Claim Inspection (`verify_jwt_claims`)

Local JWT claim inspection is an optional defense-in-depth security feature configured in the `[oauth]` section of `/etc/pam_oidc_device.conf`. 

When enabled (`verify_jwt_claims = true`), the module parses Base64URL-encoded access token payloads locally to validate expiration (`exp`), not-before (`nbf`), issuer (`iss`), and audience (`aud`) claims *before* querying downstream endpoints.

---

## Important Security Clarification

> [!WARNING]
> **Claims-only pre-flight inspection — NOT cryptographic signature verification.**
> `verify_jwt_claims` decodes the token payload locally to catch tenant mismatches, audience errors, and expired tokens fast. It does **NOT** verify the cryptographic signature of the token. Full cryptographic signature enforcement is performed downstream when the Bearer token is presented to the provider's UserInfo endpoint.

> [!NOTE]
> **Target token: the access token only.**
> In the PAM flow, `verify_jwt_claims` is invoked only on the **access token** returned from the token endpoint; the **`id_token` is not inspected**. The function is token-type-agnostic in capability, but the device-flow PAM pipeline passes only the access token. The `id_token` is intentionally out of scope because (1) its `aud` semantics differ — an `id_token` audience is the *client* application, whereas the configured `audience` matches the resource/userinfo audience of the access token; (2) some providers omit the `id_token` in the device flow; and (3) signature enforcement for authentication occurs at the provider's UserInfo endpoint, which is driven by the access token.

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
| `verify_jwt_claims` | boolean | `false` | Enables local pre-flight claims parsing (`exp`, `nbf`, `iss`, `aud`). |
| `issuer` | string | `""` | Expected issuer string (`iss`). If set, incoming tokens must match exactly. |
| `audience` | string | `""` | Expected audience string or comma-separated list (`aud`). |
| `clock_skew_leeway` | integer | `60` | Time window leeway (in seconds) permitted during `exp` and `nbf` timestamp validation. |
| `require_exp_claim` | boolean | `false` | When `true`, tokens missing an `exp` claim are rejected immediately. |

---

## Key Benefits of Pre-Flight Inspection

1. **Tenant Pinning (`iss` check):** Ensures logins are restricted strictly to your organization's specific OIDC tenant ID, preventing users from presenting valid tokens issued by foreign or personal tenants.
2. **Audience Restriction (`aud` check):** Confirms the presented token was explicitly minted for your target resource or application audience.
3. **Fail-Fast Efficiency:** Immediately rejects expired (`exp`) or premature (`nbf`) tokens locally, eliminating unnecessary TLS socket connections and UserInfo network round-trips.

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

1. Enable debug logging by setting `loglevel = debug` in `/etc/pam_oidc_device.conf`.
2. Inspect syslog output:
   ```bash
   sudo journalctl -f -u sshd | grep pam_oidc_device
   ```
3. Common mismatch log messages and fixes:
   * **`Token issuer mismatch (expected: '...', received: '...')`** — Copy the `received:` value into your `issuer` setting.
   * **`Token audience mismatch (expected: '...', received: '...')`** — Copy the `received:` value into your `audience` setting.
   * **`Invalid token structure: missing header/payload delimiter`** — The IdP returned an opaque access token instead of a 3-part JWT. Set `verify_jwt_claims = false`.