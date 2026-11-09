# Account & Group Access Control (`[access]` Section)

The optional `[access]` section in `/etc/pam_oidc_device.conf` provides fine-grained restriction controls over:
1. **Which local POSIX accounts** are permitted to attempt login.
2. **Which provider groups or roles** are required to grant access.

These controls limit the blast radius of overly permissive claim regular expressions (`claim_regex`) and prevent unauthorized system access.

---

## Configuration Reference

```ini
[access]
# Local system user controls (Evaluated LOCALLY before contacting the IdP)
allow_users = alice, bob, charlie
deny_users = root, admin
allow_root = false

# Identity Provider group & role controls (Evaluated after UserInfo claim retrieval)
group_claim_field = groups
allow_groups = sysadmins, developers
deny_groups = contractors, temp-workers
enforce_groups = false
```

### Parameter Reference

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `allow_users` | string | `""` | Comma-separated list of local usernames permitted to authenticate. Empty allows all non-denied users. |
| `deny_users` | string | `""` | Comma-separated list of local usernames denied authentication. **Takes precedence over `allow_users`.** |
| `allow_root` | boolean | `false` | When `true`, permits the `root` account to authenticate. **Default denies `root` even if it is listed in `allow_users`.** |
| `allow_groups` | string | `""` | Comma-separated list of provider groups/roles granting access. A user matching any listed group is allowed. |
| `deny_groups` | string | `""` | Comma-separated list of provider groups/roles denying access. **Takes precedence over `allow_groups`.** |
| `enforce_groups` | boolean | `false` | When `true`, requires group/role evaluation even if group lists are empty (denying access if no groups match). |
| `group_claim_field` | string | `"groups"` | JSON key in the UserInfo response containing group or role claims (e.g. `groups`, `roles`, `wids`). |

---

## 1. Local Account Filtering (`allow_users` / `deny_users`)

Local account access checks are evaluated **before making any network requests** to the identity provider.

* **Denial Precedence:** If a local user is listed in `deny_users`, authentication is refused immediately with `PAM_PERM_DENIED` without making any HTTP requests.
* **Root Default-Deny:** The `root` account is refused with `PAM_PERM_DENIED` unless `allow_root = true` is explicitly set; this applies regardless of `allow_users`/`deny_users`.
* **Allow Enforcement:** If `allow_users` is set, any local account not explicitly listed is rejected before network contact.
* **Case Sensitivity:** Matching honors the `case_sensitive` setting configured under the `[claim]` section.

### Example Scenario

```ini
[claim]
case_sensitive = false

[access]
allow_users = alice, bob
deny_users = root
```

* User `alice` -> Allowed to proceed to OIDC polling.
* User `root` -> Immediately denied (`PAM_PERM_DENIED`), no HTTP network traffic generated.
* User `eve` -> Denied (not listed in `allow_users`).

---

## 2. Group & Role Authorization (`allow_groups` / `deny_groups`)

Group authorization checks are evaluated after an access token is successfully acquired and the provider UserInfo endpoint payload is retrieved.

### Supported Group Claim Formats

The module automatically handles various JSON claim structures under `group_claim_field`:

#### 1. JSON Array of Strings (Standard OIDC)
```json
{
  "sub": "jdoe",
  "groups": ["users", "sysadmins", "developers"]
}
```

#### 2. Single JSON String
```json
{
  "sub": "jdoe",
  "roles": "sysadmins"
}
```

#### 3. Comma-Separated JSON String
```json
{
  "sub": "jdoe",
  "roles": "sysadmins, developers, users"
}
```

---

## Evaluation Precedence & Rules

1. **Bypass:** If no group lists are configured and `enforce_groups = false`, group authorization is bypassed.
2. **Deny List Precedence:** If any user group matches an entry in `deny_groups`, authentication fails immediately with `PAM_PERM_DENIED`.
3. **Allow List Validation:** If `allow_groups` is configured, at least one user group must match an allowed group entry.
4. **Enforce Groups Guard:** If `enforce_groups = true` but no group lists are defined, authentication fails.

---

## Complete Example

```ini
[oauth]
client_id = 00000000-0000-0000-0000-000000000000
device_authorization_endpoint = https://auth.example.com/device
token_endpoint = https://auth.example.com/token
userinfo_endpoint = https://auth.example.com/userinfo

[claim]
claim_field = preferred_username
claim_regex = ^([^@]+)@example\.com$
claim_capture_group = 1

[access]
# Local User Safety Rails
deny_users = root, bin, daemon
allow_users = alice, bob, charlie

# IdP Group Rules
group_claim_field = groups
allow_groups = Linux-Admins, Infrastructure-Team
deny_groups = Terminated-Employees, External-Contractors
```