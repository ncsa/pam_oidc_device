# Account & Group Access Control (`[access]` Section)

The optional `[access]` section in `/etc/pam_oidc_device.conf` provides fine-grained restriction controls over:
1. **Which local POSIX accounts** are permitted to attempt login.
2. **Which provider groups or roles** are required to grant access.

These controls limit the blast radius of overly permissive claim regular expressions (`claim_regex`) and prevent unauthorized system access.

## Table of Contents

* [Configuration Reference](#configuration-reference)
* [1. Local Account Filtering (`allow_users` / `deny_users`)](#1-local-account-filtering-allow_users--deny_users)
* [2. Group & Role Authorization (`allow_groups` / `deny_groups`)](#2-group--role-authorization-allow_groups--deny_groups)
* [Complete Example](#complete-example)

---

## Configuration Reference

```ini
[access]
# Local system user controls (Evaluated LOCALLY before contacting the IdP)
allow_users = alice, bob, charlie
deny_users = root, admin
allow_root = false
deny_system_uids = true
system_uid_min = 0
system_uid_max = 999

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
| `allow_root` | boolean | `false` | When `true`, permits uid-0 accounts (the `root` account **and** any alternative uid-0 account name such as `toor`) to authenticate. **Default denies every uid-0 account even if it is listed in `allow_users`.** An entry for the account in `deny_users` still wins — denial lists are evaluated before the root opt-in. |
| `deny_system_uids` | boolean | `true` | When `true` (default), local accounts whose **numeric UID** falls within `[system_uid_min, system_uid_max]` are refused with `PAM_PERM_DENIED` before any provider contact. The guard targets **the UID, not the name**: any account holding an in-range UID is refused even if listed in `allow_users`. A uid-0 account explicitly permitted via `allow_root = true` is exempt. |
| `system_uid_min` | integer | `0` | Inclusive lower bound of the denied system-account UID range. |
| `system_uid_max` | integer | `999` | Inclusive upper bound of the denied system-account UID range (the conventional system-account range is 0-999). Must be >= `system_uid_min`; an inverted range is rejected when the config is loaded. |
| `allow_groups` | string | `""` | Comma-separated list of provider groups/roles granting access. A user matching any listed group is allowed. |
| `deny_groups` | string | `""` | Comma-separated list of provider groups/roles denying access. **Takes precedence over `allow_groups`.** |
| `enforce_groups` | boolean | `false` | When `true`, requires group/role evaluation even if group lists are empty (denying access if no groups match). |
| `group_claim_field` | string | `"groups"` | JSON key in the UserInfo response containing group or role claims (e.g., `groups`, `roles`, `wids`). |
| `group_claim_delimiter` | character | `","` | Single character used to split a **string-typed** `group_claim_field` value into individual group/role entries. JSON array claims are unaffected (each array element is one group). Set it to your IdP's separator when the claim is a single delimited string, e.g. `group_claim_delimiter = ;` for `"member_of": "grp-a;grp-b;grp-c"`. Must be exactly one printable ASCII character (whitespace and multi-character values are rejected). |

---

## 1. Local Account Filtering (`allow_users` / `deny_users`)

Local account access checks are evaluated **before making any network requests** to the identity provider.

* **Denial Precedence:** If a local user is listed in `deny_users`, authentication is refused immediately with `PAM_PERM_DENIED` without making any HTTP requests.
* **Root Default-Deny:** Every uid-0 account is refused with `PAM_PERM_DENIED` unless `allow_root = true` is explicitly set. The guard targets **uid 0, not the name `root`**: an alternative uid-0 account (e.g. `toor`) is refused identically. The check runs independently of `allow_users`, but `deny_users` is still evaluated first — so `allow_root = true` plus `deny_users = root` refuses `root`.
* **System-Account UID-Range Default-Deny:** When `deny_system_uids = true` (default), every local account whose **numeric UID** falls within `[system_uid_min, system_uid_max]` (default `0-999`, the conventional system-account range) is refused with `PAM_PERM_DENIED` before any HTTP request. Like the root gate, the guard targets **the UID, not the name**: a long-lived application or service account holding an in-range UID is refused even if listed in `allow_users`. Names that resolve to no local account cannot hold a UID and are not refused by this gate. An explicit `allow_root = true` exempts uid-0 accounts from this second gate only. To permit an in-range account, raise `system_uid_min` above its UID, lower `system_uid_max` below it, or set `deny_system_uids = false`.
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

* User `alice` is allowed to proceed to OIDC polling.
* User `root` is immediately denied (`PAM_PERM_DENIED`); no HTTP network traffic is generated.
* User `eve` is denied (not listed in `allow_users`).

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

#### 4. Delimited JSON String (Custom Separator)
Some IdPs emit the group list as a single string joined by a separator other than a comma (for example, Active Directory / SCIM-synced attributes such as `member_of`). Set `group_claim_delimiter` to that single separator character and each entry is matched individually against `allow_groups`/`deny_groups`:
```json
{
  "sub": "jdoe",
  "member_of": "urn:example:grp-a;urn:example:grp-b;urn:example:grp-c"
}
```
With `group_claim_field = member_of` and `group_claim_delimiter = ;`. Without the delimiter setting the whole string is treated as one (unmatchable) group name, so group lists never match.

---

### Evaluation Precedence & Rules

1. **Bypass:** If no group lists are configured and `enforce_groups = false`, group authorization is bypassed.
2. **Deny List Precedence:** If any user group matches an entry in `deny_groups`, authentication fails immediately with `PAM_PERM_DENIED`.
3. **Allow List Validation:** If `allow_groups` is configured, at least one user group must match an allowed group entry.
4. **Enforce Groups Guard:** If `enforce_groups = true` but no group lists are defined, authentication fails.
5. **Fail-Closed on Unusable Claims:** With any group policy active, authentication also fails when the provider UserInfo payload is missing or invalid, the configured claim field is absent or JSON `null`, the claim has an unrecognized type (neither an array of strings nor a string), or a deny list is configured and the claim contains content that cannot be fully parsed (e.g., a non-string array element). Membership that cannot be established is treated as a non-match, which denies under both allow-only and deny-only policies — a deny list cannot be bypassed by omitting the claim or by serializing it in an unparseable form.

### Troubleshooting

When `allow_groups`/`deny_groups` behavior looks wrong, set `loglevel = verbose` (see [Logging & Auditing](getting-started.md#7-logging--auditing)): the module dumps **every** claim returned by the UserInfo endpoint (claim name + compact JSON value) at the start of claim verification, and additionally records the raw content of the `group_claim_field` claim (e.g. `Group claim 'groups' content: ["users","developers"]`) immediately before the allow/deny evaluation, so the log shows exactly what the provider sent. At lower log levels only the payload size, claim field names, and the evaluation outcome are logged — claim values are never logged below `verbose`.

---

## Complete Example

```ini
[oauth]
client_id = 00000000-0000-0000-0000-000000000000
device_authorization_endpoint = https://auth.example.com/device
token_endpoint = https://auth.example.com/token
userinfo_endpoint = https://auth.example.com/userinfo

[claim]
# claim_regex is required (no default); match its shape to the claim you select.
# 'preferred_username' is normally a bare local username, so anchor a username charset:
claim_field = preferred_username
claim_regex = ^([a-zA-Z0-9._-]+)$
# If the selected claim is a domain-pinned e-mail instead, pin your domain:
#   claim_regex = ^([^@]+)@example\.com$
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