# Getting Started: Deploying `pam_oidc_device`

The end-to-end walkthrough from a fresh host to a first successful
device-flow login: prerequisites, installation, configuration, OpenSSH
setup, PAM stack integration (including `authselect` on Enterprise Linux),
and logging. This guide focuses on OpenSSH, the module's primary use case;
§5 ends with notes on deploying the module with other PAM-managed services
(`sudo`, `su`, console logins, PAM-aware daemons).

> [!TIP]
> If you are still choosing provider values (endpoints, `client_id`, claim
> mapping), start with the [Identity Provider Examples &
> Discovery](../examples/README.md) guide — it covers OIDC discovery
> mapping, per-provider PKCE support, and three complete configuration
> templates (Keycloak, Microsoft Entra ID, CILogon).

## Table of Contents

* [1. Prerequisites](#1-prerequisites)
* [2. Install the Module](#2-install-the-module)
* [3. Configure `/etc/pam_oidc_device.conf`](#3-configure-etcpam_oidc_deviceconf)
* [4. OpenSSH Server Setup (`/etc/ssh/sshd_config`)](#4-openssh-server-setup-etcsshsshd_config)
* [5. PAM Stack Integration (`/etc/pam.d/sshd`)](#5-pam-stack-integration-etcpamdsshd)
* [6. Enterprise Linux & `authselect`](#6-enterprise-linux--authselect)
* [7. Logging & Auditing](#7-logging--auditing)
* [What's Next](#whats-next)

---

## 1. Prerequisites

* A supported Linux distribution: Enterprise Linux 8 / 9 / 10 (RHEL, Rocky
  Linux, AlmaLinux), SUSE (openSUSE Leap / SLES), Debian 13, or Ubuntu 26.04
  LTS.
* An OpenID Connect (OIDC) identity provider with the
  [OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)
  enabled for a registered OAuth client.
* `root` (or `sudo`) on the host you want to protect.
* The logins you want to protect are served by OpenSSH (`sshd`) — the
  primary focus of this guide. The module also works with other PAM-aware
  services that present the user with an interactive terminal (see §5).

---

## 2. Install the Module

Prefer a distribution package — build one with `make rpm` (EL / SUSE) or
`make deb` (Debian / Ubuntu); full instructions in
[Building RPM & DEB Packages](packaging.md). To build straight from source:

On Enterprise Linux 8 / 9 / 10 (RHEL, Rocky Linux, AlmaLinux):

```bash
# Install dependencies
sudo dnf install -y gcc pam-devel libcurl-devel libcmocka-devel json-c-devel openssl-devel make

# Clone and compile
git clone https://github.com/ncsa/pam_oidc_device.git
cd pam_oidc_device
make
sudo make install
```

On SUSE (openSUSE Leap / SLES):

```bash
sudo zypper install -y gcc make pam-devel libcurl-devel libjson-c-devel libopenssl-devel libcmocka-devel
make
sudo make install
```

On Debian 13 / Ubuntu 26.04 LTS:

```bash
sudo apt-get install -y build-essential libpam0g-dev libcurl4-openssl-dev libjson-c-dev libcmocka-dev libssl-dev
make
sudo make install PAM_DIR="/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)/security"
```

---

## 3. Configure `/etc/pam_oidc_device.conf`

Create or edit `/etc/pam_oidc_device.conf`. Start from the shipped sample or
from one of the [provider templates](../examples/README.md). The module
**fails closed** unless the file is a regular file owned by `root:root` with
mode `0600` (or `0640` with group `root`) — a mis-permissioned file blocks
logins rather than running with relaxed checks:

```bash
sudo cp config/pam_oidc_device.conf /etc/pam_oidc_device.conf
sudo chown root:root /etc/pam_oidc_device.conf
sudo chmod 0600 /etc/pam_oidc_device.conf
```

A minimal working configuration:

```ini
[oauth]
client_id = your-oauth-client-id
# client_secret = your-oauth-client-secret   # only for confidential clients (leave unset for public clients)
device_authorization_endpoint = https://auth.example.com/oauth2/v2.0/devicecode
token_endpoint = https://auth.example.com/oauth2/v2.0/token
userinfo_endpoint = https://auth.example.com/oauth2/v2.0/userinfo
scopes = openid profile email

[claim]
# Map UserInfo field 'preferred_username' (e.g., 'jdoe') to local system user 'jdoe'.
# claim_regex is REQUIRED (there is no default): config loading fails without it.
# 'preferred_username' is normally a bare local username, so anchor a username charset:
claim_field = preferred_username
claim_regex = ^([a-zA-Z0-9._-]+)$
# If your chosen claim is a domain-pinned e-mail (e.g., 'jdoe@example.com'), pin your
# domain instead:  claim_regex = ^([^@]+)@example\.com$
claim_capture_group = 1
case_sensitive = false

[runtime]
loglevel = info
max_poll_seconds = 120

[prompt]
# Optional custom prompt template (printable ASCII; use \n for newlines).
# Leave init_message unset to use the built-in default, which renders (the
# leading blank line separates the prompt from the terminal banner that shares
# its first line; it is omitted when [qr] enabled = true, where the QR block's
# quiet zone provides the separation):
#
#   Sign in via browser:
#     https://auth.example.com/oauth2/device/code?user_code=XXXX-XXXX
#
#   Manual entry: https://auth.example.com/oauth2/device/code  |  Code: XXXX-XXXX
#   Waiting for approval (expires in 2m; auto-completes on sign-in).
# (the compact URL + code block is shown when the IdP does not provide a
# direct-link URL). Placeholders: {url} (verification URL),
# {url_complete} (direct-link URL with the code embedded, if the IdP provides
# one), {code} (user code),
# {expiry} (how long the user has to complete the approval, in compact units
# such as "15m"; the provider's expires_in clamped by max_poll_seconds; expands
# to an empty string when the provider does not advertise expires_in).
# The prompt deliberately names no host: in a device-code phishing attack the
# prompt reaches the user who ran ssh (the attacker), while the approving user
# only sees the IdP's approval page — machine context belongs in the registered
# OAuth client name shown on that approval page (docs/threat-model.md §8).
# init_message = Sign in at {url} with code {code}
# Show the device-code approval window in the prompt (default: true). With the built-in
# default template it is named in the trailing status line ("Waiting for
# approval (expires in 15m; auto-completes on sign-in)."); in custom
# templates use the {expiry} token, which works regardless of this key. Set to false to
# hide the approval window.
# show_expiry = false

[qr]
# Optional: render the sign-in URL as a scannable QR code on TTY logins (phone-camera friendly).
# When disabled or rendering fails, the plain text prompt is still displayed.
enabled = false
style = utf8        # or ascii for minimal/legacy fonts (pair with: block_char = #)
# scale = 1         # 1-3 module enlargement
# vertical_quiet_zone = 4  # 0-4 blank module rows above/below (ISO minimum 4; lower = more compact)
# ec_level = M      # L/M/Q/H error correction level
# uri = complete    # or plain (encode verification_uri_complete vs. verification_uri)
```

Sections and where their full option references live:

| Section | Purpose | Full reference |
| --- | --- | --- |
| `[oauth]` | Endpoints, client credentials, scopes, PKCE (`use_pkce`), outbound HTTPS proxy (`proxy`), local JWT claim inspection (`verify_jwt_claims`, `issuer`, `audience`) | [the local JWT claim inspection reference](jwt-validation.md) |
| `[claim]` | Which provider claim maps to the local POSIX username | [the access-control guide's claim-mapping section](access-control.md) |
| `[access]` | Local user allow/deny + provider group/role allow/deny | [the access-control guide's user and group lists](access-control.md) |
| `[runtime]` | `loglevel`, `max_poll_seconds` | [Logging & Auditing](#7-logging--auditing) |
| `[prompt]` / `[qr]` | Terminal prompt template and QR rendering | sample config (above) |

> [!IMPORTANT]
> **Pin the claim regex to your own domain.** `claim_regex` decides which
> identity may become which local account — a loose pattern is the most
> common way an identity from a foreign tenant or personal account maps onto
> a local user. There is no default: the key is required, and config loading
> fails closed if it is missing. All three templates in `examples/` pin a
> specific domain in the regex for this reason.

---

## 4. OpenSSH Server Setup (`/etc/ssh/sshd_config`)

For PAM interactive authentication to present verification prompts to SSH
clients, OpenSSH must be configured to allow keyboard-interactive challenges.

### Required Directives

Edit `/etc/ssh/sshd_config` (or a drop-in file under `/etc/ssh/sshd_config.d/`):

```sshd_config
# Enable PAM integration
UsePAM yes

# Enable keyboard-interactive prompting for user-code display
KbdInteractiveAuthentication yes

# Enforce keyboard-interactive authentication method
AuthenticationMethods keyboard-interactive
```

> [!IMPORTANT]
> **Why `KbdInteractiveAuthentication`?**
> Standard non-interactive SSH authentication methods suppress standard PAM informational text messages. `KbdInteractiveAuthentication yes` enables real-time message flushing via `pam_prompt()`, allowing `pam_oidc_device` to stream the verification URL and user code directly to the user's terminal.

> [!NOTE]
> **Accessible by default.** The prompt is always plain, selectable text — the
> URL and user code never appear only in the (opt-in, off by default) QR art —
> and carries no color-only cues, keeping it screen-reader and low-vision
> friendly; `[qr] style = ascii` renders the optional QR in plain ASCII for
> minimal fonts. The interaction is entirely keyboard-driven: **Enter** begins
> waiting for your approval, **Ctrl-C** aborts the attempt (`PAM_ABORT`, login
> denied). The user-code lifetime is set by your identity provider — see the
> Note below, idle time at the confirmation prompt counts against it. See also
> [Accessibility guide](accessibility.md).

Apply configuration changes:

```bash
sudo sshd -t && sudo systemctl reload sshd
```

> [!NOTE]
> **The device code clock starts before you press Enter.** The provider's `expires_in`
> countdown begins the moment the module requests the device code — *before* you press
> Enter at the "Press [Enter] to begin..." confirmation prompt. Token-endpoint polling
> does **not** start until you press Enter; the first poll then fires immediately (no
> leading delay), so approving on your second device is picked up the moment polling
> begins. The confirmation prompt exists to flush the sign-in prompt to your terminal —
> OpenSSH keyboard-interactive clients buffer `PAM_TEXT_INFO` messages, which are only
> delivered to the screen once the module prompts you for some input — the Enter
> round-trip is that trigger (and also gives you a moment to note the URL and code).
> The module's polling window is additionally capped at `max_poll_seconds` (`[runtime]`,
> default 120 s, floor 10 s). Time spent sitting idle at the confirmation prompt
> consumes the code's remaining lifetime; approve the code on your second device
> promptly after it is displayed.

### Protecting the Provider from Connection Bursts

Every SSH connection for a username the module's allow/deny rules permit
requests a fresh device code from the identity provider **before** the user
enters anything (the request is what carries the sign-in prompt). A source
that opens connections in rapid succession — an SSH scanner, a credential
brute-forcer, or a misbehaving client retry loop — can exhaust the
provider-side rate limit for your OAuth client and lock *legitimate* users
out of their sign-ins. The module's allow/deny lists are enforced before any
provider contact, and the connecting source *is* identifiable inside the module —
sshd sets `PAM_RHOST`, which a PAM module can read with `pam_get_item(PAM_RHOST)` —
but per-source throttling would still need state shared by the concurrent `sshd`
workers, so enforce it in the SSH layer:

```sshd_config
# OpenSSH >= 9.7: progressively penalize repeated pre-auth connections
# from the same source address
PerSourcePenalties yes

# Bound unauthenticated *concurrent* sessions: keep slots up to 5,
# probabilistically drop new connections above 30, hard stop at 100
MaxStartups 5:30:100

# Cap authentication rounds per connection (each round for an allowed
# username is one potential device-code request)
MaxAuthTries 3

# Idle pre-auth connection timeout; also bounds hung device flows
LoginGraceTime 120
```

Apply with `sudo sshd -t && sudo systemctl reload sshd`, then verify the
effective values: `sudo sshd -T | grep -Ei 'maxstartups|persourcepenalties|maxauthtries|logingracetime'`.
The device-code request is cheap and disposable (unused codes expire), so the
risk is rate-limit exhaustion, not user data — but keep `allow_users`
(and sshd's `AllowUsers`) as narrow as your access model allows: usernames
rejected by the pre-flight check never reach the provider. See
[Threat Model §9](threat-model.md#9-provider-rate-limit-exhaustion--operational-hardening)
for the full threat analysis.

---

## 5. PAM Stack Integration (`/etc/pam.d/sshd`)

> [!NOTE]
> `pam_oidc_device.so` operates exclusively under the PAM `auth` management directive. It does not implement `account`, `session`, or `password` management directives.

### Recommended Stack Order

Insert `pam_oidc_device.so` into `/etc/pam.d/sshd` following standard local credential checks or system user protection rules:

```pam
# /etc/pam.d/sshd
auth        required      pam_sepermit.so
auth        substack      password-auth

# Protection Guard: Prevent system accounts (UID < 1000) from reaching OIDC flow
auth        required      pam_succeed_if.so uid >= 1000 quiet

# OAuth 2.0 Device Flow PAM Module
auth        required      pam_oidc_device.so

auth        include       postlogin
```

### Fail-Secure Control Flag (`required` vs `sufficient`)

The control flag on the `pam_oidc_device.so` line decides what happens when the module fails
for **any** reason — a rejected user code, a claim/identity mismatch, a network or IdP error,
or a bad/missing `/etc/pam_oidc_device.conf` (the module returns a failure status without
completing the device flow in all of these cases).

> [!WARNING]
> **Use `required` (or `requisite`), not `sufficient`.**
>
> - With `required` / `requisite`, *any* module failure — including an invalid or missing
>   config file — **blocks login** (fail-closed).
> - With `sufficient`, a module failure does **not** block login: PAM simply continues to the
>   next module. If a later module (e.g., `pam_unix.so`) then succeeds, the user is
>   authenticated **without ever completing the OIDC device flow**. That silently downgrades
>   step-up authentication to your fallback method the moment the module errors — which is
>   almost never what you want on a security gate.
>
> `required` runs the remainder of the stack after a failure; use `requisite` to stop
> immediately. Choose `sufficient` only when the device flow is deliberately an *additional,
> optional* path that another authentication method may bypass.

### Safety Guard Recommendation (`pam_succeed_if.so`)

Placing `auth required pam_succeed_if.so uid >= 1000 quiet` immediately **before** `pam_oidc_device.so` guarantees that system accounts (`root`, `daemon`, `bin`) are filtered locally and never trigger an OIDC authentication prompt, even if a loose identity claim regex is configured.

### Other PAM Services (Beyond SSH)

The deployment in this section targets `/etc/pam.d/sshd`, but the module
is a standard PAM module: the same device-flow sign-in works with **any
PAM-managed service that presents the user with an interactive terminal**.
Common candidates:

* **`sudo` / `su`** — add an `auth required pam_oidc_device.so` line to
  `/etc/pam.d/sudo` or `/etc/pam.d/su` for device-flow step-up before
  privilege escalation.
* **Local console and display-manager logins** — `login`/`getty`
  (`/etc/pam.d/login`) and display managers (GDM, SDDM), where the
  optional terminal QR code makes phone approval especially quick.
* **PAM-aware daemons** — services that gate their operations through
  PAM (LXD, Proxmox VE, and similar).

Caveats that apply to every non-SSH deployment:

1. **An interactive terminal is required.** The user must read the URL and
   code and press Enter, so services without an interactive user (cron
   jobs, `sudo -n`, non-interactive PAM policy checks) cannot complete
   the flow.
2. **Fail-closed control flags everywhere.** Use `required` or
   `requisite` in every stack you add the module to — never `sufficient`
   (see the warning above).
3. **Shared-stack scope on Enterprise Linux.** Integrating via the shared
   `system-auth`/`password-auth` stacks applies the device flow to
   **every** service that includes them — scope it to one service's own
   `/etc/pam.d/<service>` file when you want that (Option A in §6).
4. **`authselect` persistence.** `authselect` manages only the shared
   stack files — never a service-specific file like `/etc/pam.d/sudo` —
   so a direct edit to a service file survives profile re-applications,
   the same way Option A does for SSH.

---

## 6. Enterprise Linux & `authselect`

On modern Enterprise Linux distributions (RHEL 8/9/10, Rocky Linux, AlmaLinux, Fedora), system PAM stack configuration is managed dynamically by `authselect`.

> [!WARNING]
> Direct manual edits to the shared stack files (e.g., `/etc/pam.d/system-auth`) are
> regenerated when `authselect apply-changes` is executed; `/etc/pam.d/sshd` is not
> managed by `authselect`, but distribution updates can reconfigure it.

### Preserving Configuration with `authselect`

To permanently integrate `pam_oidc_device.so`:

1. **Option A (Recommended):** Append the module directive directly to `/etc/pam.d/sshd`. `authselect` manages only the shared stack files (`system-auth`, `password-auth`, …) plus `nsswitch.conf`/`dconf` — it never rewrites `/etc/pam.d/sshd`, so the appended directive survives `authselect apply-changes` and profile switches. The only way it can be lost is a manual or distribution-driven replacement of the `sshd` file itself.
2. **Option B (Custom Profile):** `authselect` manages only the **shared stack
   files** (`system-auth`, `password-auth`, `fingerprint-auth`,
   `smartcard-auth`, `postlogin`) plus `nsswitch.conf`/`dconf` — it does
   **not** manage `/etc/pam.d/sshd`, and `authselect apply-changes` will never
   overwrite it. So Option A already persists unless `/etc/pam.d/sshd` is
   manually replaced. A profile-based integration must instead target the
   shared stack that `sshd` pulls in (the RHEL-family `sshd` stack ends with
   `auth include password-auth`):
   ```bash
   # Find the currently active profile, then derive a custom profile from it:
   authselect select --print-id
   sudo authselect create-profile oidc-auth --base-on=<current-profile>
   ```
   Add the module to the auth section of
   `/etc/authselect/custom/oidc-auth/password-auth` (after `pam_unix.so` /
   `pam_faillock.so`, before any `sufficient` entries), then apply:
   ```bash
   sudo authselect select custom/oidc-auth
   ```
   > [!WARNING]
   > A module placed in a shared stack applies to **every** service that
   > includes that stack (`system-auth`, `password-auth`) — typically `sshd`,
   > `su`, and the display manager. If you want the device flow scoped to SSH
   > logins only, use Option A.

---

## 7. Logging & Auditing

`pam_oidc_device.so` emits standard syslog messages under the `LOG_AUTHPRIV` facility (typically `/var/log/secure` or the systemd journal).

### Verbosity Levels (`loglevel`)

Log levels can be configured in `/etc/pam_oidc_device.conf` under `[runtime]` or overridden directly on the PAM directive line in `/etc/pam.d/sshd`.

| Level String | Numeric | Description |
| --- | --- | --- |
| `none` | `0` | Disables all module syslog output. |
| `error` | `1` | Logs operational failures, invalid configurations, and network errors. |
| `info` | `2` | **Default.** Logs high-level auth success/failure lifecycle events. |
| `debug` | `3` | Logs internal workflow steps, regex claim matches, and deadline clocks. |
| `verbose` | `4` | Maximum tracing. Includes full HTTP transport methods, URLs, payload sizes, and header status. |

### Polling Timeout (`max_poll_seconds`)

`max_poll_seconds` (in `[runtime]`) caps the module's token-polling window:
default `120` seconds, accepted range `10`–`3600`. The provider's own
`expires_in` may clamp the window shorter. When the cap (or the provider
timeout) is reached without a token, authentication fails with
`PAM_AUTH_ERR`. Because the device code clock starts **before** the Enter
confirmation prompt (see the Note in §4), approve the code on your second
device promptly after it is displayed.

### User-Visible Failure Notices

In addition to syslog, a failed sign-in attempt shows a plain-text, actionable
notice in the login terminal (delivered through the PAM conversation). During
the token-polling phase the notice matches the outcome: the sign-in code
expired before approval, the sign-in request was not approved (declined), or
the identity provider service is unavailable (network failure, unexpected or
malformed response); a later claim or group-policy check failing shows the
account-denied notice. User-initiated cancellation (Ctrl-C) shows no notice.
The wording is intentionally generic —
which specific control rejected the attempt remains in the syslog entries
above. Delivery is best-effort: local console logins always display the
notice; some SSH clients buffer informational messages until the next prompt
round-trip, so the notice may not appear on every client.

### PAM Directive Override Example

Configuration settings specified directly on the PAM module command line take precedence over configuration file defaults:

```pam
auth required pam_oidc_device.so config=/etc/pam_oidc_device.conf loglevel=debug
```

### Real-Time Log Monitoring

Monitor authentication attempts in real time:

```bash
sudo journalctl -f -u sshd | grep pam_oidc_device
```

---

## What's Next

* **Verify it before relying on it** — the
  [Testing & Pre-Production Audit Guide](testing.md) covers the one-command
  e2e sandbox, `pamtester` manual tests, a real-IdP trial, and the
  pre-production audit/rollback checklist.
* **Restrict who can log in** — read the
  [Account & Group Access Control guide](access-control.md).
* **Harden token acceptance** — read the
  [Local JWT Claim Inspection guide](jwt-validation.md).
* **Understand the security model** —
  [Threat Model & Security Architecture](threat-model.md).


