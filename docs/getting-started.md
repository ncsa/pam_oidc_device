# Getting Started: Deploying `pam_oidc_device`

The end-to-end walkthrough from a fresh host to a first successful
device-flow login: prerequisites, installation, configuration, OpenSSH
setup, PAM stack integration (including `authselect` on Enterprise Linux),
and logging.

> [!TIP]
> If you are still choosing provider values (endpoints, `client_id`, claim
> mapping), start with the [Identity Provider Examples &
> Discovery](../examples/README.md) guide — it covers OIDC discovery
> mapping, per-provider PKCE support, and three complete configuration
> templates (Keycloak, Microsoft Entra ID, CILogon).

---

## 1. Prerequisites

* A supported Linux distribution: Enterprise Linux 8 / 9 / 10 (RHEL, Rocky
  Linux, AlmaLinux), SUSE (openSUSE Leap / SLES), Debian 13, or Ubuntu 26.04
  LTS.
* An OpenID Connect (OIDC) identity provider with the
  [OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)
  enabled for a registered OAuth client.
* `root` (or `sudo`) on the host you want to protect.
* The logins you want to protect are served by OpenSSH (`sshd`).

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
device_authorization_endpoint = https://auth.example.com/oauth2/v2.0/devicecode
token_endpoint = https://auth.example.com/oauth2/v2.0/token
userinfo_endpoint = https://auth.example.com/oauth2/v2.0/userinfo
scopes = openid profile email

[claim]
# Map UserInfo field 'preferred_username' (e.g., 'jdoe@example.com') to local system user 'jdoe'
claim_field = preferred_username
claim_regex = ^([^@]+)@example\.com$
claim_capture_group = 1
case_sensitive = false

[runtime]
loglevel = info
max_poll_seconds = 300

[prompt]
# Optional custom prompt template (printable ASCII; use \n for newlines).
# init_message = Sign in at {verification_uri} with code {user_code}

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
| `[oauth]` | Endpoints, client credentials, scopes, PKCE (`use_pkce`), local JWT claim inspection (`verify_jwt_claims`, `issuer`, `audience`) | [Local JWT Claim Inspection](jwt-validation.md) |
| `[claim]` | Which provider claim maps to the local POSIX username | [Account & Group Access Control](access-control.md) |
| `[access]` | Local user allow/deny + provider group/role allow/deny | [Account & Group Access Control](access-control.md) |
| `[runtime]` | `loglevel`, `max_poll_seconds` | [Logging & Auditing](#7-logging--auditing) |
| `[prompt]` / `[qr]` | Terminal prompt template and QR rendering | sample config (above) |

> [!IMPORTANT]
> **Pin the claim regex to your own domain.** `claim_regex` decides which
> identity may become which local account — a loose pattern is the most
> common way an identity from a foreign tenant or personal account maps onto
> a local user. All three templates in `examples/` pin a specific domain in
> the regex for this reason.

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

Apply configuration changes:

```bash
sudo sshd -t && sudo systemctl reload sshd
```

> [!NOTE]
> **The device code clock starts before you press Enter.** The provider's `expires_in`
> countdown begins the moment the module requests the device code — *before* you press
> ENTER at the continuation prompt. The module's polling window is additionally capped at
> `max_poll_seconds` (`[runtime]`, default 300 s, floor 10 s). Time spent sitting idle at
> the "Press ENTER to continue" prompt consumes the code's remaining lifetime; approve the
> code on your second device promptly after it is displayed.

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
>   next module. If a later module (e.g. `pam_unix.so`) then succeeds, the user is
>   authenticated **without ever completing the OIDC device flow**. That silently downgrades
>   step-up/MFA authentication to your fallback method the moment the module errors — which is
>   almost never what you want on a security gate.
>
> `required` runs the remainder of the stack after a failure; use `requisite` to stop
> immediately. Choose `sufficient` only when the device flow is deliberately an *additional,
> optional* path that another authentication method may bypass.

### Safety Guard Recommendation (`pam_succeed_if.so`)

Placing `auth required pam_succeed_if.so uid >= 1000 quiet` immediately **before** `pam_oidc_device.so` guarantees that system accounts (`root`, `daemon`, `bin`) are filtered locally and never trigger an OIDC authentication prompt, even if a loose identity claim regex is configured.

---

## 6. Enterprise Linux & `authselect`

On modern Enterprise Linux distributions (RHEL 8/9/10, Rocky Linux, AlmaLinux, Fedora), system PAM stack configuration is managed dynamically by `authselect`.

> [!WARNING]
> Direct manual edits to `/etc/pam.d/system-auth` or `/etc/pam.d/sshd` may be overwritten during system updates or when `authselect apply-changes` is executed.

### Preserving Configuration with `authselect`

To permanently integrate `pam_oidc_device.so`:

1. **Option A (Recommended):** Append the module directive directly to `/etc/pam.d/sshd`. `authselect` manages core profile files (`system-auth`, `password-auth`) but leaves custom `/etc/pam.d/sshd` additions intact unless a full profile re-application explicitly overwrites service files.
2. **Option B (Custom Profile):** Create a vendor custom authselect profile:
   ```bash
   sudo authselect create-profile oidc-sshd sssd --copy-settings-for=sshd
   ```
   Modify `/etc/authselect/custom/oidc-sshd/sshd` to include `pam_oidc_device.so`, then apply:
   ```bash
   sudo authselect select custom/oidc-sshd
   ```

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
* **Restrict who can log in** —
  [Account & Group Access Control](access-control.md).
* **Harden token acceptance** —
  [Local JWT Claim Inspection](jwt-validation.md).
* **Understand the security model** —
  [Threat Model & Security Architecture](threat-model.md).


