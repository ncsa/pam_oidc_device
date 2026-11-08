# PAM OAuth 2.0 Device Authorization Grant Module (`pam_oidc_device`)

[![Build Verification](https://github.com/ncsa/pam_oidc_device/actions/workflows/build.yml/badge.svg)](https://github.com/ncsa/pam_oidc_device/actions/workflows/build.yml)
[![Lint & Static Analysis](https://github.com/ncsa/pam_oidc_device/actions/workflows/lint.yml/badge.svg)](https://github.com/ncsa/pam_oidc_device/actions/workflows/lint.yml)
[![License](https://img.shields.io/github/license/ncsa/pam_oidc_device?color=green)](LICENSE)

> [!WARNING]
> **Prerelease Notice**:
> This version is currently in **prerelease**. While the codebase has been reviewed and vetted, unexpected edge cases may still occur. Please use with caution in production environments.

`pam_oidc_device.so` is a lightweight, secure Linux [PAM authentication module](https://www.redhat.com/en/blog/pluggable-authentication-modules-pam) written in C. It enables out-of-band multi-factor authentication (MFA) and step-up login for SSH sessions using the standard [OAuth 2.0 Device Authorization Grant](https://oauth.net/2/device-flow/) ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)).

Users authenticating over SSH are presented with a verification URL and standard user code. Once authenticated in a web browser against your OpenID Connect (OIDC) identity provider (e.g., Microsoft Entra ID, Okta, Keycloak, Auth0), the module validates provider identity claims and completes the Linux login sequence.

---

## Key Features

* **Standard RFC 8628 Flow:** Monotonic clock polling (`CLOCK_MONOTONIC`), resilient backoff for transient network errors, and real-time prompt streaming over SSH `keyboard-interactive` sessions.
* **PKCE (RFC 7636):** Optional S256 code-verifier/code-challenge pairs bind the token exchange to the originating device-flow attempt; enabled via `use_pkce = true|false|auto` (`auto` probes the provider's discovery document once and fails safe to off).
* **Flexible Claim Mapping:** Extract local system usernames from OIDC UserInfo claims (`sub`, `preferred_username`, etc.) using POSIX Extended Regular Expressions.
* **Pre-Flight Access Controls:** Reject unauthorized local accounts *before* contacting the identity provider, limiting identity mapping risks.
* **Group & Role Authorization:** Restrict access to users belonging to specific provider groups or roles.
* **Security & Memory Hardening:** Zeroes sensitive memory buffers in process RAM (`secure_memzero`), enforces strict root ownership (`0600`/`0640` permissions), and sanitizes terminal output against ANSI escape sequence injection.

---

## Quickstart Guide

Get `pam_oidc_device` deployed in 4 steps.

### Step 1: Install Build Dependencies & Compile

On Enterprise Linux 8 / 9 / 10 (RHEL, Rocky Linux, AlmaLinux):

```bash
# Install dependencies
sudo dnf install -y gcc pam-devel libcurl-devel json-c-devel openssl-devel make

# Clone and compile
git clone https://github.com/ncsa/pam_oidc_device.git
cd pam_oidc_device
make
sudo make install
```

*(To build production RPM packages instead, see [Building & RPM Packaging](#building--rpm-packaging)).*

---

### Step 2: Configure `/etc/pam_oidc_device.conf`

Create or edit `/etc/pam_oidc_device.conf`. Ensure the file is owned by `root:root` with strict `0600` permissions.

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
```

---

### Step 3: Enable OpenSSH Keyboard-Interactive Mode

Ensure `/etc/ssh/sshd_config` permits interactive PAM prompting:

```sshd_config
UsePAM yes
KbdInteractiveAuthentication yes
AuthenticationMethods keyboard-interactive
```

Reload SSH configuration:

```bash
sudo systemctl reload sshd
```

---

### Step 4: Add Module to PAM (`/etc/pam.d/sshd`)

Append `pam_oidc_device.so` into your PAM SSH authentication stack (`/etc/pam.d/sshd`):

```pam
# /etc/pam.d/sshd
auth        required      pam_sepermit.so
auth        substack      password-auth
# Guard non-system accounts (UID >= 1000)
auth        required      pam_succeed_if.so uid >= 1000 quiet
auth        required      pam_oidc_device.so
auth        include       postlogin
```

---

## Detailed Documentation & Deep Dives

For advanced configurations, policy enforcement, and operational tuning, refer to our dedicated guides:

| Document | Topic & Focus |
| --- | --- |
| 📖 **[PAM & OpenSSH Setup Guide](docs/pam-ssh-setup.md)** | Full SSH configuration, authselect profiles, stack position recommendations, and system log auditing. |
| 🔐 **[Account & Group Access Control](docs/access-control.md)** | Restricting access via `allow_users`, `deny_users`, and provider group/role claims (`allow_groups`/`deny_groups`). |
| 🛡️ **[Local JWT Claim Inspection](docs/jwt-validation.md)** | Pre-flight claims-only inspection (`verify_jwt_claims`), tenant pinning (`iss`), and audience checks (`aud`). |
| 🎯 **[Threat Model & Security Boundary](docs/threat-model.md)** | Trust boundaries, terminal injection defense, process memory scrubbing, and threat matrix. |
| 🏢 **[Identity Provider Integration Examples](examples/README.md)** | Complete config templates for Microsoft Entra ID, Okta, Keycloak, Auth0, and CILogon. |

---

## Building & RPM Packaging

### Building RPM Packages (EL8 / EL9 / EL10)

Building RPM packages locally requires `libcmocka-devel` (available in the CRB / CodeReady Builder repository):

```bash
# Enable CRB repository
sudo dnf install -y dnf-plugins-core
sudo dnf config-manager --set-enabled crb

# Install build dependencies & compile RPM
sudo dnf builddep -y packaging/pam_oidc_device.spec
make rpm
```

The resulting packages will be generated under `rpmbuild/RPMS/x86_64/`:

```bash
sudo dnf localinstall -y rpmbuild/RPMS/x86_64/pam_oidc_device-0.1.0-1.el9.x86_64.rpm
```

---

## Security & Credential Handling

For a complete security analysis, attack vector breakdown, and trust boundary mapping, see the [Threat Model](docs/threat-model.md).

* **Zero Disk Footprint:** OAuth device codes, tokens, and response bodies are never written to disk or swap files.
* **Volatile Memory Scrubbing:** Module-owned secret materials (client secrets, access/refresh tokens, decoded JSON payload fields) are explicitly zeroed out in process RAM via `secure_memzero` before memory is released.
* **Terminal Injection Defense:** URL endpoints and user verification codes are validated (`is_valid_https_url`, `is_safe_user_code`) before display, and the fully rendered prompt is validated line-by-line (`is_safe_terminal_string`, newline-tolerant) before it reaches the user's terminal, to prevent ANSI sequence and control-character injection. Custom `init_message` templates are therefore limited to printable ASCII with escaped `\n` newlines.
* **Client Authentication:** `client_id`/`client_secret` are transmitted as form-encoded request-body parameters (the RFC 6749 §2.3.1 `client_secret_post` pattern). The `client_secret_basic` (HTTP Basic `Authorization`) client-authentication method is not supported — the identity provider must accept body-posted client secrets.

---

## Logging & Auditing

All module authentication events write to `syslog` under facility `LOG_AUTHPRIV` (typically `/var/log/secure` or systemd journal).

To trace live logins and troubleshoot issues:

```bash
sudo journalctl -f -u sshd | grep pam_oidc_device
```

To enable detailed tracing, set `loglevel = debug` or `loglevel = verbose` in the `[runtime]` section of `/etc/pam_oidc_device.conf`.

---

## License & Community

* **License:** This project is licensed under the [MIT License](LICENSE).
* **Release History:** See [CHANGELOG.md](CHANGELOG.md).
* **Security Disclosures:** See [SECURITY.md](SECURITY.md).
* **Contributing:** See [CONTRIBUTING.md](CONTRIBUTING.md).

Developed and maintained by **NCSA CyberInfrastructure** ([https://www.ncsa.illinois.edu/](https://www.ncsa.illinois.edu/)).
