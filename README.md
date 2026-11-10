# PAM OAuth 2.0 Device Authorization Grant Module (`pam_oidc_device`)

[![Build Verification](https://github.com/ncsa/pam_oidc_device/actions/workflows/build.yml/badge.svg)](https://github.com/ncsa/pam_oidc_device/actions/workflows/build.yml)
[![Lint & Static Analysis](https://github.com/ncsa/pam_oidc_device/actions/workflows/lint.yml/badge.svg)](https://github.com/ncsa/pam_oidc_device/actions/workflows/lint.yml)
[![License](https://img.shields.io/github/license/ncsa/pam_oidc_device?color=green)](LICENSE)

> [!WARNING]
> **Pre-Release Notice**:
> This module is in active pre-release. It has passed initial functional testing and automated test suites, but awaits formal security review (see the [Developer Review Guide](docs/developer/review.md)). We encourage community testing and feedback, but advise against deploying to live production systems without prior internal audit.

`pam_oidc_device.so` is a lightweight, secure Linux [PAM authentication module](https://www.redhat.com/en/blog/pluggable-authentication-modules-pam) written in C. It enables out-of-band multi-factor authentication (MFA) and step-up login for SSH sessions using the standard [OAuth 2.0 Device Authorization Grant](https://oauth.net/2/device-flow/) ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)).

Users authenticating over SSH are presented with a verification URL and standard user code. Once authenticated in a web browser against your OpenID Connect (OIDC) identity provider (e.g., Microsoft Entra ID, Okta, Keycloak, Auth0), the module validates provider identity claims and completes the Linux login sequence.

---

## How It Works

The device flow delivers out-of-band multi-factor authentication without any
client-side software on the login host:

1. **Login starts.** A user runs `ssh user@host`; the PAM `auth` stack invokes
   `pam_oidc_device.so`.
2. **Verification prompt.** The module requests a one-time user code from your
   identity provider and displays the sign-in URL and code in the terminal
   (optionally also as a scannable QR code).
3. **User approves.** On a *second* device, the user opens the URL in a
   browser, signs in to their OIDC account, and authorizes the login for this
   host.
4. **Module validates.** The module polls the token endpoint on a monotonic
   clock, then validates the returned token and identity claims against the
   local system user (plus optional group/role and JWT claim checks) before
   completing the login — or fails closed, blocking it.

No passwords cross the wire in this flow, and no provider credentials live on
the host beyond the `client_id`/`client_secret` in the root-only config file.

---

## Key Features

* **Standard RFC 8628 Flow:** Monotonic clock polling (`CLOCK_MONOTONIC`), resilient backoff for transient network errors, and real-time prompt streaming over SSH `keyboard-interactive` sessions. The module polls immediately after displaying the sign-in instructions — no Enter keypress is required — so approval is detected the moment it happens on the second device.
* **PKCE (RFC 7636):** Optional S256 code-verifier/code-challenge pairs bind the token exchange to the originating device-flow attempt; enabled via `use_pkce = true|false|auto` (`auto` probes the provider's discovery document once and fails safe to off).
* **Flexible Claim Mapping:** Extract local system usernames from OIDC UserInfo claims (`sub`, `preferred_username`, etc.) using POSIX Extended Regular Expressions.
* **Pre-Flight Access Controls:** Reject unauthorized local accounts *before* contacting the identity provider, limiting identity mapping risks.
* **Group & Role Authorization:** Restrict access to users belonging to specific provider groups or roles.
* **Terminal QR Sign-in:** Opt-in `[qr]` section renders the device-flow sign-in URL as a scannable QR code on TTY logins so users can open it with a phone camera; authentication never depends on the QR — when it is disabled or rendering fails, the plain text prompt is still shown.
* **Sign-In Confirmation:** The module shows the sign-in URL and code, then waits for the user to press Enter before polling the token endpoint begins. This round-trip flushes the prompt to OpenSSH keyboard-interactive clients, which buffer `PAM_TEXT_INFO` until a prompt triggers a `USERINFO` round-trip, and ensures the user has had time to note the URL and code on a secondary device.
* **Security & Memory Hardening:** Zeroes sensitive memory buffers in process RAM (`secure_memzero`), enforces strict root ownership (`0600`/`0640` permissions), and sanitizes terminal output against ANSI escape sequence injection.

---

## Quickstart

Deploy `pam_oidc_device` in 4 steps. The complete walkthrough — prerequisites,
provider configuration values, `authselect` on Enterprise Linux, and
logging — lives in the [Getting Started guide](docs/getting-started.md); to
install a prebuilt RPM/DEB instead of compiling, see
[Building RPM & DEB Packages](docs/packaging.md).

### Step 1: Install the Module

Build from source. On Enterprise Linux 8 / 9 / 10 (RHEL, Rocky Linux, AlmaLinux):

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

> [!WARNING]
> **Use `required` (or `requisite`), not `sufficient`.** `pam_oidc_device.so` fails for any
> reason a device-flow login can't complete — a rejected user code, a claim/identity mismatch,
> a network/IdP error, or an invalid `/etc/pam_oidc_device.conf`. With `sufficient`, that
> failure does **not** block login: PAM moves on to the next module and can authenticate the
> user through your fallback method **without ever completing the OIDC flow**. `required` /
> `requisite` keeps the module fail-closed so a misconfiguration can't silently downgrade
> authentication. See [Getting Started §5](docs/getting-started.md) for the full
> discussion, and §6 for keeping the integration across `authselect` profile
> re-applications on Enterprise Linux.

---

## Documentation

Pick the guide that matches what you are about to do:

| I want to… | Read |
| --- | --- |
| **Deploy it from scratch** (install, config, OpenSSH, PAM stack, `authselect`, logging) | [Getting Started](docs/getting-started.md) |
| **Connect my identity provider** (discover endpoints, PKCE support, complete config templates) | [Provider Examples & Discovery](examples/README.md) |
| **Test it before relying on it** (one-command e2e sandbox, `pamtester`, trial IdP, pre-production audit) | [Testing & Pre-Production Audit Guide](docs/testing.md) |
| **Restrict who can log in** (local users, provider groups/roles) | [Account & Group Access Control](docs/access-control.md) |
| **Harden token acceptance** (issuer pinning, audience, `exp`/`nbf`) | [Local JWT Claim Inspection](docs/jwt-validation.md) |
| **Understand the security model** (threat matrix, injection defense, memory scrubbing) | [Security Policy](SECURITY.md) & [Threat Model](docs/threat-model.md) |
| **Build RPM/DEB packages** | [Building RPM & DEB Packages](docs/packaging.md) |
| **Contribute** (build/test gates, developing on non-Linux hosts) | [Contributing Guide](CONTRIBUTING.md) |

---

## Security & Credential Handling

For a complete security analysis, attack vector breakdown, and trust boundary mapping, see the [Threat Model](docs/threat-model.md).

* **Zero Disk Footprint:** OAuth device codes, tokens, and response bodies are never written to disk or swap files.
* **Volatile Memory Scrubbing:** Module-owned secret materials (client secrets, access/refresh tokens, decoded JSON payload fields) are explicitly zeroed out in process RAM via `secure_memzero` before memory is released.
* **Terminal Injection Defense:** URL endpoints and user verification codes are validated (`is_valid_https_url`, `is_safe_user_code`) before display, and the fully rendered prompt is validated line-by-line (`is_safe_terminal_string`, newline-tolerant) before it reaches the user's terminal, to prevent ANSI sequence and control-character injection. Custom `init_message` templates are therefore limited to printable ASCII with escaped `\n` newlines.
* **User Code Format:** Verification codes are displayed exactly as issued by the identity provider. The RFC 8628 §3.1 recommendations on code character sets (consonant-only base-20 or pure-numeric sets, omission of visually ambiguous characters) and chunked display formatting are server-side choices, so the module does not reject or reformat codes to enforce them — it applies terminal-safety filtering only.
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

## Third-Party Components & Licenses

The module's own code is MIT-licensed. It vendors exactly one third-party component —
**Project Nayuki's QR Code generator (C edition, MIT)** — and otherwise links against standard
system libraries that ship as distribution packages:

| Component | Role | License |
| --- | --- | --- |
| [Project Nayuki QR Code generator (C)](third_party/qrcodegen/AUTHORS) | Vendored into `third_party/qrcodegen/` (pinned, drift-audited) | MIT |
| Linux-PAM | Runtime system library | 3-clause BSD-style (Linux-PAM license) |
| cURL | Runtime system library | curl license (MIT-style) |
| json-c | Runtime system library | MIT |
| OpenSSL | Runtime system library | Apache-2.0 |
| CMocka | Build/test only — never shipped | Apache-2.0 |

Full licensing, provenance pins, local-deviation records, and the license-audit procedure are
maintained in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and checked automatically in CI
(the [license audit workflow](.github/workflows/license-audit.yml) plus the
[vendor drift audit](.github/workflows/vendor-audit.yml)).

---

## License & Community

* **License:** This project is licensed under the [MIT License](LICENSE).
* **Release History:** See [CHANGELOG.md](CHANGELOG.md).
* **Security Disclosures:** See [SECURITY.md](SECURITY.md).
* **Contributing:** See [CONTRIBUTING.md](CONTRIBUTING.md).

Developed and maintained by **NCSA CyberInfrastructure** ([https://www.ncsa.illinois.edu/](https://www.ncsa.illinois.edu/)).
