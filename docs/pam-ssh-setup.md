# PAM & OpenSSH Deployment Guide

This guide covers deployment, stack ordering, distribution-specific nuances (`authselect`), and logging configuration for `pam_oidc_device.so`.

---

## 1. OpenSSH Server Setup (`/etc/ssh/sshd_config`)

For PAM interactive authentication to present verification prompts to SSH clients, OpenSSH must be configured to allow keyboard-interactive challenges.

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

---

## 2. PAM Stack Integration (`/etc/pam.d/sshd`)

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

### Safety Guard Recommendation (`pam_succeed_if.so`)

Placing `auth required pam_succeed_if.so uid >= 1000 quiet` immediately **before** `pam_oidc_device.so` guarantees that system accounts (`root`, `daemon`, `bin`) are filtered locally and never trigger an OIDC authentication prompt, even if a loose identity claim regex is configured.

---

## 3. Enterprise Linux & `authselect`

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

## 4. Logging & Auditing

`pam_oidc_device.so` emits standard syslog messages under the `LOG_AUTHPRIV` facility.

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