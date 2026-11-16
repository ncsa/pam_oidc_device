# Testing & Pre-Production Audit Guide

How to test and audit `pam_oidc_device` **before** it ever touches a live
production stack. The module gates logins, so the goal of this guide is to
prove two things before rollout:

1. **It behaves correctly** — the RFC 8628 device flow completes, and every
   failure path fails *closed* (a broken provider, a broken config, or a
   wrong identity never accidentally lets someone in).
2. **It is safe in your environment** — config hygiene, TLS, account
   protection, and logging all work on *your* hosts, with a rollback path
   that restores normal logins in seconds.

## Table of Contents

* [1. Test layers at a glance](#1-test-layers-at-a-glance)
* [2. One-command sandbox (`make sandbox`)](#2-one-command-sandbox-make-sandbox)
* [3. Manual testing with `pamtester` on a Linux host](#3-manual-testing-with-pamtester-on-a-linux-host)
* [4. Trial against a real IdP](#4-trial-against-a-real-idp)
* [5. Pre-production audit checklist](#5-pre-production-audit-checklist)

---

## 1. Test layers at a glance

| Layer | What it proves | How |
| --- | --- | --- |
| Unit tests | Parsing, PKCE vectors, JWT claims, polling backoff, terminal-safety helpers | `make test` (see `CONTRIBUTING.md`) |
| Sanitizer run | No heap overflow / UAF / leaks in the module under test traffic | `make test-sanitize CC=clang` |
| Static analysis | Format, warnings, scrub-before-release discipline | `make lint` |
| **E2E sandbox (this repo)** | The *installed* module driven through a real PAM stack against an HTTPS mock IdP: full device flow, PKCE binding, claim mapping, denial paths | `make sandbox` (one command, isolated container) |
| Manual PAM tests | Same, but on a host that mirrors your production (distro, PAM version, `authselect`) | `pamtester` (Section 3) |
| Real SSH session | Prompt flushing under OpenSSH keyboard-interactive, user experience | manual `ssh` (Section 3.4) |
| Live trial IdP | Provider-specific quirks: PKCE support, discovery, claims, groups | test tenant (Section 4) |
| Staged rollout + audit | Fail-closed behavior and log/audit posture on production-adjacent hosts | checklist (Section 5) |

The E2E sandbox and the CI `e2e-sandbox` job use the same harness
(`tests/e2e/run_e2e.sh`), so a green `make sandbox` is a strong predictor of
a green CI job.

---

## 2. One-command sandbox (`make sandbox`)

```bash
make sandbox         # build + run: 7 device-flow scenarios, headless
make sandbox-shell   # same image, interactive shell to explore
```

`make sandbox` builds a disposable Ubuntu 24.04 image
(`tests/e2e/Dockerfile`) in which the module is **built and installed exactly
like a production install**, then runs `tests/e2e/run_e2e.sh`. Your host is
never modified; when the command returns, the container is gone.

What the sandbox exercises end to end (the module talks to a local HTTPS mock
OIDC provider over TLS with a self-signed certificate trusted via the system
CA store — so the module's strict `https://` endpoint validation and
mandatory certificate verification are exercised exactly as against a real
IdP):

| Scenario | Provider behavior | Expected PAM result |
| --- | --- | --- |
| `success-alice` | approves on first poll; claim maps to `alice` | `PAM_SUCCESS` (0) |
| `claim-mismatch` | approves, but the claim is `bob@…` while PAM user is `alice` | `PAM_AUTH_ERR` (7) |
| `provider-denied` | user code denied (`access_denied`) | `PAM_AUTH_ERR` (7) |
| `slowdown-backoff` | `slow_down` once, then approves (RFC 8628 §3.5 +5 s) | `PAM_SUCCESS` (0) |
| `root-denied` | (never contacted) local allow/deny lists refuse `root` | `PAM_PERM_DENIED` (6) |
| `code-expired` | code still pending when `expires_in` deadline lapses | `PAM_AUTH_ERR` (7) |
| `bad-config-perms` | config mode `0644` instead of `0600`/`0640` | `PAM_SERVICE_ERR` (3) — fails closed before any provider contact |

The sandbox configuration (`tests/e2e/pam_oidc_device.e2e.conf`) turns on the
full hardening path — `use_pkce = true` and `verify_jwt_claims = true` — and
the mock provider **enforces the PKCE S256 binding for real**: it stores the
`code_challenge` from the device-authorization request and rejects any token
request whose `code_verifier` does not re-derive to it (400
`invalid_grant`). A regression that drops or mangles the PKCE parameters
therefore fails the success scenarios; it is not just linted.

Sandbox internals:

- `tests/e2e/mock_oidc.py` — scenario-driven mock IdP (Python 3 stdlib):
  device code / token / userinfo / discovery / health endpoints.
- `tests/e2e/pam_driver.c` — deterministic PAM driver: runs
  `pam_authenticate()` against the throwaway `/etc/pam.d/e2e` stack, prints
  every `PAM_TEXT_INFO`/`PAM_ERROR_MSG` message, answers the module's
  "Press [Enter] to begin..." prompt for you, and **exits with the PAM
  return value**.
- `tests/e2e/pam.d-e2e` — the stack fixture: `auth requisite
  pam_oidc_device.so loglevel=debug` under the service name `e2e` (never
  `/etc/pam.d/sshd`).

In `make sandbox-shell`, try it by hand (run the suite once first — it lays
down the TLS trust, installs `/etc/pam.d/e2e`, and builds the driver — then
drive individual logins yourself):

```sh
./tests/e2e/run_e2e.sh                      # one-time setup + full suite
python3 tests/e2e/mock_oidc.py --port 8443 \
    --cert /tmp/pam_oidc_device_e2e/tls.crt --key /tmp/pam_oidc_device_e2e/tls.key \
    --scenario-file /tmp/pam_oidc_device_e2e/scenario &
echo approve-alice > /tmp/pam_oidc_device_e2e/scenario
/tmp/pam_oidc_device_e2e/pam_driver e2e alice   # or: pamtester e2e alice authenticate
```

(The shell you get is already `root`, so the driver needs no `sudo`.)

> [!NOTE]
> **Nobody visits the verification URL in the sandbox.** The "sign in on your
> second device" step of the real flow is *simulated*: when the module
> requests a device code, the mock IdP reads
> `/tmp/pam_oidc_device_e2e/scenario`, so the `echo approve-alice > …`
> line **is** the approval — no browser or second device is involved. The
> `/verify` URL is emitted only so the terminal prompt looks like the
> production flow; the mock serves just the OAuth endpoints
> (`/oauth2/device/code`, `/oauth2/token`, `/oauth2/userinfo`, the discovery
> document, and `/health`), so opening the link in a real browser gets you a
> JSON 404. Set the scenario file *before* starting the driver — or
> `pamtester` — and the outcome is deterministic. Useful values:
> `approve-alice` (success), `approve-bob` (the claim mismatch results in
> `PAM_AUTH_ERR`), `denied` (denying the code on the user's device results in
> `PAM_AUTH_ERR`), `slowdown-approve` (one `slow_down`, then success),
> `expired` (the lapsed code results in `PAM_AUTH_ERR`).

---

## 3. Manual testing with `pamtester` on a Linux host

`pamtester` (Debian/Ubuntu package `pamtester`; on RHEL/EL the binary ships
with the `pam` package) drives an arbitrary PAM service name through the
`auth` stack without a login session — ideal for iterating on module
configuration on a disposable host.

> [!IMPORTANT]
> **Do this on a throwaway VM or container, not a live server.** `pamtester`
> runs your *real* PAM stack entries: a misconfigured test service can lock
> out the test host.

### 3.1 One-time setup on the test host

```bash
# 1. Install the module and a copy of its config (docs/getting-started.md §2–3)
sudo make install PAM_DIR=<your PAM module dir>   # e.g., /lib64/security or /lib/x86_64-linux-gnu/security

# 2. Point a config copy at your test IdP (or the sandbox mock on 127.0.0.1:8443)
sudo cp config/pam_oidc_device.conf /etc/pam_oidc_device.conf
sudo chown root:root /etc/pam_oidc_device.conf
sudo chmod 0600 /etc/pam_oidc_device.conf

# 3. Create a throwaway PAM service so you never touch /etc/pam.d/sshd:
sudo tee /etc/pam.d/oidc-test > /dev/null <<'EOF'
auth requisite pam_oidc_device.so loglevel=debug
EOF

# 4. A local test account that maps to an identity in your IdP
sudo useradd -m testuser
```

Use `requisite` (not `required`/`sufficient`) for test stacks so the module's
return value propagates verbatim and the stack stops immediately.

### 3.2 Running a test login

```bash
sudo pamtester oidc-test testuser authenticate
```

The module then runs the full device flow in your terminal: the verification
URL, user code (and QR code if `[qr] enabled = true`), then a short
"Press [Enter] to begin..." pause — after which it polls until you sign in
on a second device. Watch the module log in parallel:

```bash
sudo journalctl -f | grep pam_oidc_device        # module syslog (LOG_AUTHPRIV)
```

`pamtester` prints the PAM status string and exits with the PAM status code.
Useful return codes (Linux-PAM `pam_constants.h`; `pamtester` prints the name
for you):

| Code | Constant | Typical module cause |
| --- | --- | --- |
| 0 | `PAM_SUCCESS` | Device flow completed; claim mapped to PAM user |
| 3 | `PAM_SERVICE_ERR` | Config missing / not `0600`–`0640` root:root / invalid key — **fails closed** |
| 6 | `PAM_PERM_DENIED` | `root` denied, `deny_users`/`deny_groups` match, group policy unsatisfied |
| 7 | `PAM_AUTH_ERR` | Claim does not match PAM user, provider denied the code, polling deadline expired, JWT claims check failed |
| 9 | `PAM_AUTHINFO_UNAVAIL` | UserInfo endpoint unreachable / non-200 |
| 10 | `PAM_USER_UNKNOWN` | PAM could not resolve the user at all |
| 26 | `PAM_ABORT` | User cancelled (Ctrl-C) mid-flow |
| 28 | `PAM_MODULE_UNKNOWN` | `pam_oidc_device.so` not found in the PAM module dir |

### 3.3 Manual negative-test matrix

Run each of these and confirm the *status and log line*, not just success:

1. **Wrong local user.** Approve the code for `alice@…` but run
   `pamtester oidc-test bob authenticate`; the result is `PAM_AUTH_ERR`, and
   the log says "claim verification failed".
2. **Provider denial.** On the second device, *deny* the code; the result is
   `PAM_AUTH_ERR`, and the log says "Non-retryable OAuth authorization error".
3. **Let the code expire.** Do not sign in; wait past `max_poll_seconds`; the
   result is `PAM_AUTH_ERR`, and the log says "timed out or denied".
4. **Root.** `pamtester oidc-test root authenticate` results in
   `PAM_PERM_DENIED` before any provider traffic (check the log: no "device
   authentication initiated" line).
5. **Broken config.** `sudo chmod 0644 /etc/pam_oidc_device.conf` results in
   `PAM_SERVICE_ERR`; the log records the permission check failure. Restore
   `0600`.
6. **Wrong issuer.** With `verify_jwt_claims = true`, set `issuer` to a
   different value than the IdP's `iss`; the result is `PAM_AUTH_ERR`, and
   the log says "JWT claim inspection failed".
7. **Kill the IdP.** Stop the mock / point `token_endpoint` at a dead port:
   the module retries with backoff until the deadline, then returns
   `PAM_AUTH_ERR`. It must never hang past `max_poll_seconds`.

> [!NOTE]
> `pamtester`'s built-in conversation handler cannot always answer the
> module's "Press [Enter] to begin..." synchronization prompt. The module
> tolerates a failed prompt and proceeds to polling (it logs a debug
> notice), but if your `pamtester` version aborts the conversation on it,
> drive the test with `tests/e2e/pam_driver` instead — a small PAM driver
> that answers the prompt deterministically and exits with the PAM status:
>
> ```bash
> cc -O2 -Wall -Wextra -Iinclude tests/e2e/pam_driver.c -o /tmp/pam_driver -lpam
> sudo /tmp/pam_driver oidc-test testuser
> ```

### 3.4 The gold standard: a real SSH session

`pamtester` cannot reproduce OpenSSH keyboard-interactive buffering (the
reason the module issues its Enter-press flush — see
`docs/getting-started.md` §4). Before relying on the UX, do one manual run
through a real `ssh` client against `KbdInteractiveAuthentication yes` and
confirm the URL/code appear in real time and the session lands the moment the
code is approved.

---

## 4. Trial against a real IdP

The sandbox proves the protocol; only a real provider proves *your
integration*. Use a dedicated **test tenant / test client** (Keycloak test
realm, CILogon test client, Entra test app registration — see `examples/`).

Checklist:

- [ ] Register the client with the **device authorization grant** enabled,
      and record whether the provider supports **device-flow PKCE** (vendor
      docs + probe a live test client — see `examples/README.md`). Set
      `use_pkce` to `true`/`auto`/`false` accordingly.
- [ ] Pin the endpoints; verify each is HTTPS and reachable from the hosts
      that will run the module.
- [ ] Set `issuer` to the provider's exact `iss` and `audience` to the
      audience your tokens carry; enable `verify_jwt_claims = true`.
- [ ] Map the claim: pick `claim_field` (e.g., `preferred_username` or `sub`)
      and write `claim_regex` so only *your* domain/tenant can map to local
      accounts (the sample's `@example.edu` pinning pattern).
- [ ] If the provider exposes group claims, configure `allow_groups` /
      `deny_groups` and `enforce_groups`, then test a user in and out of an
      allowed group.
- [ ] Observe one full login at `loglevel = debug`, then re-run at `verbose`
      if anything is off (verbose includes full HTTP transport metrics —
      keep PII out of shared logs).
- [ ] Confirm the provider's `expires_in` interplay: your local
      `max_poll_seconds` (range 10–3600, default 120) caps the wait
      regardless of the provider's code lifetime.

---

## 5. Pre-production audit checklist

Run on a **staging host that mirrors production** (same distro, PAM version,
`authselect` profile) before enabling the module for real users.

**Configuration & filesystem**

- [ ] `ls -l /etc/pam_oidc_device.conf` shows `root:root`, mode `0600` (or
      `0640` with `root` group). Anything else fails closed — verify that
      is actually what happens (checklist item 5 in §3.3).
- [ ] No provider secrets beyond `client_secret` in the file; no
      world/group read.
- [ ] All endpoint URLs are `https://` (the module refuses anything else at
      load time).

**Fail-closed behavior (the most important check)**

- [ ] `sudo mv /etc/pam_oidc_device.conf /root/conf.bak`, then attempt a
      login — the login **must fail** (`PAM_SERVICE_ERR`), and the PAM line's control
      flag must be `required`/`requisite` (never `sufficient`) — see
      `docs/getting-started.md` §5.
- [ ] Stop the network / firewall-block the IdP; logins fail with
      `PAM_AUTH_ERR` after bounded retries and never hang past
      `max_poll_seconds`.
- [ ] Rollback drill: comment out the `pam_oidc_device.so` line in
      `/etc/pam.d/sshd` (or re-apply the `authselect` profile) and confirm
      normal logins return within a minute. Document this exact rollback
      step with the change ticket.

**Accounts & hardening**

- [ ] `pam_succeed_if.so uid >= 1000 quiet` (or equivalent) sits *before*
      the module, so system accounts never reach the OIDC flow.
- [ ] `root` login is refused (default; only `allow_root = true`
      overrides).
- [ ] `allow_users` / `deny_users` lists reflect the pilot group.

**Transport**

- [ ] TLS to the IdP validates against your CA bundle (it must — the module
      never allows disabling peer verification); no proxy in the path
      downgrades below TLS 1.2.
- [ ] Clock sync (NTP) on the login hosts — a skewed clock breaks
      `exp`/`nbf` inspection and can reject valid tokens.

**Operational**

- [ ] `loglevel` set to `info` for steady state (audit-grade lifecycle
      events, no PII in routine logs — full claim payloads are `verbose`
      only).
- [ ] `max_poll_seconds` vs. `sshd_config LoginGraceTime`: the PAM poll runs
      inside the SSH login-grace window; keep `max_poll_seconds`
      comfortably below `LoginGraceTime` or raise the latter deliberately.
- [ ] `journalctl` retention covers your audit window; the module logs under
      `LOG_AUTHPRIV`.
- [ ] Phishing awareness: users will act on device codes presented on a
      second device — brief your user base that they must verify the host
      context shown in the prompt (see `docs/threat-model.md`).
- [ ] Threat model reviewed: `docs/threat-model.md` (trust boundaries,
      terminal-injection defenses, memory scrubbing).

---

*See also: [Getting Started](getting-started.md), [Access
Control](access-control.md), [Local JWT Claim Inspection](jwt-validation.md),
[Threat Model](threat-model.md), [Roadmap](developer/roadmap.md),
`CONTRIBUTING.md` (developer gates).*


