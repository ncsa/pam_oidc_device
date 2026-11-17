#!/usr/bin/env bash
# run_e2e.sh -- end-to-end device-flow scenario suite for pam_oidc_device.
#
# Drives the INSTALLED PAM module through a full RFC 8628 device flow against
# a local HTTPS mock OIDC provider (mock_oidc.py) using a deterministic PAM
# driver (pam_driver.c, built on the fly).  Nothing here touches host SSH
# configuration: a throwaway PAM service "e2e" is used (/etc/pam.d/e2e).
#
# Prerequisites:
#   * the module built and installed:   make && make install PAM_DIR=<pam dir>
#   * python3, openssl, a C compiler, and root (or passwordless sudo)
#
# Environments:
#   * Docker sandbox (make sandbox)    -- everything preinstalled by the image
#   * CI ubuntu-latest (build.yml)     -- same, after `make install`
#   * a disposable Linux host          -- for hands-on staging tests
#
# Scenarios and expected PAM return values:
#   success-alice      approve-alice       0  PAM_SUCCESS
#   claim-mismatch     approve-bob         7  PAM_AUTH_ERR   (claim != PAM user)
#   provider-denied    denied              7  PAM_AUTH_ERR   (access_denied)
#   slowdown-backoff   slowdown-approve    0  PAM_SUCCESS    (RFC 8628 +5s)
#   root-denied        approve-alice       6  PAM_PERM_DENIED (local allow/deny)
#   uid0-alias-denied  approve-alice       6  PAM_PERM_DENIED (uid-0 alias account "toor")
#   system-uid-denied  approve-alice       6  PAM_PERM_DENIED (system account "sync" uid 4 in default 0-999 range)
#   code-expired       expired             7  PAM_AUTH_ERR   (polling deadline)
#   bad-config-perms   approve-alice       3  PAM_SERVICE_ERR (fail-closed 0644)
#
# The mock provider enforces PKCE S256 (sandbox conf sets use_pkce=true): any
# code_verifier/code_challenge mismatch surfaces as 400 invalid_grant and
# fails the success scenarios, so PKCE binding is asserted for real.
#
# Environment overrides: E2E_WORKDIR, E2E_PORT.

set -euo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$E2E_DIR/../.." && pwd)"
WORKDIR="${E2E_WORKDIR:-/tmp/pam_oidc_device_e2e}"
PORT="${E2E_PORT:-8443}"
SERVICE="e2e"
CONF="/etc/pam_oidc_device.conf"
SCENARIO_FILE="$WORKDIR/scenario"
MOCK_LOG="$WORKDIR/mock.log"

if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

log() { printf '==> %s\n' "$*" >&2; }

# --- prerequisites ---------------------------------------------------------
for tool in python3 openssl cc; do
    command -v "$tool" >/dev/null 2>&1 || { log "missing required tool: $tool"; exit 1; }
done

MODULE=""
for dir in /lib64/security /lib/security /lib/*/security /usr/lib64/security; do
    if [ -f "${dir}/pam_oidc_device.so" ]; then MODULE="${dir}/pam_oidc_device.so"; break; fi
done
if [ -z "$MODULE" ]; then
    log "pam_oidc_device.so not found under any PAM module dir; run 'make install' first"
    exit 1
fi
log "using PAM module ${MODULE}"

# --- sandbox state (idempotent) --------------------------------------------
# Keep the workdir owned by the invoking user (root or a sudo user): the
# scenario file, TLS material, driver binary, and mock log below are all
# written and read without root. Take over any root-owned workdir left by an
# earlier root run (e.g. `make sandbox` on a shared host) before using it.
if [ -d "$WORKDIR" ]; then
    $SUDO chown -R "$(id -u):$(id -g)" "$WORKDIR"
fi
install -d -m 0700 "$WORKDIR"

for user in alice bob; do
    id "$user" >/dev/null 2>&1 || $SUDO useradd --no-create-home --shell /usr/sbin/nologin "$user"
done
# uid-0 alias account for the allow_root guard (e2e scenario uid0-alias-denied).
id toor >/dev/null 2>&1 || $SUDO useradd --no-create-home --shell /usr/sbin/nologin -o -u 0 toor

# The module hard-requires a root:root 0600/0640 config; install the fixture
# only when absent so a live host's real config is never clobbered.
if [ ! -f "$CONF" ]; then
    $SUDO cp "$E2E_DIR/pam_oidc_device.e2e.conf" "$CONF"
    $SUDO chown root:root "$CONF"
    $SUDO chmod 0600 "$CONF"
    log "installed sandbox config at $CONF"
else
    # The live config is root:root 0600; read it with $SUDO so this check also
    # works when the suite runs as a non-root user with passwordless sudo.
    $SUDO grep -q "127.0.0.1:${PORT}" "$CONF" 2>/dev/null \
        || { log "$CONF exists but does not point at the sandbox mock; refusing to overwrite (delete it or use a container)"; exit 1; }
    log "reusing existing sandbox config at $CONF"
fi


# Dedicated throwaway PAM service; never touches /etc/pam.d/sshd.
$SUDO install -m 0644 "$E2E_DIR/pam.d-e2e" "/etc/pam.d/${SERVICE}"

# --- TLS: self-signed CA trusted by the system store -----------------------
if [ ! -f "$WORKDIR/tls.crt" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
        -keyout "$WORKDIR/tls.key" -out "$WORKDIR/tls.crt" \
        -subj "/CN=127.0.0.1" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
fi
chmod 600 "$WORKDIR/tls.key" 2>/dev/null || true

if command -v update-ca-certificates >/dev/null 2>&1; then
    $SUDO cp "$WORKDIR/tls.crt" /usr/local/share/ca-certificates/pam-oidc-device-e2e.crt
    $SUDO update-ca-certificates >/dev/null
elif command -v update-ca-trust >/dev/null 2>&1; then
    $SUDO install -d /etc/pki/ca-trust/source/anchors
    $SUDO cp "$WORKDIR/tls.crt" /etc/pki/ca-trust/source/anchors/pam-oidc-device-e2e.crt
    $SUDO update-ca-trust extract >/dev/null
else
    log "WARNING: no update-ca-certificates/update-ca-trust; the module will reject the mock's self-signed certificate"
fi

# --- build the PAM test driver ---------------------------------------------
cc -O2 -Wall -Wextra -Werror -I"$REPO_ROOT/include" \
    "$E2E_DIR/pam_driver.c" -o "$WORKDIR/pam_driver" -lpam
log "built $WORKDIR/pam_driver"

# --- start the mock provider ------------------------------------------------
echo "approve-alice" > "$SCENARIO_FILE"
python3 "$E2E_DIR/mock_oidc.py" --port "$PORT" \
    --cert "$WORKDIR/tls.crt" --key "$WORKDIR/tls.key" \
    --scenario-file "$SCENARIO_FILE" > "$MOCK_LOG" 2>&1 &
MOCK_PID=$!
# The conf back-up/scratch files may mirror a live config (client credentials);
# remove them on exit even when a scenario aborts mid-flight.
trap 'kill "$MOCK_PID" 2>/dev/null || true; wait "$MOCK_PID" 2>/dev/null || true;
      rm -f "$WORKDIR/conf.uid0.orig" "$WORKDIR/conf.uid0.tmp"' EXIT

for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
        exec 3>&- 3<&-
        break
    fi
    if ! kill -0 "$MOCK_PID" 2>/dev/null; then
        log "mock provider exited during startup:"
        cat "$MOCK_LOG" >&2
        exit 1
    fi
    sleep 0.2
done
sleep 0.5
log "mock OIDC provider listening on https://127.0.0.1:${PORT}"

# --- scenario runner ---------------------------------------------------------
FAILURES=0
CASES=0

run_case() { # name expected_rc user scenario [expected_notice_substring]
    local name="$1" expected="$2" user="$3" scenario="$4" notice="${5:-}"
    echo "$scenario" > "$SCENARIO_FILE"
    CASES=$((CASES + 1))
    local rc=0
    timeout 90 $SUDO "$WORKDIR/pam_driver" "$SERVICE" "$user" > "$WORKDIR/${name}.out" 2>&1 || rc=$?
    if [ "$rc" -eq "$expected" ]; then
        log "PASS ${name} (PAM rc ${rc} as expected)"
    else
        log "FAIL ${name}: expected PAM rc ${expected}, got ${rc}"
        sed -n '1,30p' "$WORKDIR/${name}.out" >&2 || true
        FAILURES=$((FAILURES + 1))
    fi
    # Optional user-visible notice assertion: pam_driver prints every PAM_TEXT_INFO
    # message to stdout, so the exact notice shown to the user lands in the .out file.
    if [ -n "$notice" ]; then
        if grep -qF "$notice" "$WORKDIR/${name}.out"; then
            :
        else
            log "FAIL ${name}: PAM rc ok but expected user notice not found: ${notice}"
            sed -n '1,30p' "$WORKDIR/${name}.out" >&2 || true
            FAILURES=$((FAILURES + 1))
        fi
    fi
}

log "scenario 1/9: provider approves; claim maps to PAM user (expect PAM_SUCCESS)"
run_case success-alice 0 alice approve-alice

log "scenario 2/9: provider claims a different identity than PAM_USER (expect PAM_AUTH_ERR)"
run_case claim-mismatch 7 alice approve-bob

log "scenario 3/9: provider denies the user code (expect PAM_AUTH_ERR + declined notice)"
run_case provider-denied 7 alice denied "Sign-in was declined"

log "scenario 4/9: provider rate-limits with slow_down, then approves (expect PAM_SUCCESS after +5s backoff)"
run_case slowdown-backoff 0 alice slowdown-approve

log "scenario 5/9: root is refused before any provider contact (expect PAM_PERM_DENIED)"
run_case root-denied 6 root approve-alice

log "scenario 6/9: uid-0 alias account 'toor' is refused like root (expect PAM_PERM_DENIED)"
# Run with a config that has NO allow_users so that only the uid-0 gate can
# block 'toor': the fixture's allow_users = alice,bob would otherwise refuse
# it for a different reason, and the scenario could not distinguish the
# uid-0-alias fix from a simple allow-list miss.
# Note: the backup below must be written through a shell redirection
# (non-root when the suite runs with $SUDO), NOT `$SUDO cp` — cp run as root
# would copy the source's 0600 root:root mode, and the later
# `< conf.uid0.orig` redirection is opened by the non-root shell (EACCES).
$SUDO cat "$CONF" > "$WORKDIR/conf.uid0.orig"
chmod 600 "$WORKDIR/conf.uid0.orig"   # live configs may hold client credentials
$SUDO grep -v '^allow_users' "$CONF" > "$WORKDIR/conf.uid0.tmp"
$SUDO tee "$CONF" < "$WORKDIR/conf.uid0.tmp" > /dev/null
run_case uid0-alias-denied 6 toor approve-alice
$SUDO tee "$CONF" < "$WORKDIR/conf.uid0.orig" > /dev/null

log "scenario 7/9: system account 'sync' (uid 4) is refused by the default system-uid range guard (expect PAM_PERM_DENIED)"
# Run with a config that has NO allow_users so that only the uid-range gate can
# block 'sync' (mirror of the uid-0-alias scenario above): the fixture's
# allow_users = alice,bob would otherwise refuse it for a different reason, and
# the scenario could not distinguish the uid-range guard from a simple
# allow-list miss.
$SUDO cat "$CONF" > "$WORKDIR/conf.uidrange.orig"
chmod 600 "$WORKDIR/conf.uidrange.orig"   # live configs may hold client credentials
$SUDO grep -v '^allow_users' "$CONF" > "$WORKDIR/conf.uidrange.tmp"
$SUDO tee "$CONF" < "$WORKDIR/conf.uidrange.tmp" > /dev/null
run_case system-uid-denied 6 sync approve-alice
$SUDO tee "$CONF" < "$WORKDIR/conf.uidrange.orig" > /dev/null

log "scenario 8/9: device code expires while still pending (expect PAM_AUTH_ERR + expired notice)"
run_case code-expired 7 alice expired "Sign-in was not approved in time"

log "scenario 9/9: mis-permissioned config (0644) must fail closed (expect PAM_SERVICE_ERR)"
$SUDO chmod 0644 "$CONF"
run_case bad-config-perms 3 alice approve-alice
$SUDO chmod 0600 "$CONF"

# --- summary ----------------------------------------------------------------
echo >&2
if [ "$FAILURES" -eq 0 ]; then
    log "e2e: all ${CASES} scenarios passed"
else
    log "e2e: ${FAILURES}/${CASES} scenario(s) FAILED"
    log "mock provider log (last 40 lines):"
    tail -n 40 "$MOCK_LOG" >&2 || true
    exit 1
fi

