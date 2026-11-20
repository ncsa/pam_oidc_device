# Roadmap

Tracked follow-ups intentionally *not* implemented yet (surfaced by the
[Testing & Pre-Production Audit Guide](../testing.md)):

1. **Preflight `config-check` CLI** — a small static binary (no PAM, no
   network auth) that validates `/etc/pam_oidc_device.conf` on disk and
   probes endpoint reachability/TLS, for operator runbooks and CI config
   review.
2. **sshd-based e2e in the container** — run a real `sshd` with
   keyboard-interactive inside the sandbox image and drive an `ssh` client
   against it, closing the gap noted in `docs/testing.md` §3.4.
3. **authselect profile template** under `packaging/` for EL hosts: an
   `oidc-auth` profile created with `authselect create-profile oidc-auth
   --base-on=<current-profile>` that inserts the module into `password-auth`
   (the shared stack `sshd` includes; `authselect` manages only the shared
   stack files, never `/etc/pam.d/sshd`), so the integration survives
   `authselect apply-changes`.
4. **Provider integration matrix** — CI (or nightly) runs against public
   test tenants (e.g., Keycloak) to catch provider-side quirks.
5. **More e2e scenarios** — `PAM_ABORT` (user interrupt mid-poll), group
   allow/deny denials, `use_pkce = auto` discovery probe, transient 429/5xx
   backoff.
6. **Config parser fuzzing** — libFuzz/oss-fuzz over `parse_config_file`
   inputs.
