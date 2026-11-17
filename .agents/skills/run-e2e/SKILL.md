---
name: run-e2e
description: Drive the one-command e2e device-flow sandbox (`make sandbox`, Docker) that runs the installed module through a real PAM stack against the in-repo HTTPS mock IdP, and add a new scenario to the harness. Use for end-to-end validation of the device flow/PKCE.
---

# Run / Extend the e2e Sandbox

**Run it:**
```bash
make sandbox        # builds the module, installs it into a PAM stack, runs the 9-scenario harness
make sandbox-shell  # enter the sandbox image interactively for manual PAM tests
```
`tests/e2e/run_e2e.sh` drives the **installed** `pam_oidc_device.so` through a real PAM stack
(`/etc/pam.d/e2e`) against the in-repo HTTPS mock provider (`tests/e2e/mock_oidc.py`, PKCE S256
enforced). Mirrored by the CI `e2e-sandbox` job.

**Add a scenario:**
1. Add a case to the scenario set in `tests/e2e/run_e2e.sh` (each writes a per-case `.out`).
2. Extend `mock_oidc.py` if the case needs a new provider behavior (e.g. `slow_down`, transient
   429/5xx, group allow/deny denials, `PAM_ABORT` mid-poll — see `docs/developer/roadmap.md`
   item #5).
3. Update fixtures: `pam_oidc_device.e2e.conf` and `pam.d-e2e` as needed.
4. Run `make sandbox` and confirm the new case passes; touch `pam_driver.c` if a new
   deterministic PAM driver behavior is required.

**Notes:** The harness must keep working both as root (`make sandbox`) and unprivileged (the CI
job). See `.agents/context.md` §1 (tests/e2e layout) and the `e2e-sandbox` entry in
`.agents/memory.md` for the root/non-root privilege gotchas.
