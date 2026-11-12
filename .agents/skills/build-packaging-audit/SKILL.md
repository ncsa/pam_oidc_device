---
name: build-packaging-audit
description: Audit the Makefile, packaging/ specs, .gitattributes, and .github/workflows for compiler hardening, CI least-privilege/SHA-pinning, sanitizer integration, and RPM/DEB install paths. Use when touching the build, CI, or packaging.
---

# Build Systems, Packaging & Automation Audit

Act as a Principal DevOps & Infrastructure Engineer. Audit `Makefile`, `packaging/`, and
`.github/workflows/*.yml`:

1. **Compiler flags & hardening** — essential C security flags enforced (`-Wall`, `-Wextra`,
   `-Werror`, `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-fPIE`, `-Wformat-security`,
   `-z relro`, `-z now`); clean separation between Debug and Release configurations.
2. **CI/CD security & least privilege** — third-party action SHA pinning, explicit minimal
   `permissions:` scopes, and safe handling of context variables in shell to prevent command
   injection.
3. **Sanitizers & dynamic analysis** — ASan/UBSan/LSan + CMocka and `clang-tidy`/`cppcheck`
   cleanly integrated into the automated test targets.
4. **Packaging & distribution** — RPM/DEB specs correctly handle module install paths
   (`/lib64/security`), binary permissions, and `export-ignore` release-tarball exclusion
   patterns in `.gitattributes`.

**Steps:**
1. Run `make lint` and confirm the local gate matches `.github/workflows/lint.yml` verbatim.
2. Deliver concrete recommendations on build reproducibility, pipeline security, and packaging
   integrity.

See `.agents/context.md` §10.3 (canonical prompt) and §3 (the CI-mirrored gate set).
