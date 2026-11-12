---
name: release-bump
description: Bump the module version consistently across all five synced sources (metadata.h, Makefile, spec, gen-changelog.py, context.md) plus CHANGELOG.md. Use when cutting a new release version.
---

# Release / Version Bump

The canonical version lives in `include/metadata.h` (`PAM_OIDC_VERSION`, which also feeds the
User-Agent string). A bump must stay in sync across every source or the build, packaging, and
docs drift apart.

**Steps:**
1. `include/metadata.h` — set `PAM_OIDC_VERSION` to the new value.
2. `Makefile` — update the `VERSION ?=` default (keep the "keep in sync with metadata.h" comment).
3. `packaging/pam_oidc_device.spec` — update `%global mod_version`.
4. `packaging/gen-changelog.py` — update its `default_ver`.
5. `.agents/context.md` — update wherever the version is stated.
6. `CHANGELOG.md` — add a dated `## [X.Y.Z] - YYYY-MM-DD` section (move any `[Unreleased]`
   entries into it). Do **not** rewrite historical entries' version strings.
7. Verify with:
   ```bash
   grep -n '<new-version>' include/metadata.h Makefile packaging/pam_oidc_device.spec packaging/gen-changelog.py
   ```
   and confirm `.agents/context.md` now references the new version.

**Gotchas:** `CHANGELOG.md` historical entries keep their original version strings. The version
also feeds the User-Agent string, so a bump is observable on the wire.
