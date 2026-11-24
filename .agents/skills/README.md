# `.agents/skills/` — Reusable Cross-Tool Workflows

Follows the [Agent Skills specification](https://agentskills.io): each skill is a directory
holding a `SKILL.md` (YAML frontmatter with `name` + `description`, then step-by-step
instructions) plus any supporting `references/` or `scripts/`.

Agents read only the `description` at startup and load a full `SKILL.md` on demand, so keep
descriptions precise about *when* the skill applies.

```
.agents/skills/
└── <skill-name>/
    ├── SKILL.md          # YAML frontmatter (name, description) + procedure
    ├── references/       # optional templates / headers / examples
    └── scripts/          # optional self-contained shell/python helpers
```

Skills in this repo (one directory each, frontmatter `name` + `description` + procedure):

> **Local environment failures are not skill defects.** When a skill's gate fails for a
> *host-environment* reason (terminal/CLI mangles commands, container won't build or mount
> the repo, tool version skew, missing host deps), do not log it in `.agents/memory.md` as a
> code finding — record the failure **and the working workaround** in
> `.agents/memory.local.md` (git-ignored, host-local; see `.agents/context.md` §7) and check
> it before rerunning a gate that already "failed" for environmental reasons.

| Skill | What it does | Ported from |
|---|---|---|
| `security-audit` | Security & defensive-engineering pass over `src/` + `include/` | `context.md` §10.1 |
| `protocol-compliance-audit` | RFC 8628/7636/7519/4648/3986 compliance pass | `context.md` §10.2 |
| `build-packaging-audit` | Makefile / `packaging/` / CI / `.gitattributes` audit | `context.md` §10.3 |
| `code-quality-audit` | Maintainability, doc-accuracy, and CMocka coverage review | `context.md` §10.4 |
| `release-bump` | Version sync across the five sources + `CHANGELOG.md` | `memory.md` standing invariant |
| `sanitizer-audit` | Run + triage the ASan/UBSan/LSan gate | `Makefile` + `tests/lsan.supp` |
| `add-c-module` | New `src/*.c` + header, `Makefile`/lint/test/packaging wiring | `Makefile` + `scripts/lint.sh` |
| `run-e2e` | Drive/extend the `make sandbox` device-flow harness | `tests/e2e/` |
