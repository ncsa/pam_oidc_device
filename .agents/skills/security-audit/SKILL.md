---
name: security-audit
description: Run the Security & Defensive Engineering audit pass over src/ and include/ (memory hygiene, buffer/integer safety, POSIX & config-file hardening, terminal-injection defenses, TLS/transport). Use when reviewing C source for vulnerabilities or before a security-focused PR; pairs with `make lint`.
---

# Security & Defensive Engineering Audit

Act as a Senior Security Engineer and C Systems Security Expert. Analyze `src/` and `include/`
for vulnerability vectors and defensive-coding gaps across these domains:

1. **Memory hygiene & buffer safety** — confirm sensitive tokens, client secrets, and JSON trees
   are zeroed via volatile writes (`secure_memzero`, `secure_zero_json_tree`) on **all** exit
   paths (`return`, `goto cleanup`, error branches). Inspect `snprintf`, `memcpy`, `realloc`, and
   fixed-capacity form arrays (`DEVICE_FORM_MAX_FIELDS`, `TOKEN_FORM_MAX_FIELDS`) for integer
   wrap-around or truncation.
2. **POSIX & system hardening** — validate fd/race defenses in `load_config`: strict
   `O_NOFOLLOW` + `O_CLOEXEC`, root-ownership assertion (`uid == 0`), and `0600`/`0640`
   permission enforcement.
3. **Terminal safety & injection** — verify all provider-supplied data (URLs, user codes, prompt
   templates, QR block chars) is sanitized before display
   (`is_safe_terminal_string`, `is_safe_rendered_prompt`).
4. **Network & transport** — confirm `http_request` enforces TLS 1.2+ and peer/host certificate
   verification (`CURLOPT_SSL_VERIFYPEER=1` / `CURLOPT_SSL_VERIFYHOST=2`), request timeouts, and
   `CLOCK_MONOTONIC` monotonic polling.

**Steps:**
1. Run `make check-scrub` (the mechanical scrub gate) to anchor the memory-hygiene baseline.
2. Walk the four domains above against the actual source; cite file + function + root cause.
3. Organize findings by severity (Critical / High / Medium / Low / Informational); for each give
   the file path, function name, flaw description, root-cause analysis, and a recommended patch.

See `.agents/context.md` §10.1 for the canonical prompt and §4 for the guardrails this pass
audits.
