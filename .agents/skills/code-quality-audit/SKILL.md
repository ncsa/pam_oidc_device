---
name: code-quality-audit
description: Review C code for maintainability (cyclomatic complexity, error-handling consistency, helper/Doxygen gaps), documentation accuracy vs the implementation, and CMocka test coverage gaps. Use for maintainability reviews or before a release.
---

# Code Quality, Maintainability & Documentation Audit

Act as a Lead C Developer and Technical Writer. Examine:

1. **Code structure & maintainability** — functions with high cyclomatic complexity,
   inconsistent error-handling return codes, redundant helper functions, or missing Doxygen
   function headers.
2. **Documentation accuracy** — `README.md`, the `docs/` guides, and inline comments accurately
   reflect the actual C implementation, syslog levels, and configuration parameters.
3. **Test suite coverage** — the CMocka suite in `tests/test_suite.c`: identify untested edge
   cases (null inputs, memory allocation failures, malformed JSON structures, invalid regex
   rules, network transport errors); confirm test isolation and weak-symbol mocking reliability.

**Steps:**
1. Run `make test CC=gcc` (and `make test CC=clang`) to establish the suite's current baseline
   before judging coverage.
2. Provide structural refactoring suggestions, documentation corrections, and specific new test
   cases to improve coverage and readability.

See `.agents/context.md` §10.4 for the canonical prompt.
