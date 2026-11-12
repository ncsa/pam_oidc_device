---
name: sanitizer-audit
description: Build and run the CMocka suite under ASan+UBSan+LSan (`make test-sanitize CC=clang`) and triage findings (heap/stack overflow, use-after-free, undefined behavior, leaks). Use when investigating memory errors or verifying the sanitizer gate.
---

# Sanitizer Audit (ASan / UBSan / LSan)

**Run the gate:**
```bash
make test-sanitize CC=clang
```
This recompiles the module + test suite with
`-fsanitize=address -fsanitize=undefined -fsanitize=leak -fno-omit-frame-pointer` and *executes*
the runner under `ASAN_OPTIONS=detect_leaks=1`,
`LSAN_OPTIONS=suppressions=tests/lsan.supp`, and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`.

**Triage findings:**
1. **ASan** — heap/stack buffer overflow, use-after-free: map the stack trace to `src/*.c`;
   confirm the offending buffer's size and ownership (caller-frees convention).
2. **UBSan** — integer overflow / null-deref / bad shift: locate the arithmetic and guard it.
3. **LSan** — leaks: check whether the pointer is freed on *all* exit paths (including
   `goto cleanup`). Intentional process-lifetime third-party allocations (libcurl global state)
   are suppressed in `tests/lsan.supp` — if a genuine new leak appears, add a test-side free
   rather than a blanket suppression.
4. Re-run until clean. A leak or overflow found here is a real defect (unlike a macOS native
   build failure, which is an environment limitation — see `.agents/context.md` §3.3).

**Note:** `make sanitize` (compile-only) is **not** a CI gate — always use `test-sanitize`,
which actually runs the tests. See `.agents/context.md` §3.
