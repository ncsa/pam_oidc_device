---
name: add-c-module
description: Add a new C source file (src/*.c) with its header, wire it into the Makefile OBJS and the lint gates, add tests, and keep .gitattributes/packaging consistent. Use when introducing a new module or subsystem.
---

# Add a C Module

**Steps:**
1. Create `src/<name>.c` (and `include/<name>.h` if it exposes a public API). Follow existing
   conventions: C99/C11 + `-D_GNU_SOURCE`, `goto cleanup` teardown, caller-frees ownership, and
   `secure_memzero`/`secure_zero_json_tree` for any sensitive buffer.
2. **Build:** add the object to `OBJS` in `Makefile` (keep dependency order — the new object
   before its dependents, with `pam_module.o` last).
3. **Lint scope:** the CI gates already glob `src/*.c` (clang-format / clang-tidy / cppcheck), so
   a new file is picked up automatically — but run `make lint` and
   `clang-tidy src/*.c -- -Iinclude -D_GNU_SOURCE` to confirm it's clean.
4. **Tests:** add CMocka cases to `tests/test_suite.c` (the suite compiles `$(OBJS)`); cover null
   inputs, allocation failure, and malformed input.
5. **Packaging/export:** new source files ship via the `make rpm` tarball automatically; if you
   add a non-source asset, mirror the `export-ignore` rules in `.gitattributes`.
6. **Verify:**
   ```bash
   make clean && make CC=gcc  && make test CC=gcc
   make clean && make CC=clang && make test CC=clang
   make test-sanitize CC=clang
   ```
   (zero-warning under both compilers.)

See `.agents/context.md` §1 (subsystem layout) and §4 (code & security guardrails).
