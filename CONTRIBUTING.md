# Contributing to pam_oidc_device

Thank you for contributing to the `pam_oidc_device` project!

## Code Style & Formatting

This project enforces strict modern C coding guidelines. Before submitting a Pull Request, format **and** verify all C source, header, and test files (the exact scope CI checks):

```bash
clang-format -i src/*.c include/*.h tests/*.c
clang-format --dry-run --Werror src/*.c include/*.h tests/*.c
```

## Static Analysis & Testing

All PRs must pass the local lint gate, compile with zero warnings under **both** compilers, pass the CMocka suite, pass dynamic sanitizer analysis, and (on every push/PR to `main`) the EL8/EL9/EL10 RPM build plus the SUSE (openSUSE Leap 16.0) RPM and Debian 13 / Ubuntu 26.04 DEB native builds. `make lint` runs clang-format + clang-tidy + cppcheck + flawfinder exactly as `.github/workflows/lint.yml` does. The loop below mirrors the gate set in `AGENTS.md` §3:

```bash
# 1. Lint / static analysis (clang-format, clang-tidy, cppcheck, flawfinder)
make lint

# 2. Compile with zero warnings under the project's strict -W flags, then run
#    the CMocka suite — under both compilers (CI's compile-matrix job)
make clean && make CC=gcc && make test CC=gcc
make clean && make CC=clang && make test CC=clang

# 3. Build AND run the CMocka suite under ASan + UBSan + LSan (CI's
#    sanitize-test job). `make sanitize` is a compile-only smoke check and is
#    NOT a CI gate — run it only as an optional fast pre-check.
make test-sanitize CC=clang

# 4. Packaging (CI's rpm-build job on EL8/EL9/EL10; distro-build.yml adds
#    SUSE Leap 16.0 RPM + Debian 13 / Ubuntu 26.04 DEB)
make rpm          # EL/SUSE host with the spec's BuildRequires
make deb          # Debian/Ubuntu host with dpkg-dev + build deps
```

### Enabling the pre-commit gate (recommended)

So these checks run *before* each `git commit` (not just in CI), point git at the repo's hooks once per clone:

```bash
git config core.hooksPath .githooks
```

The `.githooks/pre-commit` hook invokes `scripts/lint.sh` (the same single source of truth as `make lint`). On a host missing a tool — or that cannot compile the translation units (e.g. macOS, which has no `libpam`) — that check is skipped with a notice, so the hook never blocks a commit for environmental reasons.

## Developing on a Non-Linux Host (macOS)

`pam_oidc_device` is a **Linux PAM** module: it links `-lpam` and its header pulls in `<security/pam_*.h>`. `libpam` has no Homebrew/MacPorts package, so `make`, `make sanitize`, `make test`, and `clang-tidy` **do not run natively on macOS**. A failing native build here is an environment limitation, not a bug — but the Linux quality gates still must pass before your PR is merged.

Run the full gate loop in a **Linux container that mirrors CI** (`ubuntu-latest` + the same apt packages the workflows use):

```bash
docker run -it --rm -v "$PWD:/work" -w /work ubuntu:24.04 \
  bash -lc '
    set -e
    apt-get update
    apt-get install -y build-essential clang clang-format clang-tidy cppcheck \
      libpam0g-dev libcurl4-openssl-dev libjson-c-dev libcmocka-dev libssl-dev
    make lint                                  # lint.yml gates (tools missing here are skipped with a notice)
    make clean && make CC=gcc && make test CC=gcc     # compile-matrix: gcc
    make clean && make CC=clang && make test CC=clang # compile-matrix: clang
    make test-sanitize CC=clang               # sanitize-test: ASan/UBSan/LSan (builds AND RUNS)
  '
```

(Or push your branch and let the GitHub Actions `ubuntu-latest` workflows — `lint.yml` and `build.yml` — run the authoritative gates. The `rpm-build` gate cannot be mirrored in the Ubuntu container — it requires an EL image such as `rockylinux:9` with `rpm-build` and `pam-devel`, as in `build.yml` — or simply run it in CI.)

For PAM-independent logic you can still work locally: `brew install clang-format` for formatting, isolated stub-based compile checks under the project's strict warning flags, and decoding any new base64url JWT test fixtures in Python to confirm they encode the intended JSON. See `AGENTS.md` §3 (Non-Linux Hosts) for details.

## Pull Request Guidelines

1. Ensure GitHub Actions build and static analysis pipelines pass completely.
2. Commit messages should clearly describe the rationale behind the change.
3. Wiping of sensitive memory buffers must use `secure_memzero()` or `explicit_bzero()`.
