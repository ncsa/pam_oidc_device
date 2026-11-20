# Module identity (NAME / VERSION / DESCRIPTION)
#
# These defaults mirror include/metadata.h, which is the single source of truth
# for module identity. They are intentionally hardcoded rather than parsed with
# `$(shell sed 's/.../\(.*\)/...')`: that sed regex's parentheses break the
# `$(...)` scanner on older GNU make (e.g. the 3.81 shipped with macOS, which
# fails with: "unterminated call to function `shell': missing `)'`), so a
# portable hardcoded default is used instead.
#
# Each value uses `?=` so it remains a default that can still be overridden
# from the environment or command line, e.g.:
#     make VERSION=0.3.0
# Keep these in sync with include/metadata.h when the metadata changes.
NAME        ?= pam_oidc_device
VERSION     ?= 0.3.6
DESCRIPTION ?= PAM authentication module for OAuth 2.0 Device Authorization Grant

CC ?= gcc
CPPFLAGS += -Iinclude -D_GNU_SOURCE
# -D_FORTIFY_SOURCE=2 (not 3): level 3 is only honored by glibc >= 2.39 / GCC 12+;
# on EL8/EL9 (glibc 2.28/2.34) glibc emits
#   #warning _FORTIFY_SOURCE > 2 is treated like 2 on this platform
# which is fatal under the CI zero-warning bar (-Werror). Level 2 is the maximum
# universally-supported level and the project's documented hardening target
# (`.agents/context.md` §10.3), and it builds warning-free on every target distro.
CFLAGS ?= -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
          -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Wformat-security -fPIE -O2 -g
# NOTE: no -pie at link time. -pie is an *executable* link flag: with -shared
# the gcc driver still pulls in the executable CRT start file (Scrt1.o), whose
# _start references main, breaking the link ("undefined reference to `main'").
# The module is a shared library: -fPIC/-fPIE objects plus -shared already make
# it fully position-independent on all target distros; -pie is redundant and,
# on modern binutils (e.g. Ubuntu gcc 14), actively harmful here.
LDFLAGS ?= -Wl,-z,relro,-z,now
# -lpthread is required on EL8 (glibc < 2.34, where libpthread is still a
# separate library; src/http.c uses pthread_once) and is a harmless no-op on
# EL9+ (pthread merged into libc), Debian, and macOS.
LIBS = -lpam -lcurl -ljson-c -lcrypto -lpthread

# Sanitizer flags for the test-execution gate (`make test-sanitize`).
# -fsanitize=address       ASan: heap/stack buffer overflow, use-after-free
# -fsanitize=undefined     UBSan: integer overflow, null-deref, shift, ...
# -fsanitize=leak          LSan: memory leak detection (enabled at exit)
# -fno-omit-frame-pointer  Keep stack traces readable under the sanitizers
SAN_FLAGS  = -fsanitize=address -fsanitize=undefined -fsanitize=leak -fno-omit-frame-pointer
SAN_RUNNER = build/sanitize/runner

# Extra flags appended to every compile recipe. CI passes
# `EXTRA_CFLAGS=-Werror` to mechanically enforce the documented zero-warning
# bar (see .github/workflows/build.yml); the default is empty for local builds.
# `?=` (not `=`) so a developer-supplied EXTRA_CFLAGS — in the environment or
# on the command line — is honored instead of silently clobbered.
EXTRA_CFLAGS ?=

TARGET = $(NAME).so
OBJS = src/config.o src/http.o src/identity.o src/jwt.o src/message.o src/pkce.o src/qr.o third_party/qrcodegen/qrcodegen.o src/pam_module.o
CONFIG_DEFAULT = config/$(NAME).conf

PAM_DIR ?= /lib64/security
CONFIG_DIR ?= /etc

.PHONY: all build lint check-scrub check-licenses sanitize test test-sanitize fuzz-preflight fuzz fuzz-build sandbox sandbox-shell install uninstall clean rpm deb

all: build

build: $(TARGET)

# Run the local lint/static-analysis gate (clang-format + clang-tidy +
# cppcheck + flawfinder + memory-scrub inspection), mirroring
# .github/workflows/lint.yml exactly. See scripts/lint.sh for the
# single source of truth.
lint:
	./scripts/lint.sh

# Memory-management inspection (`.agents/context.md` §4.1): verifies that sensitive
# buffers (tokens, secrets, PKCE material, HTTP response bodies, JSON PII
# trees) are zeroed with secure_memzero()/explicit_bzero()/
# secure_zero_json_tree() before every release (free()/json_object_put()).
# Pure bash — runs on any host; also part of `make lint` and the CI
# "memory-scrub" job.
check-scrub:
	./scripts/check-memory-scrubbing.sh

# Third-party license compliance (THIRD_PARTY_NOTICES.md): notices file present
# at the repo root, every third_party/*/ component carries license text +
# attribution + provenance pin, no copyleft text in third_party/, and every
# runtime dependency from the RPM spec's Requires: line is declared in the
# notices file. Pure bash — runs on any host; also the CI "license-compliance"
# job in .github/workflows/license-audit.yml.
check-licenses:
	./scripts/check-licenses.sh

# One-command end-to-end sandbox (docs/testing.md): builds an Ubuntu 24.04
# image with the module installed exactly like production, then runs the full
# device-flow scenario suite (tests/e2e/run_e2e.sh) against the in-image mock
# OIDC provider.  The host system is never modified.
sandbox:
	@command -v docker >/dev/null 2>&1 || { echo "make sandbox: 'docker' not found in PATH" >&2; exit 1; }
	docker build -f tests/e2e/Dockerfile -t $(NAME)-e2e:local .
	docker run --rm --name $(NAME)-e2e $(NAME)-e2e:local /opt/pam_oidc_device/tests/e2e/run_e2e.sh

# Same image, interactive shell: explore manually, e.g.
#   python3 tests/e2e/mock_oidc.py ... &      then
#   tests/e2e/pam_driver e2e alice            or
#   pamtester e2e alice authenticate
sandbox-shell:
	@command -v docker >/dev/null 2>&1 || { echo "make sandbox-shell: 'docker' not found in PATH" >&2; exit 1; }
	docker build -f tests/e2e/Dockerfile -t $(NAME)-e2e:local .
	docker run --rm -it --name $(NAME)-e2e-shell $(NAME)-e2e:local

src/%.o: src/%.c
	$(CC) -fPIC $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

# Vendored third-party code (Nayuki QR Code generator) is kept outside src/ so it
# is not subject to the project's lint/static-analysis gates. It is compiled with
# the hardening flags and basic warnings, but deliberately NOT held to the
# project's strict -Wconversion / -Wpedantic / -Werror bar: the upstream code
# predates those checks, and its int->uint8_t module-bit writes
# (setModuleBounded) trip -Wconversion on older compilers (EL8's GCC 8), where
# -Werror would otherwise break the build. Dropping the strict warning set and
# EXTRA_CFLAGS for this one TU keeps upstream pristine (preserving the
# in-directory drift audit) while -fstack-protector-strong / -D_FORTIFY_SOURCE=2
# / -fPIE / -O2 preserve the same code hardening the rest of the module gets.
QR_CFLAGS = -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Wextra -fPIE -O2 -g
third_party/qrcodegen/%.o: third_party/qrcodegen/%.c
	$(CC) -fPIC $(CPPFLAGS) $(QR_CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) -shared $(LDFLAGS) -o $@ $^ $(LIBS)

sanitize:
	@mkdir -p build/sanitize
	$(CC) $(CPPFLAGS) -fPIC -shared -Wall -Wextra $(EXTRA_CFLAGS) -g \
		-fsanitize=address -fsanitize=undefined -fsanitize=leak \
		-o build/sanitize/$(TARGET) src/config.c src/http.c src/identity.c src/jwt.c src/message.c src/pkce.c src/qr.c third_party/qrcodegen/qrcodegen.c src/pam_module.c $(LIBS)

test: $(OBJS)
	$(CC) $(CPPFLAGS) -Wall -Wextra $(EXTRA_CFLAGS) -g tests/test_suite.c $(OBJS) \
		-o tests/runner -lcmocka $(LIBS) -ldl
	./tests/runner
	@rm -f tests/runner

# Build AND RUN the CMocka test suite under ASan + UBSan + LSan.
# Unlike `sanitize` (compile-only), this executes the tests, so heap
# overflow/underflow, use-after-free, undefined behavior, and memory leaks
# are actually detected. The sources are recompiled (not $(OBJS)) so the
# module code itself is instrumented; only the strict CFLAGS subset the
# plain `test` target already proves warning-clean is applied, plus the
# sanitizer flags.
#
# LSan suppression file (tests/lsan.supp) documents intentional
# process-lifetime third-party allocations (libcurl global state) that the
# standalone test binary would otherwise report as leaks at exit.
# -ldl: tests/test_suite.c resolves the real getpwnam_r() via dlsym(RTLD_NEXT);
# required on EL8 (glibc < 2.34, where dlsym still lives in libdl), a no-op
# stub on glibc >= 2.34 and on Debian/openSUSE.
test-sanitize:
	@mkdir -p build/sanitize
	$(CC) $(CPPFLAGS) -Wall -Wextra $(EXTRA_CFLAGS) -g $(SAN_FLAGS) \
		tests/test_suite.c src/config.c src/http.c src/identity.c src/jwt.c src/message.c src/pkce.c src/qr.c third_party/qrcodegen/qrcodegen.c src/pam_module.c \
		-o $(SAN_RUNNER) -lcmocka $(LIBS) -ldl
	ASAN_OPTIONS=detect_leaks=1 \
	LSAN_OPTIONS=suppressions=$(CURDIR)/tests/lsan.supp \
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
	$(SAN_RUNNER)
	@rm -rf build/sanitize

# ---------------------------------------------------------------------------
# Fuzzing (OPT-IN; not part of `make lint` and not run by any CI workflow).
#
# Builds and runs clang/libFuzzer crash/UB/leak harnesses over the module's
# pure, input-parsing leaf functions (config parser, JWT base64url/claim
# extraction, token-metadata checks, the terminal/URL string guards, regex
# claim verification, and the PKCE S256 challenge). Each harness re-instruments
# the module sources under ASan+UBSan+LSan -- the same sanitizer set as
# `make test-sanitize` -- and drives a single function with fuzzer-generated
# bytes. See tests/fuzz/README.md for rationale and crash triage.
#
# Usage:
#   make fuzz                  # build + run every harness (FUZZ_MAX_TIME s each)
#   make fuzz FUZZ_MAX_TIME=300 FUZZ_TARGETS=config   # one harness, longer
#   make fuzz-build            # compile the harnesses only (no run)
#
# Requires clang (libFuzzer is clang-native) plus the same dev packages as the
# native build: libpam0g-dev libcurl4-openssl-dev libjson-c-dev libssl-dev.
# New "interesting" inputs are written under build/fuzz/ (git-ignored); the
# committed seed corpus in tests/fuzz/seed/ is copied, never mutated.
FUZZ_CC       ?= clang
FUZZ_MAX_TIME ?= 30
FUZZ_FLAGS    = -fsanitize=fuzzer,address,undefined,leak -fno-omit-frame-pointer
FUZZ_TARGETS  ?= config jwt_extract token_meta string_validators verify_claim pkce
FUZZ_SRC      = src/config.c src/http.c src/identity.c src/jwt.c src/message.c src/pkce.c \
                src/qr.c third_party/qrcodegen/qrcodegen.c src/pam_module.c

build/fuzz/fuzz_%: tests/fuzz/fuzz_%.c $(FUZZ_SRC)
	@mkdir -p build/fuzz
	$(FUZZ_CC) $(CPPFLAGS) -Wall -Wextra -g $(FUZZ_FLAGS) \
		$< $(FUZZ_SRC) -o $@ $(LIBS)

# Preflight gate for the fuzz targets. Fails fast with actionable, per-platform
# guidance instead of a bare compiler/linker error:
#   * non-Linux host -> libpam has no native macOS/Windows package; use a container.
#   * clang missing  -> libFuzzer is clang-only; print the package-install line.
#   * headers/libs   -> compile+link a trivial probe against pam/json-c/curl/ssl
#                       and print the install line if anything is absent.
fuzz-preflight:
	@mkdir -p build/fuzz; \
	u=$$(uname -s); \
	case "$$u" in \
	  Darwin|*MINGW*|*MSYS*) \
	    echo "ERROR: 'make fuzz' requires a Linux host -- libpam has no native macOS/Windows package,"; \
	    echo "so the fuzz harnesses cannot be built or run here. Run them in a Linux container instead:"; \
	    printf '%s\n' "docker run --rm -v \"\$$PWD:/work\" -w /work -e DEBIAN_FRONTEND=noninteractive -e TZ=America/Chicago ubuntu:24.04 bash -c 'echo \"tzdata tzdata/Areas select America\" | debconf-set-selections; echo \"tzdata tzdata/Zones/America select Chicago\" | debconf-set-selections; apt-get update -qq; apt-get install -y clang make libpam0g-dev libcurl4-openssl-dev libjson-c-dev libssl-dev; make fuzz FUZZ_MAX_TIME=30'" ; \
	    exit 1;; \
	esac; \
	if ! command -v $(FUZZ_CC) >/dev/null 2>&1; then \
	  echo "ERROR: '$(FUZZ_CC)' not found. libFuzzer is clang-only. Install clang and the module dev packages:"; \
	  echo "  RHEL/Rocky   : dnf install -y clang pam-devel libcurl-devel json-c-devel openssl-devel"; \
	  echo "  Debian/Ubuntu: apt-get install -y clang libpam0g-dev libcurl4-openssl-dev libjson-c-dev libssl-dev"; \
	  echo "then re-run 'make fuzz'."; \
	  exit 1; \
	fi; \
	printf '#include "pam_oidc_device.h"\n#include <openssl/evp.h>\nint main(void){return 0;}\n' > build/fuzz/.fuzz_probe.c; \
	if ! $(FUZZ_CC) $(CPPFLAGS) build/fuzz/.fuzz_probe.c -o build/fuzz/.fuzz_probe $(LIBS) >build/fuzz/.fuzz_probe.log 2>&1; then \
	  echo "ERROR: the fuzz build is missing required headers/libraries:"; \
	  sed 's/^/    /' build/fuzz/.fuzz_probe.log; \
	  echo "Install them and re-run 'make fuzz':"; \
	  echo "  RHEL/Rocky   : dnf install -y clang pam-devel libcurl-devel json-c-devel openssl-devel"; \
	  echo "  Debian/Ubuntu: apt-get install -y clang libpam0g-dev libcurl4-openssl-dev libjson-c-dev libssl-dev"; \
	  echo "(macOS/Windows: run 'make fuzz' in a Linux container -- see tests/fuzz/README.md)"; \
	  exit 1; \
	fi; \
	rm -f build/fuzz/.fuzz_probe.c build/fuzz/.fuzz_probe build/fuzz/.fuzz_probe.log

fuzz-build: fuzz-preflight $(addprefix build/fuzz/fuzz_, $(FUZZ_TARGETS))

fuzz: fuzz-preflight $(addprefix build/fuzz/fuzz_, $(FUZZ_TARGETS))
	@rc=0; \
	for t in $(FUZZ_TARGETS); do \
		echo "==== fuzz $$t  (max_total_time=$(FUZZ_MAX_TIME)s) ===="; \
		rm -rf build/fuzz/corpus_$$t; mkdir -p build/fuzz/corpus_$$t; \
		cp -fR tests/fuzz/seed/$$t/. build/fuzz/corpus_$$t/ 2>/dev/null || true; \
		if ./build/fuzz/fuzz_$$t -max_total_time=$(FUZZ_MAX_TIME) -rss_limit_mb=4096 \
				-artifact_prefix=build/fuzz/ build/fuzz/corpus_$$t; then \
			echo "PASS: fuzz_$$t crash/UB/leak-free"; \
		else \
			echo "FAIL: fuzz_$$t found a crash/UB/leak -- reproducer in build/fuzz/ (crash-*)"; \
			rc=1; \
		fi; \
	done; \
	exit $$rc

install: $(TARGET)
	install -d $(DESTDIR)$(PAM_DIR)
	install -d $(DESTDIR)$(CONFIG_DIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(PAM_DIR)/$(TARGET)
	@if [ ! -f $(DESTDIR)$(CONFIG_DIR)/$(NAME).conf ]; then \
		install -m 0600 $(CONFIG_DEFAULT) $(DESTDIR)$(CONFIG_DIR)/$(NAME).conf; \
	fi

uninstall:
	rm -f $(DESTDIR)$(PAM_DIR)/$(TARGET)

clean:
	rm -f src/*.o third_party/qrcodegen/*.o $(TARGET) tests/runner
	rm -rf build/ rpmbuild/

# `rpm` always starts from `clean` so the source tarball is packaged from a
# pristine tree: a prior local build's stale *.o files (or the module .so)
# must never leak into the distributed source tarball.
rpm: clean
	mkdir -p rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	tar --transform 's,^,$(NAME)-$(VERSION)/,' -czf rpmbuild/SOURCES/$(NAME)-$(VERSION).tar.gz \
		src include third_party config packaging Makefile README.md LICENSE THIRD_PARTY_NOTICES.md SECURITY.md CHANGELOG.md tests
	cp packaging/$(NAME).spec rpmbuild/SPECS/
	python3 packaging/gen-changelog.py CHANGELOG.md include/metadata.h >> rpmbuild/SPECS/$(NAME).spec
	rpmbuild --define "_topdir $(CURDIR)/rpmbuild" \
		--define "mod_name $(NAME)" \
		--define "mod_version $(VERSION)" \
		--define "mod_summary $(DESCRIPTION)" \
		-ba rpmbuild/SPECS/$(NAME).spec

# DEB packaging (Debian / Ubuntu): binary .deb hand-crafted by
# packaging/build-deb.sh (dpkg-deb + dpkg-shlibdeps — no debhelper toolchain
# needed; `dpkg-shlibdeps` derives distribution-correct runtime Depends).
# Requires a Debian/Ubuntu host with dpkg-dev plus the build dependencies:
#   sudo apt-get install -y build-essential dpkg-dev python3 \
#     libpam0g-dev libcurl4-openssl-dev libjson-c-dev libcmocka-dev libssl-dev
# CI: the "distro-build" job in .github/workflows/distro-build.yml runs
# `make deb` on Debian 13 and Ubuntu 26.04 LTS.
deb:
	./packaging/build-deb.sh $(NAME) $(VERSION) "$(DESCRIPTION)"
