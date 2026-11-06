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
#     make VERSION=0.2.0
# Keep these in sync with include/metadata.h when the metadata changes.
NAME        ?= pam_oidc_device
VERSION     ?= 0.1.0
DESCRIPTION ?= PAM authentication module for OAuth 2.0 Device Authorization Grant

CC ?= gcc
CPPFLAGS += -Iinclude -D_GNU_SOURCE
CFLAGS ?= -fstack-protector-strong -D_FORTIFY_SOURCE=3 \
          -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Wformat-security -O2 -g
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

TARGET = $(NAME).so
OBJS = src/config.o src/http.o src/identity.o src/jwt.o src/pkce.o src/pam_module.o
CONFIG_DEFAULT = config/$(NAME).conf

PAM_DIR ?= /lib64/security
CONFIG_DIR ?= /etc

.PHONY: all build lint sanitize test test-sanitize install uninstall clean rpm

all: build

build: $(TARGET)

# Run the local lint/static-analysis gate (clang-format + clang-tidy +
# cppcheck + flawfinder), mirroring .github/workflows/lint.yml exactly.
# See scripts/lint.sh for the single source of truth.
lint:
	./scripts/lint.sh

src/%.o: src/%.c
	$(CC) -fPIC $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) -shared $(LDFLAGS) -o $@ $^ $(LIBS)

sanitize:
	@mkdir -p build/sanitize
	$(CC) $(CPPFLAGS) -fPIC -shared -Wall -Wextra -g \
		-fsanitize=address -fsanitize=undefined -fsanitize=leak \
		-o build/sanitize/$(TARGET) src/config.c src/http.c src/identity.c src/jwt.c src/pkce.c src/pam_module.c $(LIBS)

test: $(OBJS)
	$(CC) $(CPPFLAGS) -Wall -Wextra -g tests/test_suite.c $(OBJS) \
		-o tests/runner -lcmocka $(LIBS)
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
test-sanitize:
	@mkdir -p build/sanitize
	$(CC) $(CPPFLAGS) -Wall -Wextra -g $(SAN_FLAGS) \
		tests/test_suite.c src/config.c src/http.c src/identity.c src/jwt.c src/pkce.c src/pam_module.c \
		-o $(SAN_RUNNER) -lcmocka $(LIBS)
	ASAN_OPTIONS=detect_leaks=1 \
	LSAN_OPTIONS=suppressions=$(CURDIR)/tests/lsan.supp \
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
	$(SAN_RUNNER)
	@rm -rf build/sanitize

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
	rm -f src/*.o $(TARGET) tests/runner
	rm -rf build/ rpmbuild/

rpm:
	mkdir -p rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	tar --transform 's,^,$(NAME)-$(VERSION)/,' -czf rpmbuild/SOURCES/$(NAME)-$(VERSION).tar.gz \
		src include config packaging Makefile README.md LICENSE SECURITY.md CHANGELOG.md tests
	cp packaging/$(NAME).spec rpmbuild/SPECS/
	python3 packaging/gen-changelog.py CHANGELOG.md include/metadata.h >> rpmbuild/SPECS/$(NAME).spec
	rpmbuild --define "_topdir $(CURDIR)/rpmbuild" \
		--define "mod_name $(NAME)" \
		--define "mod_version $(VERSION)" \
		--define "mod_summary $(DESCRIPTION)" \
		-ba rpmbuild/SPECS/$(NAME).spec
