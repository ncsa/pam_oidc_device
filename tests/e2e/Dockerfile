# pam_oidc_device end-to-end sandbox (one-command test environment).
#
#   make sandbox        -> build this image and run tests/e2e/run_e2e.sh
#   make sandbox-shell  -> drop into an interactive shell to explore
#
# Build context is the repository root (invoked as:
#   docker build -f tests/e2e/Dockerfile -t pam_oidc_device-e2e:local .)
#
# The image is a disposable Ubuntu 24.04 host with the module built and
# installed exactly like a production install; the mock OIDC provider, TLS
# trust, PAM fixture stack, and test users are set up at run time by
# tests/e2e/run_e2e.sh, so the same harness runs in Docker, in CI, and on a
# disposable Linux host.

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# PAM toolchain + e2e dependencies.  `pamtester` is installed for interactive
# use inside the sandbox shell (see docs/testing.md); the automated suite uses
# the deterministic tests/e2e/pam_driver instead.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        libpam0g-dev \
        libcurl4-openssl-dev \
        libjson-c-dev \
        libcmocka-dev \
        libssl-dev \
        make \
        openssl \
        pamtester \
        python3 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/pam_oidc_device

COPY Makefile Makefile
COPY src/ src/
COPY include/ include/
COPY third_party/ third_party/
COPY config/ config/
COPY tests/ tests/
COPY LICENSE README.md THIRD_PARTY_NOTICES.md ./

# Pre-stage the sandbox config (root:root 0600) so `make install` skips the
# stock sample; run_e2e.sh reuses it at run time.
COPY tests/e2e/pam_oidc_device.e2e.conf /etc/pam_oidc_device.conf
RUN chown root:root /etc/pam_oidc_device.conf && chmod 0600 /etc/pam_oidc_device.conf

# Build and install the module the way operators do.  The PAM module dir is
# computed per architecture: /lib64/security on Enterprise Linux, the
# multiarch dir (/lib/x86_64-linux-gnu/security, /lib/aarch64-linux-gnu/...)
# on Debian/Ubuntu.
RUN set -eux; \
    PAM_DIR="$( [ -d /lib64/security ] && echo /lib64/security \
        || echo "/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)/security" )"; \
    make CC=gcc; \
    make install PAM_DIR="$PAM_DIR" CONFIG_DIR=/etc

# Test identities for the sandbox (claims map to these local accounts).
RUN useradd --no-create-home --shell /usr/sbin/nologin alice && \
    useradd --no-create-home --shell /usr/sbin/nologin bob

# Second uid-0 account ("toor") to pin the allow_root guard: it must refuse ANY
# uid-0 account name, not just "root" (e2e scenario uid0-alias-denied).
RUN useradd --no-create-home --shell /usr/sbin/nologin -o -u 0 toor

CMD ["bash"]
