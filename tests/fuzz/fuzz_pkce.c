/**
 * @file fuzz_pkce.c
 * @brief libFuzzer harness for pkce_compute_s256_challenge().
 *
 * Exercises the S256 code-challenge computation (SHA-256 over an arbitrary
 * verifier plus Base64URL no-pad encoding and its output-length bounds check)
 * with arbitrary bytes. The verifier is always NUL-terminated; OpenSSL's
 * digest and the bounded encoder are the paths under test.
 *
 * @project     pam_oidc_device
 * @repository  https://github.com/ncsa/pam_oidc_device
 * @maintainer  National Center for Supercomputing Applications (NCSA)
 * @license     MIT License
 *
 * Copyright (c) 2026 The Board of Trustees of the University of Illinois.
 * SPDX-License-Identifier: MIT
 */

#include "pam_oidc_device.h"

#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static char verifier[512];
    size_t n = size < sizeof(verifier) - 1 ? size : sizeof(verifier) - 1;
    memcpy(verifier, data, n);
    verifier[n] = '\0';

    char out[64];
    pkce_compute_s256_challenge(verifier, out, sizeof(out));

    secure_memzero(out, sizeof(out));
    secure_memzero(verifier, sizeof(verifier));
    return 0;
}
