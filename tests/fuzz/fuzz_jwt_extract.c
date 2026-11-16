/**
 * @file fuzz_jwt_extract.c
 * @brief libFuzzer harness for jwt_extract_claim_string().
 *
 * Exercises the Base64URL decode, JWT 3-part structure validation, JSON
 * payload parsing, claim lookup, and the scrub-before-free JSON-tree
 * discipline against arbitrary bytes. The full 3-part JWT is the primary
 * input; an internal NUL (when present in the fuzzer buffer) additionally
 * fuzzes the claim-name argument. A small set of realistic claim names is
 * also probed against the same token so the extraction/lookup paths are
 * exercised even when no NUL is embedded.
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
    static char tok[4096];
    size_t n = size < sizeof(tok) - 1 ? size : sizeof(tok) - 1;
    memcpy(tok, data, n);
    tok[n] = '\0';

    /* Split at the first internal NUL to fuzz the claim-name argument too. */
    char *nul = memchr(tok, '\0', n);
    const char *claim = "sub";
    if (nul && nul[1] != '\0') {
        claim = nul + 1;
    }

    char out[512];
    jwt_extract_claim_string(tok, claim, out, sizeof(out));

    /* Also probe a small set of realistic claim names against the same token. */
    static const char *const names[] = {"sub", "iss", "aud", "exp", "nbf", "groups", "roles"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        jwt_extract_claim_string(tok, names[i], out, sizeof(out));
    }

    secure_memzero(out, sizeof(out));
    secure_memzero(tok, sizeof(tok));
    return 0;
}
