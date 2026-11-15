/**
 * @file fuzz_string_validators.c
 * @brief libFuzzer harness for the pure single-string guards.
 *
 * Drives the terminal-injection and URL-safety guards plus the checked copy
 * and log-level parser with arbitrary bytes. These are allocation-light,
 * stateless functions that sit directly in front of untrusted, provider- or
 * operator-supplied text reaching the terminal or the TLS layer, so any
 * overflow or undefined behavior here is a real defect.
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
    static char buf[2048];
    size_t n = size < sizeof(buf) - 1 ? size : sizeof(buf) - 1;
    memcpy(buf, data, n);
    buf[n] = '\0';

    /* Pure single-string guards: no shared state, fixed-size outputs only. */
    (void)is_valid_https_url(buf);
    (void)is_safe_terminal_string(buf);
    (void)is_safe_user_code(buf);

    char dst[128];
    (void)copy_checked(dst, sizeof(dst), buf);
    secure_memzero(dst, sizeof(dst));

    loglevel_t lv = LOGLEVEL_NONE;
    (void)parse_loglevel(buf, &lv);

    secure_memzero(buf, sizeof(buf));
    return 0;
}
