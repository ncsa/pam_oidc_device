/**
 * @file fuzz_verify_claim.c
 * @brief libFuzzer harness for verify_claim().
 *
 * Exercises the POSIX extended-regex extraction and local-username comparison
 * path. The regex *pattern* is held fixed (a safe, representative ERE) so the
 * fuzzer only mutates the *subject* strings (the PAM user and the raw claim)
 * that regexec() consumes; fuzzing the pattern instead would invite
 * catastrophic backtracking / compile-time blow-ups that are not memory bugs.
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
    static char buf[4096];
    size_t n = size < sizeof(buf) - 1 ? size : sizeof(buf) - 1;
    memcpy(buf, data, n);
    buf[n] = '\0';

    /* Split at the first internal NUL: pam_user | raw_claim. When no NUL is
     * present, both sides use the whole buffer (the regex subject path is
     * still exercised either way). */
    char *nul = memchr(buf, '\0', n);
    const char *user = buf;
    const char *claim = (nul && nul[1] != '\0') ? nul + 1 : buf;

    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.claim_regex, "^(.+)@example\\.com$", sizeof(cfg.claim_regex) - 1);
    cfg.claim_capture_group = 1;
    cfg.case_sensitive = 0;
    cfg.loglevel = LOGLEVEL_NONE;

    verify_claim(user, claim, &cfg, NULL);

    secure_memzero(&cfg, sizeof(cfg));
    secure_memzero(buf, sizeof(buf));
    return 0;
}
