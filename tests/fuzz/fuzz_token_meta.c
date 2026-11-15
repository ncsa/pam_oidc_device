/**
 * @file fuzz_token_meta.c
 * @brief libFuzzer harness for verify_token_metadata().
 *
 * Exercises the claims-only local JWT inspection path (Base64URL decode,
 * exp/nbf numeric coercion with clock-skew leeway, issuer/audience matching,
 * require_exp_claim policy) against arbitrary bytes. Local claim inspection is
 * enabled in the fixed configuration so all of those branches are reachable;
 * the JWT signature is intentionally never verified here (that is the
 * provider's UserInfo endpoint job), so the input is attacker-shaped without
 * any cryptographic requirement.
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
    static char jwt[4096];
    size_t n = size < sizeof(jwt) - 1 ? size : sizeof(jwt) - 1;
    memcpy(jwt, data, n);
    jwt[n] = '\0';

    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.issuer, "https://idp.example.com/oauth2", sizeof(cfg.issuer) - 1);
    strncpy(cfg.audience, "pam-client", sizeof(cfg.audience) - 1);
    cfg.clock_skew_leeway = 60;
    cfg.loglevel = LOGLEVEL_NONE;
    cfg.verify_jwt_claims = 1;
    cfg.require_exp_claim = 1;

    verify_token_metadata(jwt, &cfg, NULL);

    secure_memzero(&cfg, sizeof(cfg));
    secure_memzero(jwt, sizeof(jwt));
    return 0;
}
