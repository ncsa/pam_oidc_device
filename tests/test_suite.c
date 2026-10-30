/**
 * @file test_suite.c
 * @brief CMocka unit test suite covering configuration parsing, log level evaluation, claim mapping, sanitization,
 * prompt rendering, error handling, and local JWT token metadata verification.
 *
 * Exercises unit test cases for core module subroutines including cURL parameter encoding,
 * log level parsing, OpenID identity claim verification, terminal injection sanitization,
 * custom prompt rendering, and JWT exp/nbf/iss/aud claim validation.
 *
 * @project     pam_oidc_device
 * @repository  https://github.com/ncsa/pam_oidc_device
 * @maintainer  National Center for Supercomputing Applications (NCSA)
 * @license     MIT License
 *
 * Copyright (c) 2026 The Board of Trustees of the University of Illinois.
 * SPDX-License-Identifier: MIT
 */

#include "../include/pam_oidc_device.h"

/* clang-format off */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>
/* clang-format on */

/**
 * @brief Unit test verifying cURL URL parameter encoding functionality[cite: 7].
 *
 * Ensures special characters (e.g., '@', '&', '=') are properly percent-encoded per RFC 3986[cite: 7].
 *
 * @param[in,out] state CMocka test state context (unused)[cite: 7].
 */
static void test_url_encoding(void **state) {
    (void)state;
    assert_int_equal(oauth_http_global_init(), 0);

    CURL *curl = curl_easy_init();
    assert_non_null(curl);

    /* Verify percent-encoding of special characters[cite: 7] */
    char *encoded = url_encode_param(curl, "user@example.com&key=value");
    assert_non_null(encoded);
    assert_string_equal(encoded, "user%40example.com%26key%3Dvalue");

    curl_free(encoded);
    curl_easy_cleanup(curl);
}

/**
 * @brief Unit test verifying loglevel string and integer parsing behavior[cite: 7].
 *
 * Tests parsing of "none", "error", "info", "debug", "verbose" as well as numeric strings "0".."4"[cite: 7].
 *
 * @param[in,out] state CMocka test state context (unused)[cite: 7].
 */
static void test_parse_loglevel(void **state) {
    (void)state;
    loglevel_t lvl;

    assert_int_equal(parse_loglevel("none", &lvl), 0);
    assert_int_equal(lvl, LOGLEVEL_NONE);

    assert_int_equal(parse_loglevel("0", &lvl), 0);
    assert_int_equal(lvl, LOGLEVEL_NONE);

    assert_int_equal(parse_loglevel("error", &lvl), 0);
    assert_int_equal(lvl, LOGLEVEL_ERROR);

    assert_int_equal(parse_loglevel("1", &lvl), 0);
    assert_int_equal(lvl, LOGLEVEL_ERROR);

    assert_int_equal(parse_loglevel("info", &lvl), 0);
    assert_int_equal(lvl, LOGLEVEL_INFO);

    assert_int_equal(parse_loglevel("2", &lvl), 0);
    assert_int_equal(lvl, LOGLEVEL_INFO);

    assert_int_equal(parse_loglevel("debug", &lvl), 0);
    assert_int_equal(lvl, LOGLEVEL_DEBUG);

    assert_int_equal(parse_loglevel("3", &lvl), 0);
    assert_int_equal(lvl, LOGLEVEL_DEBUG);

    assert_int_equal(parse_loglevel("VERBOSE", &lvl), 0);
    assert_int_equal(lvl, LOGLEVEL_VERBOSE);

    assert_int_equal(parse_loglevel("4", &lvl), 0);
    assert_int_equal(lvl, LOGLEVEL_VERBOSE);

    assert_int_equal(parse_loglevel("invalid", &lvl), -1);
    assert_int_equal(parse_loglevel(NULL, &lvl), -1);
}

/**
 * @brief Unit test verifying regex capture group extraction for identity claim matching[cite: 7].
 *
 * Tests pattern compilation, capture group extraction, and target username matching[cite: 7].
 *
 * @param[in,out] state CMocka test state context (unused)[cite: 7].
 */
static void test_verify_claim_capture_group(void **state) {
    (void)state;
    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.claim_regex, "^([^@]+)@illinois\\.edu$", sizeof(cfg.claim_regex) - 1);
    cfg.claim_capture_group = 1;
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;

    /* Case 1: Valid match where extracted claim matches requesting PAM username[cite: 7] */
    int valid = verify_claim("testuser", "testuser@illinois.edu", &cfg, NULL);
    assert_int_equal(valid, 1);

    /* Case 2: Mismatch where extracted claim differs from requesting PAM username[cite: 7] */
    int invalid = verify_claim("wronguser", "testuser@illinois.edu", &cfg, NULL);
    assert_int_equal(invalid, 0);
}

/**
 * @brief Unit test verifying case-insensitive identity claim matching behavior[cite: 7].
 *
 * Validates that setting `case_sensitive = 0` enables case-insensitive ASCII comparison[cite: 7].
 *
 * @param[in,out] state CMocka test state context (unused)[cite: 7].
 */
static void test_verify_claim_case_insensitivity(void **state) {
    (void)state;
    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.claim_regex, "^([^@]+)@illinois\\.edu$", sizeof(cfg.claim_regex) - 1);
    cfg.claim_capture_group = 1;
    cfg.case_sensitive = 0;
    cfg.loglevel = LOGLEVEL_NONE;

    /* Verify case-insensitive match ("TestUser" vs "testuser")[cite: 7] */
    int valid = verify_claim("TestUser", "testuser@illinois.edu", &cfg, NULL);
    assert_int_equal(valid, 1);
}

/**
 * @brief Unit test verifying regex capture group bounds checking[cite: 7].
 *
 * Ensures requesting a capture group index exceeding pattern bounds is safely rejected[cite: 7].
 *
 * @param[in,out] state CMocka test state context (unused)[cite: 7].
 */
static void test_verify_claim_invalid_bounds(void **state) {
    (void)state;
    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.claim_regex, "^([^@]+)@illinois\\.edu$", sizeof(cfg.claim_regex) - 1);
    cfg.claim_capture_group = 5; /* Capture group index out of bounds[cite: 7] */
    cfg.loglevel = LOGLEVEL_NONE;

    int result = verify_claim("testuser", "testuser@illinois.edu", &cfg, NULL);
    assert_int_equal(result, 0);
}

/**
 * @brief Unit test verifying input sanitizers against control character and header injection[cite: 7].
 *
 * Exercises `is_safe_terminal_string`, `is_safe_user_code`, and `is_valid_https_url`[cite: 7].
 *
 * @param[in,out] state CMocka test state context (unused)[cite: 7].
 */
static void test_terminal_and_user_code_sanitizer(void **state) {
    (void)state;
    /* Validate terminal display string sanitizer[cite: 7] */
    assert_int_equal(is_safe_terminal_string("USER-CODE-123"), 1);
    assert_int_equal(is_safe_terminal_string("Code\x1b[31mRed"), 0); /* Rejects ANSI escape sequences[cite: 7] */

    /* Validate user code sanitizer[cite: 7] */
    assert_int_equal(is_safe_user_code("BCD-123"), 1);
    assert_int_equal(is_safe_user_code("Code\n[Header]"), 0); /* Rejects newline/header injection[cite: 7] */

    /* Validate URL sanitizer[cite: 7] */
    assert_int_equal(is_valid_https_url("https://auth.example.edu/device"), 1);
    assert_int_equal(is_valid_https_url("http://insecure.example.edu/device"), 0); /* Rejects HTTP scheme[cite: 7] */
    assert_int_equal(is_valid_https_url("https://user:pass@auth.example.edu/device"),
                     0); /* Rejects userinfo[cite: 7] */
}

/**
 * @brief Unit test verifying custom user prompt rendering, buffer overflow protection, and the
 *        rendered-prompt terminal-safety check (newline-tolerant `is_safe_terminal_string`)[cite: 7].
 *
 * Tests token substitution (`{url}`, `{code}`, `{url_complete}`, `\n`), buffer capacity limits,
 * default-template rendering, and rejection of C0 control characters (ANSI escapes, tabs)
 * introduced via the template, provider URL, or user code[cite: 7].
 *
 * @param[in,out] state CMocka test state context (unused)[cite: 7].
 */
static void test_prompt_rendering(void **state) {
    (void)state;
    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.init_message, "\\nURL: {url}\\nCode: {code}\\nDirect: {url_complete}\\n", sizeof(cfg.init_message) - 1);

    char out[256];
    int res =
        render_prompt_message(&cfg, "https://auth.edu/dev", "https://auth.edu/dev?c=1", "BCD-123", out, sizeof(out));
    assert_int_equal(res, 0);
    assert_string_equal(out, "\nURL: https://auth.edu/dev\nCode: BCD-123\nDirect: https://auth.edu/dev?c=1\n");

    /* Verify buffer overflow / truncation handling[cite: 7] */
    char small_out[20];
    int trunc_res = render_prompt_message(&cfg, "https://auth.edu/dev", "https://auth.edu/dev?c=1", "BCD-123",
                                          small_out, sizeof(small_out));
    assert_int_equal(trunc_res, -1);

    /* Default template (empty init_message) must render and pass the terminal-safety check[cite: 7] */
    config_t def_cfg;
    memset(&def_cfg, 0, sizeof(def_cfg));
    char def_out[512];
    int def_res = render_prompt_message(&def_cfg, "https://auth.edu/dev", "https://auth.edu/dev?c=1", "BCD-123",
                                        def_out, sizeof(def_out));
    assert_int_equal(def_res, 0);

    /* Rendered-prompt terminal-injection defense: ANSI escape bytes in the template,
     * the provider URL, or the user code must fail rendering[cite: 7] */
    config_t esc_cfg;
    memset(&esc_cfg, 0, sizeof(esc_cfg));
    strncpy(esc_cfg.init_message, "Code: \x1b[31m{code}\x1b[0m", sizeof(esc_cfg.init_message) - 1);
    char esc_out[512];
    assert_int_equal(render_prompt_message(&esc_cfg, "https://auth.edu/dev", NULL, "BCD-123", esc_out, sizeof(esc_out)),
                     -1);
    assert_int_equal(
        render_prompt_message(&def_cfg, "https://auth.edu/dev\x1b[31m", NULL, "BCD-123", esc_out, sizeof(esc_out)), -1);
    assert_int_equal(
        render_prompt_message(&def_cfg, "https://auth.edu/dev", NULL, "BCD-123\x1b[0m", esc_out, sizeof(esc_out)), -1);

    /* Tab (C0) characters in a custom template are also rejected[cite: 7] */
    config_t tab_cfg;
    memset(&tab_cfg, 0, sizeof(tab_cfg));
    strncpy(tab_cfg.init_message, "Code:\t{code}", sizeof(tab_cfg.init_message) - 1);
    assert_int_equal(render_prompt_message(&tab_cfg, "https://auth.edu/dev", NULL, "BCD-123", esc_out, sizeof(esc_out)),
                     -1);
}

/**
 * @brief Unit test verifying valid JWT metadata, issuer, audience, and expiration verification.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_jwt_valid_metadata(void **state) {
    (void)state;
    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.issuer, "https://sts.windows.net/tenant/", sizeof(cfg.issuer) - 1);
    strncpy(cfg.audience, "00000003-0000-0000-c000-000000000000", sizeof(cfg.audience) - 1);
    cfg.clock_skew_leeway = 60;
    cfg.loglevel = LOGLEVEL_NONE;

    /* Payload:
     * {"iss":"https://sts.windows.net/tenant/","aud":"00000003-0000-0000-c000-000000000000","exp":2524608000,"nbf":1600000000}
     */
    const char *valid_jwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC90ZW5hbnQvIiwiYXVkIjoiMDAwMDAwMDMtMDAwMC0wMDAwLWMwMDAtMDAwMDAwMDAw"
        "MDAwIiwiZXhwIjoyNTI0NjA4MDAwLCJuYmYiOjE2MDAwMDAwMDB9.sig";

    int res = verify_token_metadata(valid_jwt, &cfg, NULL);
    assert_int_equal(res, 0);
}

/**
 * @brief Unit test verifying expired JWT token rejection.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_jwt_expired_token(void **state) {
    (void)state;
    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.issuer, "https://sts.windows.net/tenant/", sizeof(cfg.issuer) - 1);
    strncpy(cfg.audience, "00000003-0000-0000-c000-000000000000", sizeof(cfg.audience) - 1);
    cfg.clock_skew_leeway = 60;
    cfg.loglevel = LOGLEVEL_NONE;

    /* Expired Payload (exp: 1000000000 -> Sept 2001) */
    const char *expired_jwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC90ZW5hbnQvIiwiYXVkIjoiMDAwMDAwMDMtMDAwMC0wMDAwLWMwMDAtMDAwMDAwMDAw"
        "MDAwIiwiZXhwIjoxMDAwMDAwMDAwLCJuYmYiOjEwMDAwMDAwMDB9.sig";

    int res = verify_token_metadata(expired_jwt, &cfg, NULL);
    assert_int_equal(res, -1);
}

/**
 * @brief Unit test verifying JWT issuer and audience claim mismatch detection.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_jwt_mismatch_claims(void **state) {
    (void)state;
    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.issuer, "https://sts.windows.net/wrong_tenant/", sizeof(cfg.issuer) - 1);
    strncpy(cfg.audience, "00000003-0000-0000-c000-000000000000", sizeof(cfg.audience) - 1);
    cfg.clock_skew_leeway = 60;
    cfg.loglevel = LOGLEVEL_NONE;

    const char *jwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC90ZW5hbnQvIiwiYXVkIjoiMDAwMDAwMDMtMDAwMC0wMDAwLWMwMDAtMDAwMDAwMDAw"
        "MDAwIiwiZXhwIjoyNTI0NjA4MDAwLCJuYmYiOjE2MDAwMDAwMDB9.sig";

    /* Case 1: Issuer mismatch */
    assert_int_equal(verify_token_metadata(jwt, &cfg, NULL), -1);

    /* Case 2: Audience mismatch */
    strncpy(cfg.issuer, "https://sts.windows.net/tenant/", sizeof(cfg.issuer) - 1);
    strncpy(cfg.audience, "invalid-audience-guid", sizeof(cfg.audience) - 1);
    assert_int_equal(verify_token_metadata(jwt, &cfg, NULL), -1);
}

/**
 * @brief Unit test verifying JWT audience array processing.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_jwt_audience_array(void **state) {
    (void)state;
    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.issuer, "https://sts.windows.net/tenant/", sizeof(cfg.issuer) - 1);
    strncpy(cfg.audience, "00000003-0000-0000-c000-000000000000", sizeof(cfg.audience) - 1);
    cfg.clock_skew_leeway = 60;
    cfg.loglevel = LOGLEVEL_NONE;

    /* Payload:
     * {"iss":"https://sts.windows.net/tenant/","aud":["00000003-0000-0000-c000-000000000000","client-id-2"],"exp":2524608000}
     */
    const char *aud_array_jwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC90ZW5hbnQvIiwiYXVkIjpbIjAwMDAwMDAzLTAwMDAtMDAwMC1jMDAwLTAwMDAwMDAw"
        "MDAwMCIsImNsaWVudC1pZC0yIl0sImV4cCI6MjUyNDYwODAwMH0.sig";

    int res = verify_token_metadata(aud_array_jwt, &cfg, NULL);
    assert_int_equal(res, 0);
}

/**
 * @brief Unit test verifying RFC 7519 NumericDate handling for exp/nbf: fractional
 *        (json_type_double) values are enforced, non-numeric types are rejected, and
 *        the configurable missing-exp policy (require_exp_claim) is honored.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_jwt_numeric_date_and_exp_policy(void **state) {
    (void)state;
    config_t cfg;

    /* Fractional (json_type_double) exp far in the past -> must be enforced as expired. */
    const char *frac_past_exp =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC90ZW5hbnQvIiwiYXVkIjoiMDAwMDAwMDMtMDAwMC0wMDAwLWMwMDAtMDAwMDAwMDAw"
        "MDAwIiwiZXhwIjoxMDAwMDAwMDAwLjV9.sig";

    /* Fractional exp far in the future -> accepted (enforced, not silently skipped). */
    const char *frac_future_exp =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC90ZW5hbnQvIiwiYXVkIjoiMDAwMDAwMDMtMDAwMC0wMDAwLWMwMDAtMDAwMDAwMDAw"
        "MDAwIiwiZXhwIjoyNTI0NjA4MDAwLjV9.sig";

    /* exp as a string (non-numeric) is a malformed NumericDate -> rejected. */
    const char *string_exp =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC90ZW5hbnQvIiwiYXVkIjoiMDAwMDAwMDMtMDAwMC0wMDAwLWMwMDAtMDAwMDAwMDAw"
        "MDAwIiwiZXhwIjoiZnV0dXJlIn0.sig";

    /* Payload with no exp claim at all. */
    const char *no_exp =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC90ZW5hbnQvIiwiYXVkIjoiMDAwMDAwMDMtMDAwMC0wMDAwLWMwMDAtMDAwMDAwMDAw"
        "MDAwIn0.sig";

    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.issuer, "https://sts.windows.net/tenant/", sizeof(cfg.issuer) - 1);
    strncpy(cfg.audience, "00000003-0000-0000-c000-000000000000", sizeof(cfg.audience) - 1);
    cfg.clock_skew_leeway = 60;
    cfg.loglevel = LOGLEVEL_NONE;
    cfg.require_exp_claim = 0;

    /* Fractional past exp -> expired (previously skipped when not json_type_int). */
    assert_int_equal(verify_token_metadata(frac_past_exp, &cfg, NULL), -1);
    /* Fractional future exp -> accepted. */
    assert_int_equal(verify_token_metadata(frac_future_exp, &cfg, NULL), 0);
    /* String exp -> malformed NumericDate, rejected. */
    assert_int_equal(verify_token_metadata(string_exp, &cfg, NULL), -1);

    /* Missing exp is accepted when require_exp_claim is disabled. */
    assert_int_equal(verify_token_metadata(no_exp, &cfg, NULL), 0);

    /* Missing exp is rejected when require_exp_claim is enabled. */
    cfg.require_exp_claim = 1;
    assert_int_equal(verify_token_metadata(no_exp, &cfg, NULL), -1);
}

/**
 * @brief Unit test verifying malformed JWT structure and NULL parameter handling.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_jwt_malformed_structure(void **state) {
    (void)state;
    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.loglevel = LOGLEVEL_NONE;

    /* Test NULL pointers */
    assert_int_equal(verify_token_metadata(NULL, &cfg, NULL), -1);
    assert_int_equal(verify_token_metadata("hdr.payload.sig", NULL, NULL), -1);

    /* Test missing dots */
    assert_int_equal(verify_token_metadata("invalid_jwt_no_dots", &cfg, NULL), -1);
    assert_int_equal(verify_token_metadata("invalid_jwt.one_dot", &cfg, NULL), -1);

    /* Test extra dots */
    assert_int_equal(verify_token_metadata("a.b.c.d", &cfg, NULL), -1);

    /* Test non-JSON decoded payload */
    assert_int_equal(verify_token_metadata("eyJhbGciOiJIUzI1NiJ9.bm90X2pzb24.sig", &cfg, NULL), -1);
}

/**
 * @brief Unit test verifying transient/retryable classification of OAuth token-endpoint HTTP
 *        status codes.
 *
 * RFC 8628 §3.5 well-formed token responses use 2xx for success and 4xx for `error` responses
 * (only `authorization_pending` and `slow_down` keep the polling loop alive). HTTP 429 and 5xx,
 * by contrast, are transient transport/gateway conditions (empty bodies, JSON, or HTML from a
 * proxy/LB) and MUST be retried with backoff rather than aborting authentication.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_retryable_token_http_status(void **state) {
    (void)state;

    /* Transient: rate limiting and server/gateway errors. */
    assert_int_equal(is_retryable_token_http_status(429), 1);
    assert_int_equal(is_retryable_token_http_status(500), 1);
    assert_int_equal(is_retryable_token_http_status(502), 1);
    assert_int_equal(is_retryable_token_http_status(503), 1);
    assert_int_equal(is_retryable_token_http_status(504), 1);
    assert_int_equal(is_retryable_token_http_status(599), 1);

    /* Definitive: success, other client errors, redirects, and no response. */
    assert_int_equal(is_retryable_token_http_status(200), 0);
    assert_int_equal(is_retryable_token_http_status(204), 0);
    assert_int_equal(is_retryable_token_http_status(400), 0);
    assert_int_equal(is_retryable_token_http_status(401), 0);
    assert_int_equal(is_retryable_token_http_status(403), 0);
    assert_int_equal(is_retryable_token_http_status(404), 0);
    assert_int_equal(is_retryable_token_http_status(301), 0);
    assert_int_equal(is_retryable_token_http_status(0), 0);
}

/**
 * @brief Unit test verifying local account allow/deny list enforcement.
 *
 * Exercises `verify_user_access` for no-lists, allow, deny, deny-precedence-over-allow,
 * and case-insensitive matching behaviors.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_verify_user_access(void **state) {
    (void)state;
    config_t cfg;

    /* No lists configured: every account is permitted. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    assert_int_equal(verify_user_access("alice", &cfg, NULL), 1);

    /* deny_users blocks listed accounts, permits the rest. */
    strncpy(cfg.deny_users, "root, daemon", sizeof(cfg.deny_users) - 1);
    assert_int_equal(verify_user_access("root", &cfg, NULL), 0);
    assert_int_equal(verify_user_access("alice", &cfg, NULL), 1);

    /* allow_users restricts to the listed accounts. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    strncpy(cfg.allow_users, "alice,bob", sizeof(cfg.allow_users) - 1);
    assert_int_equal(verify_user_access("alice", &cfg, NULL), 1);
    assert_int_equal(verify_user_access("mallory", &cfg, NULL), 0);

    /* Deny lists take precedence over allow lists. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    strncpy(cfg.allow_users, "alice,bob", sizeof(cfg.allow_users) - 1);
    strncpy(cfg.deny_users, "bob", sizeof(cfg.deny_users) - 1);
    assert_int_equal(verify_user_access("bob", &cfg, NULL), 0);
    assert_int_equal(verify_user_access("alice", &cfg, NULL), 1);

    /* Case-insensitive matching when case_sensitive is disabled. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 0;
    cfg.loglevel = LOGLEVEL_NONE;
    strncpy(cfg.allow_users, "Alice,Bob", sizeof(cfg.allow_users) - 1);
    assert_int_equal(verify_user_access("alice", &cfg, NULL), 1);
    assert_int_equal(verify_user_access("BOB", &cfg, NULL), 1);
    assert_int_equal(verify_user_access("carol", &cfg, NULL), 0);

    /* NULL pointers are rejected. */
    assert_int_equal(verify_user_access(NULL, &cfg, NULL), 0);
    assert_int_equal(verify_user_access("alice", NULL, NULL), 0);
}

/**
 * @brief Unit test verifying group/role allow and deny list authorization.
 *
 * Exercises `verify_group_membership` for bypass, allow-only (array + string),
 * deny-precedence, deny-only pass, a custom `group_claim_field`, and the
 * `enforce_groups` denial case.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_verify_group_membership_lists(void **state) {
    (void)state;
    config_t cfg;
    struct json_object *uinfo;

    /* No lists configured: authorization is bypassed. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    uinfo = json_tokener_parse("{\"sub\":\"jdoe\",\"groups\":[\"users\"]}");
    assert_non_null(uinfo);
    assert_int_equal(verify_group_membership(uinfo, &cfg, NULL), 1);
    json_object_put(uinfo);

    /* allow_groups: array claim containing an allowed group. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    strncpy(cfg.allow_groups, "sysadmins", sizeof(cfg.allow_groups) - 1);
    uinfo = json_tokener_parse("{\"groups\":[\"users\",\"sysadmins\"]}");
    assert_non_null(uinfo);
    assert_int_equal(verify_group_membership(uinfo, &cfg, NULL), 1);
    json_object_put(uinfo);

    /* allow_groups: array claim without an allowed group -> denied. */
    uinfo = json_tokener_parse("{\"groups\":[\"users\",\"developers\"]}");
    assert_non_null(uinfo);
    assert_int_equal(verify_group_membership(uinfo, &cfg, NULL), 0);
    json_object_put(uinfo);

    /* deny_groups takes precedence over allow_groups. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    strncpy(cfg.allow_groups, "sysadmins", sizeof(cfg.allow_groups) - 1);
    strncpy(cfg.deny_groups, "contractors", sizeof(cfg.deny_groups) - 1);
    uinfo = json_tokener_parse("{\"groups\":[\"sysadmins\",\"contractors\"]}");
    assert_non_null(uinfo);
    assert_int_equal(verify_group_membership(uinfo, &cfg, NULL), 0);
    json_object_put(uinfo);

    /* deny-only: user holds no denied group -> allowed. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    strncpy(cfg.deny_groups, "contractors", sizeof(cfg.deny_groups) - 1);
    uinfo = json_tokener_parse("{\"groups\":[\"users\",\"developers\"]}");
    assert_non_null(uinfo);
    assert_int_equal(verify_group_membership(uinfo, &cfg, NULL), 1);
    json_object_put(uinfo);

    /* Comma-separated string claim with a custom group claim field. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    strncpy(cfg.group_claim_field, "roles", sizeof(cfg.group_claim_field) - 1);
    strncpy(cfg.allow_groups, "sysadmins, devs", sizeof(cfg.allow_groups) - 1);
    uinfo = json_tokener_parse("{\"roles\":\"users, sysadmins\"}");
    assert_non_null(uinfo);
    assert_int_equal(verify_group_membership(uinfo, &cfg, NULL), 1);
    json_object_put(uinfo);

    /* enforce_groups = 1 with no lists configured: active but nothing to enforce -> denied. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    cfg.enforce_groups = 1;
    uinfo = json_tokener_parse("{\"groups\":[\"users\"]}");
    assert_non_null(uinfo);
    assert_int_equal(verify_group_membership(uinfo, &cfg, NULL), 0);
    json_object_put(uinfo);
}

/**
 * @brief Initializes a config_t with the same defaults load_config() applies before parsing.
 *
 * parse_config_file() only writes keys present in the stream, so tests that assert on
 * default-preserved fields must first seed the structure exactly as load_config() does.
 *
 * @param[out] cfg Target configuration structure.
 */
static void init_config_defaults(config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    (void)copy_checked(cfg->scopes, sizeof(cfg->scopes), "openid");
    (void)copy_checked(cfg->claim_field, sizeof(cfg->claim_field), "sub");
    (void)copy_checked(cfg->claim_regex, sizeof(cfg->claim_regex), "^(.*)$");
    cfg->claim_capture_group = 1;
    cfg->max_poll_seconds = 300;
    cfg->case_sensitive = 1;
    cfg->loglevel = LOGLEVEL_INFO;
    cfg->verify_jwt_claims = 0;
    cfg->clock_skew_leeway = 60;
    cfg->require_exp_claim = 0;
    (void)copy_checked(cfg->group_claim_field, sizeof(cfg->group_claim_field), "groups");
}

/**
 * @brief Opens an in-memory read-only stream over a NUL-terminated config text.
 *
 * @param[in] text NUL-terminated configuration text (must outlive the returned stream).
 * @return Opened FILE* for parse_config_file(), or NULL on allocation failure.
 */
static FILE *open_config_stream(const char *text) { return fmemopen((void *)text, strlen(text), "r"); }

/**
 * @brief Unit test verifying parse_config_file accepts a minimal valid configuration.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_minimal_valid(void **state) {
    (void)state;
    static const char *const text = "[oauth]\n"
                                    "client_id = test-client\n"
                                    "device_authorization_endpoint = https://idp.example.com/device\n"
                                    "token_endpoint = https://idp.example.com/token\n"
                                    "userinfo_endpoint = https://idp.example.com/userinfo\n";
    config_t cfg;
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(text);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), 0);
    fclose(f);

    assert_string_equal(cfg.client_id, "test-client");
    assert_string_equal(cfg.device_authorization_endpoint, "https://idp.example.com/device");
    assert_string_equal(cfg.token_endpoint, "https://idp.example.com/token");
    assert_string_equal(cfg.userinfo_endpoint, "https://idp.example.com/userinfo");
    /* Defaults preserved when keys are absent. */
    assert_string_equal(cfg.scopes, "openid");
    assert_string_equal(cfg.claim_field, "sub");
    assert_string_equal(cfg.claim_regex, "^(.*)$");
    assert_int_equal(cfg.claim_capture_group, 1);
    assert_int_equal(cfg.max_poll_seconds, 300);
    assert_int_equal(cfg.case_sensitive, 1);
    assert_int_equal(cfg.loglevel, LOGLEVEL_INFO);
    assert_string_equal(cfg.group_claim_field, "groups");
}

/**
 * @brief Unit test verifying parse_config_file rejects a missing mandatory key.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_missing_required(void **state) {
    (void)state;
    static const char *const text = "[oauth]\nclient_id = only-one\n";
    config_t cfg;
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(text);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);
    /* All parsed content is securely zeroed on failure. */
    assert_string_equal(cfg.client_id, "");
}

/**
 * @brief Unit test verifying parse_config_file rejects duplicate key definitions.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_duplicate_key(void **state) {
    (void)state;
    static const char *const text = "[oauth]\n"
                                    "client_id = one\n"
                                    "client_id = two\n"
                                    "device_authorization_endpoint = https://idp.example.com/device\n"
                                    "token_endpoint = https://idp.example.com/token\n"
                                    "userinfo_endpoint = https://idp.example.com/userinfo\n";
    config_t cfg;
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(text);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);
}

/**
 * @brief Unit test verifying parse_config_file handles every section and key.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_full_sections(void **state) {
    (void)state;
    static const char *const text = "# Full-coverage configuration\n"
                                    "[oauth]\n"
                                    "client_id = ci\n"
                                    "client_secret = shhh\n"
                                    "device_authorization_endpoint = https://idp.example.com/device\n"
                                    "token_endpoint = https://idp.example.com/token\n"
                                    "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                    "scopes = openid email\n"
                                    "issuer = https://idp.example.com\n"
                                    "audience = aud-1\n"
                                    "jwks_url = https://idp.example.com/jwks\n"
                                    "introspection_endpoint = https://idp.example.com/introspect\n"
                                    "verify_jwt_claims = true\n"
                                    "clock_skew_leeway = 5\n"
                                    "require_exp_claim = no\n"
                                    "[claim]\n"
                                    "claim_field = preferred_username\n"
                                    "claim_regex = ^(.*)$\n"
                                    "claim_capture_group = 1\n"
                                    "case_sensitive = false\n"
                                    "[access]\n"
                                    "allow_users = alice,bob\n"
                                    "deny_users = mallory\n"
                                    "allow_groups = sysadmins\n"
                                    "deny_groups = terminated\n"
                                    "enforce_groups = yes\n"
                                    "group_claim_field = roles\n"
                                    "[prompt]\n"
                                    "init_message = Code: %s\n"
                                    "[runtime]\n"
                                    "max_poll_seconds = 60\n"
                                    "loglevel = verbose\n";
    config_t cfg;
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(text);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), 0);
    fclose(f);

    assert_string_equal(cfg.client_id, "ci");
    assert_string_equal(cfg.client_secret, "shhh");
    assert_string_equal(cfg.scopes, "openid email");
    assert_string_equal(cfg.issuer, "https://idp.example.com");
    assert_string_equal(cfg.audience, "aud-1");
    assert_string_equal(cfg.jwks_url, "https://idp.example.com/jwks");
    assert_string_equal(cfg.introspection_endpoint, "https://idp.example.com/introspect");
    assert_string_equal(cfg.claim_field, "preferred_username");
    assert_string_equal(cfg.claim_regex, "^(.*)$");
    assert_int_equal(cfg.claim_capture_group, 1);
    assert_int_equal(cfg.case_sensitive, 0);
    assert_string_equal(cfg.allow_users, "alice,bob");
    assert_string_equal(cfg.deny_users, "mallory");
    assert_string_equal(cfg.allow_groups, "sysadmins");
    assert_string_equal(cfg.deny_groups, "terminated");
    assert_int_equal(cfg.enforce_groups, 1);
    assert_string_equal(cfg.group_claim_field, "roles");
    assert_string_equal(cfg.init_message, "Code: %s");
    assert_int_equal(cfg.max_poll_seconds, 60);
    assert_int_equal(cfg.loglevel, LOGLEVEL_VERBOSE);
    assert_int_equal(cfg.verify_jwt_claims, 1);
    assert_int_equal(cfg.clock_skew_leeway, 5);
    assert_int_equal(cfg.require_exp_claim, 0);
}

/**
 * @brief Unit test verifying parse_config_file rejects keys outside any section.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_key_before_section(void **state) {
    (void)state;
    static const char *const text = "client_id = stray\n[oauth]\n";
    config_t cfg;
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(text);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);
}

/**
 * @brief Unit test verifying parse_config_file rejects unknown section headers.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_unknown_section(void **state) {
    (void)state;
    static const char *const text = "[nonsense]\n";
    config_t cfg;
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(text);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);
}

/**
 * @brief Unit test verifying parse_config_file rejects lines longer than the read buffer.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_overlong_line(void **state) {
    (void)state;
    char buf[600];
    buf[0] = 'a';
    memset(buf + 1, 'a', sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    config_t cfg;
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(buf);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);
}

/**
 * @brief Unit test verifying parse_config_file rejects non-HTTPS or fragment-bearing URLs.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_invalid_url(void **state) {
    (void)state;
    static const char *const plain_http = "[oauth]\n"
                                          "client_id = ci\n"
                                          "device_authorization_endpoint = http://idp.example.com/device\n"
                                          "token_endpoint = https://idp.example.com/token\n"
                                          "userinfo_endpoint = https://idp.example.com/userinfo\n";
    static const char *const with_fragment = "[oauth]\n"
                                             "client_id = ci\n"
                                             "device_authorization_endpoint = https://idp.example.com/device#frag\n"
                                             "token_endpoint = https://idp.example.com/token\n"
                                             "userinfo_endpoint = https://idp.example.com/userinfo\n";

    config_t cfg;
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(plain_http);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);

    init_config_defaults(&cfg);
    f = open_config_stream(with_fragment);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);
}

/**
 * @brief Unit test verifying parse_config_file rejects out-of-range or malformed integers.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_invalid_int(void **state) {
    (void)state;
    static const char *const too_large = "[oauth]\n"
                                         "client_id = ci\n"
                                         "device_authorization_endpoint = https://idp.example.com/device\n"
                                         "token_endpoint = https://idp.example.com/token\n"
                                         "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                         "[runtime]\n"
                                         "max_poll_seconds = 99999\n";
    static const char *const not_a_number = "[oauth]\n"
                                            "client_id = ci\n"
                                            "device_authorization_endpoint = https://idp.example.com/device\n"
                                            "token_endpoint = https://idp.example.com/token\n"
                                            "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                            "[runtime]\n"
                                            "max_poll_seconds = abc\n";

    config_t cfg;
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(too_large);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);

    init_config_defaults(&cfg);
    f = open_config_stream(not_a_number);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);
}

/**
 * @brief Unit test verifying parse_config_file rejects unknown loglevel values.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_invalid_loglevel(void **state) {
    (void)state;
    static const char *const text = "[oauth]\n"
                                    "client_id = ci\n"
                                    "device_authorization_endpoint = https://idp.example.com/device\n"
                                    "token_endpoint = https://idp.example.com/token\n"
                                    "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                    "[runtime]\n"
                                    "loglevel = chatty\n";
    config_t cfg;
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(text);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);
}

/**
 * @brief Unit test verifying parse_config_file rejects malformed boolean values.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_invalid_bool(void **state) {
    (void)state;
    static const char *const text = "[oauth]\n"
                                    "client_id = ci\n"
                                    "device_authorization_endpoint = https://idp.example.com/device\n"
                                    "token_endpoint = https://idp.example.com/token\n"
                                    "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                    "[access]\n"
                                    "case_sensitive = maybe\n";
    config_t cfg;
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(text);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);
}

/**
 * @brief Unit test verifying parse_config_file rejects keys not valid in the active section.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_unknown_key_in_section(void **state) {
    (void)state;
    static const char *const text = "[oauth]\n"
                                    "client_id = ci\n"
                                    "max_poll_seconds = 60\n"
                                    "device_authorization_endpoint = https://idp.example.com/device\n"
                                    "token_endpoint = https://idp.example.com/token\n"
                                    "userinfo_endpoint = https://idp.example.com/userinfo\n";
    config_t cfg;
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(text);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);
}

/**
 * @brief Unit test verifying parse_config_file trims whitespace and skips comments.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_whitespace_and_comments(void **state) {
    (void)state;
    static const char *const text = "# leading comment\n"
                                    "\n"
                                    "   [oauth]   \n"
                                    "\tclient_id \t=\t spaced-value # kept in non-URL values \n"
                                    "device_authorization_endpoint=https://idp.example.com/device\n"
                                    "token_endpoint=https://idp.example.com/token\n"
                                    "userinfo_endpoint = https://idp.example.com/userinfo\n";
    config_t cfg;
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(text);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), 0);
    fclose(f);

    assert_string_equal(cfg.client_id, "spaced-value # kept in non-URL values");
}

/**
 * @brief Unit test verifying parse_config_file rejects a non-compiling claim regex.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_bad_regex(void **state) {
    (void)state;
    static const char *const text = "[oauth]\n"
                                    "client_id = ci\n"
                                    "device_authorization_endpoint = https://idp.example.com/device\n"
                                    "token_endpoint = https://idp.example.com/token\n"
                                    "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                    "[claim]\n"
                                    "claim_regex = (unbalanced\n";
    config_t cfg;
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(text);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);
}

/**
 * @brief Unit test verifying parse_config_file rejects NULL stream or config arguments.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_null_args(void **state) {
    (void)state;
    config_t cfg;
    init_config_defaults(&cfg);
    assert_int_equal(parse_config_file(NULL, &cfg, NULL), -1);
    assert_int_equal(parse_config_file(stdin, NULL, NULL), -1);
}

/**
 * @brief Execution entry point for the CMocka test runner suite[cite: 7].
 *
 * Registers and executes unit tests for URL encoding, loglevel parsing, identity claim mapping,
 * input sanitization, prompt message rendering, JWT metadata verification, and configuration
 * stream parsing (parse_config_file)[cite: 7].
 *
 * @return 0 if all unit tests pass, non-zero return code if any test fails[cite: 7].
 */
int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_url_encoding),
        cmocka_unit_test(test_parse_loglevel),
        cmocka_unit_test(test_verify_claim_capture_group),
        cmocka_unit_test(test_verify_claim_case_insensitivity),
        cmocka_unit_test(test_verify_claim_invalid_bounds),
        cmocka_unit_test(test_terminal_and_user_code_sanitizer),
        cmocka_unit_test(test_prompt_rendering),
        cmocka_unit_test(test_jwt_valid_metadata),
        cmocka_unit_test(test_jwt_expired_token),
        cmocka_unit_test(test_jwt_mismatch_claims),
        cmocka_unit_test(test_jwt_audience_array),
        cmocka_unit_test(test_jwt_numeric_date_and_exp_policy),
        cmocka_unit_test(test_jwt_malformed_structure),
        cmocka_unit_test(test_retryable_token_http_status),
        cmocka_unit_test(test_verify_user_access),
        cmocka_unit_test(test_verify_group_membership_lists),
        cmocka_unit_test(test_parse_config_file_minimal_valid),
        cmocka_unit_test(test_parse_config_file_full_sections),
        cmocka_unit_test(test_parse_config_file_missing_required),
        cmocka_unit_test(test_parse_config_file_duplicate_key),
        cmocka_unit_test(test_parse_config_file_key_before_section),
        cmocka_unit_test(test_parse_config_file_unknown_section),
        cmocka_unit_test(test_parse_config_file_overlong_line),
        cmocka_unit_test(test_parse_config_file_invalid_url),
        cmocka_unit_test(test_parse_config_file_invalid_int),
        cmocka_unit_test(test_parse_config_file_invalid_loglevel),
        cmocka_unit_test(test_parse_config_file_invalid_bool),
        cmocka_unit_test(test_parse_config_file_unknown_key_in_section),
        cmocka_unit_test(test_parse_config_file_whitespace_and_comments),
        cmocka_unit_test(test_parse_config_file_bad_regex),
        cmocka_unit_test(test_parse_config_file_null_args),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
