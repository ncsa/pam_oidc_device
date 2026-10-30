/**
 * @file jwt.c
 * @brief JWT Base64URL decoding, structure validation, and claims-only inspection routines.
 *
 * Implements Base64URL decoding, structure verification, expiration checks (exp/nbf),
 * issuer matching (iss), and audience validation (aud) for local zero-trust claims-only
 * token inspection. NOTE: The JWT cryptographic signature is intentionally NOT verified
 * here; signature and validity enforcement is performed downstream by the provider's
 * UserInfo endpoint.
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
#include <ctype.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * @brief Decodes a Base64URL encoded string per RFC 4648.
 *
 * Converts URL-safe characters ('-' -> '+', '_' -> '/'), calculates padding,
 * and decodes payload bytes via OpenSSL BIO stream filters.
 *
 * @param[in]  input   Base64URL encoded input string.
 * @param[out] out_len Pointer receiving decoded byte count.
 * @return Heap-allocated decoded null-terminated string, or NULL on decoding error.
 */
static char *base64url_decode(const char *input, size_t *out_len) {
    if (!input) {
        return NULL;
    }

    size_t in_len = strlen(input);
    size_t padded_len = (in_len + 3) / 4 * 4;
    char *buf = calloc(1, padded_len + 1);
    if (!buf) {
        return NULL;
    }

    for (size_t i = 0; i < in_len; i++) {
        if (input[i] == '-') {
            buf[i] = '+';
        } else if (input[i] == '_') {
            buf[i] = '/';
        } else {
            buf[i] = input[i];
        }
    }
    for (size_t i = in_len; i < padded_len; i++) {
        buf[i] = '=';
    }

    BIO *bio = BIO_new_mem_buf(buf, (int)padded_len);
    BIO *b64 = BIO_new(BIO_f_base64());
    if (!bio || !b64) {
        if (bio) {
            BIO_free(bio);
        }
        if (b64) {
            BIO_free(b64);
        }
        secure_memzero(buf, padded_len);
        free(buf);
        return NULL;
    }

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    char *out = calloc(1, padded_len + 1);
    if (!out) {
        BIO_free_all(bio);
        secure_memzero(buf, padded_len);
        free(buf);
        return NULL;
    }

    int decoded = BIO_read(bio, out, (int)padded_len);
    BIO_free_all(bio);
    secure_memzero(buf, padded_len);
    free(buf);

    if (decoded <= 0) {
        secure_memzero(out, padded_len);
        free(out);
        return NULL;
    }

    out[decoded] = '\0';
    if (out_len) {
        *out_len = (size_t)decoded;
    }
    return out;
}

/**
 * @brief Inspects a decoded JWT's claims (exp, nbf, iss, aud) for local pre-flight validation.
 *
 * NOTE: This performs claims-only inspection and does NOT verify the JWT cryptographic
 * signature. Signature and validity enforcement is performed downstream by the provider's
 * UserInfo endpoint. Enable this via the "verify_jwt_claims" configuration option.
 *
 * NOTE: Although this function is token-type-agnostic, within the PAM flow it is invoked
 * only against the token response's "access_token" field. The "id_token" (when present in
 * the token response) is deliberately NOT inspected: the module presents the access token
 * to the provider's UserInfo endpoint, where its signature and validity are authoritatively
 * enforced, and some providers (e.g. Microsoft Entra ID) do not return an id_token for
 * device-flow responses.
 *
 * @param[in] jwt_str Raw JWT access token or ID token string.
 * @param[in] cfg     Active configuration parameters containing issuer, audience, leeway,
 *                    and the require_exp_claim policy flag.
 * @param[in] pamh    PAM handle for syslog logging context (optional).
 * @return 0 on successful claim validation, -1 on invalid structure, malformed NumericDate
 *         claim, missing required exp, claim mismatch, or expired token.
 *
 * @note The `exp` and `nbf` claims are RFC 7519 NumericDate values and may be fractional;
 *       both integer and double JSON types are accepted, all others are rejected.
 */
int verify_token_metadata(const char *jwt_str, const config_t *cfg, pam_handle_t *pamh) {
    if (!cfg) {
        return -1;
    }

    if (!jwt_str) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "NULL token string provided for metadata verification");
        return -1;
    }

    /* Step 1: Count dots to confirm standard 3-part JWT structure (header.payload.signature) */
    const char *dot1 = strchr(jwt_str, '.');
    if (!dot1) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Invalid token structure: missing header/payload delimiter");
        return -1;
    }
    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Invalid token structure: missing payload/signature delimiter");
        return -1;
    }
    if (strchr(dot2 + 1, '.') != NULL) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Invalid token structure: multiple unexpected dot delimiters");
        return -1;
    }

    /* Step 2: Extract and Base64URL decode JWT Payload (Segment 2) */
    size_t payload_b64_len = (size_t)(dot2 - (dot1 + 1));
    if (payload_b64_len == 0) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR, "JWT payload segment is empty");
        return -1;
    }

    char *payload_b64 = calloc(1, payload_b64_len + 1);
    if (!payload_b64) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR, "Memory allocation failed for JWT payload buffer");
        return -1;
    }
    memcpy(payload_b64, dot1 + 1, payload_b64_len);

    size_t decoded_len = 0;
    char *payload_json_str = base64url_decode(payload_b64, &decoded_len);
    secure_memzero(payload_b64, payload_b64_len);
    free(payload_b64);

    if (!payload_json_str) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR, "Failed to Base64URL decode JWT payload");
        return -1;
    }

    struct json_object *payload_json = json_tokener_parse(payload_json_str);
    secure_memzero(payload_json_str, decoded_len);
    free(payload_json_str);

    if (!payload_json || !json_object_is_type(payload_json, json_type_object)) {
        if (payload_json) {
            json_object_put(payload_json);
        }
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR, "JWT payload is not a valid JSON object");
        return -1;
    }

    time_t now = time(NULL);
    int leeway = cfg->clock_skew_leeway >= 0 ? cfg->clock_skew_leeway : 60;

    /* Step 3: Verify Expiration Claim (exp).
     *
     * RFC 7519 defines `exp` as a NumericDate: an integer-seconds value that may
     * also be fractional. json-c parses such values as either json_type_int or
     * json_type_double, so both must be accepted. Any other JSON type is a
     * malformed claim and is rejected outright.
     *
     * A missing `exp` is accepted by default (an unexpired-check is left to the
     * downstream UserInfo endpoint) unless `require_exp_claim` is set, in which
     * case tokens lacking a well-formed `exp` are rejected.
     */
    struct json_object *j_exp = NULL;
    if (json_object_object_get_ex(payload_json, "exp", &j_exp)) {
        double exp_val = 0.0;
        if (json_object_is_type(j_exp, json_type_int)) {
            exp_val = (double)json_object_get_int64(j_exp);
        } else if (json_object_is_type(j_exp, json_type_double)) {
            exp_val = json_object_get_double(j_exp);
        } else {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Malformed JWT 'exp' claim: expected a NumericDate (numeric) value");
            json_object_put(payload_json);
            return -1;
        }
        if ((double)now > exp_val + (double)leeway) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Token has expired (exp: %.3f, current_time: %ld, leeway: %ds)", exp_val, (long)now, leeway);
            json_object_put(payload_json);
            return -1;
        }
    } else if (cfg->require_exp_claim) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR, "Token is missing the required 'exp' claim");
        json_object_put(payload_json);
        return -1;
    }

    /* Step 4: Verify Not Before Claim (nbf).
     *
     * `nbf` is an optional RFC 7519 NumericDate; accept json_type_int or
     * json_type_double (fractional) and reject any other JSON type. A missing
     * `nbf` is always accepted, as it is commonly omitted and not security-relevant.
     */
    struct json_object *j_nbf = NULL;
    if (json_object_object_get_ex(payload_json, "nbf", &j_nbf)) {
        double nbf_val = 0.0;
        if (json_object_is_type(j_nbf, json_type_int)) {
            nbf_val = (double)json_object_get_int64(j_nbf);
        } else if (json_object_is_type(j_nbf, json_type_double)) {
            nbf_val = json_object_get_double(j_nbf);
        } else {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Malformed JWT 'nbf' claim: expected a NumericDate (numeric) value");
            json_object_put(payload_json);
            return -1;
        }
        if ((double)now < nbf_val - (double)leeway) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Token not yet valid (nbf: %.3f, current_time: %ld, leeway: %ds)", nbf_val, (long)now,
                          leeway);
            json_object_put(payload_json);
            return -1;
        }
    }

    /* Step 5: Verify Issuer Claim (iss) */
    if (strlen(cfg->issuer) > 0) {
        struct json_object *j_iss = NULL;
        if (!json_object_object_get_ex(payload_json, "iss", &j_iss) || !json_object_is_type(j_iss, json_type_string) ||
            strcmp(json_object_get_string(j_iss), cfg->issuer) != 0) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Token issuer mismatch (expected: '%s', received: '%s')", cfg->issuer,
                          j_iss ? json_object_get_string(j_iss) : "(null)");
            json_object_put(payload_json);
            return -1;
        }
    }

    /* Step 6: Verify Audience Claim (aud) */
    if (strlen(cfg->audience) > 0) {
        struct json_object *j_aud = NULL;
        int aud_valid = 0;

        if (json_object_object_get_ex(payload_json, "aud", &j_aud)) {
            char aud_cfg_copy[256];
            if (copy_checked(aud_cfg_copy, sizeof(aud_cfg_copy), cfg->audience) == 0) {
                char *saveptr = NULL;
                char *expected_aud = strtok_r(aud_cfg_copy, ",", &saveptr);

                while (expected_aud && !aud_valid) {
                    while (isspace((unsigned char)*expected_aud)) {
                        expected_aud++;
                    }
                    if (*expected_aud != '\0') {
                        char *end = expected_aud + strlen(expected_aud) - 1;
                        while (end > expected_aud && isspace((unsigned char)*end)) {
                            *end = '\0';
                            end--;
                        }

                        if (json_object_is_type(j_aud, json_type_string)) {
                            if (strcmp(json_object_get_string(j_aud), expected_aud) == 0) {
                                aud_valid = 1;
                            }
                        } else if (json_object_is_type(j_aud, json_type_array)) {
                            size_t array_len = json_object_array_length(j_aud);
                            for (size_t i = 0; i < array_len; i++) {
                                struct json_object *item = json_object_array_get_idx(j_aud, i);
                                if (item && json_object_is_type(item, json_type_string) &&
                                    strcmp(json_object_get_string(item), expected_aud) == 0) {
                                    aud_valid = 1;
                                    break;
                                }
                            }
                        }
                    }
                    expected_aud = strtok_r(NULL, ",", &saveptr);
                }
            }
        }

        if (!aud_valid) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Token audience mismatch (expected: '%s', received: %s)", cfg->audience,
                          j_aud ? json_object_to_json_string(j_aud) : "(null)");
            json_object_put(payload_json);
            return -1;
        }
    }

    json_object_put(payload_json);
    pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_DEBUG, LOG_DEBUG, "JWT metadata and claim checks passed successfully");
    return 0;
}
