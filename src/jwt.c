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
#include <math.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * @brief Decodes a Base64URL encoded string per RFC 4648 §5.
 *
 * Strictly validates that every input byte belongs to the Base64URL alphabet
 * (`A-Z`, `a-z`, `0-9`, '-', '_') with optional 1-2 trailing '=' padding,
 * rejecting standard Base64 characters ('+', '/'), embedded padding,
 * whitespace, and control characters. Converts URL-safe characters
 * ('-' -> '+', '_' -> '/'), calculates padding, and decodes payload bytes
 * via OpenSSL BIO stream filters.
 *
 * @param[in]  input   Base64URL encoded input string.
 * @param[out] out_len Pointer receiving decoded byte count.
 * @return Heap-allocated decoded null-terminated string, or NULL on decoding error
 *         (invalid input alphabet, embedded padding, excess padding, or BIO failure).
 */
static char *base64url_decode(const char *input, size_t *out_len) {
    if (!input) {
        return NULL;
    }

    size_t in_len = strlen(input);

    /* Strict RFC 4648 §5 Base64URL alphabet validation: only [A-Za-z0-9_-] is
     * legal, plus up to two contiguous '=' padding characters at the very end.
     * This rejects standard Base64 '+'/'/', stray whitespace/control bytes, and
     * any '=' not part of the trailing pad, none of which are valid Base64URL. */
    size_t pad_start = in_len;
    while (pad_start > 0 && input[pad_start - 1] == '=') {
        pad_start--;
    }
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)input[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
            continue;
        }
        if (c == '=' && i >= pad_start) {
            continue; /* legal contiguous trailing padding */
        }
        return NULL;
    }

    size_t padded_len = (in_len + 3) / 4 * 4;

    /* Base64 encodes six bits per character, so a legal stream's total padding
     * (the existing trailing '=' plus whatever the 4-character group alignment
     * would append) never exceeds two '=' characters (RFC 4648 §3.5). A longer
     * pad — e.g. an unpadded length that is 1 (mod 4), which would need three —
     * is not valid Base64: OpenSSL's lenient BIO_f_base64 would nevertheless
     * "decode" it into short binary garbage, so reject up front instead of
     * relying on the JSON parse layer to catch it. */
    size_t total_pad = (in_len - pad_start) + (padded_len - in_len);
    if (total_pad > 2) {
        return NULL;
    }

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
            secure_zero_json_tree(payload_json);
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
     * `exp` must additionally be finite: json-c accepts the non-standard `NaN`
     * and `Infinity` literals as json_type_double, and every comparison with
     * NaN is false — a NaN `exp` would silently disable the expiry check.
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
            secure_zero_json_tree(payload_json);
            json_object_put(payload_json);
            return -1;
        }
        if (!isfinite(exp_val)) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Token has a non-finite 'exp' claim (NaN or Infinity)");
            secure_zero_json_tree(payload_json);
            json_object_put(payload_json);
            return -1;
        }
        if ((double)now > exp_val + (double)leeway) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Token has expired (exp: %.3f, current_time: %ld, leeway: %ds)", exp_val, (long)now, leeway);
            secure_zero_json_tree(payload_json);
            json_object_put(payload_json);
            return -1;
        }
    } else if (cfg->require_exp_claim) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR, "Token is missing the required 'exp' claim");
        secure_zero_json_tree(payload_json);
        json_object_put(payload_json);
        return -1;
    }

    /* Step 4: Verify Not Before Claim (nbf).
     *
     * `nbf` is an optional RFC 7519 NumericDate; accept json_type_int or
     * json_type_double (fractional) and reject any other JSON type. A missing
     * `nbf` is always accepted, as it is commonly omitted and not security-relevant.
     * As with `exp`, a non-finite value (json-c's `NaN`/`Infinity` literals) is
     * rejected: comparisons with NaN never trip the not-yet-valid check.
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
            secure_zero_json_tree(payload_json);
            json_object_put(payload_json);
            return -1;
        }
        if (!isfinite(nbf_val)) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Token has a non-finite 'nbf' claim (NaN or Infinity)");
            secure_zero_json_tree(payload_json);
            json_object_put(payload_json);
            return -1;
        }
        if ((double)now < nbf_val - (double)leeway) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Token not yet valid (nbf: %.3f, current_time: %ld, leeway: %ds)", nbf_val, (long)now,
                          leeway);
            secure_zero_json_tree(payload_json);
            json_object_put(payload_json);
            return -1;
        }
    }

    /* Step 5: Verify Issuer Claim (iss).
     *
     * With claims-only inspection (no local signature verification), the issuer
     * binding is the core defense against tokens minted for a different tenant or
     * client, so when verify_jwt_claims is enabled an unconfigured issuer fails
     * closed. load_config() rejects that combination up front; this branch also
     * covers direct callers of this public API. */
    if (strlen(cfg->issuer) > 0) {
        struct json_object *j_iss = NULL;
        if (!json_object_object_get_ex(payload_json, "iss", &j_iss) || !json_object_is_type(j_iss, json_type_string) ||
            strcmp(json_object_get_string(j_iss), cfg->issuer) != 0) {
            /* PII-safe: the received claim value is logged only as its length,
             * never as the value itself (the expected value is
             * administrator configuration, not provider data). */
            const char *iss_received =
                json_object_is_type(j_iss, json_type_string) ? json_object_get_string(j_iss) : NULL;
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Token issuer mismatch (expected: '%s', received value length: %zu)", cfg->issuer,
                          iss_received ? strlen(iss_received) : 0);
            secure_zero_json_tree(payload_json);
            json_object_put(payload_json);
            return -1;
        }
    } else if (cfg->verify_jwt_claims) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "JWT issuer (iss) check required but no issuer is configured");
        secure_zero_json_tree(payload_json);
        json_object_put(payload_json);
        return -1;
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
                                struct json_object *item = json_object_array_get_idx(j_aud, JSON_ARRAY_IDX(i));
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
            /* PII-safe: the received claim value is logged only as its length,
             * never as the value itself (same rationale as the issuer check). */
            size_t aud_received_len = 0;
            const char *aud_repr = NULL;
            if (j_aud != NULL) {
                aud_repr = json_object_to_json_string(j_aud);
                aud_received_len = (aud_repr != NULL) ? strlen(aud_repr) : 0;
            }
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Token audience mismatch (expected: '%s', received value length: %zu)", cfg->audience,
                          aud_received_len);
            secure_zero_json_tree(payload_json);
            json_object_put(payload_json);
            return -1;
        }
    } else if (cfg->verify_jwt_claims) {
        /* Fail closed on an unconfigured audience when verify_jwt_claims is
         * enabled, for the same reason as the issuer check above (see the
         * Step 5 note): load_config() rejects the combination up front, and
         * this branch also covers direct callers of this public API. */
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "JWT audience (aud) check required but no audience is configured");
        secure_zero_json_tree(payload_json);
        json_object_put(payload_json);
        return -1;
    }

    secure_zero_json_tree(payload_json);
    json_object_put(payload_json);
    pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_DEBUG, LOG_DEBUG, "JWT metadata and claim checks passed successfully");
    return 0;
}

/**
 * @brief Extracts a single string claim (e.g. `sub`) from a JWT's payload segment.
 *
 * Applies the same strict structural validation as verify_token_metadata()
 * (three dot-delimited segments, non-empty payload, strict RFC 4648 §5
 * Base64URL alphabet, JSON object payload) and copies the named claim's string
 * value into the caller's buffer.
 *
 * NOTE: like verify_token_metadata(), this is claims-only inspection; the JWT
 * signature is NOT verified. It exists for the JWT-`sub` vs UserInfo-`sub`
 * consistency check and must never be the sole basis for authorization.
 *
 * @param[in]  token      Raw JWT string (header.payload.signature).
 * @param[in]  claim_name Name of the payload claim to extract.
 * @param[out] out        Buffer receiving the NUL-terminated claim value.
 * @param[in]  out_len    Capacity of @p out in bytes.
 * @return 0 when the claim was found and copied; 1 when the claim is absent
 *         from the payload; -1 on NULL/empty arguments, malformed JWT
 *         structure, non-object payload, a non-string claim, or an output
 *         buffer too small for the value.
 */
int jwt_extract_claim_string(const char *token, const char *claim_name, char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return -1;
    }
    out[0] = '\0';
    if (!token || !claim_name || *claim_name == '\0') {
        return -1;
    }

    /* Step 1: Confirm standard 3-part JWT structure (header.payload.signature). */
    const char *dot1 = strchr(token, '.');
    if (!dot1) {
        return -1;
    }
    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2 || strchr(dot2 + 1, '.') != NULL) {
        return -1;
    }

    /* Step 2: Extract and Base64URL decode the payload segment. */
    size_t payload_b64_len = (size_t)(dot2 - (dot1 + 1));
    if (payload_b64_len == 0) {
        return -1;
    }

    char *payload_b64 = calloc(1, payload_b64_len + 1);
    if (!payload_b64) {
        return -1;
    }
    memcpy(payload_b64, dot1 + 1, payload_b64_len);

    size_t decoded_len = 0;
    char *payload_json_str = base64url_decode(payload_b64, &decoded_len);
    secure_memzero(payload_b64, payload_b64_len);
    free(payload_b64);
    if (!payload_json_str) {
        return -1;
    }

    struct json_object *payload_json = json_tokener_parse(payload_json_str);
    secure_memzero(payload_json_str, decoded_len);
    free(payload_json_str);
    if (!payload_json || !json_object_is_type(payload_json, json_type_object)) {
        if (payload_json) {
            secure_zero_json_tree(payload_json);
            json_object_put(payload_json);
        }
        return -1;
    }

    /* Step 3: Copy the named claim when present as a JSON string. */
    int rc = 1;
    struct json_object *j_claim = NULL;
    if (json_object_object_get_ex(payload_json, claim_name, &j_claim)) {
        if (!j_claim || !json_object_is_type(j_claim, json_type_string)) {
            rc = -1;
        } else {
            const char *val = json_object_get_string(j_claim);
            size_t val_len = strlen(val);
            if (val_len + 1 > out_len) {
                rc = -1;
            } else {
                memcpy(out, val, val_len + 1);
                rc = 0;
            }
        }
    }

    secure_zero_json_tree(payload_json);
    json_object_put(payload_json);
    return rc;
}
