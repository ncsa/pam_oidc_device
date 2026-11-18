/**
 * @file pam_module.c
 * @brief Primary Linux Pluggable Authentication Module (PAM) entry points and RFC 8628 workflow orchestrator.
 *
 * Implements the standard PAM interface methods (`pam_sm_authenticate` and `pam_sm_setcred`).
 * Handles out-of-band RFC 8628 device authorization grant polling over HTTPS, terminal messaging,
 * exponential backoff, monotonic clock polling deadlines, OpenID identity verification, group/role authorization,
 * and level-filtered syslog audit reporting.
 *
 * @project     pam_oidc_device
 * @repository  https://github.com/ncsa/pam_oidc_device
 * @maintainer  National Center for Supercomputing Applications (NCSA)
 * @license     MIT License
 * @see         RFC 8628 (OAuth 2.0 Device Authorization Grant)
 *
 * Copyright (c) 2026 The Board of Trustees of the University of Illinois.
 * SPDX-License-Identifier: MIT
 */

#include "../include/pam_oidc_device.h"
#include "device_flow.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * @brief Determines whether one POSIX `timespec` is strictly before another.
 *
 * Performs a full lexicographic comparison of both the seconds and nanoseconds
 * fields, unlike comparisons that inspect only `tv_sec`.
 *
 * @param[in] a  First timestamp.
 * @param[in] b  Second timestamp.
 * @return 1 if `a` is strictly before `b`, 0 otherwise.
 */
static int timespec_before(const struct timespec *a, const struct timespec *b) {
    return (a->tv_sec < b->tv_sec) || (a->tv_sec == b->tv_sec && a->tv_nsec < b->tv_nsec);
}

/*
 * Fixed capacities of the form-field tables that build the device-authorization
 * and token request bodies. Both are exactly at capacity today: the device
 * request carries client_id, [client_secret], [scope], code_challenge and
 * code_challenge_method (5 with secret + scope + PKCE) and the token request
 * carries client_id, [client_secret], grant_type, device_code and
 * code_verifier (5 with secret + PKCE). form_field_append() enforces these
 * bounds at runtime, so adding a future parameter that exceeds them fails
 * safe (PAM_BUF_ERR) instead of silently overflowing the stack arrays.
 */
#define DEVICE_FORM_MAX_FIELDS 5
#define TOKEN_FORM_MAX_FIELDS 5

/**
 * @brief Appends one key/value pair to a fixed-capacity form-field table.
 *
 * Enforces the table capacity so an oversized parameter set cannot silently
 * overflow the underlying stack arrays.
 *
 * @param[in]  keys      Key table (at least `capacity` slots).
 * @param[in]  vals      Value table (at least `capacity` slots).
 * @param[out] count     Current number of pairs; incremented on success.
 * @param[in]  capacity  Number of reserved slots in keys/vals.
 * @param[in]  key       Field name.
 * @param[in]  val       Field value.
 * @return 0 on success, -1 if the table is already full.
 */
int form_field_append(const char **keys, const char **vals, size_t *count, size_t capacity, const char *key,
                      const char *val) {
    if (*count >= capacity) {
        return -1;
    }
    size_t idx = *count;
    keys[idx] = key;
    vals[idx] = val;
    *count = idx + 1;
    return 0;
}

/**
 * @brief Formats arrays of key-value parameters into an HTTP `application/x-www-form-urlencoded` string.
 *
 * Handles URL encoding of values via libcurl, reallocates destination buffers dynamically,
 * and performs integer overflow checks prior to memory allocation.
 *
 * @param[in]  curl  Active cURL handle.
 * @param[in]  keys  Array of parameter key strings.
 * @param[in]  vals  Array of parameter value strings.
 * @param[in]  count Number of key-value entries in arrays.
 * @param[out] out   Pointer receiving heap-allocated URL-encoded POST field string.
 * @return 0 on success, -1 on allocation, overflow, or encoding error.
 */
static int build_form_postfields(CURL *curl, const char **keys, const char **vals, size_t count, char **out) {
    size_t buf_size = 1024;
    char *buf = calloc(1, buf_size);
    if (!buf) {
        return -1;
    }

    size_t buf_len = 0;

    for (size_t i = 0; i < count; i++) {
        if (!keys[i] || !vals[i]) {
            continue;
        }
        char *enc_val = url_encode_param(curl, vals[i]);
        if (!enc_val) {
            secure_memzero(buf, buf_size);
            free(buf);
            return -1;
        }

        size_t key_len = strlen(keys[i]);
        size_t val_len = strlen(enc_val);

        /* Prevent potential size_t wrap-around integer overflows */
        if (key_len > SIZE_MAX - val_len - 3 || buf_len > SIZE_MAX - (key_len + val_len + 3)) {
            curl_free(enc_val);
            secure_memzero(buf, buf_size);
            free(buf);
            return -1;
        }

        size_t needed = buf_len + key_len + val_len + 3;

        if (needed >= buf_size) {
            size_t new_size = buf_size;
            while (needed >= new_size) {
                if (new_size > SIZE_MAX / 2) {
                    curl_free(enc_val);
                    secure_memzero(buf, buf_size);
                    free(buf);
                    return -1;
                }
                new_size *= 2;
            }
            char *new_buf = realloc(buf, new_size);
            if (!new_buf) {
                curl_free(enc_val);
                secure_memzero(buf, buf_size);
                free(buf);
                return -1;
            }
            buf = new_buf;
            buf_size = new_size;
        }

        int written =
            snprintf(buf + buf_len, buf_size - buf_len, "%s%s=%s", (buf_len > 0) ? "&" : "", keys[i], enc_val);
        curl_free(enc_val);

        if (written < 0 || (size_t)written >= buf_size - buf_len) {
            secure_memzero(buf, buf_size);
            free(buf);
            return -1;
        }
        buf_len += (size_t)written;
    }

    *out = buf;
    return 0;
}

/**
 * @brief Recursively zero-fills every string value in a parsed json-c object tree.
 *
 * json-c retains a private heap copy of each parsed string; `json_object_put()` releases
 * those copies with a plain `free()`, so credential and identity-claim bytes would otherwise
 * remain in the process heap until the allocator reuses the region. This walks the tree and
 * scrubs every string buffer (content plus the terminating NUL) with `secure_memzero()` so
 * the caller can safely release the tree immediately afterwards.
 *
 * The recursion is inherently bounded by json-c's maximum parse depth, so a
 * provider JSON document can never drive the stack depth without limit.
 *
 * Exported via include/pam_oidc_device.h so that src/jwt.c can scrub
 * provider-parsed ID-token payload trees before json_object_put().
 *
 * @param[in] obj Root json-c node to scrub (any type, or NULL).
 */
void secure_zero_json_tree(struct json_object *obj) { // NOLINT(misc-no-recursion)
    if (!obj) {
        return;
    }
    switch (json_object_get_type(obj)) {
    case json_type_string: {
        const char *s = json_object_get_string(obj);
        secure_memzero((void *)s, strlen(s) + 1);
        break;
    }
    case json_type_array: {
        size_t count = json_object_array_length(obj);
        for (size_t i = 0; i < count; i++) {
            secure_zero_json_tree(json_object_array_get_idx(obj, JSON_ARRAY_IDX(i)));
        }
        break;
    }
    case json_type_object: {
        struct json_object_iter it;
        json_object_object_foreachC(obj, it) { secure_zero_json_tree(it.val); }
        break;
    }
    default:
        break;
    }
}

/**
 * @brief RFC 8628 s3.5 `slow_down` poll-interval adjustment.
 *
 * The provider asks for polling 5 s less frequently: bump the interval by 5 s,
 * clamped to `MAX_SUPPORTED_POLL_INTERVAL` (an interval already at — or within
 * 5 s of — the supported maximum stays at the maximum). Extracted from the
 * polling loop so the arithmetic is unit-testable.
 *
 * @param[in] interval Current poll interval in seconds (>= `MIN_POLL_INTERVAL`).
 * @return Next poll interval in seconds.
 */
int poll_interval_after_slow_down(int interval) {
    return (interval > MAX_SUPPORTED_POLL_INTERVAL - 5) ? MAX_SUPPORTED_POLL_INTERVAL : interval + 5;
}

/**
 * @brief Transient-error (HTTP 429/5xx or cURL transport error) poll-interval backoff.
 *
 * Double the interval, clamped to `MAX_SUPPORTED_POLL_INTERVAL` (an interval
 * already more than half the supported maximum stays at the maximum).
 * Extracted from the polling loop so the arithmetic is unit-testable.
 *
 * @param[in] interval Current poll interval in seconds (>= `MIN_POLL_INTERVAL`).
 * @return Next poll interval in seconds.
 */
int poll_interval_after_transient(int interval) {
    return (interval > MAX_SUPPORTED_POLL_INTERVAL / 2) ? MAX_SUPPORTED_POLL_INTERVAL : interval * 2;
}

/**
 * @brief Pure scheduling decision for one token-poll loop iteration (RFC 8628 s3.5).
 *
 * The clock is injected (`now`) instead of read here so the timing rules — the first
 * poll issued immediately with no leading sleep, subsequent polls spaced by the
 * (possibly backed-off) interval, and a next poll that would land at or after the
 * device deadline ending the wait — are unit-testable without any real sleeping.
 * Declared in src/device_flow.h (internal) so tests/test_suite.c can pin these
 * rules; not part of the public API (include/pam_oidc_device.h).
 *
 * @param[in]  first_poll 1 for the loop's first iteration (no leading sleep).
 * @param[in]  interval   Current poll interval in seconds (already clamped/backed off).
 * @param[in]  now        Current CLOCK_MONOTONIC reading (ignored when first_poll).
 * @param[in]  deadline   Device-authorization expiration deadline (monotonic).
 * @param[out] next_poll  Absolute monotonic wake time for the next request
 *                       (POLL_SCHED_SLEEP only; untouched otherwise).
 * @return POLL_SCHED_RUN_NOW, POLL_SCHED_SLEEP, or POLL_SCHED_EXPIRED.
 */
poll_sched_action_t poll_loop_schedule(int first_poll, int interval, const struct timespec *now,
                                       const struct timespec *deadline, struct timespec *next_poll) {
    if (first_poll) {
        return POLL_SCHED_RUN_NOW;
    }
    struct timespec t = *now;
    t.tv_sec += interval;
    *next_poll = t;
    return timespec_before(&t, deadline) ? POLL_SCHED_SLEEP : POLL_SCHED_EXPIRED;
}

/**
 * @brief Pure per-request deadline budget for one token poll (RFC 8628 s3.5).
 *
 * Decides, from an injected clock reading, whether another token request still
 * fits before the device-authorization deadline and returns the bounded cURL
 * timeout for it. cURL treats a zero (or negative) CURLOPT_TIMEOUT_MS as "no
 * timeout", so a request whose whole-second remainder has hit zero is refused
 * rather than fired with an unbounded lifetime. Declared in src/device_flow.h
 * (internal) so tests/test_suite.c can pin the budget rules; not part of the
 * public API (include/pam_oidc_device.h).
 *
 * @param[in]  now        Current CLOCK_MONOTONIC reading.
 * @param[in]  deadline   Device-authorization expiration deadline (monotonic).
 * @param[out] timeout_ms Bounded per-request cURL timeout in milliseconds
 *                        (1..10000, the same request-time cap the device request
 *                        uses) when returning 1.
 * @return 1 if a request may still be issued (`*timeout_ms` set), 0 if the
 *         deadline leaves no room for another request.
 */
int poll_request_budget(const struct timespec *now, const struct timespec *deadline, long *timeout_ms) {
    if (!timespec_before(now, deadline)) {
        return 0;
    }
    long remain_ms = (long)((deadline->tv_sec - now->tv_sec) * 1000);
    if (remain_ms <= 0L) {
        /* The monotonic check above guarantees `now` is before the deadline at
         * nanosecond precision, but the whole-second difference can still be zero
         * at the deadline boundary. */
        return 0;
    }
    *timeout_ms = (remain_ms < 10000L) ? remain_ms : 10000L;
    return 1;
}

/**
 * @brief RFC 8628 s3.1/s3.2 device-authorization request phase.
 *
 * Builds and POSTs the device-authorization request, then parses and validates
 * the response (device_code, verification URIs, user_code, poll interval,
 * expiry) and computes the monotonic polling deadline. The network/JSON
 * resources (the cURL-escaped request body, the HTTP response, and the parsed
 * JSON tree) are stored in caller-owned storage so the caller's single
 * `cleanup` path releases and scrubs them. This function performs NO local
 * teardown of its own: every return path (success or failure) must leave all
 * allocated resources in the caller-owned out-parameters, so do not introduce
 * function-local allocations here.
 *
 * @param[in] pamh           PAM framework handle (may be NULL in unit tests).
 * @param[in] cfg            Loaded module configuration.
 * @param[in] loglevel       Active log level.
 * @param[in] pkce_active    Whether PKCE (RFC 7636) is in effect for this attempt.
 * @param[in] code_challenge PKCE S256 challenge (ignored when !pkce_active).
 * @param[in] curl           Initialized cURL handle (used for form encoding).
 * @param[out] dev           Parsed and validated device-authorization result.
 * @param[out] resp          HTTP response (caller frees via free_http_response()).
 * @param[out] dev_json      Parsed response JSON tree (caller owns; dev's string
 *                           members borrow from it).
 * @param[out] postfields    cURL-escaped request body (caller scrubs and frees).
 * @return `PAM_SUCCESS`, or the PAM error code of the failing sub-step.
 *
 * Declared in src/device_flow.h (internal) so tests/test_suite.c can drive it
 * through the fake cURL transport; not part of the public API.
 */
int request_device_authorization(pam_handle_t *pamh, const config_t *cfg, loglevel_t loglevel, int pkce_active,
                                 const char *code_challenge, CURL *curl, device_auth_t *dev, http_response_t *resp,
                                 struct json_object **dev_json, char **postfields) {
    pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG, "Requesting device code from endpoint: %s",
                  cfg->device_authorization_endpoint);

    /*
     * Form-field table for the device-authorization request. Every append goes
     * through form_field_append(), which enforces DEVICE_FORM_MAX_FIELDS so an
     * oversized parameter set fails safe instead of overflowing the table.
     */
    const char *d_keys[DEVICE_FORM_MAX_FIELDS];
    const char *d_vals[DEVICE_FORM_MAX_FIELDS];
    size_t d_count = 0;
    int d_append_rc = 0;

    d_append_rc |= form_field_append(d_keys, d_vals, &d_count, DEVICE_FORM_MAX_FIELDS, "client_id", cfg->client_id);

    /* Client credentials are transmitted as form parameters in the request body
     * (`client_secret_post`, RFC 6749 s2.3.1); the `client_secret_basic` (HTTP Basic)
     * client-authentication method is not supported. */
    if (strlen(cfg->client_secret) > 0) {
        d_append_rc |=
            form_field_append(d_keys, d_vals, &d_count, DEVICE_FORM_MAX_FIELDS, "client_secret", cfg->client_secret);
    }
    if (strlen(cfg->scopes) > 0) {
        d_append_rc |= form_field_append(d_keys, d_vals, &d_count, DEVICE_FORM_MAX_FIELDS, "scope", cfg->scopes);
    }
    if (pkce_active) {
        d_append_rc |=
            form_field_append(d_keys, d_vals, &d_count, DEVICE_FORM_MAX_FIELDS, "code_challenge", code_challenge);
        d_append_rc |=
            form_field_append(d_keys, d_vals, &d_count, DEVICE_FORM_MAX_FIELDS, "code_challenge_method", "S256");
    }

    if (d_append_rc != 0) {
        pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Device request form-field table overflowed its fixed capacity");
        return PAM_BUF_ERR;
    }

    if (build_form_postfields(curl, d_keys, d_vals, d_count, postfields) != 0) {
        pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR, "Failed to build device request form postfields");
        return PAM_BUF_ERR;
    }

    if (http_request("POST", cfg->device_authorization_endpoint, *postfields, NULL, cfg->proxy, 10000L, resp, loglevel,
                     pamh) != 0 ||
        resp->status_code != 200 || !resp->body) {
        pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Device authorization request failed (HTTP status code: %ld)", resp->status_code);
        return PAM_AUTHINFO_UNAVAIL;
    }

    *dev_json = json_tokener_parse(resp->body);
    if (!*dev_json || !json_object_is_type(*dev_json, json_type_object)) {
        pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR, "Invalid JSON payload from device endpoint");
        return PAM_SERVICE_ERR;
    }

    struct json_object *j_code = NULL;
    struct json_object *j_uri = NULL;
    struct json_object *j_uri_complete = NULL;
    struct json_object *j_ucode = NULL;
    struct json_object *j_int = NULL;
    struct json_object *j_exp = NULL;

    json_object_object_get_ex(*dev_json, "device_code", &j_code);
    json_object_object_get_ex(*dev_json, "verification_uri", &j_uri);
    json_object_object_get_ex(*dev_json, "verification_uri_complete", &j_uri_complete);
    json_object_object_get_ex(*dev_json, "user_code", &j_ucode);
    json_object_object_get_ex(*dev_json, "interval", &j_int);
    json_object_object_get_ex(*dev_json, "expires_in", &j_exp);

    if (!j_code || !j_uri || !json_object_is_type(j_code, json_type_string) ||
        !json_object_is_type(j_uri, json_type_string)) {
        pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Missing device_code or verification_uri in endpoint response");
        return PAM_SERVICE_ERR;
    }

    /* user_code is REQUIRED per RFC 8628 Section 3.2; fail fast with a specific
       message instead of letting the injection check below trip on a placeholder. */
    if (!j_ucode || !json_object_is_type(j_ucode, json_type_string)) {
        pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR, "Missing user_code in endpoint response");
        return PAM_SERVICE_ERR;
    }

    if (copy_checked(dev->device_code, sizeof(dev->device_code), json_object_get_string(j_code)) != 0) {
        pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR, "Device code buffer capacity exceeded");
        return PAM_BUF_ERR;
    }

    dev->verification_uri = json_object_get_string(j_uri);
    dev->verification_uri_complete = (j_uri_complete && json_object_is_type(j_uri_complete, json_type_string))
                                         ? json_object_get_string(j_uri_complete)
                                         : NULL;
    dev->user_code = json_object_get_string(j_ucode);

    /* Validate provider URLs and user code against injection attacks */
    if (!is_valid_https_url(dev->verification_uri) || !is_safe_user_code(dev->user_code) ||
        (dev->verification_uri_complete && !is_valid_https_url(dev->verification_uri_complete))) {
        if (pamh) {
            pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Insecure or malformed URL/code in provider response");
        }
        return PAM_SERVICE_ERR;
    }

    int interval = (j_int && json_object_is_type(j_int, json_type_int)) ? json_object_get_int(j_int) : 5;
    if (interval < MIN_POLL_INTERVAL) {
        interval = MIN_POLL_INTERVAL;
    }

    if (interval > MAX_SUPPORTED_POLL_INTERVAL) {
        /* Documented, logged deviation from RFC 8628 §3.5: the spec forbids polling
         * more frequently than the advertised interval, so an unusually long interval
         * could simply be honored verbatim. It is clamped downward to the supported
         * maximum instead so the attempt keeps polling within the module's supported
         * window (the total wait stays bounded by `expires_in`, which `max_poll_seconds`
         * caps); honored verbatim, an interval this large would push every subsequent
         * poll past the device deadline and end the attempt without another request.
         * The trade-off is polling faster than the provider asked for — a bounded,
         * provider-visible deviation that is preferable to a guaranteed timeout.
         * Raising the cap is a public-interface change (include/pam_oidc_device.h). */
        if (pamh) {
            pam_oauth_log(pamh, loglevel, LOGLEVEL_INFO, LOG_WARNING,
                          "Provider poll interval %ds exceeds supported maximum; clamping to %ds", interval,
                          MAX_SUPPORTED_POLL_INTERVAL);
        }
        interval = MAX_SUPPORTED_POLL_INTERVAL;
    }

    int expires_in = (j_exp && json_object_is_type(j_exp, json_type_int)) ? json_object_get_int(j_exp) : 300;
    if (expires_in <= 0) {
        expires_in = 300;
    }
    if (expires_in > cfg->max_poll_seconds) {
        expires_in = cfg->max_poll_seconds;
    }

    pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                  "Device code response parsed: poll interval=%ds, expires_in=%ds", interval, expires_in);

    /* Calculate polling expiration deadline using POSIX monotonic clock */
    if (clock_gettime(CLOCK_MONOTONIC, &dev->deadline) != 0) {
        pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR, "Failed to read monotonic clock");
        return PAM_SYSTEM_ERR;
    }
    dev->deadline.tv_sec += expires_in;

    dev->poll_interval = interval;
    dev->expires_in = expires_in;
    return PAM_SUCCESS;
}

/**
 * @brief RFC 8628 s3.4/s3.5 token-polling phase.
 *
 * Builds the token request body, then polls the Token Endpoint using
 * monotonic clock timing (first poll immediate, subsequent polls spaced by the
 * provider's interval with slow_down / transient-error backoff) until token
 * issuance, expiration, denial, or an unrecoverable error. As with
 * request_device_authorization(), the network/JSON resources are stored in
 * caller-owned storage so the caller's single `cleanup` path releases and
 * scrubs them. This function performs NO local teardown of its own: every
 * return path (success or failure) must leave all allocated resources in the
 * caller-owned out-parameters, so do not introduce function-local
 * allocations here.
 *
 * @param[in] pamh            PAM framework handle (may be NULL in unit tests).
 * @param[in] cfg             Loaded module configuration.
 * @param[in] loglevel        Active log level.
 * @param[in] pam_user        Target user requesting login.
 * @param[in] dev             Device-authorization result (code, deadline, interval).
 * @param[in] code_verifier   PKCE code verifier (ignored when !pkce_active).
 * @param[in] pkce_active     Whether PKCE (RFC 7636) is in effect for this attempt.
 * @param[in] curl            Initialized cURL handle (used for form encoding).
 * @param[out] token_resp     Poll responses (caller frees via free_http_response()).
 * @param[out] tok_json       Last parsed token JSON tree (caller owns).
 * @param[out] access_token   Acquired access token, or NULL on failure (caller scrubs/frees).
 * @param[out] token_postfields cURL-escaped token request body (caller scrubs and frees).
 * @param[out] phase            On any non-success return, which user-visible notice the
 *                              caller should show (TOKEN_PHASE_EXPIRED / TOKEN_PHASE_DENIED
 *                              / TOKEN_PHASE_UNAVAILABLE; TOKEN_PHASE_UNAVAILABLE default).
 * @return `PAM_SUCCESS` when an access token was acquired, `PAM_ABORT` on user
 *         cancellation, or the PAM error code of the failing sub-step.
 *
 * Declared in src/device_flow.h (internal) so tests/test_suite.c can drive it
 * through the fake cURL transport; not part of the public API.
 */
int poll_for_access_token(pam_handle_t *pamh, const config_t *cfg, loglevel_t loglevel, const char *pam_user,
                          const device_auth_t *dev, const char *code_verifier, int pkce_active, CURL *curl,
                          http_response_t *token_resp, struct json_object **tok_json, char **access_token,
                          char **token_postfields, token_phase_t *phase) {
    /* Default notice classification for every failure path below; the sites that
     * correspond to an expired code or a declined sign-in overwrite it. */
    *phase = TOKEN_PHASE_UNAVAILABLE;

    /*
     * Form-field table for the token request. Every append goes through
     * form_field_append(), which enforces TOKEN_FORM_MAX_FIELDS so an oversized
     * parameter set fails safe instead of overflowing the table.
     */
    const char *t_keys[TOKEN_FORM_MAX_FIELDS];
    const char *t_vals[TOKEN_FORM_MAX_FIELDS];
    size_t t_count = 0;
    int t_append_rc = 0;

    t_append_rc |= form_field_append(t_keys, t_vals, &t_count, TOKEN_FORM_MAX_FIELDS, "client_id", cfg->client_id);

    /* Client credentials follow the same form-body `client_secret_post` pattern as the
     * device-authorization request above; `client_secret_basic` is not supported. */
    if (strlen(cfg->client_secret) > 0) {
        t_append_rc |=
            form_field_append(t_keys, t_vals, &t_count, TOKEN_FORM_MAX_FIELDS, "client_secret", cfg->client_secret);
    }
    t_append_rc |= form_field_append(t_keys, t_vals, &t_count, TOKEN_FORM_MAX_FIELDS, "grant_type",
                                     "urn:ietf:params:oauth:grant-type:device_code");
    t_append_rc |= form_field_append(t_keys, t_vals, &t_count, TOKEN_FORM_MAX_FIELDS, "device_code", dev->device_code);
    if (pkce_active) {
        t_append_rc |=
            form_field_append(t_keys, t_vals, &t_count, TOKEN_FORM_MAX_FIELDS, "code_verifier", code_verifier);
    }

    if (t_append_rc != 0) {
        pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Token request form-field table overflowed its fixed capacity");
        return PAM_BUF_ERR;
    }

    if (build_form_postfields(curl, t_keys, t_vals, t_count, token_postfields) != 0) {
        pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR, "Failed to build token request form postfields");
        return PAM_BUF_ERR;
    }

    pam_oauth_log(pamh, loglevel, LOGLEVEL_INFO, LOG_INFO, "Polling token endpoint for user '%s'...", pam_user);

    /* Polling loop enforcing RFC 8628 interval delay. The first poll is issued
     * immediately (no leading sleep) so the user does not wait a full interval before the
     * initial token request; subsequent polls are spaced by the (possibly adjusted) interval. */
    int interval = dev->poll_interval;
    int first_poll = 1;
    while (1) {
        /* Scheduling decision for this iteration, from the pure (clock-injected)
         * helper: first poll runs now, later polls sleep until next_poll, and a
         * next poll past the device deadline ends the wait. */
        struct timespec now;
        struct timespec next_poll;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR, "Failed to read monotonic clock");
            return PAM_SYSTEM_ERR;
        }
        poll_sched_action_t sched = poll_loop_schedule(first_poll, interval, &now, &dev->deadline, &next_poll);

        if (sched == POLL_SCHED_EXPIRED) {
            pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                          "Polling reached device authorization expiration deadline");
            *phase = TOKEN_PHASE_EXPIRED;
            break;
        }

        if (sched == POLL_SCHED_SLEEP) {
            /* Sleep until the next poll deadline: a single uninterrupted sleep of the full
             * interval, so the token endpoint is never polled more frequently than the
             * provider's `interval` allows. */
            int sleep_rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next_poll, NULL);
            if (sleep_rc == EINTR) {
                /* A signal (e.g. user-initiated cancellation / SIGTERM) interrupted the
                 * poll sleep. Resuming the loop would keep a possibly abandoned session
                 * blocking the login; abort instead — all resources are reclaimed by
                 * the caller's `cleanup`. */
                pam_oauth_log(pamh, loglevel, LOGLEVEL_INFO, LOG_INFO,
                              "Polling interrupted by a signal; aborting device-authorization wait");
                return PAM_ABORT;
            }

            if (sleep_rc != 0) {
                pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR, "Clock nanosleep failed with error %d",
                              sleep_rc);
                return PAM_SYSTEM_ERR;
            }
        }
        first_poll = 0;

        /* Deadline budget for this request, from the pure (clock-injected) helper.
         * A clock-read failure is folded into "deadline reached", matching the
         * original combined condition. The clock is re-read here so the budget
         * reflects the post-sleep time, not the scheduling decision's snapshot. */
        long req_timeout_ms = 0;
        int budget_ok = 0;
        if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
            budget_ok = poll_request_budget(&now, &dev->deadline, &req_timeout_ms);
        }
        if (!budget_ok) {
            /*
             * No room left for another request: at or past the device deadline
             * (possibly exactly at the whole-second boundary — cURL treats a zero
             * or negative CURLOPT_TIMEOUT_MS as "no timeout", so stop polling
             * instead of firing a request with an unbounded lifetime).
             */
            pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG, "Polling authorization deadline reached");
            *phase = TOKEN_PHASE_EXPIRED;
            break;
        }

        pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG, "Polling token endpoint (timeout: %ldms)",
                      req_timeout_ms);

        free_http_response(token_resp);
        int req_rc = http_request("POST", cfg->token_endpoint, *token_postfields, NULL, cfg->proxy, req_timeout_ms,
                                  token_resp, loglevel, pamh);

        if (req_rc == 0) {
            if (is_retryable_token_http_status(token_resp->status_code)) {
                /*
                 * HTTP 429 (rate limited) and 5xx (server/gateway error) are transient conditions
                 * and are NOT well-formed RFC 8628 OAuth error responses. The body may be empty, a
                 * JSON object, or an HTML error page returned by a proxy/load balancer. Back off and
                 * retry within the device-authorization deadline instead of aborting authentication.
                 */
                interval = poll_interval_after_transient(interval);
                pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                              "Transient HTTP status %ld from token endpoint; backing off poll interval to %ds",
                              token_resp->status_code, interval);
            } else if (token_resp->status_code >= 200 && token_resp->status_code < 300 && token_resp->body) {
                if (*tok_json) {
                    /*
                     * The prior tree can only be a 4xx `authorization_pending`/`slow_down` error
                     * response (a 2xx response always exits the loop), so it holds no secrets — but
                     * the scrub-before-release discipline holds on every release path, matching the
                     * `cleanup` section in pam_sm_authenticate().
                     */
                    secure_zero_json_tree(*tok_json);
                    json_object_put(*tok_json);
                }
                *tok_json = json_tokener_parse(token_resp->body);

                if (*tok_json && json_object_is_type(*tok_json, json_type_object)) {
                    /*
                     * RFC 6749 s5.1: token responses carry a `token_type` field (always "Bearer" for
                     * device-flow grants; the RFC defines the value as case-insensitive, so compare
                     * case-insensitively — some providers and proxies send "bearer"). Fail closed on a
                     * present-but-foreign token type so a
                     * malformed or unexpected token can never be passed to the UserInfo endpoint as
                     * a Bearer credential; a missing field is tolerated (DEBUG-logged) since some
                     * providers omit it.
                     */
                    struct json_object *j_ttype = NULL;
                    if (json_object_object_get_ex(*tok_json, "token_type", &j_ttype) && j_ttype) {
                        const char *ttype = json_object_get_string(j_ttype);
                        if (!ttype || strcasecmp(ttype, "Bearer") != 0) {
                            pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR,
                                          "Token response token_type '%s' is not 'Bearer'; refusing to use the token",
                                          ttype ? ttype : "<absent>");
                            return PAM_AUTH_ERR;
                        }
                    } else {
                        pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                                      "Token response omits token_type; assuming Bearer");
                    }

                    struct json_object *j_acc = NULL;
                    if (json_object_object_get_ex(*tok_json, "access_token", &j_acc) && j_acc &&
                        json_object_is_type(j_acc, json_type_string)) {
                        size_t token_len = (size_t)json_object_get_string_len(j_acc);
                        if (token_len > 0 && token_len <= MAX_ACCESS_TOKEN_LEN) {
                            *access_token = strdup(json_object_get_string(j_acc));
                            if (!*access_token) {
                                pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR,
                                              "Memory allocation failed for access_token");
                                return PAM_BUF_ERR;
                            }
                            pam_oauth_log(pamh, loglevel, LOGLEVEL_INFO, LOG_INFO,
                                          "Access token successfully acquired");
                            break; /* Access token acquired successfully */
                        } else if (token_len > MAX_ACCESS_TOKEN_LEN) {
                            pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR,
                                          "Access token length (%zu) exceeds maximum supported length (%d); aborting",
                                          token_len, MAX_ACCESS_TOKEN_LEN);
                            break; /* Token too large to process */
                        }
                    } else {
                        pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                                      "2xx token response present but no usable access_token (HTTP %ld); aborting poll",
                                      token_resp->status_code);
                    }
                }
                break;
            } else if (token_resp->status_code >= 400 && token_resp->status_code < 500 && token_resp->body) {
                /*
                 * RFC 8628 §3.5 OAuth error path (non-429 4xx): a well-formed token response carries
                 * an `error` string. `authorization_pending` and `slow_down` keep the loop alive; any
                 * other error is definitive and aborts polling. A 4xx without a parseable error body
                 * is also treated as definitive.
                 */
                if (*tok_json) {
                    /* Scrub-before-release, same discipline as the 2xx re-parse above; the prior tree
                     * is only ever the previous poll's 4xx error response (non-sensitive). */
                    secure_zero_json_tree(*tok_json);
                    json_object_put(*tok_json);
                }
                *tok_json = json_tokener_parse(token_resp->body);

                if (*tok_json && json_object_is_type(*tok_json, json_type_object)) {
                    struct json_object *j_err = NULL;
                    if (json_object_object_get_ex(*tok_json, "error", &j_err) && j_err &&
                        json_object_is_type(j_err, json_type_string)) {
                        const char *err = json_object_get_string(j_err);
                        pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG, "Token endpoint returned error: %s",
                                      err);
                        if (strcmp(err, "slow_down") == 0) {
                            interval = poll_interval_after_slow_down(interval);
                            pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                                          "Adjusted poll interval to %ds after slow_down", interval);
                        } else if (strcmp(err, "authorization_pending") != 0) {
                            /* Map the definitive OAuth error to its user-visible notice: an
                             * expired code and a declined sign-in each have their own
                             * wording; every other definitive error keeps the generic
                             * service-unavailable notice. */
                            if (strcmp(err, "expired_token") == 0) {
                                *phase = TOKEN_PHASE_EXPIRED;
                            } else if (strcmp(err, "access_denied") == 0) {
                                *phase = TOKEN_PHASE_DENIED;
                            }
                            pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR,
                                          "Non-retryable OAuth authorization error: %s", err);
                            break; /* Non-retryable OAuth authorization error */
                        }
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            } else {
                /*
                 * Definitive, non-retryable response: a 2xx without a body, a non-429 4xx without a
                 * parseable OAuth error body, a 3xx redirect (FOLLOWLOCATION is disabled), or any other
                 * unexpected status. Abort polling.
                 */
                break;
            }
        } else {
            /* Exponential backoff for transient network errors */
            if (token_resp->curl_code == CURLE_OPERATION_TIMEDOUT || token_resp->curl_code == CURLE_COULDNT_CONNECT ||
                token_resp->curl_code == CURLE_COULDNT_RESOLVE_HOST ||
                token_resp->curl_code == CURLE_COULDNT_RESOLVE_PROXY || token_resp->curl_code == CURLE_GOT_NOTHING) {
                interval = poll_interval_after_transient(interval);
                pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                              "Transient cURL error (%d); backing off poll interval to %ds", token_resp->curl_code,
                              interval);
            } else {
                pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR, "Fatal cURL error during polling: %s",
                              curl_easy_strerror(token_resp->curl_code));
                break; /* Non-recoverable network error */
            }
        }
    }

    if (!*access_token) {
        if (pamh) {
            pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Authentication failed for user '%s': timed out or denied", pam_user);
        }
        return PAM_AUTH_ERR;
    }

    return PAM_SUCCESS;
}

/**
 * @brief Primary PAM authentication hook implementation.
 *
 * Executes full RFC 8628 device authorization workflow:
 * 1. Parses PAM module parameters (`config=...`, `loglevel=...`).
 * 2. Loads module configuration settings (`load_config`).
 * 3. Sends POST request to Device Authorization Endpoint to obtain `device_code` and `user_code`
 *    (see request_device_authorization()).
 * 4. Displays the sign-in instructions to the user via a PAM conversation message (`PAM_TEXT_INFO`),
 *    optionally preceded by a scannable terminal QR code of the verification URI (`[qr]` section).
 *    A `PAM_PROMPT_ECHO_ON` "Press [Enter] to begin..." prompt is then issued; polling starts
 *    only after the user presses Enter. This round-trip flushes the buffered `PAM_TEXT_INFO`
 *    prompt to OpenSSH keyboard-interactive clients (which otherwise only render it when a
 *    subsequent prompt triggers a `USERINFO` round-trip) while acting as a synchronization
 *    barrier so the user has had time to note the URL and code.
 * 5. Polls the Token Endpoint using monotonic clock timing until token issuance, expiration, or user
 *    denial (see poll_for_access_token()).
 * 6. Performs local JWT metadata verification (exp, nbf, iss, aud) if enabled.
 * 7. Queries provider UserInfo endpoint with access token.
 * 8. Logs a PII-safe UserInfo receipt record (size + claim field) at debug level; the
 *    troubleshooting (verbose) level additionally lists claim NAMES only — claim values are
 *    never logged. When local JWT inspection is enabled, the JWT `sub` claim is also
 *    cross-checked against the UserInfo `sub` claim (token-substitution defense).
 * 9. Verifies user identity claim against `PAM_USER` via `verify_claim`.
 * 10. Evaluates group membership via `verify_group_membership` if enabled and returns `PAM_PERM_DENIED` on denial.
 * 11. Zeroes sensitive credentials in RAM and releases memory allocations.
 *
 * @param[in] pamh  PAM framework handle.
 * @param[in] flags PAM authentication flags (unused).
 * @param[in] argc  Count of module arguments supplied in PAM config.
 * @param[in] argv  Array of module argument strings.
 * @return `PAM_SUCCESS` on successful authentication, `PAM_PERM_DENIED` on group denial, or PAM error code on failure.
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags;

    int retval = PAM_AUTH_ERR;
    const char *config_file = CONFIG_PATH_DEFAULT;
    loglevel_t loglevel_override = LOGLEVEL_UNSET;
    const char *pam_user = NULL;

    CURL *curl = NULL;
    char *postfields = NULL;
    char *token_postfields = NULL;
    char *access_token = NULL;

    /* Owned device-authorization result (RFC 8628 §3.1/§3.2); see
     * request_device_authorization() for the borrowed-pointer lifetime rules. */
    device_auth_t dev;
    memset(&dev, 0, sizeof(dev));

    char code_verifier[PKCE_VERIFIER_LEN + 1];
    memset(code_verifier, 0, sizeof(code_verifier));

    char code_challenge[PKCE_S256_CHALLENGE_LEN + 1];
    memset(code_challenge, 0, sizeof(code_challenge));

    http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    http_response_t token_resp;
    memset(&token_resp, 0, sizeof(token_resp));

    http_response_t userinfo_resp;
    memset(&userinfo_resp, 0, sizeof(userinfo_resp));

    struct json_object *dev_json = NULL;
    struct json_object *tok_json = NULL;
    struct json_object *uinfo_json = NULL;

    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    /* Step 1: Parse module parameters from PAM configuration line */
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "config=", 7) == 0) {
            config_file = argv[i] + 7;
        } else if (strncmp(argv[i], "loglevel=", 9) == 0) {
            (void)parse_loglevel(argv[i] + 9, &loglevel_override);
        }
    }

    loglevel_t active_loglevel = (loglevel_override != LOGLEVEL_UNSET) ? loglevel_override : LOGLEVEL_INFO;

    /* Initialize global cURL environment exactly once */
    if (oauth_http_global_init() != 0) {
        if (pamh) {
            pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Failed to initialize global cURL environment");
        }
        notify_user_failure(pamh, USER_NOTICE_SERVICE);
        return PAM_SERVICE_ERR;
    }

    /* Retrieve target user requesting login */
    if (pam_get_user(pamh, &pam_user, NULL) != PAM_SUCCESS || !pam_user || strlen(pam_user) == 0) {
        /*
         * `pam_user` is owned by the PAM library: `pam_get_user()` exposes it through
         * a `const char **` out-parameter, so the caller only holds read-only access.
         * It must NOT be freed here (or during cleanup); doing so would be a use of
         * foreign memory.
         */
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR, "PAM_USER unavailable");
        return PAM_USER_UNKNOWN;
    }

    /* Step 2: Load and validate module configuration */
    if (load_config(config_file, &cfg, pamh) != 0) {
        retval = PAM_SERVICE_ERR;
        notify_user_failure(pamh, USER_NOTICE_SERVICE);
        goto cleanup;
    }
    if (loglevel_override != LOGLEVEL_UNSET) {
        cfg.loglevel = loglevel_override;
    }
    active_loglevel = cfg.loglevel;

    /* Enforce local account allow/deny access control before contacting the provider */
    if (!verify_user_access(pam_user, &cfg, pamh)) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Authentication refused for user '%s': account blocked by allow/deny user lists", pam_user);
        notify_user_failure(pamh, USER_NOTICE_DENIED);
        retval = PAM_PERM_DENIED;
        goto cleanup;
    }

    pam_oauth_log(pamh, active_loglevel, LOGLEVEL_INFO, LOG_INFO,
                  "OAuth 2.0 device authentication initiated for user '%s'", pam_user);

    /* Resolve the effective PKCE state for this attempt. "auto" mode probes the
     * provider's discovery document once per attempt; any probe failure fails safe
     * to "off" so a discovery outage (or inconclusive metadata) can never block
     * logins. The probe logs its decision and rationale. */
    int pkce_active = cfg.use_pkce;
    if (cfg.use_pkce == 2) {
        int supported = 0;
        (void)discovery_probe_pkce(cfg.discovery_endpoint, cfg.proxy, &supported, active_loglevel, pamh);
        pkce_active = supported;
    }

    curl = curl_easy_init();
    if (!curl) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR, "Failed to initialize cURL handle");
        retval = PAM_BUF_ERR;
        notify_user_failure(pamh, USER_NOTICE_SERVICE);
        goto cleanup;
    }

    /* Step 3a: Derive PKCE (RFC 7636) S256 material when enabled. A fresh CSPRNG
     * code verifier is generated per authentication attempt; its code_challenge is
     * sent with the device-authorization request and the verifier itself is
     * presented only at the token endpoint, binding the token exchange to this
     * flow. Both stack buffers are scrubbed unconditionally at `cleanup`. */
    if (pkce_active) {
        if (pkce_generate_code_verifier(code_verifier, sizeof(code_verifier)) != 0 ||
            pkce_compute_s256_challenge(code_verifier, code_challenge, sizeof(code_challenge)) != 0) {
            pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Failed to generate PKCE code verifier or S256 challenge");
            retval = PAM_SERVICE_ERR;
            notify_user_failure(pamh, USER_NOTICE_SERVICE);
            goto cleanup;
        }
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                      "PKCE (RFC 7636) S256 enabled for this device-authorization attempt");
    }

    /* Step 3: Request device code from the provider Device Authorization Endpoint and
     * parse/validate the RFC 8628 §3.2 response (device_code, verification URIs, user_code,
     * poll interval, expiry, monotonic polling deadline). See request_device_authorization(). */
    retval = request_device_authorization(pamh, &cfg, active_loglevel, pkce_active, code_challenge, curl, &dev, &resp,
                                          &dev_json, &postfields);
    if (retval != PAM_SUCCESS) {
        notify_user_failure(pamh, USER_NOTICE_SERVICE);
        goto cleanup;
    }

    /* Step 4: Display instructions and verification code to client terminal. Renders and
     * presents the sign-in prompt (templated text + optional QR block + Enter-to-begin
     * flush for keyboard-interactive clients) in one reviewable unit; the function owns
     * and scrubs its prompt buffer. See present_signin_prompt() in src/message.c. */
    retval = present_signin_prompt(pamh, &cfg, active_loglevel, &dev);
    if (retval != PAM_SUCCESS) {
        goto cleanup;
    }

    /* Step 5/6: Build the token request and poll the Token Endpoint (first poll immediate,
     * then RFC 8628 interval spacing with slow_down / transient-error backoff) until token
     * issuance, expiration, denial, or an unrecoverable error. See poll_for_access_token(). */
    token_phase_t poll_phase = TOKEN_PHASE_UNAVAILABLE;
    retval = poll_for_access_token(pamh, &cfg, active_loglevel, pam_user, &dev, code_verifier, pkce_active, curl,
                                   &token_resp, &tok_json, &access_token, &token_postfields, &poll_phase);
    if (retval != PAM_SUCCESS) {
        /* User-initiated cancellation (Ctrl-C) gets no notice — the user already knows.
         * Every other token-phase failure shows the notice matching its outcome: an
         * expired sign-in code, a declined sign-in request, or the generic
         * service-unavailable notice for everything else (network failure,
         * malformed/oversized token, ...). */
        if (retval != PAM_ABORT) {
            if (poll_phase == TOKEN_PHASE_DENIED) {
                notify_user_failure(pamh, USER_NOTICE_NOT_APPROVED);
            } else if (poll_phase == TOKEN_PHASE_EXPIRED) {
                notify_user_failure(pamh, USER_NOTICE_EXPIRED);
            } else {
                notify_user_failure(pamh, USER_NOTICE_SERVICE);
            }
        }
        goto cleanup;
    }

    /* Step 6b: Execute local JWT claim inspection if enabled. NOTE: claims-only check;
     * the JWT signature is verified downstream by the UserInfo endpoint, not here. */
    if (cfg.verify_jwt_claims) {
        if (verify_token_metadata(access_token, &cfg, pamh) != 0) {
            pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR, "JWT claim inspection failed for user '%s'",
                          pam_user);
            retval = PAM_AUTH_ERR;
            notify_user_failure(pamh, USER_NOTICE_DENIED);
            goto cleanup;
        }
    }

    /* Step 7: Fetch user identity claim from UserInfo Endpoint */
    pam_oauth_log(pamh, active_loglevel, LOGLEVEL_DEBUG, LOG_DEBUG, "Querying UserInfo endpoint: %s",
                  cfg.userinfo_endpoint);

    if (http_request("GET", cfg.userinfo_endpoint, NULL, access_token, cfg.proxy, 10000L, &userinfo_resp,
                     active_loglevel, pamh) != 0 ||
        userinfo_resp.status_code != 200 || !userinfo_resp.body) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR, "UserInfo query failed (HTTP status %ld)",
                      userinfo_resp.status_code);
        retval = PAM_AUTHINFO_UNAVAIL;
        notify_user_failure(pamh, USER_NOTICE_SERVICE);
        goto cleanup;
    }

    uinfo_json = json_tokener_parse(userinfo_resp.body);
    if (!uinfo_json || !json_object_is_type(uinfo_json, json_type_object)) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR, "Invalid JSON response from UserInfo endpoint");
        retval = PAM_SERVICE_ERR;
        notify_user_failure(pamh, USER_NOTICE_SERVICE);
        goto cleanup;
    }

    /* Step 7b-9: Post-UserInfo identity verification in one reviewable unit: PII-safe
     * UserInfo audit logging, configured claim-field extraction, JWT-sub vs UserInfo-sub
     * token-substitution check, claim verification against the requesting PAM user, and
     * group/role allow/deny authorization. Each failure is logged, a plain-text notice is
     * delivered, and a distinct PAM status returned. See verify_userinfo_identity() in
     * src/identity.c. */
    retval =
        verify_userinfo_identity(pamh, &cfg, active_loglevel, pam_user, uinfo_json, userinfo_resp.size, access_token);
    if (retval != PAM_SUCCESS) {
        goto cleanup;
    }

    pam_oauth_log(pamh, active_loglevel, LOGLEVEL_INFO, LOG_INFO, "Authentication successful for user '%s'", pam_user);
    retval = PAM_SUCCESS;

cleanup:
    /* Securely scrub sensitive credentials and release memory resources */
    if (dev_json) {
        secure_zero_json_tree(dev_json);
        json_object_put(dev_json);
    }
    if (tok_json) {
        secure_zero_json_tree(tok_json);
        json_object_put(tok_json);
    }
    if (uinfo_json) {
        secure_zero_json_tree(uinfo_json);
        json_object_put(uinfo_json);
    }

    free_http_response(&resp);
    free_http_response(&token_resp);
    free_http_response(&userinfo_resp);

    /*
     * Scrub each secret buffer INCLUDING its terminating NUL byte (strlen() + 1),
     * matching the `secure_zero_json_tree()` convention above. The buffers are heap
     * C strings, so the NUL is always within the allocation and scrubbing it keeps
     * the disposal consistent and leaves no residual byte at the string boundary.
     */
    if (postfields) {
        secure_memzero(postfields, strlen(postfields) + 1);
        free(postfields);
    }
    if (token_postfields) {
        secure_memzero(token_postfields, strlen(token_postfields) + 1);
        free(token_postfields);
    }
    if (access_token) {
        secure_memzero(access_token, strlen(access_token) + 1);
        free(access_token);
    }

    /*
     * `pam_user` is owned by the PAM library (a read-only `const char *` obtained from
     * `pam_get_user()`), so it is intentionally NOT freed during cleanup.
     */
    secure_memzero(&dev, sizeof(dev));
    secure_memzero(code_verifier, sizeof(code_verifier));
    secure_memzero(code_challenge, sizeof(code_challenge));
    secure_memzero(&cfg, sizeof(cfg));

    if (curl) {
        curl_easy_cleanup(curl);
    }

    return retval;
}

/**
 * @brief PAM credential-management hook (required by the PAM module ABI).
 *
 * This module is intentionally a credential-management no-op. The RFC 8628 device
 * flow is fully self-contained within `pam_sm_authenticate()`: device codes,
 * access tokens, and identity claims are never stored in PAM handle items,
 * written to disk, or otherwise retained after that call returns (sensitive
 * buffers are scrubbed before exit). Consequently there are no module-managed
 * credentials, PAM tickets, or Kerberos tokens for this hook to preset
 * (`PAM_PRESET`), reinitialize (`PAM_REINIT`), or refresh (`PAM_REFRESH`) — it
 * returns `PAM_SUCCESS` unconditionally so the rest of the PAM stack can
 * proceed. Any required credential management must be provided by another
 * module in the PAM stack.
 *
 * @param[in] pamh  PAM framework handle.
 * @param[in] flags PAM credential flags (`PAM_PRESET`, `PAM_REINIT`, `PAM_EXPIRE`, `PAM_REFRESH`).
 * @param[in] argc  Module argument count.
 * @param[in] argv  Module arguments array.
 * @return `PAM_SUCCESS` unconditionally.
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
