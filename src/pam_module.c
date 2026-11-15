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
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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
static int form_field_append(const char **keys, const char **vals, size_t *count, size_t capacity, const char *key,
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
 * @brief Validates that a fully rendered multi-line terminal prompt is display-safe.
 *
 * Rendered prompts legitimately contain newline characters, which `is_safe_terminal_string()`
 * rejects outright; this helper splits the prompt on newlines and requires every line to pass
 * the printable-ASCII terminal-safety check, so C0/C1 control bytes and non-printable bytes
 * (e.g. ANSI escape sequences) cannot reach the user's terminal whether they originate from
 * the custom template, the provider URL(s), or the user code.
 *
 * @param[in] str NUL-terminated rendered prompt text.
 * @return 1 if every line is terminal-safe, 0 otherwise (including lines longer than
 *         MAX_INIT_MSG_LEN, which fail closed).
 */
static int is_safe_rendered_prompt(const char *str) {
    if (!str) {
        return 0;
    }
    char line[MAX_INIT_MSG_LEN];
    size_t line_len = 0;
    const char *line_start = str;
    for (size_t i = 0;; i++) {
        unsigned char c = (unsigned char)str[i];
        if (c != '\n' && c != '\0') {
            line_len++;
            continue;
        }
        if (line_len >= sizeof(line)) {
            return 0; /* Fail closed if a single line exceeds the scratch buffer */
        }
        memcpy(line, line_start, line_len);
        line[line_len] = '\0';
        if (!is_safe_terminal_string(line)) {
            return 0;
        }
        if (c == '\0') {
            return 1;
        }
        line_start = str + i + 1;
        line_len = 0;
    }
}

/**
 * @brief Renders the user prompt message presented during SSH / PAM interactive authentication.
 *
 * Replaces placeholders `{url}`, `{url_complete}`, `{code}`, and newline escape sequences `\\n`.
 * If no custom template is configured, generates a clean default prompt message.
 * The fully rendered result is validated line-by-line for terminal-injection safety
 * (newline-tolerant `is_safe_terminal_string`); unsafe output fails the call.
 *
 * @param[in]  cfg          Module configuration options.
 * @param[in]  url          OAuth verification URI string.
 * @param[in]  url_complete Complete verification URI containing embedded user code (optional).
 * @param[in]  code         User verification code string.
 * @param[out] out          Buffer receiving rendered text output.
 * @param[in]  out_len      Output buffer byte capacity.
 * @return 0 on success, -1 on buffer overflow, rendering error, or terminal-safety rejection.
 */
int render_prompt_message(const config_t *cfg, const char *url, const char *url_complete, const char *code, char *out,
                          size_t out_len) {
    if (!cfg || !url || !code || !out || out_len == 0) {
        return -1;
    }

    const char *tpl = cfg->init_message;
    if (tpl[0] == '\0') {
        /* Compact default: no leading blank line. When the QR code is shown, its bottom vertical
         * quiet zone already separates the prompt from the rendered art; when it is not, the
         * prompt follows the preceding terminal output directly, saving a blank line. */
        int w = 0;
        if (url_complete && strcmp(url, url_complete) != 0) {
            w = snprintf(out, out_len,
                         "Complete authentication in your browser:\n  URL:  %s\n  Code: %s\n  (Direct: %s)\n"
                         "Waiting for your approval; this session completes automatically once you sign in.\n",
                         url, code, url_complete);
        } else {
            w = snprintf(out, out_len,
                         "Complete authentication in your browser:\n  URL:  %s\n  Code: %s\n"
                         "Waiting for your approval; this session completes automatically once you sign in.\n",
                         url, code);
        }
        if (w < 0 || (size_t)w >= out_len) {
            return -1;
        }
        return is_safe_rendered_prompt(out) ? 0 : -1;
    }

    size_t out_pos = 0;
    out[0] = '\0';

    for (size_t i = 0; tpl[i] != '\0'; i++) {
        if (tpl[i] == '\\' && tpl[i + 1] == 'n') {
            if (out_pos + 1 >= out_len) {
                return -1;
            }
            out[out_pos++] = '\n';
            i++;
        } else if (strncmp(tpl + i, "{url_complete}", 14) == 0) {
            const char *val = url_complete ? url_complete : url;
            size_t vlen = strlen(val);
            if (out_pos + vlen >= out_len) {
                return -1;
            }
            memcpy(out + out_pos, val, vlen);
            out_pos += vlen;
            i += 13;
        } else if (strncmp(tpl + i, "{url}", 5) == 0) {
            size_t vlen = strlen(url);
            if (out_pos + vlen >= out_len) {
                return -1;
            }
            memcpy(out + out_pos, url, vlen);
            out_pos += vlen;
            i += 4;
        } else if (strncmp(tpl + i, "{code}", 6) == 0) {
            size_t vlen = strlen(code);
            if (out_pos + vlen >= out_len) {
                return -1;
            }
            memcpy(out + out_pos, code, vlen);
            out_pos += vlen;
            i += 5;
        } else {
            if (out_pos + 1 >= out_len) {
                return -1;
            }
            out[out_pos++] = tpl[i];
        }
    }
    out[out_pos] = '\0';
    return is_safe_rendered_prompt(out) ? 0 : -1;
}

/*
 * Plain-text, user-facing failure notices delivered through the PAM conversation
 * (`PAM_TEXT_INFO`) so a failed attempt never ends in an unexplained
 * "permission denied" (accessibility: clear, actionable error feedback).
 *
 * Wording is deliberately generic: it identifies the class of failure and the
 * next action without revealing *which* security control rejected the attempt
 * (deny-list membership, claim-mismatch detail, group-policy specifics, ...) —
 * those details remain in the audit log only. The strings are static,
 * compile-time constants and contain only printable ASCII.
 *
 * Delivery is best-effort (a `pam_prompt` failure is intentionally ignored):
 * on a degraded conversation the notice is simply not shown, and it must never
 * change the authentication outcome. OpenSSH keyboard-interactive clients may
 * additionally buffer `PAM_TEXT_INFO` until a prompt round-trip, so SSH clients
 * are not guaranteed to display it; local console logins are.
 */
static const char *const USER_NOTICE_SERVICE =
    "Sign-in could not be completed: the identity provider service is unavailable.\n"
    "Please try again, or contact your system administrator if the problem persists.\n";
static const char *const USER_NOTICE_DENIED =
    "Authentication was denied for this account.\n"
    "Please contact your system administrator if you believe this is an error.\n";
static const char *const USER_NOTICE_EXPIRED =
    "Sign-in was not approved in time: the sign-in code expired or the identity provider\n"
    "service became unavailable. Please sign in again to start a new session.\n";

static void notify_user_failure(pam_handle_t *pamh, const char *msg) {
    if (pamh && msg != NULL) {
        (void)pam_prompt(pamh, PAM_TEXT_INFO, NULL, "%s", msg);
    }
}

/*
 * Maximum length (bytes, including the terminating NUL) of the provider-issued
 * RFC 8628 device_code.
 */
#define DEVICE_CODE_MAX_LEN 2048

/*
 * Capacity (bytes, including the terminating NUL) of the stack buffer holding
 * the JWT 'sub' claim for the JWT-sub vs UserInfo-sub consistency check.
 * OIDC Core caps 'sub' at 255 ASCII characters, so 256 = 255 + NUL.
 */
#define JWT_SUB_CLAIM_MAX 256

/*
 * Result of a successful device-authorization request (RFC 8628 s3.1/s3.2).
 * The verification_uri / verification_uri_complete / user_code members are
 * BORROWED from the *dev_json tree parsed by request_device_authorization()
 * and stay valid only until the caller releases that tree; device_code is
 * owned (copied) by this struct.
 */
typedef struct {
    char device_code[DEVICE_CODE_MAX_LEN];
    const char *verification_uri;
    const char *verification_uri_complete; /* NULL when the provider omits it */
    const char *user_code;
    int poll_interval;        /* seconds, clamped to [MIN_POLL_INTERVAL, MAX_SUPPORTED_POLL_INTERVAL] */
    int expires_in;           /* seconds, clamped to (0, cfg->max_poll_seconds] */
    struct timespec deadline; /* monotonic polling expiration deadline */
} device_auth_t;

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
 */
static int request_device_authorization(pam_handle_t *pamh, const config_t *cfg, loglevel_t loglevel, int pkce_active,
                                        const char *code_challenge, CURL *curl, device_auth_t *dev,
                                        http_response_t *resp, struct json_object **dev_json, char **postfields) {
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

    if (http_request("POST", cfg->device_authorization_endpoint, *postfields, NULL, 10000L, resp, loglevel, pamh) !=
            0 ||
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
        /* RFC 8628 §3.5 only forbids polling FASTER than the advertised interval;
         * an unusually long interval is safe to honor, so clamp to the supported
         * maximum instead of failing the authentication attempt. */
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
 * @return `PAM_SUCCESS` when an access token was acquired, or the PAM error
 *         code of the failing sub-step (PAM_AUTH_ERR on timeout/denial).
 */
static int poll_for_access_token(pam_handle_t *pamh, const config_t *cfg, loglevel_t loglevel, const char *pam_user,
                                 const device_auth_t *dev, const char *code_verifier, int pkce_active, CURL *curl,
                                 http_response_t *token_resp, struct json_object **tok_json, char **access_token,
                                 char **token_postfields) {
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
        if (!first_poll) {
            struct timespec now;
            if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
                pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR, "Failed to read monotonic clock");
                return PAM_SYSTEM_ERR;
            }
            struct timespec next_poll = now;
            next_poll.tv_sec += interval;

            if (!timespec_before(&next_poll, &dev->deadline)) {
                pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                              "Polling reached device authorization expiration deadline");
                break;
            }

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

        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || !timespec_before(&now, &dev->deadline)) {
            pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG, "Polling authorization deadline reached");
            break;
        }

        long remain_ms = (long)((dev->deadline.tv_sec - now.tv_sec) * 1000);
        if (remain_ms <= 0L) {
            /*
             * The monotonic check above guarantees `now` is before the deadline
             * at nanosecond precision, but the whole-second difference can still
             * be zero at the deadline boundary. cURL treats a zero (or negative)
             * CURLOPT_TIMEOUT_MS as "no timeout", so stop polling instead of
             * firing a request with an unbounded lifetime.
             */
            break;
        }
        long req_timeout_ms = (remain_ms < 10000L) ? remain_ms : 10000L;

        pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG, "Polling token endpoint (timeout: %ldms)",
                      req_timeout_ms);

        free_http_response(token_resp);
        int req_rc = http_request("POST", cfg->token_endpoint, *token_postfields, NULL, req_timeout_ms, token_resp,
                                  loglevel, pamh);

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
                     * device-flow grants). Fail closed on a present-but-foreign token type so a
                     * malformed or unexpected token can never be passed to the UserInfo endpoint as
                     * a Bearer credential; a missing field is tolerated (DEBUG-logged) since some
                     * providers omit it.
                     */
                    struct json_object *j_ttype = NULL;
                    if (json_object_object_get_ex(*tok_json, "token_type", &j_ttype) && j_ttype) {
                        const char *ttype = json_object_get_string(j_ttype);
                        if (!ttype || strcmp(ttype, "Bearer") != 0) {
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

    /* JWT 'sub' claim for the JWT-sub vs UserInfo-sub consistency check
     * (Step 7b); scrubbed unconditionally at `cleanup` below. */
    char jwt_sub[JWT_SUB_CLAIM_MAX];
    memset(jwt_sub, 0, sizeof(jwt_sub));

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
        (void)discovery_probe_pkce(cfg.discovery_endpoint, &supported, active_loglevel, pamh);
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

    /* Step 4: Display instructions and verification code to client terminal. The
     * rendered prompt embeds the user code and verification URIs; the stack buffer
     * is scrubbed unconditionally at `cleanup` like the other sensitive material. */
    char prompt_buf[MAX_INIT_MSG_LEN];
    if (render_prompt_message(&cfg, dev.verification_uri, dev.verification_uri_complete, dev.user_code, prompt_buf,
                              sizeof(prompt_buf)) != 0) {
        if (pamh) {
            pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR, "Failed to render prompt message");
        }
        retval = PAM_SERVICE_ERR;
        notify_user_failure(pamh, USER_NOTICE_SERVICE);
        goto cleanup;
    }

    /* Step 4b: Optionally present the verification URI as a scannable terminal QR code so the
     * user can open the page with a phone camera instead of typing. The block is informational
     * (PAM_TEXT_INFO); any rendering failure is logged at debug level and non-fatal, because the
     * text prompt below always carries the URL and user code. */
    if (cfg.qr_enabled) {
        char qr_buf[QR_RENDER_BUF_MAX];
        if (qr_render_verification_code(&cfg, active_loglevel, dev.verification_uri, dev.verification_uri_complete,
                                        qr_buf, sizeof(qr_buf), pamh) == 0) {
            int qr_res = pam_prompt(pamh, PAM_TEXT_INFO, NULL, "%s", qr_buf);
            if (qr_res != PAM_SUCCESS) {
                pam_oauth_log(pamh, active_loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                              "QR code prompt not displayed (conversation returned %d); text prompt follows", qr_res);
            }
        }
    }

    pam_oauth_log(pamh, active_loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                  "Prompting user with verification code instructions");

    /* Deliver the instructions as an informational message (PAM_TEXT_INFO), the same primitive
     * used for the QR code. OpenSSH (keyboard-interactive) buffers PAM_TEXT_INFO and flushes it
     * only when a subsequent prompt triggers a USERINFO round-trip; the mandatory PAM_PROMPT_ECHO_ON
     * "Press [Enter] to begin..." confirmation (Step 4c) forces that flush so the URL / user code
     * are reliably visible before polling begins. */
    int prompt_res = pam_prompt(pamh, PAM_TEXT_INFO, NULL, "%s", prompt_buf);
    if (prompt_res != PAM_SUCCESS) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR, "User prompt delivery failed or was cancelled");
        retval = prompt_res;
        goto cleanup;
    }

    /* Step 4c: Sign-in confirmation. Wait for a single Enter before polling begins. This
     * reliably flushes the PAM_TEXT_INFO sign-in prompt (URL / QR / user code) to OpenSSH
     * keyboard-interactive clients, which otherwise buffer it until a prompt triggers a
     * USERINFO round-trip. The keystroke is intentionally ignored — the device-code flow
     * is already in progress. */
    if (pamh) {
        int flush_rc = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, NULL, "Press [Enter] to begin... ");
        if (flush_rc == PAM_ABORT) {
            pam_oauth_log(pamh, active_loglevel, LOGLEVEL_INFO, LOG_INFO, "Authentication aborted by user");
            retval = PAM_ABORT;
            goto cleanup;
        }
        if (flush_rc != PAM_SUCCESS) {
            /* Best-effort: the URL / user code above were already sent as PAM_TEXT_INFO. Log and
             * continue polling rather than hard-failing on a degraded conversation. */
            pam_oauth_log(pamh, active_loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                          "Key-press prompt returned %d; proceeding to polling", flush_rc);
        }
    }

    /* Step 5/6: Build the token request and poll the Token Endpoint (first poll immediate,
     * then RFC 8628 interval spacing with slow_down / transient-error backoff) until token
     * issuance, expiration, denial, or an unrecoverable error. See poll_for_access_token(). */
    retval = poll_for_access_token(pamh, &cfg, active_loglevel, pam_user, &dev, code_verifier, pkce_active, curl,
                                   &token_resp, &tok_json, &access_token, &token_postfields);
    if (retval != PAM_SUCCESS) {
        /* User-initiated cancellation (Ctrl-C) gets no notice — the user already knows. */
        if (retval != PAM_ABORT) {
            notify_user_failure(pamh, USER_NOTICE_EXPIRED);
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

    if (http_request("GET", cfg.userinfo_endpoint, NULL, access_token, 10000L, &userinfo_resp, active_loglevel, pamh) !=
            0 ||
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

    /* PII-safe UserInfo audit logging: the raw claim payload contains personal
     * data (emails, phone numbers, group memberships) and must never be
     * persisted to the system log. Routine logging (DEBUG) records only the
     * payload size and the configured claim field; the troubleshooting level
     * (VERBOSE) additionally lists the claim NAMES returned by the provider —
     * enough to debug claim-field configuration — without logging any claim
     * VALUES. */
    pam_oauth_log(pamh, active_loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                  "UserInfo claim payload received: %zu bytes, claim field '%s' present", userinfo_resp.size,
                  cfg.claim_field);
    {
        struct json_object_iter it;
        /* Cap the claim-name listing; larger payloads get a summary line
         * instead. json_object_object_length() returns int on older json-c
         * (EL8/EL9) and size_t on newer releases, so capture through an
         * explicit long and range-check it; both the total and the remaining
         * budget stay opaque runtime values, so the budget check below is
         * not statically foldable. */
        const long claims_raw = (long)json_object_object_length(uinfo_json);
        const size_t total_claims = (claims_raw > 0) ? (size_t)claims_raw : 0;
        size_t names_left = (total_claims < 32) ? total_claims : 32;
        json_object_object_foreachC(uinfo_json, it) {
            if (names_left == 0) {
                break;
            }
            int name_safe = 1;
            for (const char *p = it.key; p && *p != '\0'; p++) {
                if ((unsigned char)*p < 0x20 || (unsigned char)*p > 0x7E) {
                    name_safe = 0;
                    break;
                }
            }
            if (name_safe) {
                pam_oauth_log(pamh, active_loglevel, LOGLEVEL_VERBOSE, LOG_DEBUG, "UserInfo claim present: '%s'",
                              it.key);
            } else {
                pam_oauth_log(pamh, active_loglevel, LOGLEVEL_VERBOSE, LOG_DEBUG,
                              "UserInfo claim present: (name contains non-printable bytes; withheld)");
            }
            names_left--;
        }
        if (total_claims > 32) {
            pam_oauth_log(pamh, active_loglevel, LOGLEVEL_VERBOSE, LOG_DEBUG,
                          "UserInfo claim list truncated: 32 of %zu claim names shown", total_claims);
        }
    }

    struct json_object *j_claim = NULL;
    if (!json_object_object_get_ex(uinfo_json, cfg.claim_field, &j_claim) || !j_claim ||
        !json_object_is_type(j_claim, json_type_string)) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "UserInfo response missing string claim field '%s'", cfg.claim_field);
        retval = PAM_AUTH_ERR;
        goto cleanup;
    }

    /* Step 7b: JWT-sub vs UserInfo-sub consistency check (token-substitution
     * defense). When local JWT claim inspection is enabled and the access
     * token carries a 'sub' claim, it must match the UserInfo 'sub': the
     * UserInfo exchange is the module's only authoritative token
     * validity/signature check, and on multi-audience IdPs a token minted
     * for a different client could otherwise authorize the wrong subject. A
     * missing 'sub' on either side is skipped (logged; providers differ),
     * while a present-but-mismatched or malformed 'sub' fails closed. */
    if (cfg.verify_jwt_claims) {
        int sub_rc = jwt_extract_claim_string(access_token, "sub", jwt_sub, sizeof(jwt_sub));
        if (sub_rc == 0) {
            struct json_object *j_uinfo_sub = NULL;
            if (json_object_object_get_ex(uinfo_json, "sub", &j_uinfo_sub) && j_uinfo_sub &&
                json_object_is_type(j_uinfo_sub, json_type_string)) {
                if (strcmp(jwt_sub, json_object_get_string(j_uinfo_sub)) != 0) {
                    pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
                                  "JWT subject does not match UserInfo subject for user '%s' "
                                  "(token substitution suspected)",
                                  pam_user);
                    notify_user_failure(pamh, USER_NOTICE_DENIED);
                    retval = PAM_AUTH_ERR;
                    goto cleanup;
                }
                pam_oauth_log(pamh, active_loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                              "JWT subject matches UserInfo subject for user '%s'", pam_user);
            } else {
                pam_oauth_log(pamh, active_loglevel, LOGLEVEL_INFO, LOG_WARNING,
                              "UserInfo response carries no string 'sub' claim; JWT subject consistency check skipped");
            }
        } else if (sub_rc == 1) {
            pam_oauth_log(pamh, active_loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                          "Access token carries no 'sub' claim; JWT subject consistency check skipped");
        } else {
            pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Malformed 'sub' claim in access token for user '%s'", pam_user);
            retval = PAM_AUTH_ERR;
            notify_user_failure(pamh, USER_NOTICE_DENIED);
            goto cleanup;
        }
    }

    /* Step 8: Verify identity claim against requesting PAM user */
    const char *raw_claim = json_object_get_string(j_claim);
    int valid = verify_claim(pam_user, raw_claim, &cfg, pamh);
    if (!valid) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Authentication failed for user '%s': claim verification failed", pam_user);
        retval = PAM_AUTH_ERR;
        notify_user_failure(pamh, USER_NOTICE_DENIED);
        goto cleanup;
    }

    /* Step 9: Enforce Group / Role Authorization (allow/deny group lists) */
    if (!verify_group_membership(uinfo_json, &cfg, pamh)) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Group authorization denied for user '%s': group/role allow/deny lists not satisfied", pam_user);
        retval = PAM_PERM_DENIED;
        notify_user_failure(pamh, USER_NOTICE_DENIED);
        goto cleanup;
    }
    pam_oauth_log(pamh, active_loglevel, LOGLEVEL_DEBUG, LOG_DEBUG, "Group authorization succeeded for user '%s'",
                  pam_user);

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
    /* prompt_buf embeds the user code and verification URIs; jwt_sub holds the
     * JWT subject identifier. Both are sensitive display/identity material and
     * are scrubbed unconditionally, like every other secret above. */
    secure_memzero(prompt_buf, sizeof(prompt_buf));
    secure_memzero(jwt_sub, sizeof(jwt_sub));
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
