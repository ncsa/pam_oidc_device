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
 * @param[in] obj Root json-c node to scrub (any type, or NULL).
 */
static void secure_zero_json_tree(struct json_object *obj) { // NOLINT(misc-no-recursion)
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
            secure_zero_json_tree(json_object_array_get_idx(obj, (int)i));
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
        int w = 0;
        if (url_complete && strcmp(url, url_complete) != 0) {
            w = snprintf(out, out_len,
                         "\nComplete authentication in your browser:\n  URL:  %s\n  Code: %s\n  (Direct: %s)\n\n"
                         "Waiting for your approval; this session completes automatically once you sign in.\n",
                         url, code, url_complete);
        } else {
            w = snprintf(out, out_len,
                         "\nComplete authentication in your browser:\n  URL:  %s\n  Code: %s\n\n"
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

/**
 * @brief Primary PAM authentication hook implementation.
 *
 * Executes full RFC 8628 device authorization workflow:
 * 1. Parses PAM module parameters (`config=...`, `loglevel=...`).
 * 2. Loads module configuration settings (`load_config`).
 * 3. Sends POST request to Device Authorization Endpoint to obtain `device_code` and `user_code`.
 * 4. Displays the sign-in instructions to the user via a PAM conversation message (`PAM_TEXT_INFO`),
 *    optionally preceded by a scannable terminal QR code of the verification URI (`[qr]` section).
 *    A `PAM_PROMPT_ECHO_ON` "Press [Enter] to begin..." prompt is then issued; polling starts
 *    only after the user presses Enter. This round-trip flushes the buffered `PAM_TEXT_INFO`
 *    prompt to OpenSSH keyboard-interactive clients (which otherwise only render it when a
 *    subsequent prompt triggers a `USERINFO` round-trip) while acting as a synchronization
 *    barrier so the user has had time to note the URL and code.
 * 5. Polls the Token Endpoint using monotonic clock timing until token issuance, expiration, or user
 *    denial.
 * 6. Performs local JWT metadata verification (exp, nbf, iss, aud) if enabled.
 * 7. Queries provider UserInfo endpoint with access token.
 * 8. Logs a redacted UserInfo receipt record (size + claim field) at debug level; the full claim payload
 *    is logged only at verbose (troubleshooting) level to keep PII out of routine logs.
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

    char device_code[2048];
    memset(device_code, 0, sizeof(device_code));

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
            goto cleanup;
        }
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                      "PKCE (RFC 7636) S256 enabled for this device-authorization attempt");
    }

    /* Step 3: Request device code from provider Device Endpoint */
    pam_oauth_log(pamh, active_loglevel, LOGLEVEL_DEBUG, LOG_DEBUG, "Requesting device code from endpoint: %s",
                  cfg.device_authorization_endpoint);

    /*
     * Form-field table for the device-authorization request. Every append goes
     * through form_field_append(), which enforces DEVICE_FORM_MAX_FIELDS so an
     * oversized parameter set fails safe instead of overflowing the table.
     */
    const char *d_keys[DEVICE_FORM_MAX_FIELDS];
    const char *d_vals[DEVICE_FORM_MAX_FIELDS];
    size_t d_count = 0;
    int d_append_rc = 0;

    d_append_rc |= form_field_append(d_keys, d_vals, &d_count, DEVICE_FORM_MAX_FIELDS, "client_id", cfg.client_id);

    /* Client credentials are transmitted as form parameters in the request body
     * (`client_secret_post`, RFC 6749 s2.3.1); the `client_secret_basic` (HTTP Basic)
     * client-authentication method is not supported. */
    if (strlen(cfg.client_secret) > 0) {
        d_append_rc |=
            form_field_append(d_keys, d_vals, &d_count, DEVICE_FORM_MAX_FIELDS, "client_secret", cfg.client_secret);
    }
    if (strlen(cfg.scopes) > 0) {
        d_append_rc |= form_field_append(d_keys, d_vals, &d_count, DEVICE_FORM_MAX_FIELDS, "scope", cfg.scopes);
    }
    if (pkce_active) {
        d_append_rc |=
            form_field_append(d_keys, d_vals, &d_count, DEVICE_FORM_MAX_FIELDS, "code_challenge", code_challenge);
        d_append_rc |=
            form_field_append(d_keys, d_vals, &d_count, DEVICE_FORM_MAX_FIELDS, "code_challenge_method", "S256");
    }

    if (d_append_rc != 0) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Device request form-field table overflowed its fixed capacity");
        retval = PAM_BUF_ERR;
        goto cleanup;
    }

    if (build_form_postfields(curl, d_keys, d_vals, d_count, &postfields) != 0) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR, "Failed to build device request form postfields");
        retval = PAM_BUF_ERR;
        goto cleanup;
    }

    if (http_request("POST", cfg.device_authorization_endpoint, postfields, NULL, 10000L, &resp, active_loglevel,
                     pamh) != 0 ||
        resp.status_code != 200 || !resp.body) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Device authorization request failed (HTTP status code: %ld)", resp.status_code);
        retval = PAM_AUTHINFO_UNAVAIL;
        goto cleanup;
    }

    dev_json = json_tokener_parse(resp.body);
    if (!dev_json || !json_object_is_type(dev_json, json_type_object)) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR, "Invalid JSON payload from device endpoint");
        retval = PAM_SERVICE_ERR;
        goto cleanup;
    }

    struct json_object *j_code = NULL;
    struct json_object *j_uri = NULL;
    struct json_object *j_uri_complete = NULL;
    struct json_object *j_ucode = NULL;
    struct json_object *j_int = NULL;
    struct json_object *j_exp = NULL;

    json_object_object_get_ex(dev_json, "device_code", &j_code);
    json_object_object_get_ex(dev_json, "verification_uri", &j_uri);
    json_object_object_get_ex(dev_json, "verification_uri_complete", &j_uri_complete);
    json_object_object_get_ex(dev_json, "user_code", &j_ucode);
    json_object_object_get_ex(dev_json, "interval", &j_int);
    json_object_object_get_ex(dev_json, "expires_in", &j_exp);

    if (!j_code || !j_uri || !json_object_is_type(j_code, json_type_string) ||
        !json_object_is_type(j_uri, json_type_string)) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Missing device_code or verification_uri in endpoint response");
        retval = PAM_SERVICE_ERR;
        goto cleanup;
    }

    /* user_code is REQUIRED per RFC 8628 Section 3.2; fail fast with a specific
       message instead of letting the injection check below trip on a placeholder. */
    if (!j_ucode || !json_object_is_type(j_ucode, json_type_string)) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR, "Missing user_code in endpoint response");
        retval = PAM_SERVICE_ERR;
        goto cleanup;
    }

    if (copy_checked(device_code, sizeof(device_code), json_object_get_string(j_code)) != 0) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR, "Device code buffer capacity exceeded");
        retval = PAM_BUF_ERR;
        goto cleanup;
    }

    const char *url_str = json_object_get_string(j_uri);
    const char *url_comp_str = (j_uri_complete && json_object_is_type(j_uri_complete, json_type_string))
                                   ? json_object_get_string(j_uri_complete)
                                   : NULL;
    const char *user_code_str = json_object_get_string(j_ucode);

    /* Validate provider URLs and user code against injection attacks */
    if (!is_valid_https_url(url_str) || !is_safe_user_code(user_code_str) ||
        (url_comp_str && !is_valid_https_url(url_comp_str))) {
        if (pamh) {
            pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Insecure or malformed URL/code in provider response");
        }
        retval = PAM_SERVICE_ERR;
        goto cleanup;
    }

    int interval = (j_int && json_object_is_type(j_int, json_type_int)) ? json_object_get_int(j_int) : 5;
    if (interval < MIN_POLL_INTERVAL) {
        interval = MIN_POLL_INTERVAL;
    }

    if (interval > MAX_SUPPORTED_POLL_INTERVAL) {
        if (pamh) {
            pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Provider poll interval %d exceeds supported maximum", interval);
        }
        retval = PAM_SERVICE_ERR;
        goto cleanup;
    }

    int expires_in = (j_exp && json_object_is_type(j_exp, json_type_int)) ? json_object_get_int(j_exp) : 300;
    if (expires_in <= 0) {
        expires_in = 300;
    }
    if (expires_in > cfg.max_poll_seconds) {
        expires_in = cfg.max_poll_seconds;
    }

    pam_oauth_log(pamh, active_loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                  "Device code response parsed: poll interval=%ds, expires_in=%ds", interval, expires_in);

    /* Calculate polling expiration deadline using POSIX monotonic clock */
    struct timespec device_deadline;
    if (clock_gettime(CLOCK_MONOTONIC, &device_deadline) != 0) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR, "Failed to read monotonic clock");
        retval = PAM_SYSTEM_ERR;
        goto cleanup;
    }
    device_deadline.tv_sec += expires_in;

    /* Step 4: Display instructions and verification code to client terminal */
    char prompt_buf[MAX_INIT_MSG_LEN];
    if (render_prompt_message(&cfg, url_str, url_comp_str, user_code_str, prompt_buf, sizeof(prompt_buf)) != 0) {
        if (pamh) {
            pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR, "Failed to render prompt message");
        }
        retval = PAM_SERVICE_ERR;
        goto cleanup;
    }

    /* Step 4b: Optionally present the verification URI as a scannable terminal QR code so the
     * user can open the page with a phone camera instead of typing. The block is informational
     * (PAM_TEXT_INFO); any rendering failure is logged at debug level and non-fatal, because the
     * text prompt below always carries the URL and user code. */
    if (cfg.qr_enabled) {
        char qr_buf[QR_RENDER_BUF_MAX];
        if (qr_render_verification_code(&cfg, active_loglevel, url_str, url_comp_str, qr_buf, sizeof(qr_buf), pamh) ==
            0) {
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

    /* Step 5: Build token request body prior to entering polling loop */
    /*
     * Form-field table for the token request. Every append goes through
     * form_field_append(), which enforces TOKEN_FORM_MAX_FIELDS so an oversized
     * parameter set fails safe instead of overflowing the table.
     */
    const char *t_keys[TOKEN_FORM_MAX_FIELDS];
    const char *t_vals[TOKEN_FORM_MAX_FIELDS];
    size_t t_count = 0;
    int t_append_rc = 0;

    t_append_rc |= form_field_append(t_keys, t_vals, &t_count, TOKEN_FORM_MAX_FIELDS, "client_id", cfg.client_id);

    /* Client credentials follow the same form-body `client_secret_post` pattern as the
     * device-authorization request above; `client_secret_basic` is not supported. */
    if (strlen(cfg.client_secret) > 0) {
        t_append_rc |=
            form_field_append(t_keys, t_vals, &t_count, TOKEN_FORM_MAX_FIELDS, "client_secret", cfg.client_secret);
    }
    t_append_rc |= form_field_append(t_keys, t_vals, &t_count, TOKEN_FORM_MAX_FIELDS, "grant_type",
                                     "urn:ietf:params:oauth:grant-type:device_code");
    t_append_rc |= form_field_append(t_keys, t_vals, &t_count, TOKEN_FORM_MAX_FIELDS, "device_code", device_code);
    if (pkce_active) {
        t_append_rc |=
            form_field_append(t_keys, t_vals, &t_count, TOKEN_FORM_MAX_FIELDS, "code_verifier", code_verifier);
    }

    if (t_append_rc != 0) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Token request form-field table overflowed its fixed capacity");
        retval = PAM_BUF_ERR;
        goto cleanup;
    }

    if (build_form_postfields(curl, t_keys, t_vals, t_count, &token_postfields) != 0) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR, "Failed to build token request form postfields");
        retval = PAM_BUF_ERR;
        goto cleanup;
    }

    pam_oauth_log(pamh, active_loglevel, LOGLEVEL_INFO, LOG_INFO, "Polling token endpoint for user '%s'...", pam_user);

    /* Step 6: Polling loop enforcing RFC 8628 interval delay. The first poll is issued
     * immediately (no leading sleep) so the user does not wait a full interval before the
     * initial token request; subsequent polls are spaced by the (possibly adjusted) interval. */
    int first_poll = 1;
    while (1) {
        if (!first_poll) {
            struct timespec now;
            if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
                pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR, "Failed to read monotonic clock");
                retval = PAM_SYSTEM_ERR;
                goto cleanup;
            }
            struct timespec next_poll = now;
            next_poll.tv_sec += interval;

            if (!timespec_before(&next_poll, &device_deadline)) {
                pam_oauth_log(pamh, active_loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
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
                 * blocking the login; abort instead — all resources are reclaimed at
                 * `cleanup`. */
                pam_oauth_log(pamh, active_loglevel, LOGLEVEL_INFO, LOG_INFO,
                              "Polling interrupted by a signal; aborting device-authorization wait");
                retval = PAM_ABORT;
                goto cleanup;
            }

            if (sleep_rc != 0) {
                pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR, "Clock nanosleep failed with error %d",
                              sleep_rc);
                retval = PAM_SYSTEM_ERR;
                goto cleanup;
            }
        }
        first_poll = 0;

        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || !timespec_before(&now, &device_deadline)) {
            pam_oauth_log(pamh, active_loglevel, LOGLEVEL_DEBUG, LOG_DEBUG, "Polling authorization deadline reached");
            break;
        }

        long remain_ms = (long)((device_deadline.tv_sec - now.tv_sec) * 1000);
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

        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_DEBUG, LOG_DEBUG, "Polling token endpoint (timeout: %ldms)",
                      req_timeout_ms);

        free_http_response(&token_resp);
        int req_rc = http_request("POST", cfg.token_endpoint, token_postfields, NULL, req_timeout_ms, &token_resp,
                                  active_loglevel, pamh);

        if (req_rc == 0) {
            if (is_retryable_token_http_status(token_resp.status_code)) {
                /*
                 * HTTP 429 (rate limited) and 5xx (server/gateway error) are transient conditions
                 * and are NOT well-formed RFC 8628 OAuth error responses. The body may be empty, a
                 * JSON object, or an HTML error page returned by a proxy/load balancer. Back off and
                 * retry within the device-authorization deadline instead of aborting authentication.
                 */
                interval = (interval > MAX_SUPPORTED_POLL_INTERVAL / 2) ? MAX_SUPPORTED_POLL_INTERVAL : interval * 2;
                pam_oauth_log(pamh, active_loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                              "Transient HTTP status %ld from token endpoint; backing off poll interval to %ds",
                              token_resp.status_code, interval);
            } else if (token_resp.status_code >= 200 && token_resp.status_code < 300 && token_resp.body) {
                if (tok_json) {
                    json_object_put(tok_json);
                }
                tok_json = json_tokener_parse(token_resp.body);

                if (tok_json && json_object_is_type(tok_json, json_type_object)) {
                    struct json_object *j_acc = NULL;
                    if (json_object_object_get_ex(tok_json, "access_token", &j_acc) && j_acc &&
                        json_object_is_type(j_acc, json_type_string)) {
                        size_t token_len = (size_t)json_object_get_string_len(j_acc);
                        if (token_len > 0 && token_len <= MAX_ACCESS_TOKEN_LEN) {
                            access_token = strdup(json_object_get_string(j_acc));
                            if (!access_token) {
                                pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
                                              "Memory allocation failed for access_token");
                                retval = PAM_BUF_ERR;
                                goto cleanup;
                            }
                            pam_oauth_log(pamh, active_loglevel, LOGLEVEL_INFO, LOG_INFO,
                                          "Access token successfully acquired");
                            break; /* Access token acquired successfully */
                        } else if (token_len > MAX_ACCESS_TOKEN_LEN) {
                            pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
                                          "Access token length (%zu) exceeds maximum supported length (%d); aborting",
                                          token_len, MAX_ACCESS_TOKEN_LEN);
                            break; /* Token too large to process */
                        }
                    }
                }
                break;
            } else if (token_resp.status_code >= 400 && token_resp.status_code < 500 && token_resp.body) {
                /*
                 * RFC 8628 §3.5 OAuth error path (non-429 4xx): a well-formed token response carries
                 * an `error` string. `authorization_pending` and `slow_down` keep the loop alive; any
                 * other error is definitive and aborts polling. A 4xx without a parseable error body
                 * is also treated as definitive.
                 */
                if (tok_json) {
                    json_object_put(tok_json);
                }
                tok_json = json_tokener_parse(token_resp.body);

                if (tok_json && json_object_is_type(tok_json, json_type_object)) {
                    struct json_object *j_err = NULL;
                    if (json_object_object_get_ex(tok_json, "error", &j_err) && j_err &&
                        json_object_is_type(j_err, json_type_string)) {
                        const char *err = json_object_get_string(j_err);
                        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                                      "Token endpoint returned error: %s", err);
                        if (strcmp(err, "slow_down") == 0) {
                            interval = (interval > MAX_SUPPORTED_POLL_INTERVAL - 5) ? MAX_SUPPORTED_POLL_INTERVAL
                                                                                    : interval + 5;
                            pam_oauth_log(pamh, active_loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                                          "Adjusted poll interval to %ds after slow_down", interval);
                        } else if (strcmp(err, "authorization_pending") != 0) {
                            pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
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
            if (token_resp.curl_code == CURLE_OPERATION_TIMEDOUT || token_resp.curl_code == CURLE_COULDNT_CONNECT ||
                token_resp.curl_code == CURLE_COULDNT_RESOLVE_HOST ||
                token_resp.curl_code == CURLE_COULDNT_RESOLVE_PROXY || token_resp.curl_code == CURLE_GOT_NOTHING) {
                interval = (interval > MAX_SUPPORTED_POLL_INTERVAL / 2) ? MAX_SUPPORTED_POLL_INTERVAL : interval * 2;
                pam_oauth_log(pamh, active_loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                              "Transient cURL error (%d); backing off poll interval to %ds", token_resp.curl_code,
                              interval);
            } else {
                pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR, "Fatal cURL error during polling: %s",
                              curl_easy_strerror(token_resp.curl_code));
                break; /* Non-recoverable network error */
            }
        }
    }

    if (!access_token) {
        if (pamh) {
            pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Authentication failed for user '%s': timed out or denied", pam_user);
        }
        retval = PAM_AUTH_ERR;
        goto cleanup;
    }

    /* Step 6b: Execute local JWT claim inspection if enabled. NOTE: claims-only check;
     * the JWT signature is verified downstream by the UserInfo endpoint, not here. */
    if (cfg.verify_jwt_claims) {
        if (verify_token_metadata(access_token, &cfg, pamh) != 0) {
            pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR, "JWT claim inspection failed for user '%s'",
                          pam_user);
            retval = PAM_AUTH_ERR;
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
        goto cleanup;
    }

    uinfo_json = json_tokener_parse(userinfo_resp.body);
    if (!uinfo_json || !json_object_is_type(uinfo_json, json_type_object)) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR, "Invalid JSON response from UserInfo endpoint");
        retval = PAM_SERVICE_ERR;
        goto cleanup;
    }

    /* Redacted PII-safe UserInfo audit log at LOGLEVEL_DEBUG: the raw claim payload
     * contains personal data (emails, phone numbers, group memberships) and must not
     * be persisted to the system log at the routine debug level. The full payload is
     * emitted only at LOGLEVEL_VERBOSE, the troubleshooting level. */
    pam_oauth_log(pamh, active_loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                  "UserInfo claim payload received: %zu bytes, claim field '%s' present", userinfo_resp.size,
                  cfg.claim_field);
    pam_oauth_log(pamh, active_loglevel, LOGLEVEL_VERBOSE, LOG_DEBUG, "UserInfo claim payload received: %s",
                  userinfo_resp.body);

    struct json_object *j_claim = NULL;
    if (!json_object_object_get_ex(uinfo_json, cfg.claim_field, &j_claim) || !j_claim ||
        !json_object_is_type(j_claim, json_type_string)) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "UserInfo response missing string claim field '%s'", cfg.claim_field);
        retval = PAM_AUTH_ERR;
        goto cleanup;
    }

    /* Step 8: Verify identity claim against requesting PAM user */
    const char *raw_claim = json_object_get_string(j_claim);
    int valid = verify_claim(pam_user, raw_claim, &cfg, pamh);
    if (!valid) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Authentication failed for user '%s': claim verification failed", pam_user);
        retval = PAM_AUTH_ERR;
        goto cleanup;
    }

    /* Step 9: Enforce Group / Role Authorization (allow/deny group lists) */
    if (!verify_group_membership(uinfo_json, &cfg, pamh)) {
        pam_oauth_log(pamh, active_loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Group authorization denied for user '%s': group/role allow/deny lists not satisfied", pam_user);
        retval = PAM_PERM_DENIED;
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
    secure_memzero(device_code, sizeof(device_code));
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
