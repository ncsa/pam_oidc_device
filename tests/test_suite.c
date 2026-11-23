/**
 * @file test_suite.c
 * @brief CMocka unit test suite covering configuration parsing, log level evaluation, claim mapping, sanitization,
 * prompt rendering, terminal QR code encoding/rendering, error handling, and local JWT token metadata verification.
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

/*
 * libcurl's <curl/curl.h> includes typecheck-gcc.h when compiled with a
 * real GCC >= 4.3, which redefines curl_easy_setopt(), curl_easy_getinfo()
 * and the multi/share setopt variants as variadic argument type-checking
 * macros built from __extension__ blocks. That macro would expand at the
 * weak curl_easy_setopt() override below ("expected identifier or '('
 * before '__extension__'"). libcurl's own guard offers an explicit opt-out
 * via CURL_DISABLE_TYPECHECK; the macros are purely a compile-time argument
 * check and this translation unit never calls curl_easy_setopt() directly,
 * so disabling them here is safe. (Clang masquerades as GCC 4.2, so it
 * never enables the macros — which is why only the gcc CI job fails.)
 */
#define CURL_DISABLE_TYPECHECK

#include "../include/pam_oidc_device.h"

/* clang-format off */
#include <dlfcn.h>
#include <errno.h>
#include <pwd.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <unistd.h>
#include <wchar.h>
/* clang-format on */

/*
 * Internal device-flow contract (src/device_flow.h): device_auth_t,
 * token_phase_t, poll_sched_action_t and the test-exported device-authorization
 * / poll-loop helpers from src/pam_module.c. The header is internal (NOT part
 * of the public API in include/pam_oidc_device.h) and exists so this suite and
 * src/pam_module.c share one declaration of these symbols.
 */
#include "../src/device_flow.h"

/*
 * Weak overrides of libcurl's transport entry points, used exclusively by the
 * http_request()/discovery_probe_pkce tests. Defining these global symbols in
 * the test executable redirects the calls made by the module code here
 * instead of into libcurl (no real transfer is ever performed):
 *  - curl_easy_setopt() records the TLS options, the proxy URL, the no-proxy
 *    string, and the proxy-TLS options requested by http_request() and captures the WRITEFUNCTION/WRITEDATA
 *    pair so a
 *    fake response body can be "received" by the module's write callback;
 *  - curl_easy_perform() returns `g_fake_curl_perform_rc` and, when a fake
 *    body is configured, invokes the captured write callback with it;
 *  - curl_easy_getinfo() reports `g_fake_curl_status_code` for
 *    CURLINFO_RESPONSE_CODE.
 * Every setopt call is a no-op returning CURLE_OK.
 */
/* libcurl's curl_write_callback signature (curl/curl.h), given a local name so
 * va_arg() below never embeds an anonymous function-pointer type-id, whose
 * formatting differs across clang-format versions. */
typedef size_t (*test_write_cb)(void *ptr, size_t size, size_t nmemb, void *userdata);

static int tls_opt_seen;
static long tls_opt_ssl_verifypeer;
static long tls_opt_ssl_verifyhost;
static int tls_opt_ssl_version;
/** Last CURLOPT_PROXY value requested ("" when the proxy is explicitly cleared). */
static char g_fake_curl_proxy[512];
/** Last CURLOPT_NOPROXY value requested ("" when the no-proxy list is explicitly cleared). */
static char g_fake_curl_noproxy[512];
/** Last CURLOPT_PROXY_SSL_VERIFYPEER value requested (-1 if not yet set). */
static long proxy_tls_opt_verifypeer = -1L;
/** Last CURLOPT_PROXY_SSL_VERIFYHOST value requested (-1 if not yet set). */
static long proxy_tls_opt_verifyhost = -1L;
/** Last CURLOPT_PROXY_SSLVERSION value requested (-1 if not yet set). */
static int proxy_tls_opt_version = -1;

static CURLcode g_fake_curl_perform_rc = CURLE_OK;
static long g_fake_curl_status_code = 0;
static const char *g_fake_curl_body = NULL;
static test_write_cb g_fake_write_cb;
static void *g_fake_write_data;

/*
 * Optional scripted response sequence for multi-round flows (the device-flow
 * poll loop): when g_fake_steps_count > 0, each curl_easy_perform() call serves
 * the next (body, status) pair in order; once the script is exhausted the last
 * entry repeats. g_fake_perform_count counts every perform call so tests can
 * assert exactly how many HTTP requests a flow issued.
 */
#define FAKE_TRANSPORT_MAX_STEPS 8
static const char *g_fake_steps_bodies[FAKE_TRANSPORT_MAX_STEPS];
static long g_fake_steps_codes[FAKE_TRANSPORT_MAX_STEPS];
static int g_fake_steps_count;
static int g_fake_step_index;
static int g_fake_perform_count;

/** Resets the fake-transport state so individual tests never leak into each other. */
static void reset_fake_curl_transport(void) {
    g_fake_curl_perform_rc = CURLE_OK;
    g_fake_curl_status_code = 0;
    g_fake_curl_body = NULL;
    g_fake_write_cb = NULL;
    g_fake_write_data = NULL;
    g_fake_curl_proxy[0] = '\0';
    g_fake_curl_noproxy[0] = '\0';
    for (int i = 0; i < FAKE_TRANSPORT_MAX_STEPS; i++) {
        g_fake_steps_bodies[i] = NULL;
        g_fake_steps_codes[i] = 0;
    }
    g_fake_steps_count = 0;
    g_fake_step_index = 0;
    g_fake_perform_count = 0;
}

/**
 * @brief Installs a scripted sequence of fake HTTP responses.
 *
 * @param[in] bodies Response bodies served in order (final entry repeats once exhausted).
 * @param[in] codes  HTTP status codes matching each body.
 * @param[in] count  Number of scripted steps (clamped to FAKE_TRANSPORT_MAX_STEPS).
 */
static void script_fake_responses(const char *const bodies[], const long codes[], int count) {
    g_fake_steps_count = (count > FAKE_TRANSPORT_MAX_STEPS) ? FAKE_TRANSPORT_MAX_STEPS : count;
    for (int i = 0; i < g_fake_steps_count; i++) {
        g_fake_steps_bodies[i] = bodies[i];
        g_fake_steps_codes[i] = codes[i];
    }
    g_fake_step_index = 0;
}

/*
 * Weak/strong note: this override is deliberately a STRONG definition (unlike
 * the curl fakes above). The sanitizer build links ASan's runtime into the test
 * executable, and that runtime aliases its own weak __interceptor_getpwnam_r to
 * getpwnam_r; two weak definitions in one executable resolve to the runtime's
 * copy, silently bypassing this fake (the large-entry test then sees call count
 * 0). A strong definition beats both the ASan alias and libc's shared-library
 * definition, so module calls always land here; unscripted calls forward to the
 * real NSS lookup via dlsym(RTLD_NEXT, "getpwnam_r"), so behavior stays
 * identical either way.
 *
 * Weak override of getpwnam_r(), used exclusively by the verify_user_access()
 * uid-gate tests. The host's real NSS database cannot deterministically provide
 * a "passwd entry larger than the initial buffer" or a "persistent lookup
 * failure", so those tests script the outcome. Unless a name is scripted, every
 * call forwards to the real NSS lookup (resolved once via
 * dlsym(RTLD_NEXT, "getpwnam_r")), so the rest of the suite sees /etc/passwd
 * exactly as before. Scripted modes (g_fake_pwnam_mode):
 *  - FAKE_PWNAM_ERANGE_THEN_FOUND: g_fake_pwnam_script_name gets
 *    g_fake_pwnam_script_erange_calls ERANGE replies (regardless of the buffer
 *    size offered) and then a fabricated FOUND record with uid
 *    g_fake_pwnam_script_uid -- simulating an entry larger than the early
 *    buffers (an LDAP/SSSD record with a long GECOS string or home path);
 *  - FAKE_PWNAM_ERANGE_FOREVER: g_fake_pwnam_script_name gets ERANGE on every
 *    call -- simulating a persistent backend failure; the module's
 *    buffer-growth cap must terminate the retry loop.
 * g_fake_pwnam_call_count counts intercepted calls for the scripted name.
 */
enum { FAKE_PWNAM_OFF, FAKE_PWNAM_ERANGE_THEN_FOUND, FAKE_PWNAM_ERANGE_FOREVER };
typedef int (*fake_getpwnam_r_fn)(const char *, struct passwd *, char *, size_t, struct passwd **);
static fake_getpwnam_r_fn g_fake_pwnam_real;
static int g_fake_pwnam_mode;
static char g_fake_pwnam_script_name[32];
static int g_fake_pwnam_script_erange_calls;
static uid_t g_fake_pwnam_script_uid;
static int g_fake_pwnam_call_count;

/** Resets the scripted getpwnam_r() state so individual tests never leak into each other. */
static void reset_fake_pwnam_lookup(void) {
    g_fake_pwnam_mode = FAKE_PWNAM_OFF;
    g_fake_pwnam_script_name[0] = '\0';
    g_fake_pwnam_script_erange_calls = 0;
    g_fake_pwnam_script_uid = 0;
    g_fake_pwnam_call_count = 0;
}

int getpwnam_r(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result) {
    if (g_fake_pwnam_mode != FAKE_PWNAM_OFF && g_fake_pwnam_script_name[0] != '\0' &&
        strcmp(name, g_fake_pwnam_script_name) == 0) {
        g_fake_pwnam_call_count++;
        if (g_fake_pwnam_mode == FAKE_PWNAM_ERANGE_FOREVER || g_fake_pwnam_script_erange_calls > 0) {
            if (g_fake_pwnam_script_erange_calls > 0) {
                g_fake_pwnam_script_erange_calls--;
            }
            *result = NULL;
            return ERANGE;
        }
        pwd->pw_name = g_fake_pwnam_script_name;
        pwd->pw_passwd = "";
        pwd->pw_uid = g_fake_pwnam_script_uid;
        pwd->pw_gid = g_fake_pwnam_script_uid;
        pwd->pw_gecos = "";
        pwd->pw_dir = "";
        pwd->pw_shell = "";
        *result = pwd;
        return 0;
    }
    if (g_fake_pwnam_real == NULL) {
        g_fake_pwnam_real = (fake_getpwnam_r_fn)dlsym(RTLD_NEXT, "getpwnam_r");
    }
    if (g_fake_pwnam_real != NULL) {
        return g_fake_pwnam_real(name, pwd, buf, buflen, result);
    }
    /* The real NSS backend is unresolvable: report "no record", the outcome
     * getpwnam_r() gives for an unknown name. */
    *result = NULL;
    return 0;
}

__attribute__((weak)) CURLcode curl_easy_setopt(CURL *curl, CURLoption option, ...) {
    (void)curl;
    va_list args;
    va_start(args, option);
    if (option == CURLOPT_SSL_VERIFYPEER) {
        tls_opt_ssl_verifypeer = va_arg(args, long);
        tls_opt_seen++;
    } else if (option == CURLOPT_SSL_VERIFYHOST) {
        tls_opt_ssl_verifyhost = va_arg(args, long);
        tls_opt_seen++;
    } else if (option == CURLOPT_SSLVERSION) {
        tls_opt_ssl_version = va_arg(args, int);
        tls_opt_seen++;
    } else if (option == CURLOPT_PROXY) {
        const char *p = va_arg(args, const char *);
        snprintf(g_fake_curl_proxy, sizeof(g_fake_curl_proxy), "%s", (p != NULL) ? p : "");
    } else if (option == CURLOPT_NOPROXY) {
        const char *np = va_arg(args, const char *);
        snprintf(g_fake_curl_noproxy, sizeof(g_fake_curl_noproxy), "%s", (np != NULL) ? np : "");
    } else if (option == CURLOPT_PROXY_SSL_VERIFYPEER) {
        proxy_tls_opt_verifypeer = va_arg(args, long);
    } else if (option == CURLOPT_PROXY_SSL_VERIFYHOST) {
        proxy_tls_opt_verifyhost = va_arg(args, long);
    } else if (option == CURLOPT_PROXY_SSLVERSION) {
        proxy_tls_opt_version = va_arg(args, int);
    } else if (option == CURLOPT_WRITEFUNCTION) {
        g_fake_write_cb = va_arg(args, test_write_cb);
    } else if (option == CURLOPT_WRITEDATA) {
        g_fake_write_data = va_arg(args, void *);
    }
    va_end(args);
    return CURLE_OK;
}

__attribute__((weak)) CURLcode curl_easy_perform(CURL *curl) {
    (void)curl;
    g_fake_perform_count++;
    if (g_fake_steps_count > 0) {
        /* Scripted sequence: serve the next (body, status) pair; repeat the
         * last entry once the script is exhausted. */
        int idx = (g_fake_step_index < g_fake_steps_count) ? g_fake_step_index++ : g_fake_steps_count - 1;
        g_fake_curl_status_code = g_fake_steps_codes[idx];
        if (g_fake_curl_perform_rc == CURLE_OK && g_fake_steps_bodies[idx] && g_fake_write_cb) {
            (void)g_fake_write_cb((void *)g_fake_steps_bodies[idx], strlen(g_fake_steps_bodies[idx]), 1,
                                  g_fake_write_data);
        }
        return g_fake_curl_perform_rc;
    }
    if (g_fake_curl_perform_rc == CURLE_OK && g_fake_curl_body && g_fake_write_cb) {
        (void)g_fake_write_cb((void *)g_fake_curl_body, strlen(g_fake_curl_body), 1, g_fake_write_data);
    }
    return g_fake_curl_perform_rc;
}

__attribute__((weak)) CURLcode curl_easy_getinfo(CURL *curl, CURLINFO info, ...) {
    (void)curl;
    va_list args;
    va_start(args, info);
    if (info == CURLINFO_RESPONSE_CODE) {
        long *code = va_arg(args, long *);
        if (code) {
            *code = g_fake_curl_status_code;
        }
    }
    va_end(args);
    return CURLE_OK;
}

/*
 * Weak overrides of libcurl's linked-list helpers, used ONLY by the
 * scrub_and_free_slist() test (test_http_request_scrubs_bearer_header_nodes).
 * When g_slist_scrub_check is on, curl_slist_append() records the data pointer
 * and length of each freshly-created node, and curl_slist_free_all() asserts —
 * immediately before freeing — that every one of those nodes had its header
 * bytes securely zeroed. This lets the suite observe the scrub discipline that
 * happens inside http_request()'s private scrub_and_free_slist() without any
 * production-code changes. When g_slist_scrub_check is off (the default for
 * every other test), both overrides behave exactly like libcurl's real
 * implementations (link at the tail / free every node), so the transport
 * plumbing they feed stays indistinguishable from the real thing.
 */
#define SLIST_SCRUB_CAPTURE_MAX 16
static struct curl_slist *g_slist_scrub_nodes[SLIST_SCRUB_CAPTURE_MAX];
static size_t g_slist_scrub_lens[SLIST_SCRUB_CAPTURE_MAX];
static int g_slist_scrub_on;
static int g_slist_scrub_count;

__attribute__((weak)) struct curl_slist *curl_slist_append(struct curl_slist *list, const char *data) {
    size_t len = strlen(data);
    struct curl_slist *node = calloc(1, sizeof(*node));
    if (!node) {
        return NULL;
    }
    node->data = malloc(len + 1);
    if (!node->data) {
        free(node);
        return NULL;
    }
    memcpy(node->data, data, len + 1);

    if (g_slist_scrub_on && g_slist_scrub_count < SLIST_SCRUB_CAPTURE_MAX) {
        g_slist_scrub_nodes[g_slist_scrub_count] = node;
        g_slist_scrub_lens[g_slist_scrub_count] = len;
        g_slist_scrub_count++;
    }

    if (list == NULL) {
        return node;
    }
    struct curl_slist *it = list;
    while (it->next != NULL) {
        it = it->next;
    }
    it->next = node;
    return list;
}

__attribute__((weak)) void curl_slist_free_all(struct curl_slist *head) {
    if (g_slist_scrub_on) {
        /* Verify each recorded node's header bytes were securely zeroed before
         * releasing the list (scrub_and_free_slist() zeroes non-NUL bytes via
         * secure_memzero(); the string length of an all-zero string is what was
         * recorded at append time). */
        int idx = 0;
        struct curl_slist *it = head;
        while (it != NULL) {
            struct curl_slist *const next = it->next;
            if (idx < g_slist_scrub_count && it == g_slist_scrub_nodes[idx]) {
                for (size_t i = 0; i < g_slist_scrub_lens[idx]; i++) {
                    assert_true(((const unsigned char *)it->data)[i] == 0U);
                }
                idx++;
            }
            free(it->data);
            free(it);
            it = next;
        }
        assert_int_equal(idx, g_slist_scrub_count);
        g_slist_scrub_on = 0;
        g_slist_scrub_count = 0;
        return;
    }
    struct curl_slist *it = head;
    while (it != NULL) {
        struct curl_slist *const next = it->next;
        free(it->data);
        free(it);
        it = next;
    }
}

/* Weak override of libpam's pam_syslog() (prototype in <security/pam_ext.h>):
 * captures the exact line pam_oauth_log() (src/http.c) forwards to syslog so
 * its C-escaping rules can be asserted. pam_oauth_log() always invokes it as
 * pam_syslog(pamh, priority, "%s", escaped), so the rendered (escaped) line is
 * the sole vararg. Diagnostic calls libpam itself emits resolve inside
 * libpam.so and do not reach this override.
 */
static char g_captured_syslog_line[8192 * 4 + 1];
static int g_captured_syslog_calls;
static int g_captured_syslog_priority;

__attribute__((weak)) void pam_syslog(const pam_handle_t *pamh, int priority, const char *fmt, ...) {
    (void)pamh;
    va_list args;
    va_start(args, fmt);
    (void)vsnprintf(g_captured_syslog_line, sizeof(g_captured_syslog_line), fmt, args);
    va_end(args);
    g_captured_syslog_calls++;
    g_captured_syslog_priority = priority;
}

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
 * Tests token substitution (`{url}`, `{code}`, `{url_complete}`, `{expiry}`, `\n`),
 * buffer capacity limits,
 * default-template rendering (the leading blank line present when the QR code is disabled
 * and absent when it is enabled; the compact device-code approval window named in the
 * trailing status line when `show_expiry` is set and the window is known; the parenthetical
 * absent when `show_expiry` is off or the window is unknown — and no host identification at
 * all: in a
 * device-code phishing attack the
 * prompt reaches the ssh initiator, not the approving user, docs/threat-model.md §8), and
 * rejection of
 * C0 control characters (ANSI escapes, tabs)
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
        render_prompt_message(&cfg, "https://auth.edu/dev", "https://auth.edu/dev?c=1", "BCD-123", 0, out, sizeof(out));
    assert_int_equal(res, 0);
    assert_string_equal(out, "\nURL: https://auth.edu/dev\nCode: BCD-123\nDirect: https://auth.edu/dev?c=1\n");

    /* Verify buffer overflow / truncation handling[cite: 7] */
    char small_out[20];
    int trunc_res = render_prompt_message(&cfg, "https://auth.edu/dev", "https://auth.edu/dev?c=1", "BCD-123", 0,
                                          small_out, sizeof(small_out));
    assert_int_equal(trunc_res, -1);

    /* Default template (empty init_message) must render and pass the terminal-safety check[cite: 7] */
    config_t def_cfg;
    memset(&def_cfg, 0, sizeof(def_cfg));
    char def_out[512];
    int def_res = render_prompt_message(&def_cfg, "https://auth.edu/dev", "https://auth.edu/dev?c=1", "BCD-123", 0,
                                        def_out, sizeof(def_out));
    assert_int_equal(def_res, 0);
    /* The default template (QR disabled) carries a leading blank line separating the prompt
     * from the terminal banner that shares its first line, separates the sign-in block from
     * the status line with a single blank line, and carries no host identification: in a
     * device-code phishing attack the prompt reaches the ssh initiator (the attacker), not the
     * approving user, so machine context belongs on the IdP's approval page
     * (docs/threat-model.md §8)[cite: 7] */
    assert_string_equal(def_out, "\nSign in via browser:\n  https://auth.edu/dev?c=1\n\n"
                                 "Manual entry: https://auth.edu/dev  |  Code: BCD-123\n"
                                 "Waiting for approval.\n");
    char def_plain_out[512];
    assert_int_equal(render_prompt_message(&def_cfg, "https://auth.edu/dev", NULL, "BCD-123", 0, def_plain_out,
                                           sizeof(def_plain_out)),
                     0);
    assert_string_equal(def_plain_out, "\nSign in via browser:\n  URL:  https://auth.edu/dev\n  Code: BCD-123\n\n"
                                       "Waiting for approval.\n");

    /* With show_expiry on the built-in default carries the compact "(expires in ...)" clause in
     * the trailing status line; the window is the provider's expires_in clamped by
     * [runtime] max_poll_seconds, rendered in compact units */
    config_t def_exp_cfg;
    memset(&def_exp_cfg, 0, sizeof(def_exp_cfg));
    def_exp_cfg.show_expiry = 1;
    char def_exp_out[512];
    assert_int_equal(render_prompt_message(&def_exp_cfg, "https://auth.edu/dev", "https://auth.edu/dev?c=1", "BCD-123",
                                           900, def_exp_out, sizeof(def_exp_out)),
                     0);
    assert_string_equal(def_exp_out, "\nSign in via browser:\n  https://auth.edu/dev?c=1\n\n"
                                     "Manual entry: https://auth.edu/dev  |  Code: BCD-123\n"
                                     "Waiting for approval (expires in 15m).\n");
    /* Sub-minute windows render in seconds (plain-URL form, no manual-entry line) */
    char def_exp_sec_out[512];
    assert_int_equal(render_prompt_message(&def_exp_cfg, "https://auth.edu/dev", NULL, "BCD-123", 45, def_exp_sec_out,
                                           sizeof(def_exp_sec_out)),
                     0);
    assert_string_equal(def_exp_sec_out, "\nSign in via browser:\n  URL:  https://auth.edu/dev\n  Code: BCD-123\n\n"
                                         "Waiting for approval (expires in 45s).\n");
    /* show_expiry on but the window unknown (0): the expiry parenthetical is omitted entirely */
    char def_exp_unknown_out[512];
    assert_int_equal(render_prompt_message(&def_exp_cfg, "https://auth.edu/dev", NULL, "BCD-123", 0,
                                           def_exp_unknown_out, sizeof(def_exp_unknown_out)),
                     0);
    assert_string_equal(def_exp_unknown_out, "\nSign in via browser:\n  URL:  https://auth.edu/dev\n  Code: BCD-123\n\n"
                                             "Waiting for approval.\n");
    /* show_expiry off with a known window: the approval window never appears in the
     * built-in default */
    char def_noexp_out[512];
    assert_int_equal(render_prompt_message(&def_cfg, "https://auth.edu/dev", "https://auth.edu/dev?c=1", "BCD-123", 900,
                                           def_noexp_out, sizeof(def_noexp_out)),
                     0);
    assert_string_equal(def_noexp_out, "\nSign in via browser:\n  https://auth.edu/dev?c=1\n\n"
                                       "Manual entry: https://auth.edu/dev  |  Code: BCD-123\n"
                                       "Waiting for approval.\n");

    /* [qr] enabled = true: the leading blank line is omitted — the QR block's bottom vertical
     * quiet zone already separates the prompt from the rendered art */
    config_t def_qr_cfg;
    memset(&def_qr_cfg, 0, sizeof(def_qr_cfg));
    def_qr_cfg.qr_enabled = 1;
    char def_qr_out[512];
    assert_int_equal(render_prompt_message(&def_qr_cfg, "https://auth.edu/dev", "https://auth.edu/dev?c=1", "BCD-123",
                                           0, def_qr_out, sizeof(def_qr_out)),
                     0);
    assert_string_equal(def_qr_out, "Sign in via browser:\n  https://auth.edu/dev?c=1\n\n"
                                    "Manual entry: https://auth.edu/dev  |  Code: BCD-123\n"
                                    "Waiting for approval.\n");

    /* {expiry} template token expands to the compact approval window in any template
     * (independent of show_expiry), or to an empty string when the window is unknown */
    config_t exp_cfg;
    memset(&exp_cfg, 0, sizeof(exp_cfg));
    strncpy(exp_cfg.init_message, "Approval window: {expiry}\\n", sizeof(exp_cfg.init_message) - 1);
    char exp_out[256];
    assert_int_equal(
        render_prompt_message(&exp_cfg, "https://auth.edu/dev", NULL, "BCD-123", 900, exp_out, sizeof(exp_out)), 0);
    assert_string_equal(exp_out, "Approval window: 15m\n");
    assert_int_equal(
        render_prompt_message(&exp_cfg, "https://auth.edu/dev", NULL, "BCD-123", 3600, exp_out, sizeof(exp_out)), 0);
    assert_string_equal(exp_out, "Approval window: 1h\n");
    assert_int_equal(
        render_prompt_message(&exp_cfg, "https://auth.edu/dev", NULL, "BCD-123", 0, exp_out, sizeof(exp_out)), 0);
    assert_string_equal(exp_out, "Approval window: \n");

    /* Rendered-prompt terminal-injection defense: ANSI escape bytes in the template,
     * the provider URL, or the user code must fail rendering[cite: 7] */
    config_t esc_cfg;
    memset(&esc_cfg, 0, sizeof(esc_cfg));
    strncpy(esc_cfg.init_message, "Code: \x1b[31m{code}\x1b[0m", sizeof(esc_cfg.init_message) - 1);
    char esc_out[512];
    assert_int_equal(
        render_prompt_message(&esc_cfg, "https://auth.edu/dev", NULL, "BCD-123", 0, esc_out, sizeof(esc_out)), -1);
    assert_int_equal(
        render_prompt_message(&def_cfg, "https://auth.edu/dev\x1b[31m", NULL, "BCD-123", 0, esc_out, sizeof(esc_out)),
        -1);
    assert_int_equal(
        render_prompt_message(&def_cfg, "https://auth.edu/dev", NULL, "BCD-123\x1b[0m", 0, esc_out, sizeof(esc_out)),
        -1);
    /* Tab (C0) characters in a custom template are also rejected[cite: 7] */
    config_t tab_cfg;
    memset(&tab_cfg, 0, sizeof(tab_cfg));
    strncpy(tab_cfg.init_message, "Code:\t{code}", sizeof(tab_cfg.init_message) - 1);
    assert_int_equal(
        render_prompt_message(&tab_cfg, "https://auth.edu/dev", NULL, "BCD-123", 0, esc_out, sizeof(esc_out)), -1);
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
 * @brief Unit test verifying the fail-closed iss/aud policy when verify_jwt_claims
 *        is enabled without a configured issuer or audience.
 *
 * With claims-only inspection (no local signature verification), an iss/aud
 * expectation that is not configured must not be silently skipped while the
 * feature is enabled — the token binding simply cannot be checked, so it fails
 * closed. load_config() rejects the combination up front; this covers direct
 * callers of the public API.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_jwt_unconfigured_binding_fail_closed(void **state) {
    (void)state;
    config_t cfg;

    /* Payload:
     * {"iss":"https://sts.windows.net/tenant/","aud":"00000003-0000-0000-c000-000000000000","exp":2524608000}
     */
    const char *jwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC90ZW5hbnQvIiwiYXVkIjoiMDAwMDAwMDMtMDAwMC0wMDAwLWMwMDAtMDAwMDAwMDAw"
        "MDAwIiwiZXhwIjoyNTI0NjA4MDAwfQ.sig";

    /* verify_jwt_claims enabled without an issuer: fail closed. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.verify_jwt_claims = 1;
    cfg.clock_skew_leeway = 60;
    cfg.loglevel = LOGLEVEL_NONE;
    assert_int_equal(verify_token_metadata(jwt, &cfg, NULL), -1);

    /* Issuer configured but no audience: still fail closed. */
    strncpy(cfg.issuer, "https://sts.windows.net/tenant/", sizeof(cfg.issuer) - 1);
    assert_int_equal(verify_token_metadata(jwt, &cfg, NULL), -1);

    /* Both configured: accepted. */
    strncpy(cfg.audience, "00000003-0000-0000-c000-000000000000", sizeof(cfg.audience) - 1);
    assert_int_equal(verify_token_metadata(jwt, &cfg, NULL), 0);

    /* Legacy direct-call behavior preserved: with verify_jwt_claims disabled,
     * unconfigured iss/aud checks are skipped rather than failing. */
    cfg.verify_jwt_claims = 0;
    cfg.issuer[0] = '\0';
    cfg.audience[0] = '\0';
    assert_int_equal(verify_token_metadata(jwt, &cfg, NULL), 0);
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
 * @brief Unit test verifying that non-finite exp/nbf claims are rejected.
 *
 * json-c accepts the non-standard `NaN` and `Infinity` literals as
 * json_type_double, and every comparison with NaN is false — without an
 * explicit finiteness check, a token carrying `"exp": NaN` would bypass the
 * expiry check unconditionally.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_jwt_non_finite_claims_rejected(void **state) {
    (void)state;
    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.issuer, "https://sts.windows.net/tenant/", sizeof(cfg.issuer) - 1);
    strncpy(cfg.audience, "00000003-0000-0000-c000-000000000000", sizeof(cfg.audience) - 1);
    cfg.clock_skew_leeway = 60;
    cfg.loglevel = LOGLEVEL_NONE;

    /* Payload with "exp": NaN (json-c parses it as json_type_double). */
    const char *exp_nan =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC90ZW5hbnQvIiwiYXVkIjoiMDAwMDAwMDMtMDAwMC0wMDAwLWMwMDAtMDAwMDAwMDAw"
        "MDAwIiwiZXhwIjpOYU59.sig";

    /* Payload with "exp": Infinity. */
    const char *exp_inf =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC90ZW5hbnQvIiwiYXVkIjoiMDAwMDAwMDMtMDAwMC0wMDAwLWMwMDAtMDAwMDAwMDAw"
        "MDAwIiwiZXhwIjpJbmZpbml0eX0.sig";

    /* Payload with "nbf": NaN. */
    const char *nbf_nan =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC90ZW5hbnQvIiwiYXVkIjoiMDAwMDAwMDMtMDAwMC0wMDAwLWMwMDAtMDAwMDAwMDAw"
        "MDAwIiwibmJmIjpOYU59.sig";

    /* Control: a finite far-future exp is still accepted. */
    const char *exp_future =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC90ZW5hbnQvIiwiYXVkIjoiMDAwMDAwMDMtMDAwMC0wMDAwLWMwMDAtMDAwMDAwMDAw"
        "MDAwIiwiZXhwIjoyNTI0NjA4MDAwfQ.sig";

    assert_int_equal(verify_token_metadata(exp_nan, &cfg, NULL), -1);
    assert_int_equal(verify_token_metadata(exp_inf, &cfg, NULL), -1);
    assert_int_equal(verify_token_metadata(nbf_nan, &cfg, NULL), -1);
    assert_int_equal(verify_token_metadata(exp_future, &cfg, NULL), 0);
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
 * @brief Unit test verifying strict RFC 4648 §5 Base64URL alphabet enforcement during
 *        JWT payload decoding.
 *
 * Payload segments containing standard Base64 characters ('+', '/'), whitespace or
 * control bytes, or embedded padding must be rejected, while legal trailing '='
 * padding must continue to be accepted.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_jwt_base64url_strict_alphabet(void **state) {
    (void)state;
    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.loglevel = LOGLEVEL_NONE;

    /* Standard Base64 '+' and '/' characters are not valid Base64URL. */
    assert_int_equal(verify_token_metadata("eyJhbGciOiJIUzI1NiJ9.AAA+AAA.sig", &cfg, NULL), -1);
    assert_int_equal(verify_token_metadata("eyJhbGciOiJIUzI1NiJ9.AAA/AAA.sig", &cfg, NULL), -1);

    /* Embedded newline (C0 control byte) is rejected. */
    assert_int_equal(verify_token_metadata("eyJhbGciOiJIUzI1NiJ9.AA\nAAA.sig", &cfg, NULL), -1);

    /* Padding appearing mid-segment is rejected. */
    assert_int_equal(verify_token_metadata("eyJhbGciOiJIUzI1NiJ9.AAAA=BAAA.sig", &cfg, NULL), -1);

    /* Trailing whitespace is rejected. */
    assert_int_equal(verify_token_metadata("eyJhbGciOiJIUzI1NiJ9.AAA= .sig", &cfg, NULL), -1);

    /* Legal trailing padding is still accepted (payload decodes to {"sub":"test_user"}). */
    assert_int_equal(verify_token_metadata("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0X3VzZXIifQ==.sig", &cfg, NULL), 0);
}

/**
 * @brief Unit test verifying rejection of Base64URL payload segments whose total
 *        padding exceeds the two '=' characters a legal Base64 stream may carry.
 *
 * An unpadded segment whose length is 1 (mod 4) would need three trailing
 * padding characters to reach a multiple of four, which is not valid Base64
 * (RFC 4648 §3.5); the same holds for 2/3 (mod 4) segments that already carry
 * trailing pads. OpenSSL's lenient BIO_f_base64 would nevertheless "decode"
 * such input into short binary garbage, so base64url_decode() rejects it up
 * front; this pins that rejection end-to-end through verify_token_metadata().
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_jwt_base64url_excess_padding_rejected(void **state) {
    (void)state;
    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.loglevel = LOGLEVEL_NONE;

    /* Unpadded payload of length 1 (mod 4): three pads would be required. */
    assert_int_equal(verify_token_metadata("eyJhbGciOiJIUzI1NiJ9.abcde.sig", &cfg, NULL), -1);
    /* The 1-byte extreme of the same class. */
    assert_int_equal(verify_token_metadata("eyJhbGciOiJIUzI1NiJ9.a.sig", &cfg, NULL), -1);
    /* 2 (mod 4) segment with one trailing pad: alignment appends two more. */
    assert_int_equal(verify_token_metadata("eyJhbGciOiJIUzI1NiJ9.abcde=.sig", &cfg, NULL), -1);
    /* 3 (mod 4) segment with two trailing pads: alignment appends one more. */
    assert_int_equal(verify_token_metadata("eyJhbGciOiJIUzI1NiJ9.abcde==.sig", &cfg, NULL), -1);

    /* Control: a legal two-pad segment still decodes ({"sub":"test_user"}). */
    assert_int_equal(verify_token_metadata("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0X3VzZXIifQ==.sig", &cfg, NULL), 0);
}

/**
 * @brief Unit test verifying jwt_extract_claim_string() claim extraction semantics.
 *
 * Covers the found / absent / non-string claim trichotomy, malformed JWT
 * structure rejection (mirroring verify_token_metadata), argument validation,
 * and the undersized-output-buffer failure. Fixture payloads (base64url of
 * JSON, verified with Python):
 *  - SUB_JWT payload: {"iss":"https://sts.windows.net/tenant/",
 *    "aud":"00000003-0000-0000-c000-000000000000","sub":"test-subject-123",
 *    "exp":2524608000}
 *  - NO_SUB_JWT payload: same without the "sub" member.
 *  - NON_STR_SUB_JWT payload: {"iss":"https://sts.windows.net/tenant/",
 *    "sub":12345,"exp":2524608000} (sub is a JSON number).
 *  - LONG_SUB_JWT payload: {"sub":"<300 x's>","exp":2524608000} (exceeds the
 *    256-byte output buffer).
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_jwt_extract_claim_string(void **state) {
    (void)state;
    char out[256];

    const char *sub_jwt =
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC90ZW5hbnQvIiwiYXVkIjoiMDAwMDAwMDMtMDAwMC0wMDAwLWMwMDAtMDAwMDAwMDAw"
        "MDAwIiwic3ViIjoidGVzdC1zdWJqZWN0LTEyMyIsImV4cCI6MjUyNDYwODAwMH0.sig";
    const char *no_sub_jwt =
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC90ZW5hbnQvIiwiYXVkIjoiMDAwMDAwMDMtMDAwMC0wMDAwLWMwMDAtMDAwMDAwMDAw"
        "MDAwIiwiZXhwIjoyNTI0NjA4MDAwfQ.sig";
    const char *non_str_sub_jwt =
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC90ZW5hbnQvIiwic3ViIjoxMjM0NSwiZXhwIjoyNTI0NjA4MDAwfQ.sig";
    const char *long_sub_jwt = "eyJhbGciOiJIUzI1NiJ9."
                               "eyJzdWIiOiJ4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh"
                               "4eHh4eHh4eHh4eHh4eHh4eHh4"
                               "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh"
                               "4eHh4eHh4eHh4eHh4eHh4eHh4"
                               "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh"
                               "4eHh4eHh4eHh4eHh4eHh4eHh4"
                               "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh"
                               "4eHh4eHh4eHh4eHh4eHh4eHh4"
                               "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh"
                               "4eHh4eHh4eHh4eHh4eHh4eHh4"
                               "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHgiLCJleHAiOjI1MjQ2MDgwMDB9.sig";

    /* Found: string claim copied verbatim, including an unrelated claim. */
    assert_int_equal(jwt_extract_claim_string(sub_jwt, "sub", out, sizeof(out)), 0);
    assert_string_equal(out, "test-subject-123");
    assert_int_equal(jwt_extract_claim_string(sub_jwt, "iss", out, sizeof(out)), 0);
    assert_string_equal(out, "https://sts.windows.net/tenant/");

    /* Absent claim: distinguished from failure; output reset to empty. */
    assert_int_equal(jwt_extract_claim_string(no_sub_jwt, "sub", out, sizeof(out)), 1);
    assert_string_equal(out, "");

    /* Non-string claim type: malformed for this helper, fails closed. */
    assert_int_equal(jwt_extract_claim_string(non_str_sub_jwt, "sub", out, sizeof(out)), -1);

    /* Claim value longer than the output buffer: fails closed. */
    assert_int_equal(jwt_extract_claim_string(long_sub_jwt, "sub", out, sizeof(out)), -1);

    /* Malformed JWT structure (mirrors verify_token_metadata rejection). */
    assert_int_equal(jwt_extract_claim_string("invalid_jwt_no_dots", "sub", out, sizeof(out)), -1);
    assert_int_equal(jwt_extract_claim_string("invalid_jwt.one_dot", "sub", out, sizeof(out)), -1);
    assert_int_equal(jwt_extract_claim_string("a.b.c.d", "sub", out, sizeof(out)), -1);
    assert_int_equal(jwt_extract_claim_string("eyJhbGciOiJIUzI1NiJ9..sig", "sub", out, sizeof(out)), -1);
    assert_int_equal(jwt_extract_claim_string("eyJhbGciOiJIUzI1NiJ9.bm90X2pzb24.sig", "sub", out, sizeof(out)), -1);

    /* NULL / empty arguments. */
    assert_int_equal(jwt_extract_claim_string(NULL, "sub", out, sizeof(out)), -1);
    assert_int_equal(jwt_extract_claim_string(sub_jwt, NULL, out, sizeof(out)), -1);
    assert_int_equal(jwt_extract_claim_string(sub_jwt, "", out, sizeof(out)), -1);
    assert_int_equal(jwt_extract_claim_string(sub_jwt, "sub", NULL, sizeof(out)), -1);
    assert_int_equal(jwt_extract_claim_string(sub_jwt, "sub", out, 0), -1);
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
 * @brief Unit test verifying that http_request() enforces strict TLS options.
 *
 * curl_easy_setopt/curl_easy_perform are weakly overridden in this test binary
 * (see the weak definitions at the top of this file), so no real network
 * transfer occurs. The test captures the TLS-related options and asserts that
 * certificate validation is enabled and the minimum protocol version is
 * TLS 1.2.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_http_request_enforces_tls_options(void **state) {
    (void)state;

    tls_opt_seen = 0;
    tls_opt_ssl_verifypeer = 0;
    tls_opt_ssl_verifyhost = 0;
    tls_opt_ssl_version = -1;

    http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    int rc = http_request("GET", "https://auth.example/token", NULL, NULL, NULL, 1000L, &resp, LOGLEVEL_NONE, NULL);
    assert_int_equal(rc, 0);

    assert_true(tls_opt_seen >= 2);
    assert_int_equal(tls_opt_ssl_verifypeer, 1);
    assert_int_equal(tls_opt_ssl_verifyhost, 2);
#if LIBCURL_VERSION_NUM >= 0x072000
    assert_int_equal(tls_opt_ssl_version, (int)CURL_SSLVERSION_TLSv1_2);
#endif
}

/**
 * @brief Unit test verifying http_request() proxy routing (CURLOPT_PROXY,
 *        CURLOPT_NOPROXY, and the CURLOPT_PROXY_SSL_* options that pin the
 *        proxy connection's TLS leg).
 *
 * The weak curl_easy_setopt override captures the requested proxy, no-proxy,
 * and proxy-TLS values. When no proxy is configured, CURLOPT_PROXY must be set
 * to the empty string so libcurl never falls back to the caller's *_proxy
 * environment variables (user-controlled under a setuid PAM caller), and in
 * all cases CURLOPT_NOPROXY must be set to the empty string so the
 * no_proxy/NO_PROXY environment variables never bypass the configured proxy;
 * a configured proxy must be routed through verbatim. The TLS leg to the
 * proxy is governed by the separate CURLOPT_PROXY_SSL_* options (the
 * provider-connection CURLOPT_SSL_* options do not cover it), so certificate
 * validation and a TLS >= 1.2 minimum must be pinned there on every request.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_http_request_proxy_routing(void **state) {
    (void)state;
    reset_fake_curl_transport();
    proxy_tls_opt_verifypeer = -1L;
    proxy_tls_opt_verifyhost = -1L;
    proxy_tls_opt_version = -1;

    http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    /* No proxy configured: CURLOPT_PROXY is explicitly empty (env override)
     * and CURLOPT_NOPROXY is explicitly empty (no_proxy env bypass). */
    int rc = http_request("GET", "https://auth.example/token", NULL, NULL, NULL, 1000L, &resp, LOGLEVEL_NONE, NULL);
    assert_int_equal(rc, 0);
    assert_string_equal(g_fake_curl_proxy, "");
    assert_string_equal(g_fake_curl_noproxy, "");
#if LIBCURL_VERSION_NUM >= 0x073400
    /* The proxy TLS leg is pinned on every request, proxy configured or not. */
    assert_int_equal(proxy_tls_opt_verifypeer, 1);
    assert_int_equal(proxy_tls_opt_verifyhost, 2);
    assert_int_equal(proxy_tls_opt_version, (int)CURL_SSLVERSION_TLSv1_2);
#endif
    free_http_response(&resp);

    /* Configured proxy: routed through verbatim; no-proxy list still cleared. */
    memset(&resp, 0, sizeof(resp));
    rc = http_request("GET", "https://auth.example/token", NULL, NULL, "https://proxy.example:8443", 1000L, &resp,
                      LOGLEVEL_NONE, NULL);
    assert_int_equal(rc, 0);
    assert_string_equal(g_fake_curl_proxy, "https://proxy.example:8443");
    assert_string_equal(g_fake_curl_noproxy, "");
#if LIBCURL_VERSION_NUM >= 0x073400
    assert_int_equal(proxy_tls_opt_verifypeer, 1);
    assert_int_equal(proxy_tls_opt_verifyhost, 2);
    assert_int_equal(proxy_tls_opt_version, (int)CURL_SSLVERSION_TLSv1_2);
#endif
    free_http_response(&resp);
}

/**
 * @brief Unit test verifying the MAX_HTTP_RESPONSE_SIZE cap enforced by write_callback().
 *
 * The weak curl_easy_perform override feeds the fake body through the module's
 * captured write callback, so the cap's accept/reject behavior is exercised
 * without a network. A body of exactly 256 KiB is captured in full (realloc
 * growth up to the cap); one byte over is rejected and nothing is captured —
 * under real libcurl that short write aborts the transfer (CURLE_WRITE_ERROR),
 * so http_request() would report a transport failure.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_http_request_response_size_cap(void **state) {
    (void)state;
    reset_fake_curl_transport();

    size_t cap = MAX_HTTP_RESPONSE_SIZE;
    char *body = malloc(cap + 2);
    assert_non_null(body);
    memset(body, 'A', cap + 1);

    http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    /* Exactly at the cap: captured in full. */
    body[cap] = '\0';
    g_fake_curl_body = body;
    int rc = http_request("GET", "https://auth.example/token", NULL, NULL, NULL, 1000L, &resp, LOGLEVEL_NONE, NULL);
    assert_int_equal(rc, 0);
    assert_non_null(resp.body);
    assert_true(resp.size == cap);
    free_http_response(&resp);

    /* One byte over the cap: write callback rejects; nothing captured. */
    memset(&resp, 0, sizeof(resp));
    body[cap] = 'B';
    body[cap + 1] = '\0';
    (void)http_request("GET", "https://auth.example/token", NULL, NULL, NULL, 1000L, &resp, LOGLEVEL_NONE, NULL);
    assert_null(resp.body);
    assert_int_equal((int)resp.size, 0);
    free_http_response(&resp);

    free(body);
    g_fake_curl_body = NULL;
}

/* PAM conversation function for the log-drop test below: never invoked (no
 * converse is issued from pam_syslog); returns PAM_ABORT if it ever were. */
static int test_pam_noop_conv(int num_messages, const struct pam_message **message, struct pam_response **response,
                              void *appdata_ptr) {
    (void)num_messages;
    (void)message;
    (void)response;
    (void)appdata_ptr;
    return PAM_ABORT;
}

/**
 * @brief Unit test exercising pam_oauth_log()'s "log line dropped" marker branches.
 *
 * The wrapper emits a static "log line dropped (...)" syslog marker — instead of
 * crashing or dropping the event silently — when (a) vsnprintf() cannot render
 * the line, or (b) the escape buffer cannot be allocated. This test drives
 * branch (a) deterministically: an unrenderable wide character ((wchar_t)-1)
 * makes vsnprintf() report an encoding error (negative return) on glibc, every
 * supported distro's libc. A separate over-length argument exercises the
 * truncation path (the 8192-byte line cap clamps rather than fails), and a
 * normal line keeps the success path clean. The sibling branch (b) (escape-
 * buffer malloc failure) is deliberately not covered: it requires a failing
 * malloc, which this suite cannot cheaply simulate. A live PAM handle is
 * created because pam_oauth_log() early-returns on a null handle.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_pam_oauth_log_line_dropped_marker(void **state) {
    (void)state;
    static struct pam_conv test_pam_conv = {test_pam_noop_conv, NULL};
    pam_handle_t *pamh = NULL;
    assert_int_equal(pam_start("pam_oidc_device_test", "probeuser", &test_pam_conv, &pamh), PAM_SUCCESS);
    assert_non_null(pamh);

    /* Unrenderable wide character: vsnprintf encoding error -> static marker,
     * no crash, untrusted bytes scrubbed. */
    pam_oauth_log(pamh, LOGLEVEL_VERBOSE, LOGLEVEL_DEBUG, LOG_DEBUG, "%lc", (wchar_t)-1);

    /* Over-length argument: vsnprintf succeeds but overflows the 8192-byte
     * line buffer -> truncated to the cap, still logged (no marker). */
    char *huge = malloc(9000);
    assert_non_null(huge);
    memset(huge, 'A', 8999);
    huge[8999] = '\0';
    pam_oauth_log(pamh, LOGLEVEL_VERBOSE, LOGLEVEL_DEBUG, LOG_DEBUG, "line: %s", huge);
    free(huge);

    /* Normal-length line on the same handle: success path stays clean. */
    pam_oauth_log(pamh, LOGLEVEL_VERBOSE, LOGLEVEL_DEBUG, LOG_DEBUG, "probe: %s", "ok");

    assert_int_equal(pam_end(pamh, PAM_SUCCESS), PAM_SUCCESS);
}

/**
 * @brief Pins pam_oauth_log()'s C-escaping rules via a weak pam_syslog()
 *        override that captures the exact forwarded line.
 *
 * Complements test_pam_oauth_log_line_dropped_marker(): that test covers the
 * vsnprintf-failure and over-length branches, while this one asserts the
 * happy-path escaping itself — printable ASCII passes through byte-for-byte
 * while control bytes (LF/CR/TAB and C0/C1/high-bit bytes) become C escapes
 * (\\n, \\r, \\t, \\xHH) so no untrusted byte can forge a syslog record — plus
 * the level filter and the syslog priority passthrough.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_pam_oauth_log_escapes_untrusted_bytes(void **state) {
    (void)state;
    static struct pam_conv test_pam_conv = {test_pam_noop_conv, NULL};
    pam_handle_t *pamh = NULL;
    assert_int_equal(pam_start("pam_oidc_device_test", "probeuser", &test_pam_conv, &pamh), PAM_SUCCESS);
    assert_non_null(pamh);
    /* Baseline the capture AFTER pam_start so libpam chatter (if any) cannot
     * perturb the counts asserted below. */
    g_captured_syslog_calls = 0;
    g_captured_syslog_line[0] = '\0';
    g_captured_syslog_priority = -1;

    /* Level filter: below the configured threshold nothing is emitted. */
    pam_oauth_log(pamh, LOGLEVEL_NONE, LOGLEVEL_ERROR, LOG_ERR, "hidden");
    assert_int_equal(g_captured_syslog_calls, 0);

    /* Printable ASCII renders byte-for-byte; priority passes through. */
    pam_oauth_log(pamh, LOGLEVEL_VERBOSE, LOGLEVEL_DEBUG, LOG_DEBUG, "user '%s' probe", "alice");
    assert_int_equal(g_captured_syslog_calls, 1);
    assert_string_equal(g_captured_syslog_line, "user 'alice' probe");
    assert_int_equal(g_captured_syslog_priority, LOG_DEBUG);

    /* Control and high-bit bytes in an untrusted value become C escapes; no
     * raw LF/CR/TAB or C0/C1 byte can forge or garble the syslog record. */
    pam_oauth_log(pamh, LOGLEVEL_VERBOSE, LOGLEVEL_DEBUG, LOG_ERR, "claim '%s'", "bad\nuser\rx\tv\x01\x7f\xff");
    assert_int_equal(g_captured_syslog_calls, 2);
    assert_string_equal(g_captured_syslog_line, "claim 'bad\\nuser\\rx\\tv\\x01\\x7F\\xFF'");
    assert_int_equal(g_captured_syslog_priority, LOG_ERR);

    assert_int_equal(pam_end(pamh, PAM_SUCCESS), PAM_SUCCESS);
}

/**
 * @brief Verifies that discovery_probe_pkce fails safe on a non-200 transport
 *        result (or no response status at all).
 *
 * The probe must return -1 and leave *supported == 0, exercising the fail-safe
 * branch over http_request()'s zero-initialized response (no body; no
 * uninitialized read or spurious free).
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_discovery_probe_pkce_failsafe_non_200(void **state) {
    (void)state;
    const char *url = "https://idp.example/.well-known/openid-configuration";

    /* Transport success with a non-200 status (e.g. HTTP 500) -> fail safe. */
    reset_fake_curl_transport();
    g_fake_curl_status_code = 500;
    int supported = 1; /* Sentinel: the probe must clear it */
    assert_int_equal(discovery_probe_pkce(url, NULL, &supported, LOGLEVEL_NONE, NULL), -1);
    assert_int_equal(supported, 0);

    /* Default fake status (0 == "no response") -> fail safe as well. */
    g_fake_curl_status_code = 0;
    supported = 1;
    assert_int_equal(discovery_probe_pkce(url, NULL, &supported, LOGLEVEL_NONE, NULL), -1);
    assert_int_equal(supported, 0);
}

/**
 * @brief Verifies that discovery_probe_pkce fails safe when the fake transport
 *        reports a cURL-level error.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_discovery_probe_pkce_failsafe_transport_error(void **state) {
    (void)state;
    reset_fake_curl_transport();
    g_fake_curl_perform_rc = CURLE_COULDNT_CONNECT;
    int supported = 1;
    assert_int_equal(discovery_probe_pkce("https://idp.example/.well-known/openid-configuration", NULL, &supported,
                                          LOGLEVEL_NONE, NULL),
                     -1);
    assert_int_equal(supported, 0);
}

/**
 * @brief Verifies that discovery_probe_pkce fails safe when the discovery
 *        document body (HTTP 200) is not a JSON object.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_discovery_probe_pkce_failsafe_malformed_document(void **state) {
    (void)state;
    const char *url = "https://idp.example/.well-known/openid-configuration";

    reset_fake_curl_transport();
    g_fake_curl_status_code = 200;

    g_fake_curl_body = "this is not a JSON document";
    int supported = 1;
    assert_int_equal(discovery_probe_pkce(url, NULL, &supported, LOGLEVEL_NONE, NULL), -1);
    assert_int_equal(supported, 0);

    /* A valid JSON scalar is still not a discovery document object. */
    g_fake_curl_body = "123";
    supported = 1;
    assert_int_equal(discovery_probe_pkce(url, NULL, &supported, LOGLEVEL_NONE, NULL), -1);
    assert_int_equal(supported, 0);
}

/**
 * @brief Exercises the discovery_probe_pkce success matrix (HTTP 200 + JSON
 *        object) and its three-way PKCE gating decision.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_discovery_probe_pkce_support_matrix(void **state) {
    (void)state;
    const char *url = "https://idp.example/.well-known/openid-configuration";

    reset_fake_curl_transport();
    g_fake_curl_status_code = 200;

    /* S256 advertised AND device_authorization_endpoint present -> enable. */
    g_fake_curl_body = "{\"code_challenge_methods_supported\": [\"S256\"], "
                       "\"device_authorization_endpoint\": \"https://idp.example/device\"}";
    int supported = 0;
    assert_int_equal(discovery_probe_pkce(url, NULL, &supported, LOGLEVEL_NONE, NULL), 0);
    assert_int_equal(supported, 1);

    /* S256 advertised but no device_authorization_endpoint -> disable. */
    g_fake_curl_body = "{\"code_challenge_methods_supported\": [\"S256\"]}";
    supported = 1;
    assert_int_equal(discovery_probe_pkce(url, NULL, &supported, LOGLEVEL_NONE, NULL), 0);
    assert_int_equal(supported, 0);

    /* S256 not advertised -> disable. */
    g_fake_curl_body = "{\"issuer\": \"https://idp.example\"}";
    supported = 1;
    assert_int_equal(discovery_probe_pkce(url, NULL, &supported, LOGLEVEL_NONE, NULL), 0);
    assert_int_equal(supported, 0);
}

/**
 * @brief Verifies that discovery_probe_pkce rejects NULL arguments.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_discovery_probe_pkce_null_args(void **state) {
    (void)state;
    int supported = 0;
    assert_int_equal(discovery_probe_pkce(NULL, NULL, &supported, LOGLEVEL_NONE, NULL), -1);
    assert_int_equal(
        discovery_probe_pkce("https://idp.example/.well-known/openid-configuration", NULL, NULL, LOGLEVEL_NONE, NULL),
        -1);
}

/**
 * @brief Pins the transient/retryable classification of token-endpoint HTTP
 *        status codes (`is_retryable_token_http_status()`).
 *
 * HTTP 429 and every 5xx status are transient (retry with backoff within the
 * device-authorization deadline); success, definitive 4xx OAuth errors,
 * redirects, and "no response" are all handled separately.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_is_retryable_token_http_status_matrix(void **state) {
    (void)state;

    /* 429 (rate limited) and 5xx (server/gateway) are transient. */
    assert_int_equal(is_retryable_token_http_status(429), 1);
    assert_int_equal(is_retryable_token_http_status(500), 1);
    assert_int_equal(is_retryable_token_http_status(502), 1);
    assert_int_equal(is_retryable_token_http_status(503), 1);
    assert_int_equal(is_retryable_token_http_status(504), 1);
    assert_int_equal(is_retryable_token_http_status(599), 1);

    /* Everything else is success, definitive, a redirect, or no response. */
    assert_int_equal(is_retryable_token_http_status(0), 0);
    assert_int_equal(is_retryable_token_http_status(200), 0);
    assert_int_equal(is_retryable_token_http_status(204), 0);
    assert_int_equal(is_retryable_token_http_status(301), 0);
    assert_int_equal(is_retryable_token_http_status(400), 0);
    assert_int_equal(is_retryable_token_http_status(401), 0);
    assert_int_equal(is_retryable_token_http_status(404), 0);
    assert_int_equal(is_retryable_token_http_status(428), 0);
    assert_int_equal(is_retryable_token_http_status(430), 0);
    assert_int_equal(is_retryable_token_http_status(499), 0);
    assert_int_equal(is_retryable_token_http_status(600), 0);
}

/**
 * @brief Pins the RFC 8628 s3.5 poll-interval backoff arithmetic extracted
 *        from the polling loop: `slow_down` (+5 s) and transient 429/5xx /
 *        cURL-transport-error (doubling), each clamped at
 *        MAX_SUPPORTED_POLL_INTERVAL.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_poll_interval_backoff_math(void **state) {
    (void)state;

    /* `slow_down`: +5 s, clamped at the supported maximum. */
    assert_int_equal(poll_interval_after_slow_down(MIN_POLL_INTERVAL), MIN_POLL_INTERVAL + 5);
    assert_int_equal(poll_interval_after_slow_down(60), 65);
    assert_int_equal(poll_interval_after_slow_down(MAX_SUPPORTED_POLL_INTERVAL - 5), MAX_SUPPORTED_POLL_INTERVAL);
    assert_int_equal(poll_interval_after_slow_down(MAX_SUPPORTED_POLL_INTERVAL - 4), MAX_SUPPORTED_POLL_INTERVAL);
    assert_int_equal(poll_interval_after_slow_down(MAX_SUPPORTED_POLL_INTERVAL), MAX_SUPPORTED_POLL_INTERVAL);

    /* Transient 429/5xx / cURL transport error: doubling, clamped at the supported maximum. */
    assert_int_equal(poll_interval_after_transient(MIN_POLL_INTERVAL), MIN_POLL_INTERVAL * 2);
    assert_int_equal(poll_interval_after_transient(60), 120);
    assert_int_equal(poll_interval_after_transient(MAX_SUPPORTED_POLL_INTERVAL / 2 + 1), MAX_SUPPORTED_POLL_INTERVAL);
    assert_int_equal(poll_interval_after_transient(MAX_SUPPORTED_POLL_INTERVAL), MAX_SUPPORTED_POLL_INTERVAL);
}

/**
 * @brief Pins the pure poll-loop scheduling rules extracted from
 *        poll_for_access_token(): immediate first poll, absolute next-poll
 *        time derived from an injected clock reading (nanoseconds carried),
 *        and expiry once the next poll would land at/after the deadline.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_poll_loop_schedule_rules(void **state) {
    (void)state;
    struct timespec now = {100, 500};
    struct timespec deadline = {1000, 0};
    struct timespec next_poll = {0, 0};

    /* First poll: request immediately — no leading sleep, output untouched. */
    assert_int_equal(poll_loop_schedule(1, MIN_POLL_INTERVAL, &now, &deadline, &next_poll), POLL_SCHED_RUN_NOW);
    assert_int_equal(next_poll.tv_sec, 0);
    assert_int_equal(next_poll.tv_nsec, 0);

    /* Subsequent poll: next_poll = now + interval. */
    assert_int_equal(poll_loop_schedule(0, 5, &now, &deadline, &next_poll), POLL_SCHED_SLEEP);
    assert_int_equal(next_poll.tv_sec, 105);
    assert_int_equal(next_poll.tv_nsec, 500);

    /* A next poll landing exactly ON the deadline expires (strictly-before rule). */
    now.tv_sec = 995;
    now.tv_nsec = 0;
    assert_int_equal(poll_loop_schedule(0, 5, &now, &deadline, &next_poll), POLL_SCHED_EXPIRED);
    now.tv_sec = 996; /* Anything later, too. */
    assert_int_equal(poll_loop_schedule(0, 5, &now, &deadline, &next_poll), POLL_SCHED_EXPIRED);
}

/**
 * @brief Pins the per-request cURL timeout budget: capped at the 10 s request
 *        cap, whole-second truncation, and no request once the whole-second
 *        remainder hits zero (a zero CURLOPT_TIMEOUT_MS would mean "no
 *        timeout" to cURL).
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_poll_request_budget_rules(void **state) {
    (void)state;
    struct timespec deadline = {1000, 0};
    struct timespec now = {995, 123};
    long timeout_ms = -1;

    /* Five whole seconds left (nanoseconds truncate): budget 5000 ms. */
    assert_int_equal(poll_request_budget(&now, &deadline, &timeout_ms), 1);
    assert_int_equal(timeout_ms, 5000);

    /* Plenty of time: capped at the per-request maximum. */
    now.tv_sec = 500;
    assert_int_equal(poll_request_budget(&now, &deadline, &timeout_ms), 1);
    assert_int_equal(timeout_ms, 10000);

    /* At / past the deadline: no request. */
    now.tv_sec = 1000;
    now.tv_nsec = 0;
    assert_int_equal(poll_request_budget(&now, &deadline, &timeout_ms), 0);
    now.tv_sec = 1001;
    assert_int_equal(poll_request_budget(&now, &deadline, &timeout_ms), 0);

    /* Sub-second remainder only: whole-second budget truncates to zero, and a
     * zero timeout must not be handed to cURL. */
    deadline.tv_nsec = 500000000;
    now.tv_sec = 1000;
    now.tv_nsec = 100000000;
    assert_int_equal(poll_request_budget(&now, &deadline, &timeout_ms), 0);
}

/**
 * @brief Pins the exact whole-second-remainder-zero boundary of
 *        poll_request_budget(): when @p now and @p deadline share the same
 *        whole second (so `now` is still before `deadline` at nanosecond
 *        precision) the request-timeout remainder truncates to exactly 0, and
 *        the helper must refuse the request and leave the timeout untouched —
 *        handing cURL a 0/absent CURLOPT_TIMEOUT_MS would mean "no timeout".
 *
 * Complement's test_poll_request_budget_rules()'s packed boundary checks with a
 * dedicated, self-contained pin of the no-unbounded-timeout branch.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_poll_request_budget_whole_second_zero(void **state) {
    (void)state;
    struct timespec deadline = {1000, 700000000};
    struct timespec now = {1000, 100000000};
    long timeout_ms = -12345; /* sentinel: must be left unmodified on refusal. */

    /* Same tv_sec, now still ahead of deadline in ns: 600 ms of real headroom
     * but zero WHOLE seconds -> the remainder is exactly 0 -> refuse. */
    assert_int_equal(poll_request_budget(&now, &deadline, &timeout_ms), 0);
    assert_int_equal(timeout_ms, -12345);

    /* One whole second of headroom -> exactly 1000 ms, no refusal. */
    deadline.tv_sec = 1001;
    assert_int_equal(poll_request_budget(&now, &deadline, &timeout_ms), 1);
    assert_int_equal(timeout_ms, 1000);
}

/**
 * @brief Verifies that http_request()'s private scrub_and_free_slist() securely
 *        zeroes every request-header node (including the Bearer Authorization
 *        header) before releasing libcurl's linked list.
 *
 * The weak curl_slist_append()/curl_slist_free_all() overrides (top of file)
 * capture each freshly-allocated header node and assert, immediately before
 * free, that all of its bytes were zeroed — so the scrub discipline happening
 * inside the static scrub_and_free_slist() is observable end-to-end through
 * http_request() with no production-code change.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_http_request_scrubs_bearer_header_nodes(void **state) {
    (void)state;
    reset_fake_curl_transport();
    g_slist_scrub_on = 1;
    g_slist_scrub_count = 0;

    http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    /* POST + Bearer token -> exactly two slist nodes (Content-Type and
     * Authorization). Both must be zeroed before free; the override also
     * asserts the recorded node count matches (no node skipped). */
    int rc = http_request("POST", "https://idp.example/token", "grant_type=abc", "sekrit-bearer-token", NULL, 5000L,
                          &resp, LOGLEVEL_NONE, NULL);
    assert_int_equal(rc, 0);
    assert_int_equal(g_slist_scrub_on, 0); /* capture mode consumed + reset */
    free_http_response(&resp);
}

/**
 * @brief Pins the fixed-capacity form-field table guard: form_field_append()
 *        accepts exactly `capacity` pairs and then returns -1 on the next
 *        append — the overflow that request_device_authorization() and
 *        poll_for_access_token() map to PAM_BUF_ERR — without ever advancing
 *        the count past capacity (no silent stack-array overflow).
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_form_field_append_overflow_guard(void **state) {
    (void)state;
    const char *keys[5];
    const char *vals[5];
    size_t count = 0;
    const size_t capacity = 5;

    for (size_t i = 0; i < capacity; i++) {
        assert_int_equal(form_field_append(keys, vals, &count, capacity, "k", "v"), 0);
        assert_int_equal(count, i + 1);
    }
    /* The oversized append trips the guard (-1) and leaves the count untouched. */
    assert_int_equal(form_field_append(keys, vals, &count, capacity, "overflow", "x"), -1);
    assert_int_equal(count, capacity);
}

/**
 * @brief Drives http_request()'s bearer-header truncation guard: a token longer
 *        than MAX_ACCESS_TOKEN_LEN cannot fit the fixed
 *        "Authorization: Bearer <token>" stack buffer, so snprintf() truncates
 *        and the overflow check returns -1 with the response left
 *        zero-initialized (and the truncated prefix of the token scrubbed).
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_http_request_bearer_header_truncation(void **state) {
    (void)state;
    reset_fake_curl_transport();

    size_t token_len = MAX_ACCESS_TOKEN_LEN + 8;
    char *token = malloc(token_len + 1);
    assert_non_null(token);
    memset(token, 'A', token_len);
    token[token_len] = '\0';

    http_response_t resp;
    memset(&resp, 0, sizeof(resp));
    int rc = http_request("GET", "https://idp.example/userinfo", NULL, token, NULL, 5000L, &resp, LOGLEVEL_NONE, NULL);
    assert_int_equal(rc, -1);
    assert_null(resp.body);
    assert_int_equal(resp.size, 0);

    free(token);
}

/* Forward declaration (the canonical one lives below with its doc block): this
 * later-defined fixture helper is used by the tests ABOVE that declaration. */
static void init_config_defaults(config_t *cfg);

/**
 * @brief Pins the definitive-abort fall-through for a malformed provider
 *        response that a caller may misread as `authorization_pending`: a
 *        non-429 4xx with a body that parses but lacks a usable `error` string
 *        (JSON object without `error`, wrong JSON type, or not valid JSON at
 *        all) must NOT be treated as a retryable pending sign-in. The poll
 *        issues exactly one HTTP request, classifies the failure as
 *        TOKEN_PHASE_UNAVAILABLE, and returns PAM_AUTH_ERR.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_poll_loop_malformed_pending_definitive_abort(void **state) {
    (void)state;
    static const char *const malformed_bodies[] = {
        "{\"message\":\"no error field\"}", /* JSON object but no `error` string */
        "\"not an object\"",                /* valid JSON, wrong JSON type */
        "plain-malformed-body",             /* not valid JSON at all */
    };

    for (int i = 0; i < 3; i++) {
        reset_fake_curl_transport();
        config_t cfg;
        init_config_defaults(&cfg);
        assert_int_equal(copy_checked(cfg.client_id, sizeof(cfg.client_id), "test-client"), 0);
        assert_int_equal(copy_checked(cfg.token_endpoint, sizeof(cfg.token_endpoint), "https://idp.example/token"), 0);

        struct timespec now;
        assert_int_equal(clock_gettime(CLOCK_MONOTONIC, &now), 0);
        device_auth_t dev;
        memset(&dev, 0, sizeof(dev));
        assert_int_equal(copy_checked(dev.device_code, sizeof(dev.device_code), "DEV123"), 0);
        dev.poll_interval = MIN_POLL_INTERVAL;
        dev.expires_in = 60;
        dev.deadline.tv_sec = now.tv_sec + dev.expires_in;
        dev.deadline.tv_nsec = now.tv_nsec;

        CURL *curl = curl_easy_init();
        assert_non_null(curl);
        http_response_t resp;
        memset(&resp, 0, sizeof(resp));
        struct json_object *tok_json = NULL;
        char *access_token = NULL;
        char *postfields = NULL;
        token_phase_t phase = TOKEN_PHASE_UNAVAILABLE;

        const long code = 400;
        script_fake_responses(&malformed_bodies[i], &code, 1);
        assert_int_equal(poll_for_access_token(NULL, &cfg, LOGLEVEL_NONE, "probeuser", &dev, NULL, 0, curl, &resp,
                                               &tok_json, &access_token, &postfields, &phase),
                         PAM_AUTH_ERR);
        assert_int_equal(phase, TOKEN_PHASE_UNAVAILABLE);
        assert_null(access_token);
        /* Not a retryable authorization_pending: exactly ONE HTTP request, then
         * the definitive abort (no further poll is attempted). */
        assert_int_equal(g_fake_perform_count, 1);

        if (postfields) {
            secure_memzero(postfields, strlen(postfields));
            free(postfields);
        }
        secure_zero_json_tree(tok_json);
        if (tok_json) {
            json_object_put(tok_json);
        }
        free_http_response(&resp);
        curl_easy_cleanup(curl);
    }
}

/**
 * @brief Forward declaration: the device-flow tests below call this fixture
 *        helper, which is defined (with its doc block) further down this file.
 */
static void init_config_defaults(config_t *cfg);

/**
 * @brief Drives request_device_authorization() through the fake cURL
 *        transport and pins the provider-response parsing and clamping
 *        rules: field extraction, interval/expires_in clamping, and the
 *        monotonic deadline computed from the clamped expires_in.
 *
 * The response's interval (999 s) and expires_in (99999 s) both exceed their
 * supported maxima so both clamps are observable. Teardown mirrors the
 * module's cleanup discipline (scrub the escaped postfields, scrub the JSON
 * tree, free the response).
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_request_device_authorization_parses_provider_response(void **state) {
    (void)state;
    reset_fake_curl_transport();
    config_t cfg;
    init_config_defaults(&cfg);
    assert_int_equal(copy_checked(cfg.client_id, sizeof(cfg.client_id), "test-client"), 0);
    assert_int_equal(copy_checked(cfg.device_authorization_endpoint, sizeof(cfg.device_authorization_endpoint),
                                  "https://idp.example.com/device"),
                     0);

    CURL *curl = curl_easy_init();
    assert_non_null(curl);
    http_response_t resp;
    memset(&resp, 0, sizeof(resp));
    device_auth_t dev;
    memset(&dev, 0, sizeof(dev));
    struct json_object *dev_json = NULL;
    char *postfields = NULL;

    g_fake_curl_status_code = 200;
    g_fake_curl_body = "{\"device_code\":\"DEV123\",\"user_code\":\"ABCD-EFGH\","
                       "\"verification_uri\":\"https://idp.example.com/verify\","
                       "\"verification_uri_complete\":\"https://idp.example.com/verify?uc=ABCD\","
                       "\"interval\":999,\"expires_in\":99999}";
    assert_int_equal(
        request_device_authorization(NULL, &cfg, LOGLEVEL_NONE, 0, NULL, curl, &dev, &resp, &dev_json, &postfields),
        PAM_SUCCESS);
    assert_string_equal(dev.device_code, "DEV123");
    assert_string_equal(dev.user_code, "ABCD-EFGH");
    assert_string_equal(dev.verification_uri, "https://idp.example.com/verify");
    assert_string_equal(dev.verification_uri_complete, "https://idp.example.com/verify?uc=ABCD");
    assert_int_equal(dev.poll_interval, MAX_SUPPORTED_POLL_INTERVAL);
    assert_int_equal(dev.expires_in, cfg.max_poll_seconds);

    /* deadline = monotonic now + clamped expires_in (allow scheduler jitter). */
    struct timespec now;
    assert_int_equal(clock_gettime(CLOCK_MONOTONIC, &now), 0);
    long delta = dev.deadline.tv_sec - (now.tv_sec + dev.expires_in);
    assert_true(delta >= -1 && delta <= 1);

    /* Teardown mirrors pam_sm_authenticate()'s cleanup discipline. */
    if (postfields) {
        secure_memzero(postfields, strlen(postfields));
        free(postfields);
    }
    secure_zero_json_tree(dev_json);
    if (dev_json) {
        json_object_put(dev_json);
    }
    free_http_response(&resp);
    curl_easy_cleanup(curl);
}

/**
 * @brief Drives poll_for_access_token() through the fake cURL transport with
 *        an immediately-issued token: the first poll (RUN_NOW, no leading
 *        sleep) parses the 2xx response, accepts the Bearer token, and
 *        strdup()s the access token for the caller.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_poll_loop_immediate_token_success(void **state) {
    (void)state;
    reset_fake_curl_transport();
    config_t cfg;
    init_config_defaults(&cfg);
    assert_int_equal(copy_checked(cfg.client_id, sizeof(cfg.client_id), "test-client"), 0);
    assert_int_equal(copy_checked(cfg.token_endpoint, sizeof(cfg.token_endpoint), "https://idp.example.com/token"), 0);

    struct timespec now;
    assert_int_equal(clock_gettime(CLOCK_MONOTONIC, &now), 0);
    device_auth_t dev;
    memset(&dev, 0, sizeof(dev));
    assert_int_equal(copy_checked(dev.device_code, sizeof(dev.device_code), "DEV123"), 0);
    dev.poll_interval = MIN_POLL_INTERVAL;
    dev.expires_in = 60;
    dev.deadline.tv_sec = now.tv_sec + dev.expires_in;
    dev.deadline.tv_nsec = now.tv_nsec;

    CURL *curl = curl_easy_init();
    assert_non_null(curl);
    http_response_t resp;
    memset(&resp, 0, sizeof(resp));
    struct json_object *tok_json = NULL;
    char *access_token = NULL;
    char *postfields = NULL;
    token_phase_t phase = TOKEN_PHASE_UNAVAILABLE;

    g_fake_curl_status_code = 200;
    g_fake_curl_body = "{\"access_token\":\"testtok123\",\"token_type\":\"Bearer\"}";
    assert_int_equal(poll_for_access_token(NULL, &cfg, LOGLEVEL_NONE, "probeuser", &dev, NULL, 0, curl, &resp,
                                           &tok_json, &access_token, &postfields, &phase),
                     PAM_SUCCESS);
    assert_string_equal(access_token, "testtok123");
    assert_int_equal(g_fake_perform_count, 1);

    secure_memzero(access_token, strlen(access_token));
    free(access_token);
    if (postfields) {
        secure_memzero(postfields, strlen(postfields));
        free(postfields);
    }
    secure_zero_json_tree(tok_json);
    if (tok_json) {
        json_object_put(tok_json);
    }
    free_http_response(&resp);
    curl_easy_cleanup(curl);
}

/**
 * @brief Drives the poll loop through one authorization_pending round and
 *        pins the deadline enforcement: with the device deadline closer than
 *        one poll interval, the second iteration must stop WITHOUT issuing
 *        another request (exactly one HTTP round trip) and classify the
 *        failure as TOKEN_PHASE_EXPIRED.
 *
 * The near deadline keeps the test sleep-free: the next poll lands at/after
 * the deadline, so the loop exits before clock_nanosleep() runs.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_poll_loop_pending_then_deadline_expiry(void **state) {
    (void)state;
    reset_fake_curl_transport();
    config_t cfg;
    init_config_defaults(&cfg);
    assert_int_equal(copy_checked(cfg.client_id, sizeof(cfg.client_id), "test-client"), 0);
    assert_int_equal(copy_checked(cfg.token_endpoint, sizeof(cfg.token_endpoint), "https://idp.example.com/token"), 0);

    struct timespec now;
    assert_int_equal(clock_gettime(CLOCK_MONOTONIC, &now), 0);
    device_auth_t dev;
    memset(&dev, 0, sizeof(dev));
    assert_int_equal(copy_checked(dev.device_code, sizeof(dev.device_code), "DEV123"), 0);
    dev.poll_interval = MIN_POLL_INTERVAL;
    dev.expires_in = 2; /* Shorter than one poll interval. */
    dev.deadline.tv_sec = now.tv_sec + dev.expires_in;
    dev.deadline.tv_nsec = now.tv_nsec;

    CURL *curl = curl_easy_init();
    assert_non_null(curl);
    http_response_t resp;
    memset(&resp, 0, sizeof(resp));
    struct json_object *tok_json = NULL;
    char *access_token = NULL;
    char *postfields = NULL;
    token_phase_t phase = TOKEN_PHASE_UNAVAILABLE;

    const char *bodies[] = {"{\"error\":\"authorization_pending\"}"};
    const long codes[] = {400};
    script_fake_responses(bodies, codes, 1);
    assert_int_equal(poll_for_access_token(NULL, &cfg, LOGLEVEL_NONE, "probeuser", &dev, NULL, 0, curl, &resp,
                                           &tok_json, &access_token, &postfields, &phase),
                     PAM_AUTH_ERR);
    assert_int_equal(phase, TOKEN_PHASE_EXPIRED);
    assert_null(access_token);
    /* The pending round consumed the one scripted response; the expired
     * second iteration must not have issued another request. */
    assert_int_equal(g_fake_perform_count, 1);

    if (postfields) {
        secure_memzero(postfields, strlen(postfields));
        free(postfields);
    }
    secure_zero_json_tree(tok_json);
    if (tok_json) {
        json_object_put(tok_json);
    }
    free_http_response(&resp);
    curl_easy_cleanup(curl);
}

/**
 * @brief Pins the definitive provider-error classifications in the poll loop:
 *        expired_token -> TOKEN_PHASE_EXPIRED, access_denied ->
 *        TOKEN_PHASE_DENIED, and any other provider error (here server_error)
 *        -> TOKEN_PHASE_UNAVAILABLE, each failing with PAM_AUTH_ERR and no
 *        token issued.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_poll_loop_maps_provider_error_phases(void **state) {
    (void)state;
    static const char *const bodies[] = {
        "{\"error\":\"expired_token\"}",
        "{\"error\":\"access_denied\"}",
        "{\"error\":\"server_error\"}",
    };
    static const token_phase_t expected[] = {TOKEN_PHASE_EXPIRED, TOKEN_PHASE_DENIED, TOKEN_PHASE_UNAVAILABLE};

    for (int i = 0; i < 3; i++) {
        reset_fake_curl_transport();
        config_t cfg;
        init_config_defaults(&cfg);
        assert_int_equal(copy_checked(cfg.client_id, sizeof(cfg.client_id), "test-client"), 0);
        assert_int_equal(copy_checked(cfg.token_endpoint, sizeof(cfg.token_endpoint), "https://idp.example.com/token"),
                         0);

        struct timespec now;
        assert_int_equal(clock_gettime(CLOCK_MONOTONIC, &now), 0);
        device_auth_t dev;
        memset(&dev, 0, sizeof(dev));
        assert_int_equal(copy_checked(dev.device_code, sizeof(dev.device_code), "DEV123"), 0);
        dev.poll_interval = MIN_POLL_INTERVAL;
        dev.expires_in = 60;
        dev.deadline.tv_sec = now.tv_sec + dev.expires_in;
        dev.deadline.tv_nsec = now.tv_nsec;

        CURL *curl = curl_easy_init();
        assert_non_null(curl);
        http_response_t resp;
        memset(&resp, 0, sizeof(resp));
        struct json_object *tok_json = NULL;
        char *access_token = NULL;
        char *postfields = NULL;
        token_phase_t phase = TOKEN_PHASE_UNAVAILABLE;

        const long code = 400;
        script_fake_responses(&bodies[i], &code, 1);
        assert_int_equal(poll_for_access_token(NULL, &cfg, LOGLEVEL_NONE, "probeuser", &dev, NULL, 0, curl, &resp,
                                               &tok_json, &access_token, &postfields, &phase),
                         PAM_AUTH_ERR);
        assert_int_equal(phase, expected[i]);
        assert_null(access_token);
        assert_int_equal(g_fake_perform_count, 1);

        if (postfields) {
            secure_memzero(postfields, strlen(postfields));
            free(postfields);
        }
        secure_zero_json_tree(tok_json);
        if (tok_json) {
            json_object_put(tok_json);
        }
        free_http_response(&resp);
        curl_easy_cleanup(curl);
    }
}

/**
 * @brief Unit test verifying RFC 7636 code verifier generation properties.
 *
 * Asserts the verifier is exactly 64 Base64URL (no padding) characters drawn
 * from the RFC 4648 §5 URL-safe alphabet, that consecutive draws differ
 * (CSPRNG output), and that NULL/undersized output buffers fail closed.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_pkce_code_verifier(void **state) {
    (void)state;

    char verifier[PKCE_VERIFIER_LEN + 1];
    memset(verifier, 0xAA, sizeof(verifier));
    assert_int_equal(pkce_generate_code_verifier(verifier, sizeof(verifier)), 0);
    assert_int_equal(strlen(verifier), PKCE_VERIFIER_LEN);
    for (size_t i = 0; i < strlen(verifier); i++) {
        unsigned char c = (unsigned char)verifier[i];
        assert_true((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_');
    }

    char verifier2[PKCE_VERIFIER_LEN + 1];
    assert_int_equal(pkce_generate_code_verifier(verifier2, sizeof(verifier2)), 0);
    assert_string_not_equal(verifier, verifier2);

    /* Fail closed: NULL buffer or buffer too small for 64 chars + NUL. */
    char small[PKCE_VERIFIER_LEN];
    assert_int_equal(pkce_generate_code_verifier(small, sizeof(small)), -1);
    assert_int_equal(pkce_generate_code_verifier(NULL, sizeof(small)), -1);
}

/**
 * @brief Unit test verifying S256 code challenge computation against the RFC 7636 known vector.
 *
 * Uses the Appendix B example from RFC 7636: the base example verifier must
 * produce exactly the published challenge, and invalid inputs must fail closed.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_pkce_s256_challenge(void **state) {
    (void)state;

    const char *verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const char *expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    char challenge[PKCE_S256_CHALLENGE_LEN + 1];
    assert_int_equal(pkce_compute_s256_challenge(verifier, challenge, sizeof(challenge)), 0);
    assert_string_equal(challenge, expected);
    assert_int_equal(strlen(challenge), PKCE_S256_CHALLENGE_LEN);

    /* Fail closed: NULL/empty verifier, NULL output, or undersized buffer. */
    char small[PKCE_S256_CHALLENGE_LEN];
    assert_int_equal(pkce_compute_s256_challenge(verifier, small, sizeof(small)), -1);
    assert_int_equal(pkce_compute_s256_challenge(NULL, challenge, sizeof(challenge)), -1);
    assert_int_equal(pkce_compute_s256_challenge("", challenge, sizeof(challenge)), -1);
    assert_int_equal(pkce_compute_s256_challenge(verifier, NULL, sizeof(challenge)), -1);
}

/**
 * @brief Unit test verifying local account allow/deny list enforcement.
 *
 * Exercises `verify_user_access` for no-lists, allow, deny, deny-precedence-over-allow,
 * case-insensitive matching, the uid-0 (root) gate semantics, and the system-account
 * uid-range gate (deny_system_uids) semantics.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
/**
 * @brief Locate the first non-root local account whose uid lies in the conventional system
 *        range [1..999], returning its name and uid.
 *
 * No such account name (or uid) is guaranteed on the supported platforms: openSUSE ships no
 * account at all below uid 1000, and RHEL and Debian assign different uids to conventional
 * names such as "daemon" and "bin" — callers must therefore treat "not found" as vacuous.
 * The static /etc/passwd file is parsed directly because the getpwent_r/setgrent APIs
 * require _GNU_SOURCE, which the test target is not compiled with.
 *
 * @param[out] out_name    Receives the account name; must be at least 32 bytes.
 * @param[out] out_uid     Receives the account's numeric uid.
 * @return 1 if an account was found, 0 otherwise.
 */
static int find_system_range_account(char *out_name, int *out_uid) {
    FILE *fp = fopen("/etc/passwd", "re");
    if (fp == NULL) {
        return 0;
    }
    int found = 0;
    char line[512];
    while (fgets(line, sizeof(line), fp) != NULL) {
        /* name (field 1) : ... : uid (field 3) : ... */
        char *f1_end = strchr(line, ':');
        char *f2_end = (f1_end != NULL) ? strchr(f1_end + 1, ':') : NULL;
        char *f3_end = (f2_end != NULL) ? strchr(f2_end + 1, ':') : NULL;
        if (f1_end == NULL || f2_end == NULL || f3_end == NULL) {
            continue;
        }
        *f1_end = '\0';
        *f3_end = '\0';
        long uid = strtol(f2_end + 1, NULL, 10);
        if (uid >= 1 && uid <= 999) {
            strncpy(out_name, line, 31);
            out_name[31] = '\0';
            *out_uid = (int)uid;
            found = 1;
            break;
        }
    }
    (void)fclose(fp);
    return found;
}

static void test_verify_user_access(void **state) {
    (void)state;
    config_t cfg;

    /* No lists configured: every non-root account is permitted; root is denied by
     * default even without any user lists. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    assert_int_equal(verify_user_access("alice", &cfg, NULL), 1);
    assert_int_equal(verify_user_access("root", &cfg, NULL), 0);

    /* Root requires the explicit allow_root opt-in; listing root in allow_users alone
     * never grants root access. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    strncpy(cfg.allow_users, "root,alice", sizeof(cfg.allow_users) - 1);
    assert_int_equal(verify_user_access("root", &cfg, NULL), 0);
    assert_int_equal(verify_user_access("alice", &cfg, NULL), 1);
    cfg.allow_root = 1;
    assert_int_equal(verify_user_access("root", &cfg, NULL), 1);

    /* The root guard targets uid 0, not the name "root": a name that resolves to no
     * local account cannot be a local uid-0 account (uid-0 accounts always exist in the
     * account database), so the uid gate must NOT refuse it -- only the user lists
     * decide. The name is longer than the Linux 32-character login-name limit, so it
     * is guaranteed absent on any host. (The authoritative uid-0 alias case is covered
     * deterministically by the e2e 'toor' scenario.) */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    assert_int_equal(verify_user_access("f3_unit_test_absent_user_name_long", &cfg, NULL), 1);
    strncpy(cfg.deny_users, "f3_unit_test_absent_user_name_long", sizeof(cfg.deny_users) - 1);
    assert_int_equal(verify_user_access("f3_unit_test_absent_user_name_long", &cfg, NULL), 0);

    /* deny_users blocks listed accounts, permits the rest. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
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

    /* System-account uid-range gate: with the guard on at the default range (0-999), a
     * uid-0 account is denied even when listed in allow_users — "root" resolves to uid 0
     * by the module itself, so this is deterministic on every supported platform. A name
     * that resolves to no local account cannot carry an in-range uid and is not denied by
     * the gate. No non-root account name (or uid) in-range is guaranteed on every
     * platform (openSUSE ships no accounts below uid 1000; RHEL and Debian disagree on
     * "daemon"/"bin"), so the assertions covering one use a dynamically located account
     * and are vacuously skipped where none exists. */
    char peer[32];
    int peer_uid = 0;
    int have_peer = find_system_range_account(peer, &peer_uid);

    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    cfg.deny_system_uids = 1;
    cfg.system_uid_min = 0;
    cfg.system_uid_max = 999;
    assert_int_equal(verify_user_access("root", &cfg, NULL), 0);
    assert_int_equal(verify_user_access("f3_unit_test_absent_user_name_long", &cfg, NULL), 1);
    /* "Not found" is distinct from "lookup error" and must not trip either uid gate:
     * a name with no local account entry satisfies no range check and is still
     * decided by the user lists alone (listing it in allow_users permits it). The
     * PWNAM_ERROR path (persistent ERANGE, NSS outage) fails closed; it is induced
     * deterministically in test_verify_user_access_large_entry() via the scripted
     * getpwnam_r() override. */
    strncpy(cfg.allow_users, "f3_unit_test_absent_user_name_long", sizeof(cfg.allow_users) - 1);
    assert_int_equal(verify_user_access("f3_unit_test_absent_user_name_long", &cfg, NULL), 1);
    cfg.allow_users[0] = '\0';
    assert_int_equal(verify_user_access("f3_unit_test_absent_user_name_long", &cfg, NULL), 1);
    strncpy(cfg.allow_users, "root", sizeof(cfg.allow_users) - 1);
    assert_int_equal(verify_user_access("root", &cfg, NULL), 0);
    cfg.allow_users[0] = '\0';
    /* A non-root in-range account is denied by the range gate even though it is not
     * listed in allow_users (the guard targets the uid, not the user lists). */
    if (have_peer) {
        assert_int_equal(verify_user_access(peer, &cfg, NULL), 0);
    }
    /* Raising the lower bound above the account's uid permits it; disabling the guard
     * does as well. */
    if (have_peer) {
        cfg.system_uid_min = peer_uid + 1;
        assert_int_equal(verify_user_access(peer, &cfg, NULL), 1);
        cfg.system_uid_min = 0;
        cfg.deny_system_uids = 0;
        assert_int_equal(verify_user_access(peer, &cfg, NULL), 1);
    }
    /* An explicitly inverted range is unsatisfiable (load_config() rejects it) and is
     * treated as inactive by the gate. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    cfg.deny_system_uids = 1;
    cfg.system_uid_min = 999;
    cfg.system_uid_max = 0;
    if (have_peer) {
        assert_int_equal(verify_user_access(peer, &cfg, NULL), 1);
    }
    /* The allow_root opt-in exempts uid-0 accounts from both the uid-0 gate and the range
     * gate: root is permitted while other in-range system accounts are still refused. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    cfg.deny_system_uids = 1;
    cfg.system_uid_min = 0;
    cfg.system_uid_max = 999;
    cfg.allow_root = 1;
    assert_int_equal(verify_user_access("root", &cfg, NULL), 1);
    if (have_peer) {
        assert_int_equal(verify_user_access(peer, &cfg, NULL), 0);
    }

    /* NULL pointers are rejected. */
    assert_int_equal(verify_user_access(NULL, &cfg, NULL), 0);
    assert_int_equal(verify_user_access("alice", NULL, NULL), 0);
}

/**
 * @brief Unit test for verify_user_access()'s uid lookup against large and unreachable
 *        passwd entries (scripted getpwnam_r() override).
 *
 * Pins both halves of the uid-gate lookup contract: (1) an account whose passwd entry is
 * too large for the initial getpwnam_r() buffer (ERANGE) must be rescued by the
 * growing-buffer retry and not locked out; (2) a persistent lookup failure must still
 * fail closed while any uid gate is active, the retry loop must terminate at the
 * buffer-growth cap, and a lookup error is not a refusal when no gate is active.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_verify_user_access_large_entry(void **state) {
    (void)state;
    config_t cfg;

    reset_fake_pwnam_lookup();

    /* A passwd entry larger than the early buffers: the first two lookups report
     * ERANGE whatever the offered buffer size, then the account resolves to uid 1500
     * (outside the default system range 0..999). Without the growing-buffer retry the
     * lookup would end in PWNAM_ERROR and the active uid gate would lock out this
     * legitimate account. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    cfg.deny_system_uids = 1;
    cfg.system_uid_min = 0;
    cfg.system_uid_max = 999;
    g_fake_pwnam_mode = FAKE_PWNAM_ERANGE_THEN_FOUND;
    strncpy(g_fake_pwnam_script_name, "biguser", sizeof(g_fake_pwnam_script_name) - 1);
    g_fake_pwnam_script_erange_calls = 2;
    g_fake_pwnam_script_uid = 1500;
    assert_int_equal(verify_user_access("biguser", &cfg, NULL), 1);
    assert_int_equal(g_fake_pwnam_call_count, 3); /* ERANGE, ERANGE (buffer grew), FOUND */

    /* A persistent backend failure fails closed under an active uid gate... */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    cfg.deny_system_uids = 1;
    cfg.system_uid_min = 0;
    cfg.system_uid_max = 999;
    reset_fake_pwnam_lookup();
    g_fake_pwnam_mode = FAKE_PWNAM_ERANGE_FOREVER;
    strncpy(g_fake_pwnam_script_name, "ghostuser", sizeof(g_fake_pwnam_script_name) - 1);
    assert_int_equal(verify_user_access("ghostuser", &cfg, NULL), 0);
    /* ...and the buffer-growth cap keeps the retry loop finite (it retried at least
     * once past the initial buffer before giving up). */
    assert_true(g_fake_pwnam_call_count >= 2);

    /* With no active uid gate the same lookup error is not a refusal: allow_root
     * exempts the uid-0 gate and deny_system_uids stays off. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    cfg.allow_root = 1;
    assert_int_equal(verify_user_access("ghostuser", &cfg, NULL), 1);

    reset_fake_pwnam_lookup();
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
 * @brief Test helper building a UserInfo object whose `groups` field holds `claim` as a JSON string.
 *
 * @param[in] claim NUL-terminated group claim string.
 * @return New `{"groups": claim}` json_object tree (caller owns it), or NULL on allocation failure.
 */
static struct json_object *group_claim_uinfo(const char *claim) {
    struct json_object *uinfo = json_object_new_object();
    if (!uinfo) {
        return NULL;
    }
    struct json_object *j_claim = json_object_new_string(claim);
    /* json_object_object_add() returns 0 on success and -1 on failure, so a
     * nonzero return (not a falsy one) is the failure condition. */
    if (!j_claim || json_object_object_add(uinfo, "groups", j_claim) != 0) {
        json_object_put(uinfo);
        return NULL;
    }
    return uinfo;
}

/**
 * @brief Unit test verifying that a deny-only group policy fails closed on unusable claims.
 *
 * Regression test: when `deny_groups` is configured (and `allow_groups` is empty), a claim that
 * is missing, JSON null, of an unrecognized type, or a comma-delimited string that cannot be
 * fully parsed must be DENIED — not treated as "nothing to check". Long string claims
 * (past the old 256-byte scratch-buffer bound) must still be split and matched.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_verify_group_membership_deny_only_fail_closed(void **state) {
    (void)state;
    config_t cfg;
    struct json_object *uinfo;
    char long_claim[300];
    size_t pad;

    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    strncpy(cfg.deny_groups, "contractors", sizeof(cfg.deny_groups) - 1);

    /* deny-only: claim field absent from UserInfo -> denied. */
    uinfo = json_tokener_parse("{\"sub\":\"jdoe\"}");
    assert_non_null(uinfo);
    assert_int_equal(verify_group_membership(uinfo, &cfg, NULL), 0);
    json_object_put(uinfo);

    /* deny-only: NULL UserInfo payload -> denied. */
    assert_int_equal(verify_group_membership(NULL, &cfg, NULL), 0);

    /* deny-only: claim present but JSON null -> denied. */
    uinfo = json_tokener_parse("{\"groups\":null}");
    assert_non_null(uinfo);
    assert_int_equal(verify_group_membership(uinfo, &cfg, NULL), 0);
    json_object_put(uinfo);

    /* deny-only: claim present but wrong type (number) -> denied. */
    uinfo = json_tokener_parse("{\"groups\":123}");
    assert_non_null(uinfo);
    assert_int_equal(verify_group_membership(uinfo, &cfg, NULL), 0);
    json_object_put(uinfo);

    /* deny-only: array claim containing a non-string element -> denied. */
    uinfo = json_tokener_parse("{\"groups\":[\"users\",123]}");
    assert_non_null(uinfo);
    assert_int_equal(verify_group_membership(uinfo, &cfg, NULL), 0);
    json_object_put(uinfo);

    /* allow-only: non-string array elements are skipped; string items still match. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    strncpy(cfg.allow_groups, "sysadmins", sizeof(cfg.allow_groups) - 1);
    uinfo = json_tokener_parse("{\"groups\":[123,\"users\",\"sysadmins\"]}");
    assert_non_null(uinfo);
    assert_int_equal(verify_group_membership(uinfo, &cfg, NULL), 1);
    json_object_put(uinfo);

    /* deny-only: 300-byte comma-separated claim containing a denied token -> denied. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.case_sensitive = 1;
    cfg.loglevel = LOGLEVEL_NONE;
    strncpy(cfg.deny_groups, "contractors", sizeof(cfg.deny_groups) - 1);
    memset(long_claim, 'a', sizeof(long_claim) - 1);
    long_claim[sizeof(long_claim) - 1] = '\0';
    memcpy(long_claim, "contractors,", 12);
    uinfo = group_claim_uinfo(long_claim);
    assert_non_null(uinfo);
    assert_int_equal(verify_group_membership(uinfo, &cfg, NULL), 0);
    json_object_put(uinfo);

    /* deny-only: denied token past byte 255 of a long comma-separated claim -> denied
     * (previously the 256-byte scratch buffer made the split fail silently -> allowed). */
    for (pad = 0; pad < 260; pad++) {
        long_claim[pad] = (char)('a' + (pad % 26));
    }
    memcpy(long_claim + 260, ",contractors", 12);
    long_claim[272] = '\0';
    uinfo = group_claim_uinfo(long_claim);
    assert_non_null(uinfo);
    assert_int_equal(verify_group_membership(uinfo, &cfg, NULL), 0);
    json_object_put(uinfo);

    /* deny-only: long claim with no denied group -> allowed (no spurious deny). */
    for (pad = 0; pad < 299; pad++) {
        long_claim[pad] = ((pad % 2) == 0) ? 'b' : ',';
    }
    long_claim[299] = '\0';
    uinfo = group_claim_uinfo(long_claim);
    assert_non_null(uinfo);
    assert_int_equal(verify_group_membership(uinfo, &cfg, NULL), 1);
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
    /* No claim_regex default (matches load_config): fixtures that parse successfully
     * must set claim_regex explicitly; parse_config_file() rejects an empty value. */
    cfg->claim_capture_group = 1;
    cfg->max_poll_seconds = 120;
    cfg->case_sensitive = 1;
    cfg->show_expiry = 1;
    cfg->loglevel = LOGLEVEL_INFO;
    cfg->deny_system_uids = 1;
    cfg->system_uid_min = 0;
    cfg->system_uid_max = 999;
    cfg->verify_jwt_claims = 0;
    cfg->clock_skew_leeway = 60;
    cfg->require_exp_claim = 0;
    (void)copy_checked(cfg->group_claim_field, sizeof(cfg->group_claim_field), "groups");
    /* Keep in sync with load_config() defaults. */
    cfg->qr_enabled = 0;
    cfg->qr_style = QR_STYLE_UTF8;
    (void)copy_checked(cfg->qr_block_char, sizeof(cfg->qr_block_char), "#");
    cfg->qr_scale = 1;
    cfg->qr_ec_level = QR_EC_MEDIUM;
    cfg->qr_uri_complete = 1;
    cfg->qr_vertical_quiet_zone = QR_QUIET_ZONE;
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
                                    "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                    "[claim]\n"
                                    "claim_regex = ^([a-zA-Z0-9._-]+)$\n";
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
    /* claim_regex is required (no default) and was explicitly set above. */
    assert_string_equal(cfg.claim_regex, "^([a-zA-Z0-9._-]+)$");
    assert_int_equal(cfg.claim_capture_group, 1);
    assert_int_equal(cfg.max_poll_seconds, 120);
    assert_int_equal(cfg.case_sensitive, 1);
    assert_int_equal(cfg.show_expiry, 1);
    assert_int_equal(cfg.loglevel, LOGLEVEL_INFO);
    assert_int_equal(cfg.deny_system_uids, 1);
    assert_int_equal(cfg.system_uid_min, 0);
    assert_int_equal(cfg.system_uid_max, 999);
    assert_string_equal(cfg.group_claim_field, "groups");
    assert_int_equal(cfg.use_pkce, 0);
    /* QR defaults preserved when the [qr] section is absent. */
    assert_int_equal(cfg.qr_enabled, 0);
    assert_int_equal(cfg.qr_style, QR_STYLE_UTF8);
    assert_string_equal(cfg.qr_block_char, "#");
    assert_int_equal(cfg.qr_scale, 1);
    assert_int_equal(cfg.qr_ec_level, QR_EC_MEDIUM);
    assert_int_equal(cfg.qr_uri_complete, 1);
    assert_int_equal(cfg.qr_vertical_quiet_zone, QR_QUIET_ZONE);
}

/**
 * @brief Unit test verifying parse_config_file rejects a configuration without
 *        an explicit claim_regex (the identity-mapping regex is required; there is
 *        no catch-all default, and an explicitly empty value is rejected as well).
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_claim_regex_required(void **state) {
    (void)state;
    static const char *const missing = "[oauth]\n"
                                       "client_id = test-client\n"
                                       "device_authorization_endpoint = https://idp.example.com/device\n"
                                       "token_endpoint = https://idp.example.com/token\n"
                                       "userinfo_endpoint = https://idp.example.com/userinfo\n";
    config_t cfg;
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(missing);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);
    /* All parsed content is securely zeroed on failure. */
    assert_string_equal(cfg.client_id, "");

    static const char *const empty = "[oauth]\n"
                                     "client_id = test-client\n"
                                     "device_authorization_endpoint = https://idp.example.com/device\n"
                                     "token_endpoint = https://idp.example.com/token\n"
                                     "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                     "[claim]\n"
                                     "claim_regex = \n";
    init_config_defaults(&cfg);
    f = open_config_stream(empty);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);
    assert_string_equal(cfg.client_id, "");
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
                                    "use_pkce = true\n"
                                    "discovery_endpoint = https://idp.example.com/.well-known/openid-configuration\n"
                                    "proxy = https://proxy.example.com:3129\n"
                                    "[claim]\n"
                                    "claim_field = preferred_username\n"
                                    "claim_regex = ^(.*)$\n"
                                    "claim_capture_group = 1\n"
                                    "case_sensitive = false\n"
                                    "[access]\n"
                                    "allow_users = alice,bob\n"
                                    "deny_users = mallory\n"
                                    "allow_root = yes\n"
                                    "deny_system_uids = no\n"
                                    "system_uid_min = 100\n"
                                    "system_uid_max = 500\n"
                                    "allow_groups = sysadmins\n"
                                    "deny_groups = terminated\n"
                                    "enforce_groups = yes\n"
                                    "group_claim_field = roles\n"
                                    "[prompt]\n"
                                    "init_message = Code: %s\n"
                                    "show_expiry = false\n"
                                    "[runtime]\n"
                                    "max_poll_seconds = 60\n"
                                    "loglevel = verbose\n"
                                    "[qr]\n"
                                    "enabled = yes\n"
                                    "style = ascii\n"
                                    "block_char = @\n"
                                    "scale = 2\n"
                                    "vertical_quiet_zone = 2\n"
                                    "ec_level = h\n"
                                    "uri = plain\n";
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
    assert_int_equal(cfg.allow_root, 1);
    assert_int_equal(cfg.deny_system_uids, 0);
    assert_int_equal(cfg.system_uid_min, 100);
    assert_int_equal(cfg.system_uid_max, 500);
    assert_string_equal(cfg.allow_groups, "sysadmins");
    assert_string_equal(cfg.deny_groups, "terminated");
    assert_int_equal(cfg.enforce_groups, 1);
    assert_string_equal(cfg.group_claim_field, "roles");
    assert_string_equal(cfg.init_message, "Code: %s");
    assert_int_equal(cfg.show_expiry, 0);
    assert_int_equal(cfg.max_poll_seconds, 60);
    assert_int_equal(cfg.loglevel, LOGLEVEL_VERBOSE);
    assert_int_equal(cfg.verify_jwt_claims, 1);
    assert_int_equal(cfg.clock_skew_leeway, 5);
    assert_int_equal(cfg.require_exp_claim, 0);
    assert_int_equal(cfg.use_pkce, 1);
    assert_string_equal(cfg.discovery_endpoint, "https://idp.example.com/.well-known/openid-configuration");
    assert_string_equal(cfg.proxy, "https://proxy.example.com:3129");
    assert_int_equal(cfg.qr_enabled, 1);
    assert_int_equal(cfg.qr_style, QR_STYLE_ASCII);
    assert_string_equal(cfg.qr_block_char, "@");
    assert_int_equal(cfg.qr_scale, 2);
    assert_int_equal(cfg.qr_vertical_quiet_zone, 2);
    assert_int_equal(cfg.qr_ec_level, QR_EC_HIGH);
    assert_int_equal(cfg.qr_uri_complete, 0);
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
 * @brief Unit test verifying a long [access] list parses and round-trips.
 *
 * Regression guard for the 256-byte list-field cap: operators deny a large
 * production /etc/passwd service-account list (>500 bytes), which used to fail
 * with "Failed to parse key 'deny_users'". Build a ~590-byte deny_users value
 * (100 accounts), longer than the old 255-char limit, and confirm it now loads
 * and is preserved intact.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_long_access_list(void **state) {
    (void)state;
    char deny[ACCESS_LIST_LEN];
    size_t off = 0;
    for (int i = 0; i < 100; i++) {
        off += (size_t)snprintf(deny + off, sizeof(deny) - off, "%ssvc%d", i ? "," : "", i);
    }
    assert_true(off > 255); /* the very length that used to overflow the old 256-byte field */

    char text[ACCESS_LIST_LEN + 256];
    int tlen = snprintf(text, sizeof(text),
                        "[oauth]\n"
                        "client_id = ci\n"
                        "device_authorization_endpoint = https://idp.example.com/device\n"
                        "token_endpoint = https://idp.example.com/token\n"
                        "userinfo_endpoint = https://idp.example.com/userinfo\n"
                        "[claim]\n"
                        "claim_regex = ^([a-zA-Z0-9._-]+)$\n"
                        "[access]\n"
                        "deny_users = %s\n",
                        deny);
    assert_true(tlen > 0 && (size_t)tlen < sizeof(text));

    config_t cfg;
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(text);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), 0);
    fclose(f);
    assert_string_equal(cfg.deny_users, deny);
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
                                    "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                    "[claim]\n"
                                    "claim_regex = ^([a-zA-Z0-9._-]+)$\n";
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
 * @brief Unit test verifying parse_config_file accepts the three-state use_pkce "auto" mode.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_pkce_auto(void **state) {
    (void)state;
    static const char *const text = "[oauth]\n"
                                    "client_id = ci\n"
                                    "device_authorization_endpoint = https://idp.example.com/device\n"
                                    "token_endpoint = https://idp.example.com/token\n"
                                    "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                    "use_pkce = auto\n"
                                    "discovery_endpoint = https://idp.example.com/.well-known/openid-configuration\n"
                                    "[claim]\n"
                                    "claim_regex = ^([a-zA-Z0-9._-]+)$\n";
    config_t cfg;
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(text);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), 0);
    fclose(f);
    assert_int_equal(cfg.use_pkce, 2);
    assert_string_equal(cfg.discovery_endpoint, "https://idp.example.com/.well-known/openid-configuration");
}

/**
 * @brief Unit test verifying parse_config_file rejects use_pkce = auto without discovery_endpoint.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_pkce_auto_requires_discovery(void **state) {
    (void)state;
    static const char *const text = "[oauth]\n"
                                    "client_id = ci\n"
                                    "device_authorization_endpoint = https://idp.example.com/device\n"
                                    "token_endpoint = https://idp.example.com/token\n"
                                    "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                    "use_pkce = auto\n";
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
 * @brief Unit test verifying parse_config_file rejects verify_jwt_claims = true
 *        unless both issuer and audience are configured.
 *
 * The iss/aud checks fail closed without a configured expectation, so the
 * combination is rejected at load time instead of failing every
 * authentication attempt at token-verification time.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_jwt_claims_requires_binding(void **state) {
    (void)state;
    config_t cfg;

    /* Neither issuer nor audience configured. */
    static const char *const neither = "[oauth]\n"
                                       "client_id = ci\n"
                                       "device_authorization_endpoint = https://idp.example.com/device\n"
                                       "token_endpoint = https://idp.example.com/token\n"
                                       "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                       "verify_jwt_claims = true\n"
                                       "[claim]\n"
                                       "claim_regex = ^([a-zA-Z0-9._-]+)$\n";
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(neither);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);
    /* All parsed content is securely zeroed on failure. */
    assert_string_equal(cfg.client_id, "");

    /* Issuer only. */
    static const char *const issuer_only = "[oauth]\n"
                                           "client_id = ci\n"
                                           "device_authorization_endpoint = https://idp.example.com/device\n"
                                           "token_endpoint = https://idp.example.com/token\n"
                                           "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                           "verify_jwt_claims = true\n"
                                           "issuer = https://idp.example.com\n"
                                           "[claim]\n"
                                           "claim_regex = ^([a-zA-Z0-9._-]+)$\n";
    init_config_defaults(&cfg);
    f = open_config_stream(issuer_only);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);

    /* Audience only. */
    static const char *const audience_only = "[oauth]\n"
                                             "client_id = ci\n"
                                             "device_authorization_endpoint = https://idp.example.com/device\n"
                                             "token_endpoint = https://idp.example.com/token\n"
                                             "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                             "verify_jwt_claims = true\n"
                                             "audience = aud-1\n"
                                             "[claim]\n"
                                             "claim_regex = ^([a-zA-Z0-9._-]+)$\n";
    init_config_defaults(&cfg);
    f = open_config_stream(audience_only);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);

    /* Both configured: accepted. */
    static const char *const both = "[oauth]\n"
                                    "client_id = ci\n"
                                    "device_authorization_endpoint = https://idp.example.com/device\n"
                                    "token_endpoint = https://idp.example.com/token\n"
                                    "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                    "verify_jwt_claims = true\n"
                                    "issuer = https://idp.example.com\n"
                                    "audience = aud-1\n"
                                    "[claim]\n"
                                    "claim_regex = ^([a-zA-Z0-9._-]+)$\n";
    init_config_defaults(&cfg);
    f = open_config_stream(both);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), 0);
    fclose(f);
    assert_int_equal(cfg.verify_jwt_claims, 1);
    assert_string_equal(cfg.issuer, "https://idp.example.com");
    assert_string_equal(cfg.audience, "aud-1");
}

/**
 * @brief Unit test verifying parse_config_file rejects an invalid system-UID range.
 *
 * Covers the cross-field check (system_uid_min must not exceed system_uid_max) and the
 * per-key bounds check (values outside 0..INT_MAX are rejected).
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_system_uid_range_invalid(void **state) {
    (void)state;
    static const char *const inverted = "[oauth]\n"
                                        "client_id = ci\n"
                                        "device_authorization_endpoint = https://idp.example.com/device\n"
                                        "token_endpoint = https://idp.example.com/token\n"
                                        "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                        "[access]\n"
                                        "system_uid_min = 100\n"
                                        "system_uid_max = 50\n";
    config_t cfg;
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(inverted);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);
    /* All parsed content is securely zeroed on failure. */
    assert_string_equal(cfg.client_id, "");

    static const char *const out_of_bounds = "[oauth]\n"
                                             "client_id = ci\n"
                                             "device_authorization_endpoint = https://idp.example.com/device\n"
                                             "token_endpoint = https://idp.example.com/token\n"
                                             "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                             "[access]\n"
                                             "system_uid_max = 5000000000\n";
    init_config_defaults(&cfg);
    f = open_config_stream(out_of_bounds);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);
}

/**
 * @brief Unit test verifying parse_config_file rejects a non-HTTPS discovery_endpoint.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_invalid_discovery_endpoint(void **state) {
    (void)state;
    static const char *const text =
        "[oauth]\n"
        "client_id = ci\n"
        "device_authorization_endpoint = https://idp.example.com/device\n"
        "token_endpoint = https://idp.example.com/token\n"
        "userinfo_endpoint = https://idp.example.com/userinfo\n"
        "use_pkce = auto\n"
        "discovery_endpoint = http://insecure.example.com/.well-known/openid-configuration\n";
    config_t cfg;
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(text);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);
}

/**
 * @brief Unit test verifying parse_config_file rejects a duplicated discovery_endpoint key.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_duplicate_discovery_endpoint(void **state) {
    (void)state;
    static const char *const text = "[oauth]\n"
                                    "client_id = ci\n"
                                    "device_authorization_endpoint = https://idp.example.com/device\n"
                                    "token_endpoint = https://idp.example.com/token\n"
                                    "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                    "use_pkce = auto\n"
                                    "discovery_endpoint = https://a.example.com/.well-known/openid-configuration\n"
                                    "discovery_endpoint = https://b.example.com/.well-known/openid-configuration\n";
    config_t cfg;
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(text);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);
}

/**
 * @brief Unit test verifying [oauth] proxy parsing: a valid HTTPS proxy URL
 *        loads, an explicitly empty value loads (disabled), and unsafe values
 *        (plain HTTP, embedded credentials) are rejected.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_parse_config_file_proxy(void **state) {
    (void)state;
    config_t cfg;

    /* A valid HTTPS proxy loads and is stored verbatim. */
    static const char *const valid = "[oauth]\n"
                                     "client_id = test-client\n"
                                     "device_authorization_endpoint = https://idp.example.com/device\n"
                                     "token_endpoint = https://idp.example.com/token\n"
                                     "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                     "proxy = https://proxy.example.com:3129\n"
                                     "[claim]\n"
                                     "claim_regex = ^([a-zA-Z0-9._-]+)$\n";
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(valid);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), 0);
    fclose(f);
    assert_string_equal(cfg.proxy, "https://proxy.example.com:3129");

    /* An explicitly empty proxy value loads and keeps the default (disabled). */
    static const char *const empty = "[oauth]\n"
                                     "client_id = test-client\n"
                                     "device_authorization_endpoint = https://idp.example.com/device\n"
                                     "token_endpoint = https://idp.example.com/token\n"
                                     "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                     "proxy =\n"
                                     "[claim]\n"
                                     "claim_regex = ^([a-zA-Z0-9._-]+)$\n";
    init_config_defaults(&cfg);
    f = open_config_stream(empty);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), 0);
    fclose(f);
    assert_string_equal(cfg.proxy, "");

    /* A plain-HTTP proxy is rejected (HTTPS-only, matching the endpoint rule). */
    static const char *const insecure = "[oauth]\n"
                                        "client_id = test-client\n"
                                        "device_authorization_endpoint = https://idp.example.com/device\n"
                                        "token_endpoint = https://idp.example.com/token\n"
                                        "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                        "proxy = http://proxy.example.com:3128\n"
                                        "[claim]\n"
                                        "claim_regex = ^([a-zA-Z0-9._-]+)$\n";
    init_config_defaults(&cfg);
    f = open_config_stream(insecure);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);

    /* A proxy URL with embedded userinfo (credentials) is rejected. */
    static const char *const credentialed = "[oauth]\n"
                                            "client_id = test-client\n"
                                            "device_authorization_endpoint = https://idp.example.com/device\n"
                                            "token_endpoint = https://idp.example.com/token\n"
                                            "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                            "proxy = https://user:pass@proxy.example.com:3129\n"
                                            "[claim]\n"
                                            "claim_regex = ^([a-zA-Z0-9._-]+)$\n";
    init_config_defaults(&cfg);
    f = open_config_stream(credentialed);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);

    /* A duplicated proxy key is rejected (house rule). */
    static const char *const duplicated = "[oauth]\n"
                                          "client_id = test-client\n"
                                          "device_authorization_endpoint = https://idp.example.com/device\n"
                                          "token_endpoint = https://idp.example.com/token\n"
                                          "userinfo_endpoint = https://idp.example.com/userinfo\n"
                                          "proxy = https://a.example.com:3129\n"
                                          "proxy = https://b.example.com:3129\n"
                                          "[claim]\n"
                                          "claim_regex = ^([a-zA-Z0-9._-]+)$\n";
    init_config_defaults(&cfg);
    f = open_config_stream(duplicated);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
    fclose(f);
}

/**
 * @brief Unit test verifying discovery_json_advertises_s256 classifies discovery metadata.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_discovery_json_advertises_s256(void **state) {
    (void)state;
    /* S256 present among other methods, plus a device-authorization endpoint. */
    struct json_object *doc = json_tokener_parse("{\"code_challenge_methods_supported\":[\"plain\",\"S256\"],\"device_"
                                                 "authorization_endpoint\":\"https://x/d\"}");
    assert_non_null(doc);
    assert_int_equal(discovery_json_advertises_s256(doc), 1);
    json_object_put(doc);

    /* S256 as the sole advertised method. */
    doc = json_tokener_parse("{\"code_challenge_methods_supported\":[\"S256\"]}");
    assert_non_null(doc);
    assert_int_equal(discovery_json_advertises_s256(doc), 1);
    json_object_put(doc);

    /* Only the auth-code-flow plain method advertised. */
    doc = json_tokener_parse("{\"code_challenge_methods_supported\":[\"plain\"]}");
    assert_non_null(doc);
    assert_int_equal(discovery_json_advertises_s256(doc), 0);
    json_object_put(doc);

    /* Field missing entirely (e.g., Microsoft Entra ID v2.0 discovery document). */
    doc = json_tokener_parse("{\"issuer\":\"https://idp.example.com\",\"token_endpoint\":\"https://idp/token\"}");
    assert_non_null(doc);
    assert_int_equal(discovery_json_advertises_s256(doc), 0);
    json_object_put(doc);

    /* Wrong member type (string instead of array) is not advertised. */
    doc = json_tokener_parse("{\"code_challenge_methods_supported\":\"S256\"}");
    assert_non_null(doc);
    assert_int_equal(discovery_json_advertises_s256(doc), 0);
    json_object_put(doc);

    /* Non-string array elements are skipped; a valid "S256" element still counts. */
    doc = json_tokener_parse("{\"code_challenge_methods_supported\":[42,\"S256\"]}");
    assert_non_null(doc);
    assert_int_equal(discovery_json_advertises_s256(doc), 1);
    json_object_put(doc);

    /* PKCE method names are case-sensitive per RFC 7636: lowercase is not a match. */
    doc = json_tokener_parse("{\"code_challenge_methods_supported\":[\"s256\"]}");
    assert_non_null(doc);
    assert_int_equal(discovery_json_advertises_s256(doc), 0);
    json_object_put(doc);

    /* A non-object document (e.g., a JSON array) cannot advertise anything. */
    doc = json_tokener_parse("[\"S256\"]");
    assert_non_null(doc);
    assert_int_equal(discovery_json_advertises_s256(doc), 0);
    json_object_put(doc);

    /* NULL input is safe. */
    assert_int_equal(discovery_json_advertises_s256(NULL), 0);
}

/** Minimal [oauth] section accepted by parse_config_file, used to append [qr] keys under test. */
#define QR_TEST_BASE_CONF                                                                                              \
    "[oauth]\n"                                                                                                        \
    "client_id = ci\n"                                                                                                 \
    "device_authorization_endpoint = https://idp.example.com/device\n"                                                 \
    "token_endpoint = https://idp.example.com/token\n"                                                                 \
    "userinfo_endpoint = https://idp.example.com/userinfo\n"                                                           \
    "[claim]\n"                                                                                                        \
    "claim_regex = ^([a-zA-Z0-9._-]+)$\n"

/**
 * @brief Unit test for [qr] section configuration parsing (valid values, rejections, duplicates).
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_qr_config_parsing(void **state) {
    (void)state;
    config_t cfg;
    char text[1024];

    /* A fully populated [qr] section (case-insensitive values). */
    snprintf(text, sizeof(text),
             QR_TEST_BASE_CONF "[qr]\n"
                               "enabled = yes\n"
                               "style = UTF8\n"
                               "block_char = x\n"
                               "scale = 3\n"
                               "vertical_quiet_zone = 3\n"
                               "ec_level = q\n"
                               "uri = Complete\n");
    init_config_defaults(&cfg);
    FILE *f = open_config_stream(text);
    assert_non_null(f);
    assert_int_equal(parse_config_file(f, &cfg, NULL), 0);
    fclose(f);
    assert_int_equal(cfg.qr_enabled, 1);
    assert_int_equal(cfg.qr_style, QR_STYLE_UTF8);
    assert_string_equal(cfg.qr_block_char, "x");
    assert_int_equal(cfg.qr_scale, 3);
    assert_int_equal(cfg.qr_vertical_quiet_zone, 3);
    assert_int_equal(cfg.qr_ec_level, QR_EC_QUARTILE);
    assert_int_equal(cfg.qr_uri_complete, 1);

    /* Every malformed or duplicated [qr] entry must fail the whole parse. */
    static const char *const bad_entries[] = {
        "enabled = maybe\n",
        "style = unicode\n",
        "style = utf8x\n",
        "block_char = ab\n",
        "block_char = \n",
        "scale = 0\n",
        "scale = 4\n",
        "scale = 2x\n",
        "vertical_quiet_zone = -1\n",
        "vertical_quiet_zone = 5\n",
        "vertical_quiet_zone = 4x\n",
        "ec_level = x\n",
        "ec_level = MM\n",
        "uri = both\n",
        "enabled = true\nenabled = false\n",
        "foo = 1\n",
    };
    for (size_t i = 0; i < sizeof(bad_entries) / sizeof(bad_entries[0]); i++) {
        snprintf(text, sizeof(text), QR_TEST_BASE_CONF "[qr]\n%s", bad_entries[i]);
        memset(&cfg, 0, sizeof(cfg));
        f = open_config_stream(text);
        assert_non_null(f);
        assert_int_equal(parse_config_file(f, &cfg, NULL), -1);
        fclose(f);
    }
}
/**
 * @brief Unit test for qr_render_matrix: quiet zone, ASCII/UTF-8 styles, scaling, error paths.
 *
 * The fixture is a synthetic all-dark 21x21 symbol so the expected terminal art is hand-computable;
 * encode-then-render correctness is covered separately by the golden output test and by
 * independent QR decoding of the rendered art (see build/verify/qr_verify.py).
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_qr_render_matrix(void **state) {
    (void)state;
    /* All-dark 21x21 symbol: byte 0 stores the symbol size (21), module bits 0..440 set. */
    uint8_t m[57];
    m[0] = 21;
    memset(m + 1, 0xFF, 55);
    m[56] = 0x01;

    char out[16384];
    char expect[16384];

    /* ASCII style, scale 1, both block characters. */
    for (int blk = 0; blk < 2; blk++) {
        char block = (char)(blk ? '@' : '#');
        size_t pos = 0;
        for (int y = 0; y < 29; y++) {
            for (int x = 0; x < 29; x++) {
                int dark = (y >= 4 && y < 25) && (x >= 4 && x < 25);
                expect[pos++] = (char)(dark ? block : ' ');
            }
            expect[pos++] = '\n';
        }
        expect[pos] = '\0';
        assert_int_equal(qr_render_matrix(m, 21, QR_STYLE_ASCII, 1, block, 4, out, sizeof(out)), 0);
        assert_string_equal(out, expect);
    }

    /* ASCII style, scale 2: every glyph duplicated horizontally and vertically. */
    size_t pos = 0;
    for (int y = 0; y < 29; y++) {
        for (int rep = 0; rep < 2; rep++) {
            for (int x = 0; x < 29; x++) {
                int dark = (y >= 4 && y < 25) && (x >= 4 && x < 25);
                expect[pos++] = (char)(dark ? '#' : ' ');
                expect[pos++] = (char)(dark ? '#' : ' ');
            }
            expect[pos++] = '\n';
        }
    }
    expect[pos] = '\0';
    assert_int_equal(qr_render_matrix(m, 21, QR_STYLE_ASCII, 2, '#', 4, out, sizeof(out)), 0);
    assert_string_equal(out, expect);

    /* ASCII style, compact vertical quiet zone (2): two light rows above and below. */
    pos = 0;
    for (int y = 0; y < 25; y++) {
        for (int x = 0; x < 29; x++) {
            int dark = (y >= 2 && y < 23) && (x >= 4 && x < 25);
            expect[pos++] = (char)(dark ? '#' : ' ');
        }
        expect[pos++] = '\n';
    }
    expect[pos] = '\0';
    assert_int_equal(qr_render_matrix(m, 21, QR_STYLE_ASCII, 1, '#', 2, out, sizeof(out)), 0);
    assert_string_equal(out, expect);

    /* UTF-8 style, scale 1: stacked module pairs become block glyphs. */
    pos = 0;
    for (int y = 0; y < 29; y += 2) {
        for (int x = 0; x < 29; x++) {
            int top = (y >= 4 && y < 25) && (x >= 4 && x < 25);
            int bot = (y + 1 < 29) && (y + 1 >= 4 && y + 1 < 25) && (x >= 4 && x < 25);
            if (top && bot) {
                memcpy(expect + pos, "\342\226\210", 3); /* U+2588 */
                pos += 3;
            } else if (top) {
                memcpy(expect + pos, "\342\226\200", 3); /* U+2580 */
                pos += 3;
            } else if (bot) {
                memcpy(expect + pos, "\342\226\204", 3); /* U+2584 */
                pos += 3;
            } else {
                expect[pos++] = ' ';
            }
        }
        expect[pos++] = '\n';
    }
    expect[pos] = '\0';
    assert_int_equal(qr_render_matrix(m, 21, QR_STYLE_UTF8, 1, '#', 4, out, sizeof(out)), 0);
    assert_string_equal(out, expect);

    /* UTF-8 style, compact vertical quiet zone (2): one blank line above and below. */
    pos = 0;
    for (int y = 0; y < 25; y += 2) {
        for (int x = 0; x < 29; x++) {
            int top = (y >= 2 && y < 23) && (x >= 4 && x < 25);
            int bot = (y + 1 < 25) && (y + 1 >= 2 && y + 1 < 23) && (x >= 4 && x < 25);
            if (top && bot) {
                memcpy(expect + pos, "\342\226\210", 3); /* U+2588 */
                pos += 3;
            } else if (top) {
                memcpy(expect + pos, "\342\226\200", 3); /* U+2580 */
                pos += 3;
            } else if (bot) {
                memcpy(expect + pos, "\342\226\204", 3); /* U+2584 */
                pos += 3;
            } else {
                expect[pos++] = ' ';
            }
        }
        expect[pos++] = '\n';
    }
    expect[pos] = '\0';
    assert_int_equal(qr_render_matrix(m, 21, QR_STYLE_UTF8, 1, '#', 2, out, sizeof(out)), 0);
    assert_string_equal(out, expect);

    /* Error paths. */
    assert_int_equal(qr_render_matrix(m, 20, QR_STYLE_ASCII, 1, '#', 4, out, sizeof(out)), -1);
    assert_int_equal(qr_render_matrix(m, 99, QR_STYLE_ASCII, 1, '#', 4, out, sizeof(out)), -1);
    assert_int_equal(qr_render_matrix(m, 21, QR_STYLE_ASCII, 0, '#', 4, out, sizeof(out)), -1);
    assert_int_equal(qr_render_matrix(m, 21, QR_STYLE_ASCII, 4, '#', 4, out, sizeof(out)), -1);
    assert_int_equal(qr_render_matrix(m, 21, QR_STYLE_ASCII, 1, ' ', 4, out, sizeof(out)), -1);
    assert_int_equal(qr_render_matrix(m, 21, QR_STYLE_ASCII, 1, '\033', 4, out, sizeof(out)), -1);
    assert_int_equal(qr_render_matrix(m, 21, (qr_style_t)9, 1, '#', 4, out, sizeof(out)), -1);
    assert_int_equal(qr_render_matrix(m, 21, QR_STYLE_ASCII, 1, '#', -1, out, sizeof(out)), -1);
    assert_int_equal(qr_render_matrix(m, 21, QR_STYLE_ASCII, 1, '#', 5, out, sizeof(out)), -1);
    assert_int_equal(qr_render_matrix(m, 21, QR_STYLE_ASCII, 1, '#', 4, out, 4), -1);
    assert_int_equal(qr_render_matrix(NULL, 21, QR_STYLE_ASCII, 1, '#', 4, out, sizeof(out)), -1);
    assert_int_equal(qr_render_matrix(m, 21, QR_STYLE_UTF8, 1, '#', 4, NULL, sizeof(out)), -1);
}
/**
 * @brief Unit test for qr_encode_uri: version sizing, error-correction scaling, determinism, errors.
 *
 * The version sizes are the ISO/IEC 18004 byte-mode capacities for the fixed test URLs
 * (44 bytes at 25/33/37 modules, 13 bytes at 25 modules); encode-then-decode correctness of
 * the underlying encoder is verified independently in build/verify/qr_verify.py.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_qr_encode_uri(void **state) {
    (void)state;
    uint8_t qr[QR_MATRIX_BYTES_MAX];
    uint8_t qr2[QR_MATRIX_BYTES_MAX];
    int size = 0;

    assert_int_equal(qr_encode_uri("https://ex.io/d", QR_EC_MEDIUM, qr, sizeof(qr), &size), 0);
    assert_int_equal(size, 25);

    const char *const url = "https://auth.example.edu/link?code=WXYZ-9012";
    int s_l = 0, s_m = 0, s_h = 0;
    assert_int_equal(qr_encode_uri(url, QR_EC_LOW, qr, sizeof(qr), &s_l), 0);
    assert_int_equal(qr_encode_uri(url, QR_EC_MEDIUM, qr, sizeof(qr), &s_m), 0);
    assert_int_equal(qr_encode_uri(url, QR_EC_HIGH, qr, sizeof(qr), &s_h), 0);
    assert_int_equal(s_l, 29);
    assert_int_equal(s_m, 33);
    assert_int_equal(s_h, 37);
    assert_true(s_l <= s_m && s_m <= s_h);

    /* Determinism: identical inputs produce identical module grids. */
    int s2 = 0;
    assert_int_equal(qr_encode_uri(url, QR_EC_MEDIUM, qr, sizeof(qr), &s_m), 0);
    assert_int_equal(qr_encode_uri(url, QR_EC_MEDIUM, qr2, sizeof(qr2), &s2), 0);
    assert_int_equal(s2, s_m);
    assert_memory_equal(qr, qr2, ((size_t)s_m * (size_t)s_m) / 8);

    /* A URL beyond version-20 byte capacity at any EC level must fail cleanly. */
    char big[1501];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    assert_int_equal(qr_encode_uri(big, QR_EC_MEDIUM, qr, sizeof(qr), &size), -1);
    assert_int_equal(size, 0);

    /* Argument validation. */
    assert_int_equal(qr_encode_uri(NULL, QR_EC_MEDIUM, qr, sizeof(qr), &size), -1);
    assert_int_equal(qr_encode_uri("", QR_EC_MEDIUM, qr, sizeof(qr), &size), -1);
    assert_int_equal(qr_encode_uri(url, (qr_ec_t)QR_EC_HIGH + 1, qr, sizeof(qr), &size), -1);
    uint8_t small[QR_MATRIX_BYTES_MAX - 1];
    assert_int_equal(qr_encode_uri(url, QR_EC_MEDIUM, small, sizeof(small), &size), -1);
    assert_int_equal(qr_encode_uri(url, QR_EC_MEDIUM, qr, sizeof(qr), NULL), -1);
}
/**
 * @brief Unit test for qr_render_verification_code: URI selection, styles, safety, error paths.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_qr_render_verification_code(void **state) {
    (void)state;
    config_t cfg;
    char out[QR_RENDER_BUF_MAX];
    char out2[QR_RENDER_BUF_MAX];
    const char *const url_plain = "https://auth.example.edu/device";
    const char *const url_complete = "https://auth.example.edu/link?code=WXYZ-9012";

    init_config_defaults(&cfg);
    /* Complete URI preferred; UTF-8 art must carry block glyphs and the instruction header. */
    assert_int_equal(qr_render_verification_code(&cfg, LOGLEVEL_DEBUG, url_plain, url_complete, out, sizeof(out), NULL),
                     0);
    assert_int_equal(strncmp(out, "Scan this QR code", 17), 0);
    assert_non_null(strstr(out, "\342\226\210"));
    /* Plain URI (complete unavailable) must differ from the complete-URI symbol. */
    assert_int_equal(qr_render_verification_code(&cfg, LOGLEVEL_DEBUG, url_plain, NULL, out2, sizeof(out2), NULL), 0);
    assert_string_not_equal(out, out2);
    /* uri=plain must select the plain URI even when the complete one is available. */
    cfg.qr_uri_complete = 0;
    assert_int_equal(qr_render_verification_code(&cfg, LOGLEVEL_DEBUG, url_plain, url_complete, out, sizeof(out), NULL),
                     0);
    assert_string_equal(out, out2);

    /* ASCII style at scale 3: output must be pure printable ASCII plus newlines. */
    cfg.qr_uri_complete = 1;
    cfg.qr_style = QR_STYLE_ASCII;
    cfg.qr_scale = 3;
    assert_int_equal(qr_render_verification_code(&cfg, LOGLEVEL_DEBUG, url_plain, url_complete, out, sizeof(out), NULL),
                     0);
    for (size_t i = 0; out[i] != '\0'; i++) {
        unsigned char c = (unsigned char)out[i];
        assert_true(c == ' ' || c == '\n' || (c >= 0x21u && c <= 0x7Eu));
    }

    /* Argument / capacity validation. */
    assert_int_equal(qr_render_verification_code(NULL, LOGLEVEL_DEBUG, url_plain, NULL, out, sizeof(out), NULL), -1);
    assert_int_equal(qr_render_verification_code(&cfg, LOGLEVEL_DEBUG, "", NULL, out, sizeof(out), NULL), -1);
    assert_int_equal(qr_render_verification_code(&cfg, LOGLEVEL_DEBUG, url_plain, NULL, out, 16, NULL), -1);
    /* Undersized buffers must be rejected before the `out_len - 1` size arithmetic: with
     * out_len == 0 that subtraction underflowed to SIZE_MAX and made snprintf() effectively
     * unbounded. Must match QR_HEADER_LINE in src/qr.c. */
    const char *const header = "Scan this QR code with your phone's camera to open the verification page:";
    assert_int_equal(qr_render_verification_code(&cfg, LOGLEVEL_DEBUG, url_plain, NULL, out, 0, NULL), -1);
    out[0] = 'X';
    assert_int_equal(qr_render_verification_code(&cfg, LOGLEVEL_DEBUG, url_plain, NULL, out, 1, NULL), -1);
    assert_true(out[0] == 'X'); /* rejected before writing anything */
    assert_int_equal(qr_render_verification_code(&cfg, LOGLEVEL_DEBUG, url_plain, NULL, out, 2, NULL), -1);
    assert_int_equal(qr_render_verification_code(&cfg, LOGLEVEL_DEBUG, url_plain, NULL, out, strlen(header) + 1, NULL),
                     -1);
    /* The smallest buffer passing the guard (header + newline + NUL) still cannot hold any
     * rendered art and must fail cleanly at the header-capacity check, not overflow. */
    assert_int_equal(qr_render_verification_code(&cfg, LOGLEVEL_DEBUG, url_plain, NULL, out, strlen(header) + 2, NULL),
                     -1);
    /* One byte past the header still cannot hold the first art line: fails cleanly, no overflow. */
    assert_int_equal(qr_render_verification_code(&cfg, LOGLEVEL_DEBUG, url_plain, NULL, out, strlen(header) + 3, NULL),
                     -1);

    /* The compact vertical quiet zone (2) removes exactly one blank line above and one below the
     * art (and no separator blank line is appended any more), for two fewer lines overall. */
    cfg.qr_style = QR_STYLE_UTF8;
    cfg.qr_scale = 1;
    assert_int_equal(qr_render_verification_code(&cfg, LOGLEVEL_DEBUG, url_plain, url_complete, out, sizeof(out), NULL),
                     0);
    size_t newlines_default = 0;
    for (size_t i = 0; out[i] != '\0'; i++) {
        if (out[i] == '\n') {
            newlines_default++;
        }
    }
    cfg.qr_vertical_quiet_zone = 2;
    assert_int_equal(
        qr_render_verification_code(&cfg, LOGLEVEL_DEBUG, url_plain, url_complete, out2, sizeof(out2), NULL), 0);
    size_t newlines_compact = 0;
    for (size_t i = 0; out2[i] != '\0'; i++) {
        if (out2[i] == '\n') {
            newlines_compact++;
        }
    }
    assert_int_equal(newlines_compact + 2, newlines_default);
    /* No trailing separator blank line: the block ends with the art's own final newline. */
    assert_true(out2[strlen(out2) - 1] == '\n');
    assert_true(out2[strlen(out2) - 2] != '\n');
}
/**
 * @brief Unit test pinning the exact UTF-8 terminal rendering of a fixed verification URI.
 *
 * The golden output was generated by this module and cross-checked by an independent QR
 * decoder (ZXing, see build/verify/qr_verify.py); it guards the encoder + renderer against
 * regressions in glyph mapping, quiet zone, ordering, and header formatting.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_qr_render_golden_utf8(void **state) {
    (void)state;
    config_t cfg;
    char out[QR_RENDER_BUF_MAX];
    init_config_defaults(&cfg);
    assert_int_equal(qr_render_verification_code(&cfg, LOGLEVEL_DEBUG, "https://auth.example.edu/device",
                                                 "https://auth.example.edu/link?code=WXYZ-9012", out, sizeof(out),
                                                 NULL),
                     0);
    static const char *const golden = "Scan this QR code with your phone's camera to open the verification page:\n"
                                      "                                         \n"
                                      "                                         \n"
                                      "    █▀▀▀▀▀█  ▀█ ▀██▄▄█▀▀▀ ▄▀▄ █▀▀▀▀▀█    \n"
                                      "    █ ███ █ █  ▄ ▀▄ ▄▀▀██▄▄█▄ █ ███ █    \n"
                                      "    █ ▀▀▀ █ █▄▀▀▄█▄█▄ ▀ ▄█▄ █ █ ▀▀▀ █    \n"
                                      "    ▀▀▀▀▀▀▀ █ █ ▀ █▄▀ ▀ ▀▄█▄█ ▀▀▀▀▀▀▀    \n"
                                      "    ▀▄█▀██▀▄ ██▄ ▀▀▀▄▀▄▄ ▄█▄█ ██▀██ ▄    \n"
                                      "    ▀▀▄ ██▀ █ ▀▀  ▄▀▄ ▀ ██▄ █ █ █▄█▀     \n"
                                      "    ▄█▄▄▀ ▀▀ ▄ ▀▄ ▄▄▄ ▀ ▄▀▄█▄ ▄  █▄█▄    \n"
                                      "     ▀▄█ ▄▀██▄▀█▀▄█ ▄ ▄█▄█  ▄██▄▄▀█▀     \n"
                                      "     ▀██▀ ▀██▀▀▀▄ █ ▄█ █▄ ▀▄▀▀▄█▀█▄ █    \n"
                                      "    ▀ ▄ ▄ ▀▄▄ ▄█▀█ █▀█▄ ▄ ▀ ▀█▀██▄██▄    \n"
                                      "    ██ ▀▀▄▀▄  █▀█▄▄▄▀ ▄▀▀█▀▄▄▄▄  █ ▀█    \n"
                                      "    █ █▄ █▀▀ ▄█▄██▄█▀   ▀█▄ █▄ █▄██▀     \n"
                                      "    ▀ ▀▀  ▀▀▄▄▀ █▄▀▀▄▀█▄▄▄▀▄█▀▀▀█▀█▀█    \n"
                                      "    █▀▀▀▀▀█ ▄█  ▄▀ █▄ ▀  █▄██ ▀ █▄██▄    \n"
                                      "    █ ███ █ ██▀█▄█ ▄▄▄▀ ▄▀▄▄██▀▀██▄ ▄    \n"
                                      "    █ ▀▀▀ █ ▀▀▀██▄▄ ▄▀ █▄███▀▀█▀▄█▄      \n"
                                      "    ▀▀▀▀▀▀▀ ▀ ▀  ▀   ▀ ▀▀ ▀ ▀▀ ▀ ▀▀▀     \n"
                                      "                                         \n"
                                      "                                         \n";
    assert_string_equal(out, golden);
}

/**
 * @brief Rasterizes terminal QR art and decodes it with an independent scanner.
 *
 * Writes the given rendered art to a file, rasterizes it with
 * tests/qr_scan/art2png.py (the same rasterization a monospace terminal
 * display produces) as a binary P5 PGM, and decodes it with zbarimg (libzbar —
 * a QR decoder independent of both the Nayuki encoder and the local ZXing
 * fixture check). The raster is written as a binary P5 PGM rather than a PNG:
 * it is spec-trivial (no zlib/chunk/CRC machinery) and decodes under any
 * zbarimg image backend (ImageMagick's native PGM coder or libzbar's
 * built-in PPM/PGM reader). (PNG output stays available to the rasterizer for
 * human/phone-camera leg use.)
 *
 * @param[in]  art         Rendered art (quiet zone included, no header).
 * @param[in]  art_path    Art file path (created/overwritten).
 * @param[in]  pgm_path    Rasterized P5 PGM path (created/overwritten).
 * @param[in]  vquiet      Vertical quiet zone in module rows (forwarded to art2png.py).
 * @param[out] decoded     Buffer for the decoded payload.
 * @param[in]  decoded_cap Capacity of decoded (NUL included).
 * @return 0 on a successful decode, -1 on any failure.
 */
static int qr_scan_decode_art(const char *art, const char *art_path, const char *pgm_path, int vquiet, char *decoded,
                              size_t decoded_cap) {
    char cmd[512];
    FILE *f = fopen(art_path, "w");
    if (!f) {
        return -1;
    }
    fputs(art, f);
    fclose(f);
    snprintf(cmd, sizeof(cmd), "python3 tests/qr_scan/art2png.py %s %s 3 %d >/dev/null", art_path, pgm_path, vquiet);
    if (system(cmd) != 0) {
        return -1;
    }
    char zcmd[512];
    snprintf(zcmd, sizeof(zcmd), "zbarimg --quiet --raw %s", pgm_path);
    FILE *zp = popen(zcmd, "r");
    if (!zp) {
        return -1;
    }
    size_t n = fread(decoded, 1, decoded_cap - 1, zp);
    int status = pclose(zp);
    decoded[n] = '\0';
    while (n > 0 && (decoded[n - 1] == '\n' || decoded[n - 1] == '\r')) {
        decoded[--n] = '\0';
    }
    return (status != 0 || n == 0) ? -1 : 0;
}

/**
 * @brief End-to-end terminal QR round trip through an independent scanner.
 *
 * Renders the verification-URI art through the production code path
 * (qr_render_verification_code) in BOTH terminal styles at BOTH the ISO default
 * (4-module) and the compact (2-module) vertical quiet zone, rasterizes it exactly
 * as a monospace terminal displays it, and requires zbarimg to recover the
 * exact complete verification URI. This is the CI-enforced leg of the
 * "independent scanner" check; the phone-camera leg (manual scan of the
 * published art) is covered by the qr-scan-audit job, which writes the
 * rendered art into the workflow step summary.
 *
 * Skips cleanly when zbarimg or python3 is not installed (e.g. the rpm %check
 * container); CI installs zbar-tools so the test runs in the compile-matrix
 * and sanitizer jobs.
 *
 * @param[in,out] state CMocka test state context (unused).
 */
static void test_qr_scan_roundtrip(void **state) {
    (void)state;
    if (system("command -v zbarimg >/dev/null 2>&1") != 0 || system("command -v python3 >/dev/null 2>&1") != 0) {
        printf("SKIP test_qr_scan_roundtrip: zbarimg and python3 are not installed\n");
        return;
    }

    const char *const uri_plain = "https://auth.example.edu/device";
    const char *const uri_complete = "https://auth.example.edu/link?code=WXYZ-9012";
    config_t cfg;
    char full[QR_RENDER_BUF_MAX];
    char art[QR_RENDER_BUF_MAX];
    char art_path[64] = "/tmp/pam_oidc_qr_scan_XXXXXX";
    char pgm_path[100];
    char decoded[512];

    init_config_defaults(&cfg);
    cfg.qr_scale = 3;

    int fd = mkstemp(art_path);
    assert_int_not_equal(fd, -1);
    close(fd);
    snprintf(pgm_path, sizeof(pgm_path), "%s.pgm", art_path);

    for (int style = 0; style <= QR_STYLE_ASCII; style++) {
        cfg.qr_style = (style == 0) ? QR_STYLE_UTF8 : QR_STYLE_ASCII;
        /* Both the ISO default vertical quiet zone (4) and the compact setting (2) must survive
         * the independent decode; the art is everything after the one-line instruction header
         * (no trailing separator blank line is appended any more). */
        for (int vq = 2; vq <= QR_QUIET_ZONE; vq += 2) {
            cfg.qr_vertical_quiet_zone = vq;
            assert_int_equal(
                qr_render_verification_code(&cfg, LOGLEVEL_DEBUG, uri_plain, uri_complete, full, sizeof(full), NULL),
                0);
            const char *art_start = strchr(full, '\n') + 1;
            memcpy(art, art_start, strlen(art_start) + 1);
            assert_int_equal(qr_scan_decode_art(art, art_path, pgm_path, vq, decoded, sizeof(decoded)), 0);
            assert_string_equal(decoded, uri_complete);
        }
    }

    unlink(art_path);
    unlink(pgm_path);
}

/**
 * @brief Execution entry point for the CMocka test runner suite[cite: 7].
 *
 * Registers and executes unit tests for URL encoding, loglevel parsing, identity claim mapping,
 * input sanitization, prompt message rendering, JWT metadata verification, configuration
 * stream parsing (parse_config_file), and terminal QR code encoding/rendering (qr.c),
 * including an independent-scanner decode round trip (test_qr_scan_roundtrip).
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
        cmocka_unit_test(test_jwt_unconfigured_binding_fail_closed),
        cmocka_unit_test(test_jwt_audience_array),
        cmocka_unit_test(test_jwt_numeric_date_and_exp_policy),
        cmocka_unit_test(test_jwt_non_finite_claims_rejected),
        cmocka_unit_test(test_jwt_malformed_structure),
        cmocka_unit_test(test_jwt_base64url_strict_alphabet),
        cmocka_unit_test(test_jwt_base64url_excess_padding_rejected),
        cmocka_unit_test(test_jwt_extract_claim_string),
        cmocka_unit_test(test_retryable_token_http_status),
        cmocka_unit_test(test_http_request_enforces_tls_options),
        cmocka_unit_test(test_http_request_proxy_routing),
        cmocka_unit_test(test_http_request_response_size_cap),
        cmocka_unit_test(test_http_request_scrubs_bearer_header_nodes),
        cmocka_unit_test(test_http_request_bearer_header_truncation),
        cmocka_unit_test(test_pam_oauth_log_line_dropped_marker),
        cmocka_unit_test(test_pam_oauth_log_escapes_untrusted_bytes),
        cmocka_unit_test(test_pkce_code_verifier),
        cmocka_unit_test(test_pkce_s256_challenge),
        cmocka_unit_test(test_verify_user_access),
        cmocka_unit_test(test_verify_user_access_large_entry),
        cmocka_unit_test(test_verify_group_membership_lists),
        cmocka_unit_test(test_verify_group_membership_deny_only_fail_closed),
        cmocka_unit_test(test_parse_config_file_minimal_valid),
        cmocka_unit_test(test_parse_config_file_claim_regex_required),
        cmocka_unit_test(test_parse_config_file_full_sections),
        cmocka_unit_test(test_parse_config_file_missing_required),
        cmocka_unit_test(test_parse_config_file_duplicate_key),
        cmocka_unit_test(test_parse_config_file_key_before_section),
        cmocka_unit_test(test_parse_config_file_unknown_section),
        cmocka_unit_test(test_parse_config_file_overlong_line),
        cmocka_unit_test(test_parse_config_file_long_access_list),
        cmocka_unit_test(test_parse_config_file_invalid_url),
        cmocka_unit_test(test_parse_config_file_invalid_int),
        cmocka_unit_test(test_parse_config_file_invalid_loglevel),
        cmocka_unit_test(test_parse_config_file_invalid_bool),
        cmocka_unit_test(test_parse_config_file_unknown_key_in_section),
        cmocka_unit_test(test_parse_config_file_whitespace_and_comments),
        cmocka_unit_test(test_parse_config_file_bad_regex),
        cmocka_unit_test(test_parse_config_file_null_args),
        cmocka_unit_test(test_parse_config_file_pkce_auto),
        cmocka_unit_test(test_parse_config_file_pkce_auto_requires_discovery),
        cmocka_unit_test(test_parse_config_file_jwt_claims_requires_binding),
        cmocka_unit_test(test_parse_config_file_system_uid_range_invalid),
        cmocka_unit_test(test_parse_config_file_invalid_discovery_endpoint),
        cmocka_unit_test(test_parse_config_file_duplicate_discovery_endpoint),
        cmocka_unit_test(test_parse_config_file_proxy),
        cmocka_unit_test(test_discovery_json_advertises_s256),
        cmocka_unit_test(test_discovery_probe_pkce_failsafe_non_200),
        cmocka_unit_test(test_discovery_probe_pkce_failsafe_transport_error),
        cmocka_unit_test(test_discovery_probe_pkce_failsafe_malformed_document),
        cmocka_unit_test(test_discovery_probe_pkce_support_matrix),
        cmocka_unit_test(test_discovery_probe_pkce_null_args),
        cmocka_unit_test(test_is_retryable_token_http_status_matrix),
        cmocka_unit_test(test_poll_interval_backoff_math),
        cmocka_unit_test(test_poll_loop_schedule_rules),
        cmocka_unit_test(test_poll_request_budget_rules),
        cmocka_unit_test(test_poll_request_budget_whole_second_zero),
        cmocka_unit_test(test_form_field_append_overflow_guard),
        cmocka_unit_test(test_request_device_authorization_parses_provider_response),
        cmocka_unit_test(test_poll_loop_immediate_token_success),
        cmocka_unit_test(test_poll_loop_pending_then_deadline_expiry),
        cmocka_unit_test(test_poll_loop_maps_provider_error_phases),
        cmocka_unit_test(test_poll_loop_malformed_pending_definitive_abort),
        cmocka_unit_test(test_qr_config_parsing),
        cmocka_unit_test(test_qr_render_matrix),
        cmocka_unit_test(test_qr_encode_uri),
        cmocka_unit_test(test_qr_render_verification_code),
        cmocka_unit_test(test_qr_render_golden_utf8),
        cmocka_unit_test(test_qr_scan_roundtrip),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
