/**
 * @file http.c
 * @brief cURL HTTP network client wrappers, level-filtered syslog reporting, and thread-safe global initialization
 * logic.
 *
 * Provides HTTP client execution for OAuth device authorization, token polling,
 * and OpenID UserInfo queries. Enforces TLS/HTTPS transport security, dynamic response memory management,
 * integer overflow protection, HTTP transport tracing, and thread-safe cURL global state initialization.
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
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Central level-filtered logging wrapper for PAM syslog messages.
 *
 * Emits log output via `pam_vsyslog` only if `cfg_level` is not `LOGLEVEL_NONE` and `cfg_level` is
 * greater than or equal to the required `msg_level`.
 *
 * @param[in] pamh      PAM framework handle context.
 * @param[in] cfg_level Configured runtime log level threshold.
 * @param[in] msg_level Minimum verbosity level required to emit this message.
 * @param[in] priority  syslog priority level (e.g. LOG_ERR, LOG_INFO, LOG_DEBUG).
 * @param[in] fmt       Printf-style format string.
 */
void pam_oauth_log(pam_handle_t *pamh, loglevel_t cfg_level, loglevel_t msg_level, int priority, const char *fmt, ...) {
    if (!pamh || cfg_level == LOGLEVEL_NONE || cfg_level < msg_level) {
        return;
    }
    va_list args;
    va_start(args, fmt);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
    pam_vsyslog(pamh, priority, fmt, args);
#pragma GCC diagnostic pop
    va_end(args);
}

/** @brief POSIX thread once control primitive for atomic cURL initialization. */
static pthread_once_t g_curl_init_once = PTHREAD_ONCE_INIT;

/** @brief Global result status code for libcurl global initialization. */
static int g_curl_init_rc = -1;

/**
 * @brief Thread-safe cURL global initialization worker routine.
 *
 * Invoked once across process threads via `pthread_once`.
 */
static void init_curl_global_impl(void) { g_curl_init_rc = (curl_global_init(CURL_GLOBAL_ALL) == CURLE_OK) ? 0 : -1; }

/**
 * @brief Public interface ensuring thread-safe cURL global initialization.
 *
 * @return 0 on success, -1 on failure.
 */
int oauth_http_global_init(void) {
    (void)pthread_once(&g_curl_init_once, init_curl_global_impl);
    return g_curl_init_rc;
}

/**
 * @brief Libcurl write callback function for receiving incoming response payloads.
 *
 * Dynamically expands memory destination buffer while verifying integer overflow
 * limits and enforcing the maximum response size limit (`MAX_HTTP_RESPONSE_SIZE`).
 *
 * @param[in] contents Pointer to chunk of incoming response data.
 * @param[in] size     Size of individual element in bytes.
 * @param[in] nmemb    Number of elements in chunk.
 * @param[in] userp    Pointer to output http_response_t structure.
 * @return Total bytes processed, or 0 on memory allocation or overflow error.
 */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    if (size != 0 && nmemb > SIZE_MAX / size) {
        return 0;
    }
    size_t realsize = size * nmemb;
    http_response_t *mem = (http_response_t *)userp;

    if (realsize > MAX_HTTP_RESPONSE_SIZE - mem->size) {
        return 0;
    }

    char *ptr = realloc(mem->body, mem->size + realsize + 1);
    if (!ptr) {
        return 0;
    }

    mem->body = ptr;
    memcpy(&(mem->body[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->body[mem->size] = 0;

    return realsize;
}

/**
 * @brief URL encodes parameter values per RFC 3986 using cURL.
 *
 * @param[in] curl Active cURL handle.
 * @param[in] str  Input parameter string.
 * @return Heap-allocated encoded string (must be freed using curl_free), or NULL on failure.
 */
char *url_encode_param(CURL *curl, const char *str) {
    if (!curl || !str) {
        return NULL;
    }
    return curl_easy_escape(curl, str, (int)strlen(str));
}

/**
 * @brief Clears and frees memory in an HTTP response container.
 *
 * Zeroes body buffer content prior to freeing heap memory.
 *
 * @param[in,out] resp HTTP response structure to cleanse.
 */
void free_http_response(http_response_t *resp) {
    if (resp) {
        if (resp->body) {
            /* Scrub the payload plus its NUL terminator (write_callback always terminates the
             * buffer), matching the module's strlen + 1 scrubbing convention. */
            secure_memzero(resp->body, resp->size + 1);
            free(resp->body);
            resp->body = NULL;
        }
        resp->size = 0;
        resp->status_code = 0;
        resp->curl_code = CURLE_OK;
    }
}

/**
 * @brief Classifies an OAuth token-endpoint HTTP status code as transient/retryable.
 *
 * Returns 1 for HTTP 429 (rate limited) and any 5xx status, which are transient server/gateway
 * conditions and are NOT RFC 8628 OAuth error responses; these should be retried with backoff
 * within the device-authorization deadline. Returns 0 for all other statuses (success,
 * definitive 4xx OAuth errors, redirects, or no response), which the caller handles separately.
 *
 * @param[in] status_code HTTP status code returned by the token endpoint.
 * @return 1 if the status is transient/retryable, 0 otherwise.
 */
int is_retryable_token_http_status(long status_code) {
    return (status_code == 429 || (status_code >= 500 && status_code <= 599)) ? 1 : 0;
}

/**
 * @brief Classifies a parsed OIDC/OAuth discovery document as advertising S256 PKCE.
 *
 * Returns 1 when `doc` is a JSON object whose `code_challenge_methods_supported` member
 * is an array of strings containing the exact value "S256" (case-sensitive, per RFC 7636).
 * Malformed, missing, or non-conforming members conservatively classify as "not
 * advertised". NOTE: this field is defined for the authorization-code flow; it is used
 * here only as a heuristic hint for device-flow PKCE gating (see the header prototype).
 */
int discovery_json_advertises_s256(const struct json_object *doc) {
    if (!doc || json_object_get_type(doc) != json_type_object) {
        return 0;
    }
    struct json_object *arr = NULL;
    if (!json_object_object_get_ex(doc, "code_challenge_methods_supported", &arr)) {
        return 0;
    }
    if (json_object_get_type(arr) != json_type_array) {
        return 0;
    }
    size_t len = json_object_array_length(arr);
    for (size_t i = 0; i < len; i++) {
        /* JSON_ARRAY_IDX (public header) selects the index type the linked json-c expects. */
        struct json_object *el = json_object_array_get_idx(arr, JSON_ARRAY_IDX(i));
        if (!el || json_object_get_type(el) != json_type_string) {
            continue;
        }
        if (strcmp(json_object_get_string(el), "S256") == 0) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Probes a provider's discovery document once to decide device-flow PKCE gating.
 *
 * Decision matrix (logged on completion so operators can audit the suggestion):
 * - S256 advertised AND `device_authorization_endpoint` present -> PKCE enabled.
 * - S256 advertised but no device-authorization endpoint        -> PKCE disabled (warning).
 * - S256 not advertised                                         -> PKCE disabled, with a
 *   hint that device-flow PKCE is not advertised by standard discovery metadata and
 *   `use_pkce = true` should be set manually once provider support is confirmed.
 * Any transport, HTTP (non-200), or JSON parse failure returns -1 with *supported == 0;
 * callers MUST treat that as "no PKCE" (fail-safe) so a discovery outage never blocks
 * logins. The response body is scrubbed and freed via `free_http_response()`.
 */
int discovery_probe_pkce(const char *url, int *supported, loglevel_t loglevel, pam_handle_t *pamh) {
    if (!url || !supported) {
        return -1;
    }
    *supported = 0;

    http_response_t resp = {0};
    if (http_request("GET", url, NULL, NULL, 5000L, &resp, loglevel, pamh) != 0 || resp.status_code != 200 ||
        !resp.body) {
        pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_WARNING,
                      "PKCE auto-detection: discovery probe of %s failed (HTTP status %ld); continuing without "
                      "PKCE for this attempt",
                      url, resp.status_code);
        free_http_response(&resp);
        return -1;
    }

    struct json_object *doc = json_tokener_parse(resp.body);
    free_http_response(&resp);
    if (!doc || json_object_get_type(doc) != json_type_object) {
        if (doc) {
            json_object_put(doc);
        }
        pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_WARNING,
                      "PKCE auto-detection: discovery document at %s is not a JSON object; continuing without "
                      "PKCE for this attempt",
                      url);
        return -1;
    }

    int s256 = discovery_json_advertises_s256(doc);
    struct json_object *dev_ep = NULL;
    int has_device_endpoint = json_object_object_get_ex(doc, "device_authorization_endpoint", &dev_ep) &&
                              json_object_get_type(dev_ep) == json_type_string;

    if (s256 && has_device_endpoint) {
        *supported = 1;
        pam_oauth_log(pamh, loglevel, LOGLEVEL_INFO, LOG_INFO,
                      "PKCE auto-detection: provider metadata advertises S256 PKCE and a device-authorization "
                      "endpoint; enabling PKCE (RFC 7636) for this attempt. Device-flow PKCE is not advertised "
                      "by a dedicated standard discovery field - re-verify with your provider's documentation");
    } else if (s256) {
        pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_WARNING,
                      "PKCE auto-detection: provider metadata advertises S256 PKCE but no "
                      "device_authorization_endpoint; continuing without PKCE for this attempt");
    } else {
        pam_oauth_log(pamh, loglevel, LOGLEVEL_INFO, LOG_INFO,
                      "PKCE auto-detection: provider metadata does not advertise S256 PKCE support; continuing "
                      "without PKCE for this attempt. If your provider supports device-flow PKCE (see "
                      "examples/README.md), set use_pkce = true to enable it");
    }

    json_object_put(doc);
    return 0;
}

/**
 * @brief Executes an HTTP GET or POST request using libcurl.
 *
 * Configures headers (`Content-Type`, `Accept`, `Authorization: Bearer`), enforces
 * strict TLS/HTTPS transport security (certificate validation via
 * `CURLOPT_SSL_VERIFYPEER`/`CURLOPT_SSL_VERIFYHOST` and a TLS >= 1.2 minimum via
 * `CURLOPT_SSLVERSION`), disables signal handling for multi-threaded safety,
 * logs HTTP transport tracing at LOGLEVEL_VERBOSE, sets request timeouts, and captures response codes.
 *
 * @param[in]  method       HTTP method ("GET" or "POST").
 * @param[in]  url          Target URL endpoint.
 * @param[in]  postfields   URL-encoded request body (for POST requests).
 * @param[in]  bearer_token Access token for Authorization header (optional).
 * @param[in]  timeout_ms   Request timeout limit in milliseconds.
 * @param[out] resp         Pointer to response object receiving result; zero-initialized by this
 *                          function before any return (success or error), so callers may always
 *                          read `status_code`/`size` and pass it to free_http_response().
 * @param[in]  loglevel     Active syslog verbosity level.
 * @param[in]  pamh         PAM handle context for syslog reporting.
 * @return 0 on transport execution success, -1 on error.
 */
int http_request(const char *method, const char *url, const char *postfields, const char *bearer_token, long timeout_ms,
                 http_response_t *resp, loglevel_t loglevel, pam_handle_t *pamh) {
    if (!url || !resp || !method) {
        return -1;
    }

    /*
     * Zero the response before any failure path (global init failure, handle
     * allocation failure, setopt failure, ...) so that on EVERY return --
     * success or error -- the caller can safely read `status_code`/`size` and
     * pass the struct to free_http_response() without touching uninitialized
     * memory or freeing a garbage `body` pointer.
     */
    memset(resp, 0, sizeof(http_response_t));

    if (oauth_http_global_init() != 0) {
        if (pamh) {
            pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR, "Global libcurl initialization failed");
        }
        return -1;
    }

    /* HTTP transport tracing during troubleshooting (LOGLEVEL_VERBOSE) */
    pam_oauth_log(pamh, loglevel, LOGLEVEL_VERBOSE, LOG_DEBUG, "HTTP request: method=%s, url=%s, timeout=%ldms", method,
                  url, timeout_ms);
    if (postfields) {
        pam_oauth_log(pamh, loglevel, LOGLEVEL_VERBOSE, LOG_DEBUG, "HTTP POST payload size: %zu bytes",
                      strlen(postfields));
    }
    if (bearer_token) {
        pam_oauth_log(pamh, loglevel, LOGLEVEL_VERBOSE, LOG_DEBUG,
                      "HTTP Request includes Bearer authorization token header");
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        if (pamh) {
            pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR, "Failed to initialize easy cURL handle");
        }
        return -1;
    }

    struct curl_slist *headers = NULL;

    /* Set default request content negotiation headers */
    if (strcmp(method, "POST") == 0) {
        struct curl_slist *tmp = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
        if (!tmp) {
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return -1;
        }
        headers = tmp;
    } else {
        struct curl_slist *tmp = curl_slist_append(headers, "Accept: application/json");
        if (!tmp) {
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return -1;
        }
        headers = tmp;
    }

    /* Add Bearer Authorization header if access token was provided */
    if (bearer_token) {
        /* Sized to hold "Authorization: Bearer <token>" for a token up to MAX_ACCESS_TOKEN_LEN,
         * plus the terminating NUL. The overflow check below is a defensive backstop. */
        char auth_hdr[MAX_ACCESS_TOKEN_LEN + sizeof("Authorization: Bearer ")];
        int written = snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s", bearer_token);
        if (written < 0 || (size_t)written >= sizeof(auth_hdr)) {
            if (pamh) {
                pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR, "Bearer token header exceeds buffer capacity");
            }
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return -1;
        }
        struct curl_slist *tmp = curl_slist_append(headers, auth_hdr);
        secure_memzero(auth_hdr, sizeof(auth_hdr));
        if (!tmp) {
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return -1;
        }
        headers = tmp;
    }

    CURLcode err;
#define CHECK_SETOPT(opt, val)                                                                                         \
    do {                                                                                                               \
        err = curl_easy_setopt(curl, opt, val);                                                                        \
        if (err != CURLE_OK) {                                                                                         \
            if (pamh) {                                                                                                \
                pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR, "curl_easy_setopt error: %s",                   \
                              curl_easy_strerror(err));                                                                \
            }                                                                                                          \
            curl_slist_free_all(headers);                                                                              \
            curl_easy_cleanup(curl);                                                                                   \
            return -1;                                                                                                 \
        }                                                                                                              \
    } while (0)

    CHECK_SETOPT(CURLOPT_URL, url);
    CHECK_SETOPT(CURLOPT_HTTPHEADER, headers);

    if (strcmp(method, "POST") == 0) {
        CHECK_SETOPT(CURLOPT_POSTFIELDS, postfields ? postfields : "");
    } else {
        CHECK_SETOPT(CURLOPT_HTTPGET, 1L);
    }

    CHECK_SETOPT(CURLOPT_WRITEFUNCTION, write_callback);
    CHECK_SETOPT(CURLOPT_WRITEDATA, (void *)resp);
    CHECK_SETOPT(CURLOPT_TIMEOUT_MS, timeout_ms);
    CHECK_SETOPT(CURLOPT_USERAGENT, MODULE_USER_AGENT);
    CHECK_SETOPT(CURLOPT_NOSIGNAL, 1L);
    CHECK_SETOPT(CURLOPT_FOLLOWLOCATION, 0L);

#if LIBCURL_VERSION_NUM >= 0x075500
    CHECK_SETOPT(CURLOPT_PROTOCOLS_STR, "https");
    CHECK_SETOPT(CURLOPT_REDIR_PROTOCOLS_STR, "https");
#else
    CHECK_SETOPT(CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
    CHECK_SETOPT(CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
#endif

    /* Enforce strict TLS certificate validation and a TLS >= 1.2 minimum protocol
     * version (defense in depth on top of the HTTPS-only restriction above). */
    CHECK_SETOPT(CURLOPT_SSL_VERIFYPEER, 1L);
    CHECK_SETOPT(CURLOPT_SSL_VERIFYHOST, 2L);
#if LIBCURL_VERSION_NUM >= 0x072000
    CHECK_SETOPT(CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
#endif

#undef CHECK_SETOPT

    resp->curl_code = curl_easy_perform(curl);
    if (resp->curl_code == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp->status_code);
        pam_oauth_log(pamh, loglevel, LOGLEVEL_VERBOSE, LOG_DEBUG,
                      "HTTP %s %s completed: HTTP status %ld, body size=%zu bytes", method, url, resp->status_code,
                      resp->size);
    } else {
        if (pamh) {
            pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR, "cURL request failed for %s: %s", url,
                          curl_easy_strerror(resp->curl_code));
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return (resp->curl_code == CURLE_OK) ? 0 : -1;
}
