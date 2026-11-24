/**
 * @file pam_oidc_device.h
 * @brief Header definitions, data structures, and function prototypes for the PAM OAuth 2.0 Device Authorization
 * module.
 *
 * This header defines configuration constants, security structures, HTTP response containers,
 * log levels, and external function prototypes used across the pam_oidc_device authentication module.
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

#ifndef PAM_OIDC_DEVICE_H
#define PAM_OIDC_DEVICE_H

#include "metadata.h"

#include <curl/curl.h>
#include <json-c/json.h>
#include <json-c/json_c_version.h>
#include <pthread.h>
#include <regex.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>

/* ============================================================================
 * json-c Array-Index Compatibility
 * ============================================================================ */

/*
 * json_object_array_get_idx() takes a `size_t` index on every json-c release in the
 * supported matrix (EL8's json-c 0.13.1 through 0.18 on EL10/Ubuntu/Debian/SUSE). All
 * callers iterate with a `size_t` index bounded by json_object_array_length(); the
 * explicit size_t cast matches the parameter type and keeps -Wconversion /
 * -Wsign-conversion quiet on every platform. (An earlier shim that narrowed the index
 * to `int` on pre-0.17 releases was wrong: json-c already used `size_t` there.)
 */
#define JSON_ARRAY_IDX(i) ((size_t)(i))

/* ============================================================================
 * Configuration & Runtime Constants
 * ============================================================================ */

/** @brief Default system configuration file path. */
#define CONFIG_PATH_DEFAULT "/etc/pam_oidc_device.conf"

/** @brief Minimum permitted polling interval in seconds per RFC 8628. */
#define MIN_POLL_INTERVAL 5

/** @brief Maximum standard polling interval in seconds. */
#define MAX_POLL_INTERVAL 60

/** @brief Maximum supported polling interval upper bound in seconds; provider-advertised
 *         intervals above this are clamped down to it (never a fatal error). */
#define MAX_SUPPORTED_POLL_INTERVAL 120

/** @brief Maximum buffer capacity for custom initial user prompt templates. */
#define MAX_INIT_MSG_LEN 1024

/**
 * @brief Byte capacity of the [access] user/group allow/deny list fields
 * (`allow_users`, `deny_users`, `allow_groups`, `deny_groups`).
 *
 * 2048 bytes comfortably holds a full production deny list of local service
 * accounts (e.g. every account from /etc/passwd, ~500-1000 bytes). Must stay in
 * lockstep with the scratch buffer in identity.c's list_contains() — the two
 * bounds are the same logical cap, so raising one without the other would let
 * a longer list parse but then fail to match at runtime.
 */
#define ACCESS_LIST_LEN 2048

/** @brief Maximum allowable HTTP response payload size (256 KiB). */
#define MAX_HTTP_RESPONSE_SIZE ((size_t)256 * 1024)

/** @brief Maximum supported access token length in bytes. */
#define MAX_ACCESS_TOKEN_LEN 8192

/** @brief Number of CSPRNG bytes used to derive an RFC 7636 PKCE code verifier. */
#define PKCE_VERIFIER_BYTES 48

/** @brief Length of the Base64URL (no padding) encoding of a PKCE code verifier (48 input bytes). */
#define PKCE_VERIFIER_LEN 64

/** @brief Length of the Base64URL (no padding) encoding of an S256 PKCE code challenge (32 digest bytes). */
#define PKCE_S256_CHALLENGE_LEN 43

/** @brief Light (quiet-zone) modules drawn left and right of the terminal QR code, and the default vertical
 *  quiet zone. ISO/IEC 18004 requires 4 on every side; the [qr] vertical_quiet_zone option may lower the
 *  vertical zone (never the horizontal one) for a more compact terminal display.
 */
#define QR_QUIET_ZONE 4

/** @brief Maximum QR Code symbol version this module will render (symbol width 21-97 modules). */
#define QR_MAX_VERSION 20

/** @brief Byte capacity of the packed module grid of any QR symbol up to QR_MAX_VERSION. */
#define QR_MATRIX_BYTES_MAX ((((((QR_MAX_VERSION) * 4 + 17) * ((QR_MAX_VERSION) * 4 + 17) + 7) / 8) + 1))

/** @brief Worst-case byte capacity of a fully rendered terminal QR block (version 20, scale 3, UTF-8 glyphs). */
#define QR_RENDER_BUF_MAX 32768

/* ============================================================================
 * Data Structures & Enumerations
 * ============================================================================ */

/**
 * @enum loglevel_t
 * @brief Identifies configurable syslog verbosity levels.
 */
typedef enum {
    LOGLEVEL_UNSET = -1, /**< Unset or uninitialized state threshold indicator. */
    LOGLEVEL_NONE = 0,   /**< Completely disables syslog logging output. */
    LOGLEVEL_ERROR = 1,  /**< Logs operational failures and error conditions. */
    LOGLEVEL_INFO = 2,   /**< Logs high-level auth success/failure lifecycle events. */
    LOGLEVEL_DEBUG = 3,  /**< Logs detailed internal state and execution flow events. */
    LOGLEVEL_VERBOSE = 4 /**< Enables maximum tracing including HTTP transport details. */
} loglevel_t;

/**
 * @enum config_section_t
 * @brief Identifies configuration file sections during line parsing.
 */
typedef enum {
    SEC_NONE = 0, /**< Initial unassigned section state. */
    SEC_OAUTH,    /**< [oauth] section: Identity provider credentials and endpoints. */
    SEC_CLAIM,    /**< [claim] section: Identity claim field extraction and matching rules. */
    SEC_ACCESS,   /**< [access] section: Local account and provider group allow/deny controls. */
    SEC_PROMPT,   /**< [prompt] section: User interaction message formatting. */
    SEC_RUNTIME,  /**< [runtime] section: Module operational limits and debugging settings. */
    SEC_QR        /**< [qr] section: Terminal QR code rendering options. */
} config_section_t;

/**
 * @enum qr_style_t
 * @brief Terminal rendering style for the verification-URI QR code.
 */
typedef enum {
    QR_STYLE_UTF8 = 0, /**< Compact UTF-8 half-block glyphs (U+2580, U+2584, U+2588); one character per
                          two stacked modules. Densest output, but requires a font that covers these glyphs. */
    QR_STYLE_ASCII = 1 /**< One configurable printable-ASCII character per module (default '#'); maximum
                          font/terminal compatibility, including legacy or minimal-font terminals. */
} qr_style_t;

/**
 * @enum qr_ec_t
 * @brief QR Code error-correction level (ISO/IEC 18004). Higher levels tolerate more damaged or
 * obfuscated modules (e.g., terminal rendering artifacts) at the cost of a larger symbol.
 */
typedef enum {
    QR_EC_LOW = 0,      /**< ~7% codeword recovery; smallest symbol. */
    QR_EC_MEDIUM = 1,   /**< ~15% codeword recovery; default. */
    QR_EC_QUARTILE = 2, /**< ~25% codeword recovery. */
    QR_EC_HIGH = 3      /**< ~30% codeword recovery; most robust, largest symbol. */
} qr_ec_t;

/**
 * @struct config_t
 * @brief Holds runtime configuration parameters loaded from the module configuration file.
 */
typedef struct {
    char client_id[256];                     /**< OAuth 2.0 Client Identifier. */
    char client_secret[256];                 /**< OAuth 2.0 Client Secret (optional for public clients);
                                              *  transmitted as a form parameter in the request body
                                              *  (`client_secret_post`, RFC 6749 s2.3.1). The
                                              *  `client_secret_basic` (HTTP Basic Authorization)
                                              *  client-authentication method is not supported. */
    char device_authorization_endpoint[512]; /**< Authorization server Device Authorization Endpoint URL. */
    char token_endpoint[512];                /**< Authorization server Token Endpoint URL. */
    char userinfo_endpoint[512];             /**< OpenID Connect UserInfo Endpoint URL. */
    char scopes[256];                        /**< Requested OAuth/OIDC authorization scopes. */
    char claim_field[64];                    /**< JSON field name in UserInfo response containing user identity. */
    char claim_regex[256];                   /**< Regular expression pattern to extract local username. Required: the
                                              *  operator must set it explicitly (there is no default); config loading
                                              *  fails closed when it is missing or empty. */
    int claim_capture_group;                 /**< Regex capture group index to select username slice. */
    int max_poll_seconds;                    /**< Maximum total polling time allowed before timing out. */
    char init_message[MAX_INIT_MSG_LEN];     /**< Custom template string for user terminal prompt. */
    int show_expiry;                         /**< Flag: 1 (default) adds the device-code approval window to the
                                              *  trailing status line of the built-in default template
                                              *  ("Waiting for approval (expires in 15m)."); 0 hides it
                                              *  ("Waiting for approval."). The window is the provider's
                                              *  `expires_in` clamped by `max_poll_seconds`. Independent of this
                                              *  flag, the `{expiry}` token in any template expands to the
                                              *  compact duration ("45s", "15m", "1h 5m") or to an empty string
                                              *  when the window is unknown. */
    int case_sensitive;                      /**< Flag: 1 for case-sensitive username comparison, 0 otherwise. */
    loglevel_t loglevel; /**< Configured syslog verbosity level (none, error, info, debug, verbose). */
    char issuer[512];    /**< Expected token issuer claim (iss). */
    char audience[256];  /**< Expected token audience claim (aud). */
    char jwks_url[512];  /**< Reserved: JWKS endpoint URL; parsed and validated, but not yet used for JWT signature
                            verification. */
    char introspection_endpoint[512]; /**< Reserved: RFC 7662 Token Introspection endpoint URL; parsed and validated,
                                         but not yet used. */
    char proxy[512];                  /**< Optional outbound HTTPS proxy URL (must begin with `https://`); empty (the
                                       *  default) routes provider traffic directly. The proxy URL must not embed
                                       *  credentials; proxies requiring authentication are not supported. */
    int verify_jwt_claims; /**< Flag: 1 to enforce local JWT claim inspection (exp, nbf, iss, aud). Claims-only; NOT a
                              signature check. */
    int clock_skew_leeway; /**< Allowed clock skew leeway in seconds for exp/nbf validation. */
    int require_exp_claim; /**< Flag: 1 to require a well-formed 'exp' claim when verify_jwt_claims is enabled. */
    char allow_users[ACCESS_LIST_LEN]; /**< Comma-separated local usernames permitted to authenticate (empty = all
                                          allowed). */
    char deny_users[ACCESS_LIST_LEN];  /**< Comma-separated local usernames denied authentication (takes precedence over
                                          allow). */
    int allow_root;                    /**< Flag: 1 to permit uid-0 accounts (`root` and any alternative uid-0 name) to
                                        *   authenticate; 0 (default) denies every uid-0 account. */
    int deny_system_uids;              /**< Flag: 1 (default) to deny local accounts whose numeric UID falls within
                                        *   [system_uid_min, system_uid_max] before any provider contact; 0 disables
                                        *   the guard. Targets the UID, not the name. A uid-0 account explicitly
                                        *   permitted via `allow_root` is exempt. */
    int system_uid_min;                /**< Inclusive lower bound of the numeric-UID range denied by
                                        *   `deny_system_uids` (default 0, the conventional system-account floor). */
    int system_uid_max;                /**< Inclusive upper bound of the numeric-UID range denied by
                                        *   `deny_system_uids` (default 999, the conventional system-account ceiling).
                                        *   Must be >= `system_uid_min`; an inverted range is rejected at load. */
    char allow_groups[ACCESS_LIST_LEN]; /**< Comma-separated provider groups/roles granting access (any single match
                                           suffices). */
    char deny_groups[ACCESS_LIST_LEN];  /**< Comma-separated provider groups/roles denying access (takes precedence over
                                           allow). */
    int enforce_groups;         /**< Flag: 1 to require group/role authorization when no group lists are configured. */
    char group_claim_field[64]; /**< JSON field name in UserInfo containing group/role claims (e.g., "groups", "roles").
                                 */
    char group_claim_delimiter[2]; /**< Single printable ASCII character used to split a string-typed group claim
                                    *  value into individual group/role entries (default `','`). JSON-array claims are
                                    *  unaffected (each element is one group). Example: an IdP that emits a single
                                    *  semicolon-joined string (`"grp-a;grp-b"`) is configured with `';'`. */
    int use_pkce;                  /**< Three-state PKCE gate: 0 (default) off; 1 always extend the RFC 8628 device
                                    *  flow with RFC 7636 PKCE (fresh CSPRNG `code_verifier` per attempt, its `S256`
                                    *  `code_challenge` sent to the device authorization endpoint, the verifier
                                    *  presented at the token endpoint); 2 ("auto") probe `discovery_endpoint` once
                                    *  per attempt and enable PKCE only when the provider metadata advertises S256
                                    *  PKCE support plus a device-authorization endpoint; probe failures fail safe
                                    *  to 0. */
    char discovery_endpoint[512];  /**< OIDC/OAuth discovery metadata URL (e.g.,
                                    *  `https://idp/.well-known/openid-configuration`); used only when
                                    *  `use_pkce` is 2 ("auto"). Empty otherwise. */
    int qr_enabled;                /**< Flag: 1 to render the verification URI as a scannable terminal QR code
                                    *  before the text prompt (default 0). Rendering failure is non-fatal. */
    qr_style_t qr_style;           /**< Terminal glyph style: QR_STYLE_UTF8 (compact half-blocks, default) or
                                    *  QR_STYLE_ASCII (one block character per module; maximum font support). */
    char qr_block_char[2];         /**< Single printable ASCII character used for dark modules in the
                                    *  QR_STYLE_ASCII style (default "#"). */
    int qr_scale;                  /**< Integer enlargement factor for rendered QR modules, 1-3 (default 1). */
    int qr_vertical_quiet_zone;    /**< Light (quiet-zone) module rows rendered above and below the QR symbol,
                                    *  0-QR_QUIET_ZONE (default QR_QUIET_ZONE = the ISO/IEC 18004 minimum).
                                    *  Lower values shrink the terminal block at the cost of scanner
                                    *  robustness; the horizontal quiet zone always stays QR_QUIET_ZONE. */
    qr_ec_t qr_ec_level;           /**< QR error-correction level (default QR_EC_MEDIUM). */
    int qr_uri_complete;           /**< Flag: 1 (default) to encode `verification_uri_complete` when the provider
                                    *  supplies it (the code is embedded, so no typing is needed on the second
                                    *  device); 0 to prefer the plain `verification_uri` with manual code entry. */
} config_t;

/**
 * @struct http_response_t
 * @brief Container for HTTP response data received via cURL transfers.
 */
typedef struct {
    char *body;         /**< Heap-allocated dynamically expanding response body buffer. */
    size_t size;        /**< Total bytes currently stored in body buffer. */
    long status_code;   /**< HTTP status code returned by server (e.g., 200, 400). */
    CURLcode curl_code; /**< Return code from libcurl easy transfer operations. */
} http_response_t;

/* ============================================================================
 * Function Prototypes
 * ============================================================================ */

/**
 * @brief Level-filtered wrapper around the PAM syslog API.
 *
 * Emits log output via PAM syslog only if `cfg_level` is not `LOGLEVEL_NONE` and `cfg_level` is
 * greater than or equal to the required `msg_level`. The formatted line is escaped before it
 * reaches syslog: bytes outside printable ASCII are replaced with C-style escapes ("\n", "\r",
 * "\t" or "\xHH") so untrusted values embedded by callers (PAM usernames, provider-supplied
 * claim values) cannot forge or garble log records.
 *
 * @param[in] pamh      PAM framework handle.
 * @param[in] cfg_level Active runtime log level threshold.
 * @param[in] msg_level Minimum verbosity level required to emit this message.
 * @param[in] priority  syslog priority level (e.g., LOG_ERR, LOG_INFO, LOG_DEBUG).
 * @param[in] fmt       Printf-style format string.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 5, 6))) /* flawfinder: ignore */
#endif
void pam_oauth_log(pam_handle_t *pamh, loglevel_t cfg_level, loglevel_t msg_level, int priority, const char *fmt, ...);

/**
 * @brief Parses log level string representations ("none", "error", "info", "debug", "verbose" or "0".."4").
 *
 * @param[in]  val Raw string setting value.
 * @param[out] out Target loglevel_t pointer receiving parsed enum result.
 * @return 0 on success, -1 on unknown or invalid setting string.
 */
int parse_loglevel(const char *val, loglevel_t *out);

/**
 * @brief Volatile memory wiper to prevent sensitive data exposure in process memory.
 *
 * Overwrites memory buffer with zeroes using a volatile pointer to prevent compiler dead-code
 * elimination optimizations.
 *
 * @param[in,out] v Pointer to memory buffer to erase.
 * @param[in]     n Size of memory buffer in bytes.
 */
void secure_memzero(void *v, size_t n);

/**
 * @brief Recursively zero-fills every string value in a parsed json-c object tree.
 *
 * json-c retains a private heap copy of each parsed string; `json_object_put()`
 * releases those copies with a plain `free()`, so credential and PII bytes
 * would otherwise remain in the process heap until the allocator reuses the
 * region. Call this on a provider-parsed tree before `json_object_put()`.
 *
 * @param[in] obj Root json-c node to scrub (any type, or NULL).
 */
void secure_zero_json_tree(struct json_object *obj);

/**
 * @brief Safe bounds-checked string buffer copy wrapper.
 *
 * @param[out] dst      Destination buffer pointer.
 * @param[in]  dst_size Capacity of destination buffer in bytes.
 * @param[in]  src      Source null-terminated string pointer.
 * @return 0 on success, -1 if inputs are invalid or truncation would occur.
 */
int copy_checked(char *dst, size_t dst_size, const char *src);

/**
 * @brief Validates whether a given string is a safe HTTPS URL.
 *
 * Enforces HTTPS scheme, checks for control/whitespace characters, and rejects URLs containing userinfo.
 *
 * @param[in] url Candidate URL string.
 * @return 1 if valid HTTPS URL, 0 otherwise.
 */
int is_valid_https_url(const char *url);

/**
 * @brief Verifies that a string contains only safe printable ASCII characters.
 *
 * Prevents ANSI terminal escape sequence injection and control character attacks.
 *
 * @param[in] str Candidate terminal display string.
 * @return 1 if string is safe for terminal output, 0 otherwise.
 */
int is_safe_terminal_string(const char *str);

/**
 * @brief Validates an OAuth user code for terminal output safety.
 *
 * Restricts input to printable alphanumeric, hyphen, space, and underscore characters up to 64 bytes.
 *
 * @param[in] str User code string.
 * @return 1 if code structure is valid and safe, 0 otherwise.
 */
int is_safe_user_code(const char *str);

/**
 * @brief Thread-safe global libcurl environment initializer.
 *
 * Uses POSIX thread primitives (`pthread_once`) to ensure libcurl global initialization happens exactly once.
 *
 * @return 0 on success, -1 on initialization failure.
 */
int oauth_http_global_init(void);

/**
 * @brief Parses and validates module configuration file settings.
 *
 * Enforces strict POSIX file permissions (root-owned, 0600/0640) and loads section options into a config_t structure.
 *
 * @param[in]  path Path to configuration file.
 * @param[out] cfg  Pointer to configuration structure to populate.
 * @param[in]  pamh PAM handle for syslog logging context (optional, can be NULL).
 * @return 0 on success, -1 on parsing or security validation failure.
 */
int load_config(const char *path, config_t *cfg, pam_handle_t *pamh);

/**
 * @brief Parses configuration key/value pairs from an open file stream.
 *
 * Pure parsing counterpart of load_config(3): reads lines from the supplied stream,
 * handles section headers, trims whitespace, rejects overlong lines, and dispatches
 * each key/value pair for validation and duplicate tracking. Does not perform any
 * filesystem checks or stream lifecycle management (open/fclose) of its own.
 *
 * @param[in]  fp   Opened configuration stream; the read position may be anywhere in the file.
 * @param[out] cfg  Pointer to configuration structure to populate.
 * @param[in]  pamh PAM handle for syslog logging context (optional, may be NULL).
 * @return 0 on successful parse of a complete and valid configuration, -1 on parse,
 *         validation, duplication, or EOF-with-missing-keys failure.
 */
int parse_config_file(FILE *fp, config_t *cfg, pam_handle_t *pamh);

/**
 * @brief Performs an HTTP request using libcurl.
 *
 * Supports GET and POST methods, handles header injection, enforces TLS/HTTPS protocols, logs transport tracing,
 * and manages execution timeouts.
 *
 * @param[in]  method       HTTP method string ("GET" or "POST").
 * @param[in]  url          Target URL string.
 * @param[in]  postfields   URL-encoded POST request payload (can be NULL for GET).
 * @param[in]  bearer_token Optional OAuth Bearer access token string for authorization.
 * @param[in]  proxy        Optional outbound HTTPS proxy URL (`https://host[:port]`,
 *                         validated at config load). Empty/NULL routes traffic directly.
 *                         In either case the `*_proxy` and `no_proxy`/`NO_PROXY`
 *                         environment variables are never honored.
 * @param[in]  timeout_ms   Request timeout period in milliseconds.
 * @param[out] resp         Pointer to http_response_t structure receiving response data.
 * @param[in]  loglevel     Active log verbosity level for HTTP transport tracing.
 * @param[in]  pamh         PAM handle for syslog logging context (optional).
 * @return 0 on HTTP execution success, -1 on transport or error conditions.
 */
int http_request(const char *method, const char *url, const char *postfields, const char *bearer_token,
                 const char *proxy, long timeout_ms, http_response_t *resp, loglevel_t loglevel, pam_handle_t *pamh);

/**
 * @brief Securely frees resources allocated in an HTTP response structure.
 *
 * Zeroes response buffer memory prior to freeing heap space.
 *
 * @param[in,out] resp Response container to clear and free.
 */
void free_http_response(http_response_t *resp);

/**
 * @brief Classifies an OAuth token-endpoint HTTP status code as transient/retryable.
 *
 * Per RFC 8628 §3.5, a well-formed token response uses 2xx for success and 4xx for `error`
 * responses, where only `authorization_pending` and `slow_down` permit the polling loop to
 * continue. HTTP 429 (rate limiting) and 5xx (server/gateway errors, such as empty bodies or
 * HTML error pages returned by a proxy/load balancer) are transport-level conditions, not
 * OAuth errors, and are transient. Such responses MUST be retried with backoff within the
 * device-authorization deadline instead of aborting authentication.
 *
 * @param[in] status_code HTTP status code returned by the token endpoint.
 * @return 1 if the status is transient (HTTP 429 or 5xx) and should be retried, 0 otherwise.
 */
int is_retryable_token_http_status(long status_code);

/**
 * @brief Classifies a parsed OIDC/OAuth discovery document as advertising S256 PKCE.
 *
 * Returns 1 when the document is a JSON object whose `code_challenge_methods_supported`
 * member is an array of strings containing the exact value "S256". NOTE: that metadata
 * field (defined for the authorization-code flow) is treated here as a *heuristic hint*
 * for device-flow PKCE: no standard discovery parameter advertises PKCE for the RFC 8628
 * device grant specifically, so callers must treat the result as a recommendation, not
 * proof (see examples/README.md).
 *
 * @param[in] doc Parsed discovery-document JSON object (may be NULL).
 * @return 1 if S256 is advertised, 0 otherwise (including malformed or missing fields).
 */
int discovery_json_advertises_s256(const struct json_object *doc);

/**
 * @brief Probes a provider's discovery document once to decide device-flow PKCE gating.
 *
 * Performs a GET against `url` (bounded to 5000 ms), parses the metadata, and applies
 * the auto-mode decision: PKCE is enabled only when the document both advertises S256
 * via `code_challenge_methods_supported` and advertises a `device_authorization_endpoint`.
 * The decision (and its rationale) is logged so operators can audit the suggestion.
 *
 * @param[in]  url        HTTPS discovery metadata URL (must be pre-validated).
 * @param[in]  proxy      Optional outbound HTTPS proxy URL; empty/NULL routes directly.
 * @param[out] supported  Set to 1 when PKCE should be enabled, 0 otherwise.
 * @param[in]  loglevel   Active syslog verbosity level.
 * @param[in]  pamh       PAM handle for syslog logging context (optional).
 * @return 0 when the probe completed (check *supported for the decision), -1 when the
 *         probe could not complete (transport/HTTP/JSON failure; *supported is 0).
 */
int discovery_probe_pkce(const char *url, const char *proxy, int *supported, loglevel_t loglevel, pam_handle_t *pamh);

/**
 * @brief Encodes a verification URI into a packed QR Code module matrix.
 *
 * Byte-mode encoding per ISO/IEC 180004 with automatic mask selection; the smallest symbol
 * version in 1..QR_MAX_VERSION that fits the input at the requested error-correction level is
 * chosen (the input must not contain NUL bytes).
 *
 * @param[in]  url        NUL-terminated verification URI to encode.
 * @param[in]  ec         Requested error-correction level.
 * @param[out] qrdata     Packed module grid in qrcodegen layout: byte 0 stores the symbol size;
 *                        module (x, y) occupies bit (y*size + x) % 8 of byte (y*size + x) / 8 + 1
 *                        (LSB-first).
 * @param[in]  qrdata_cap Byte capacity of qrdata; must be at least QR_MATRIX_BYTES_MAX.
 * @param[out] out_size   Symbol width/height in modules (21 + 4 * version) on success.
 * @return 0 on success, -1 if arguments are invalid or the URI does not fit any version up to
 *         QR_MAX_VERSION at the requested error-correction level.
 */
int qr_encode_uri(const char *url, qr_ec_t ec, uint8_t *qrdata, size_t qrdata_cap, int *out_size);

/**
 * @brief Renders a packed QR module matrix as terminal text with a configurable quiet zone.
 *
 * QR_STYLE_UTF8 pairs stacked module rows into half-block glyph rows (U+2580/U+2584/U+2588),
 * halving the number of text lines; QR_STYLE_ASCII emits one `block_char` per dark module.
 * `scale` repeats each glyph `scale` times horizontally and vertically (1-3). Every output
 * line is newline-terminated, including the final line.
 *
 * @param[in]  qrdata     Packed module grid as produced by qrcodegen_encodeText()/qr_encode_uri().
 * @param[in]  size       Symbol width/height in modules (21-97 for versions 1-20).
 * @param[in]  style      Rendering style.
 * @param[in]  scale      Enlargement factor, 1-3.
 * @param[in]  block_char Dark-module character for QR_STYLE_ASCII (printable ASCII; ignored for
 *                        QR_STYLE_UTF8, where the fixed half-block glyphs are used).
 * @param[in]  vquiet     Vertical quiet zone in light module rows, 0-QR_QUIET_ZONE (the horizontal quiet
 *                        zone is always QR_QUIET_ZONE modules).
 * @param[out] out        Buffer receiving the rendered block.
 * @param[in]  out_len    Byte capacity of out.
 * @return 0 on success, -1 on invalid arguments or output-buffer overflow.
 */
int qr_render_matrix(const uint8_t *qrdata, int size, qr_style_t style, int scale, char block_char, int vquiet,
                     char *out, size_t out_len);

/**
 * @brief Renders the verification URI as a scannable terminal QR code block with a header line.
 *
 * Selects `verification_uri_complete` when configured and available (falling back to the plain
 * verification URI), encodes it at the configured error-correction level, renders it in the
 * configured style/scale, and prefixes it with a short instruction line. All rendering failures
 * (URI too long, buffer overflow, ...) are reported via the syslog and returned as -1; callers
 * must treat the result as optional and continue with the plain text prompt.
 *
 * @param[in]  cfg        Module configuration (qr_* fields).
 * @param[in]  loglevel   Active syslog verbosity level.
 * @param[in]  url_plain     Provider `verification_uri` (required).
 * @param[in]  url_complete  Provider `verification_uri_complete` (may be NULL).
 * @param[out] out          Buffer receiving the full rendered block.
 * @param[in]  out_len      Byte capacity of out.
 * @param[in]  pamh       PAM handle for syslog logging context (optional, may be NULL).
 * @return 0 on success, -1 if the block could not be rendered.
 */
int qr_render_verification_code(const config_t *cfg, loglevel_t loglevel, const char *url_plain,
                                const char *url_complete, char *out, size_t out_len, pam_handle_t *pamh);

/**
 * @brief Encodes a URL parameter string per RFC 3986 using cURL.
 *
 * @param[in] curl Active cURL easy handle.
 * @param[in] str  Input string to encode.
 * @return Heap-allocated encoded string pointer (must be freed using curl_free), or NULL on failure.
 */
char *url_encode_param(CURL *curl, const char *str);

/**
 * @brief Generates a high-entropy RFC 7636 PKCE code verifier from the OpenSSL CSPRNG.
 *
 * Reads 48 random bytes from `RAND_bytes()` and encodes them as unpadded Base64URL
 * (RFC 4648 §5), yielding a 64-character verifier drawn from the RFC 7636 §4.2
 * character set (Base64URL's `-`/`_` substitute for `+`/`/`; `.`/`~` are unused).
 *
 * The caller owns `out` and is expected to scrub it with `secure_memzero()` on
 * every termination path; this function never logs or returns the verifier.
 *
 * @param[out] out    Buffer receiving the NUL-terminated verifier.
 * @param[in]  out_len Buffer capacity in bytes (must be at least PKCE_VERIFIER_LEN + 1).
 * @return 0 on success, -1 on NULL inputs, undersized buffer, or CSPRNG failure.
 */
int pkce_generate_code_verifier(char *out, size_t out_len);

/**
 * @brief Computes the S256 PKCE code challenge for a code verifier (RFC 7636 §4.2).
 *
 * `code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))` without padding,
 * yielding a 43-character string.
 *
 * @param[in]  verifier  NUL-terminated code verifier string.
 * @param[out] out       Buffer receiving the NUL-terminated challenge.
 * @param[in]  out_len   Buffer capacity in bytes (must be at least PKCE_S256_CHALLENGE_LEN + 1).
 * @return 0 on success, -1 on NULL inputs, empty verifier, undersized buffer, or
 *         digest computation failure.
 */
int pkce_compute_s256_challenge(const char *verifier, char *out, size_t out_len);

/**
 * @brief Formats prompt display string presented to user during authentication.
 *
 * Evaluates configured template tokens ({url}, {url_complete}, {code}, {expiry}) and
 * newline escape sequences. The {expiry} token carries the human-readable device-code approval
 * window (the provider's `expires_in`, clamped by `max_poll_seconds`; e.g. "15 minutes"), or
 * expands to an empty string when the window is unknown. The prompt deliberately carries no
 * host identification: in a device-code phishing attack (docs/threat-model.md §8) the prompt
 * reaches the party that *ran ssh* (the attacker), while the approving user only ever sees the
 * identity provider's approval page — so machine context must live in the registered OAuth
 * client name shown on that approval page, not in this prompt. The fully rendered result is
 * validated line-by-line for terminal-injection safety (newline-tolerant `is_safe_terminal_string`);
 * unsafe template/URL/code output fails the call (fail-closed).
 *
 * @param[in]  cfg          Active configuration context.
 * @param[in]  url          Base verification URI string.
 * @param[in]  url_complete Complete verification URI string containing embedded user code (optional).
 * @param[in]  code         User verification code string.
 * @param[in]  expires_in   Device-code approval window in seconds (provider `expires_in`, clamped
 *                          to `[runtime] max_poll_seconds`); 0 or negative means unknown.
 * @param[out] out          Buffer receiving rendered prompt text.
 * @param[in]  out_len      Destination buffer size in bytes.
 * @return 0 on success, -1 on buffer overflow, rendering error, or terminal-safety rejection.
 */
int render_prompt_message(const config_t *cfg, const char *url, const char *url_complete, const char *code,
                          int expires_in, char *out, size_t out_len);

/**
 * @brief Matches raw identity claim value against expected PAM username using regex mapping rules.
 *
 * Extracts claim substring via configured capture group and performs case-sensitive or case-insensitive matching.
 *
 * @param[in] pam_user  Target POSIX system username.
 * @param[in] raw_claim Raw claim value extracted from OpenID UserInfo response.
 * @param[in] cfg       Module configuration parameters containing claim regex rules and active loglevel.
 * @param[in] pamh      PAM handle for syslog logging (optional).
 * @return 1 if target user matches extracted identity claim, 0 otherwise.
 */
int verify_claim(const char *pam_user, const char *raw_claim, const config_t *cfg, pam_handle_t *pamh);

/**
 * @brief Enforces local account allow/deny list controls against the requesting PAM username.
 *
 * Evaluates the configured `deny_users` and `allow_users` lists (comma-separated, honoring
 * `case_sensitive`) for the requesting local account. Denial lists take precedence over
 * allow lists. Any uid-0 account (the account named `root` plus any alternative uid-0
 * name, e.g. "toor") is denied by default and only authenticates when `allow_root` is
 * explicitly enabled, regardless of the user lists. Independently, when
 * `deny_system_uids` is enabled (default), any local account whose numeric UID falls
 * within [system_uid_min, system_uid_max] (default 0-999, the conventional
 * system-account range) is denied regardless of the user lists; a uid-0 account already
 * exempted via `allow_root` is not re-denied by this range guard. This is a purely
 * local decision made before any provider interaction.
 *
 * @param[in] pam_user  Target POSIX system username.
 * @param[in] cfg       Module configuration parameters containing the account lists and
 *                      the uid-range guard settings.
 * @param[in] pamh      PAM handle for syslog logging (optional).
 * @return 1 if the account is permitted to authenticate, 0 if it is denied.
 */
int verify_user_access(const char *pam_user, const config_t *cfg, pam_handle_t *pamh);

/**
 * @brief Evaluates array or string claims (e.g., groups or roles) to enforce group authorization.
 *
 * Evaluates the configured `allow_groups`/`deny_groups` lists against the UserInfo
 * group/role claims located under `cfg->group_claim_field`. Denial lists take precedence
 * over allow lists.
 *
 * @param[in] uinfo_json Parsed JSON payload object from provider UserInfo response.
 * @param[in] cfg        Active module configuration settings.
 * @param[in] pamh       PAM handle used for emitting system log messages.
 * @return 1 if group authorization succeeds or is not configured, 0 if permission is denied.
 */
int verify_group_membership(const struct json_object *uinfo_json, const config_t *cfg, pam_handle_t *pamh);

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
int verify_token_metadata(const char *jwt_str, const config_t *cfg, pam_handle_t *pamh);

/**
 * @brief Extracts a single string claim (e.g. `sub`) from a JWT's payload segment.
 *
 * Applies the same strict structural validation as verify_token_metadata()
 * (three dot-delimited segments, non-empty payload, strict RFC 4648 §5
 * Base64URL alphabet, JSON object payload) and copies the named claim's string
 * value into the caller's buffer. Claims-only inspection: the JWT signature is
 * NOT verified; never use this as the sole basis for authorization.
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
int jwt_extract_claim_string(const char *token, const char *claim_name, char *out, size_t out_len);

#endif /* PAM_OIDC_DEVICE_H */
