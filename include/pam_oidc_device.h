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
#include <pthread.h>
#include <regex.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>

/* ============================================================================
 * Configuration & Runtime Constants
 * ============================================================================ */

/** @brief Default system configuration file path. */
#define CONFIG_PATH_DEFAULT "/etc/pam_oidc_device.conf"

/** @brief Minimum permitted polling interval in seconds per RFC 8628. */
#define MIN_POLL_INTERVAL 5

/** @brief Maximum standard polling interval in seconds. */
#define MAX_POLL_INTERVAL 60

/** @brief Maximum supported polling interval upper bound in seconds. */
#define MAX_SUPPORTED_POLL_INTERVAL 120

/** @brief Maximum buffer capacity for custom initial user prompt templates. */
#define MAX_INIT_MSG_LEN 1024

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
    SEC_RUNTIME   /**< [runtime] section: Module operational limits and debugging settings. */
} config_section_t;

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
    char claim_regex[256];                   /**< Regular expression pattern to extract local username. */
    int claim_capture_group;                 /**< Regex capture group index to select username slice. */
    int max_poll_seconds;                    /**< Maximum total polling time allowed before timing out. */
    char init_message[MAX_INIT_MSG_LEN];     /**< Custom template string for user terminal prompt. */
    int case_sensitive;                      /**< Flag: 1 for case-sensitive username comparison, 0 otherwise. */
    loglevel_t loglevel; /**< Configured syslog verbosity level (none, error, info, debug, verbose). */
    char issuer[512];    /**< Expected token issuer claim (iss). */
    char audience[256];  /**< Expected token audience claim (aud). */
    char jwks_url[512];  /**< Reserved: JWKS endpoint URL; parsed and validated, but not yet used for JWT signature
                            verification. */
    char introspection_endpoint[512]; /**< Reserved: RFC 7662 Token Introspection endpoint URL; parsed and validated,
                                         but not yet used. */
    int verify_jwt_claims;  /**< Flag: 1 to enforce local JWT claim inspection (exp, nbf, iss, aud). Claims-only; NOT a
                               signature check. */
    int clock_skew_leeway;  /**< Allowed clock skew leeway in seconds for exp/nbf validation. */
    int require_exp_claim;  /**< Flag: 1 to require a well-formed 'exp' claim when verify_jwt_claims is enabled. */
    char allow_users[256];  /**< Comma-separated local usernames permitted to authenticate (empty = all allowed). */
    char deny_users[256];   /**< Comma-separated local usernames denied authentication (takes precedence over allow). */
    int allow_root;         /**< Flag: 1 to permit the `root` account to authenticate; 0 (default) denies root. */
    char allow_groups[256]; /**< Comma-separated provider groups/roles granting access (any single match suffices). */
    char deny_groups[256];  /**< Comma-separated provider groups/roles denying access (takes precedence over allow). */
    int enforce_groups;     /**< Flag: 1 to require group/role authorization when no group lists are configured. */
    char group_claim_field[64]; /**< JSON field name in UserInfo containing group/role claims (e.g., "groups", "roles").
                                 */
    int use_pkce;               /**< Three-state PKCE gate: 0 (default) off; 1 always extend the RFC 8628 device
                                 *  flow with RFC 7636 PKCE (fresh CSPRNG `code_verifier` per attempt, its `S256`
                                 *  `code_challenge` sent to the device authorization endpoint, the verifier
                                 *  presented at the token endpoint); 2 ("auto") probe `discovery_endpoint` once
                                 *  per attempt and enable PKCE only when the provider metadata advertises S256
                                 *  PKCE support plus a device-authorization endpoint; probe failures fail safe
                                 *  to 0. */
    char discovery_endpoint[512]; /**< OIDC/OAuth discovery metadata URL (e.g.,
                                   *  `https://idp/.well-known/openid-configuration`); used only when
                                   *  `use_pkce` is 2 ("auto"). Empty otherwise. */
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
 * @brief Level-filtered wrapper around `pam_vsyslog`.
 *
 * Emits log output via `pam_vsyslog` only if `cfg_level` is not `LOGLEVEL_NONE` and `cfg_level` is
 * greater than or equal to the required `msg_level`.
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
 * @param[in]  timeout_ms   Request timeout period in milliseconds.
 * @param[out] resp         Pointer to http_response_t structure receiving response data.
 * @param[in]  loglevel     Active log verbosity level for HTTP transport tracing.
 * @param[in]  pamh         PAM handle for syslog logging context (optional).
 * @return 0 on HTTP execution success, -1 on transport or error conditions.
 */
int http_request(const char *method, const char *url, const char *postfields, const char *bearer_token, long timeout_ms,
                 http_response_t *resp, loglevel_t loglevel, pam_handle_t *pamh);

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
 * @param[out] supported  Set to 1 when PKCE should be enabled, 0 otherwise.
 * @param[in]  loglevel   Active syslog verbosity level.
 * @param[in]  pamh       PAM handle for syslog logging context (optional).
 * @return 0 when the probe completed (check *supported for the decision), -1 when the
 *         probe could not complete (transport/HTTP/JSON failure; *supported is 0).
 */
int discovery_probe_pkce(const char *url, int *supported, loglevel_t loglevel, pam_handle_t *pamh);

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
 * Evaluates configured template tokens ({url}, {url_complete}, {code}) and newline escape sequences.
 * The fully rendered result is validated line-by-line for terminal-injection safety
 * (newline-tolerant `is_safe_terminal_string`); unsafe output fails the call.
 *
 * @param[in]  cfg          Active configuration context.
 * @param[in]  url          Base verification URI string.
 * @param[in]  url_complete Complete verification URI string containing embedded user code (optional).
 * @param[in]  code         User verification code string.
 * @param[out] out          Buffer receiving rendered prompt text.
 * @param[in]  out_len      Destination buffer size in bytes.
 * @return 0 on success, -1 on buffer overflow, rendering error, or terminal-safety rejection.
 */
int render_prompt_message(const config_t *cfg, const char *url, const char *url_complete, const char *code, char *out,
                          size_t out_len);

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
 * allow lists. The `root` account is denied by default and only authenticates when
 * `allow_root` is explicitly enabled, regardless of the user lists. This is a purely
 * local decision made before any provider interaction.
 *
 * @param[in] pam_user  Target POSIX system username.
 * @param[in] cfg       Module configuration parameters containing the account lists.
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

#endif /* PAM_OIDC_DEVICE_H */
