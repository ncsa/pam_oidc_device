/**
 * @file config.c
 * @brief Configuration file parsing, strict POSIX security checks, and option enforcement.
 *
 * Implements secure configuration loading for the PAM module. Validates file descriptors
 * (`O_NOFOLLOW`, `O_CLOEXEC`), strict file ownership (root:root, uid 0), restrictive file permissions
 * (`0600` / `0640`), section parsing, duplicate entry tracking, regular expression verification,
 * and loglevel setting conversion.
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
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * @enum config_key_id_t
 * @brief Stable index of every recognized configuration key.
 *
 * One constant per key in the CONFIG_KEYS[] table, in declaration order. The
 * value doubles as the duplicate-tracking bit position in the
 * parse_config_kv() `seen` bitmask, so CK_KEY_COUNT must stay <= 63.
 */
typedef enum {
    CK_CLIENT_ID,                     /**< [oauth] client_id */
    CK_CLIENT_SECRET,                 /**< [oauth] client_secret */
    CK_DEVICE_AUTHORIZATION_ENDPOINT, /**< [oauth] device_authorization_endpoint */
    CK_TOKEN_ENDPOINT,                /**< [oauth] token_endpoint */
    CK_USERINFO_ENDPOINT,             /**< [oauth] userinfo_endpoint */
    CK_SCOPES,                        /**< [oauth] scopes */
    CK_ISSUER,                        /**< [oauth] issuer */
    CK_AUDIENCE,                      /**< [oauth] audience */
    CK_JWKS_URL,                      /**< [oauth] jwks_url */
    CK_INTROSPECTION_ENDPOINT,        /**< [oauth] introspection_endpoint */
    CK_VERIFY_JWT_CLAIMS,             /**< [oauth] verify_jwt_claims */
    CK_CLOCK_SKEW_LEEWAY,             /**< [oauth] clock_skew_leeway */
    CK_REQUIRE_EXP_CLAIM,             /**< [oauth] require_exp_claim */
    CK_USE_PKCE,                      /**< [oauth] use_pkce */
    CK_DISCOVERY_ENDPOINT,            /**< [oauth] discovery_endpoint */
    CK_PROXY,                         /**< [oauth] proxy */
    CK_CLAIM_FIELD,                   /**< [claim] claim_field */
    CK_CLAIM_REGEX,                   /**< [claim] claim_regex */
    CK_CLAIM_CAPTURE_GROUP,           /**< [claim] claim_capture_group */
    CK_CASE_SENSITIVE,                /**< [claim] case_sensitive */
    CK_ALLOW_USERS,                   /**< [access] allow_users */
    CK_DENY_USERS,                    /**< [access] deny_users */
    CK_ALLOW_ROOT,                    /**< [access] allow_root */
    CK_DENY_SYSTEM_UIDS,              /**< [access] deny_system_uids */
    CK_SYSTEM_UID_MIN,                /**< [access] system_uid_min */
    CK_SYSTEM_UID_MAX,                /**< [access] system_uid_max */
    CK_ALLOW_GROUPS,                  /**< [access] allow_groups */
    CK_DENY_GROUPS,                   /**< [access] deny_groups */
    CK_ENFORCE_GROUPS,                /**< [access] enforce_groups */
    CK_GROUP_CLAIM_FIELD,             /**< [access] group_claim_field */
    CK_INIT_MESSAGE,                  /**< [prompt] init_message */
    CK_SHOW_EXPIRY,                   /**< [prompt] show_expiry */
    CK_MAX_POLL_SECONDS,              /**< [runtime] max_poll_seconds */
    CK_LOGLEVEL,                      /**< [runtime] loglevel */
    CK_QR_ENABLED,                    /**< [qr] enabled */
    CK_QR_STYLE,                      /**< [qr] style */
    CK_QR_BLOCK_CHAR,                 /**< [qr] block_char */
    CK_QR_SCALE,                      /**< [qr] scale */
    CK_QR_VQUIET,                     /**< [qr] vertical_quiet_zone */
    CK_QR_EC_LEVEL,                   /**< [qr] ec_level */
    CK_QR_URI,                        /**< [qr] uri */
    CK_KEY_COUNT                      /**< Sentinel: number of recognized keys. */
} config_key_id_t;

/** Duplicate-tracking bit for one config_key_id_t (see config_seen_t). */
#define CFG_SEEN_BIT(id) (1ULL << (id))

/**
 * @typedef config_seen_t
 * @brief Bitmask tracking seen configuration keys to reject duplicate key definitions.
 *
 * One CFG_SEEN_BIT(config_key_id_t) per recognized key: a key set twice in the
 * same file is rejected as a duplicate by parse_config_kv().
 */
typedef unsigned long long config_seen_t;

/**
 * @brief Erases memory buffer contents using volatile pointer access.
 *
 * Prevents optimizing compilers from eliding zero-fill loops (Dead Code Elimination)
 * when scrubbing sensitive keys or tokens before freeing process memory.
 *
 * @param[in,out] v Pointer to memory region to scrub.
 * @param[in]     n Size of memory region in bytes.
 */
void secure_memzero(void *v, size_t n) {
    if (!v || n == 0) {
        return;
    }
    volatile unsigned char *p = (volatile unsigned char *)v;
    while (n--) {
        *p++ = 0;
    }
}

/**
 * @brief Bounds-checked string buffer copy helper.
 *
 * @param[out] dst      Destination buffer pointer.
 * @param[in]  dst_size Total byte capacity of destination buffer.
 * @param[in]  src      Null-terminated source string pointer.
 * @return 0 on successful copy, -1 if inputs are null, capacity is zero, or truncation would occur.
 */
int copy_checked(char *dst, size_t dst_size, const char *src) {
    if (!dst || !src || dst_size == 0) {
        return -1;
    }
    size_t len = strlen(src);
    if (len >= dst_size) {
        return -1;
    }
    memcpy(dst, src, len + 1);
    return 0;
}

/**
 * @brief Validates URL format and security criteria.
 *
 * Ensures URL begins strictly with `https://`, contains printable non-space ASCII characters,
 * contains no hash fragments, and rejects authority userinfo components (`user:pass@host`).
 *
 * @param[in] url URL string to evaluate.
 * @return 1 if valid secure HTTPS URL, 0 otherwise.
 */
int is_valid_https_url(const char *url) {
    if (!url || strncmp(url, "https://", 8) != 0) {
        return 0;
    }
    for (size_t i = 0; url[i] != '\0'; i++) {
        unsigned char c = (unsigned char)url[i];
        if (c <= 32 || c >= 127 || c == '#' || c == ' ') {
            return 0;
        }
    }
    const char *path_start = strchr(url + 8, '/');
    const char *at_ptr = strchr(url + 8, '@');
    if (at_ptr && (!path_start || at_ptr < path_start)) {
        return 0;
    }
    return 1;
}

/**
 * @brief Sanitizes terminal output strings against control character injection.
 *
 * @param[in] str Input text string.
 * @return 1 if string contains printable ASCII characters (range 32..126), 0 otherwise.
 */
int is_safe_terminal_string(const char *str) {
    if (!str) {
        return 0;
    }
    for (size_t i = 0; str[i] != '\0'; i++) {
        unsigned char c = (unsigned char)str[i];
        if (c < 32 || c >= 127) {
            return 0;
        }
    }
    return 1;
}

/**
 * @brief Validates OAuth user verification codes for safe presentation.
 *
 * @param[in] str Candidate user code string.
 * @return 1 if code is non-empty, under 64 characters, and consists of
 *         ASCII alphanumeric/hyphen/space/underscore chars, 0 otherwise.
 */
int is_safe_user_code(const char *str) {
    if (!str || strlen(str) == 0 || strlen(str) > 64) {
        return 0;
    }
    for (size_t i = 0; str[i] != '\0'; i++) {
        unsigned char c = (unsigned char)str[i];
        /*
         * Explicit ASCII ranges instead of locale-dependent isalnum(), so the
         * accepted set cannot vary with the ambient locale -- consistent with
         * the byte-wise style of the other terminal-safety helpers.
         */
        int ascii_alnum = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        if (!(ascii_alnum || c == '-' || c == ' ' || c == '_')) {
            return 0;
        }
    }
    return 1;
}

/**
 * @brief Trims leading and trailing whitespace from a string in-place.
 *
 * @param[in,out] str Target string pointer.
 * @return Pointer to first non-whitespace character in string, or NULL if input is NULL.
 */
static char *trim_whitespace(char *str) {
    if (!str) {
        return NULL;
    }
    while (isspace((unsigned char)*str)) {
        str++;
    }
    if (*str == '\0') {
        return str;
    }
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
    return str;
}

/**
 * @brief Parses boolean configuration values ("true"/"false", "1"/"0", "yes"/"no").
 *
 * @param[in]  val Raw string representation of boolean setting.
 * @param[out] out Integer receiving parsed result (1 for true, 0 for false).
 * @return 0 on successful conversion, -1 if string is invalid or NULL.
 */
static int parse_bool(const char *val, int *out) {
    if (!val) {
        return -1;
    }
    if (strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0 || strcasecmp(val, "yes") == 0) {
        *out = 1;
        return 0;
    }
    if (strcasecmp(val, "false") == 0 || strcmp(val, "0") == 0 || strcasecmp(val, "no") == 0) {
        *out = 0;
        return 0;
    }
    return -1;
}

/**
 * @brief Parses the three-state `use_pkce` configuration value.
 *
 * Accepts the boolean forms of `parse_bool` plus the case-insensitive "auto" mode, which
 * probes `discovery_endpoint` once per authentication attempt to gate device-flow PKCE.
 *
 * @param[in]  val Raw string setting value ("true"/"1"/"yes", "false"/"0"/"no", "auto").
 * @param[out] out Integer receiving 1 (always on), 0 (off), or 2 (auto).
 * @return 0 on successful conversion, -1 if string is invalid or NULL.
 */
static int parse_pkce_mode(const char *val, int *out) {
    if (!val || !out) {
        return -1;
    }
    if (strcasecmp(val, "auto") == 0) {
        *out = 2;
        return 0;
    }
    return parse_bool(val, out);
}

/**
 * @brief Parses loglevel configuration values ("none", "error", "info", "debug", "verbose" or "0".."4").
 *
 * @param[in]  val Raw string setting value.
 * @param[out] out Target loglevel_t pointer receiving parsed enum result.
 * @return 0 on success, -1 on unknown or invalid setting string.
 */
int parse_loglevel(const char *val, loglevel_t *out) {
    if (!val || !out) {
        return -1;
    }
    if (strcasecmp(val, "none") == 0 || strcmp(val, "0") == 0) {
        *out = LOGLEVEL_NONE;
        return 0;
    }
    if (strcasecmp(val, "error") == 0 || strcmp(val, "1") == 0) {
        *out = LOGLEVEL_ERROR;
        return 0;
    }
    if (strcasecmp(val, "info") == 0 || strcmp(val, "2") == 0) {
        *out = LOGLEVEL_INFO;
        return 0;
    }
    if (strcasecmp(val, "debug") == 0 || strcmp(val, "3") == 0) {
        *out = LOGLEVEL_DEBUG;
        return 0;
    }
    if (strcasecmp(val, "verbose") == 0 || strcmp(val, "4") == 0) {
        *out = LOGLEVEL_VERBOSE;
        return 0;
    }
    return -1;
}

/**
 * @brief Parses an integer string and validates that it falls within expected bounds.
 *
 * @param[in]  val   Raw integer string value.
 * @param[in]  min_v Minimum allowed inclusive threshold.
 * @param[in]  max_v Maximum allowed inclusive threshold.
 * @param[out] out   Target integer pointer receiving value.
 * @return 0 on success, -1 if string is malformed or out of bounds.
 */
static int parse_int_range(const char *val, int min_v, int max_v, int *out) {
    if (!val || *val == '\0') {
        return -1;
    }
    char *endptr = NULL;
    errno = 0;
    long v = strtol(val, &endptr, 10);
    if (errno != 0 || *endptr != '\0' || v < min_v || v > max_v) {
        return -1;
    }
    *out = (int)v;
    return 0;
}

/**
 * @brief Parses the QR terminal rendering style ("utf8" or "ascii", case-insensitive).
 *
 * @param[in]  val Raw string setting value.
 * @param[out] out Target qr_style_t pointer receiving parsed style.
 * @return 0 on success, -1 on unknown or invalid setting string.
 */
static int parse_qr_style(const char *val, qr_style_t *out) {
    if (!val || !out) {
        return -1;
    }
    if (strcasecmp(val, "utf8") == 0) {
        *out = QR_STYLE_UTF8;
        return 0;
    }
    if (strcasecmp(val, "ascii") == 0) {
        *out = QR_STYLE_ASCII;
        return 0;
    }
    return -1;
}

/**
 * @brief Parses the QR block character (exactly one printable, non-space ASCII character).
 *
 * @param[in]  val Raw string setting value (e.g. "#", "@").
 * @param[out] out 2-byte destination buffer receiving the character plus NUL.
 * @return 0 on success, -1 if the value is not a single printable ASCII character 0x21-0x7E.
 */
static int parse_qr_block_char(const char *val, char *out) {
    if (!val || !out || strlen(val) != 1) {
        return -1;
    }
    unsigned char c = (unsigned char)val[0];
    if (c < 0x21U || c > 0x7EU) {
        return -1;
    }
    out[0] = (char)c;
    out[1] = '\0';
    return 0;
}

/**
 * @brief Parses the QR error-correction level ("L", "M", "Q", "H", case-insensitive).
 *
 * @param[in]  val Raw string setting value.
 * @param[out] out Target qr_ec_t pointer receiving parsed level.
 * @return 0 on success, -1 on unknown or invalid setting string.
 */
static int parse_qr_ec_level(const char *val, qr_ec_t *out) {
    if (!val || !out || strlen(val) != 1) {
        return -1;
    }
    unsigned char c = (unsigned char)val[0];
    if (c >= 'a' && c <= 'z') {
        c = (unsigned char)(c - 'a' + 'A');
    }
    switch (c) {
    case 'L':
        *out = QR_EC_LOW;
        return 0;
    case 'M':
        *out = QR_EC_MEDIUM;
        return 0;
    case 'Q':
        *out = QR_EC_QUARTILE;
        return 0;
    case 'H':
        *out = QR_EC_HIGH;
        return 0;
    default:
        return -1;
    }
}

/**
 * @brief Parses the QR source URI preference ("complete" or "plain", case-insensitive).
 *
 * @param[in]  val Raw string setting value.
 * @param[out] out Integer receiving 1 (embed user code via verification_uri_complete) or 0
 *                 (plain verification_uri with manual code entry).
 * @return 0 on success, -1 on unknown or invalid setting string.
 */
static int parse_qr_uri(const char *val, int *out) {
    if (!val || !out) {
        return -1;
    }
    if (strcasecmp(val, "complete") == 0) {
        *out = 1;
        return 0;
    }
    if (strcasecmp(val, "plain") == 0) {
        *out = 0;
        return 0;
    }
    return -1;
}

/**
 * @enum cfg_val_kind_t
 * @brief Value-handler kind for one table-driven configuration key.
 */
typedef enum {
    CFG_VAL_STRING,        /**< copy_checked() into the member's fixed-size buffer. */
    CFG_VAL_HTTPS_URL,     /**< is_valid_https_url() gate, then copy_checked(). */
    CFG_VAL_PROXY,         /**< CFG_VAL_HTTPS_URL where an empty value means "no proxy". */
    CFG_VAL_BOOL,          /**< parse_bool() into the int member. */
    CFG_VAL_INT_RANGE,     /**< parse_int_range() within [min_val, max_val]. */
    CFG_VAL_LOGLEVEL,      /**< parse_loglevel() into the loglevel_t member. */
    CFG_VAL_PKCE_MODE,     /**< parse_pkce_mode() into the int member. */
    CFG_VAL_QR_STYLE,      /**< parse_qr_style() into the qr_style_t member. */
    CFG_VAL_QR_BLOCK_CHAR, /**< parse_qr_block_char() into the 2-byte member. */
    CFG_VAL_QR_EC_LEVEL,   /**< parse_qr_ec_level() into the qr_ec_t member. */
    CFG_VAL_QR_URI         /**< parse_qr_uri() into the int member. */
} cfg_val_kind_t;

/**
 * @struct config_key_spec_t
 * @brief Declarative specification of one configuration key.
 *
 * The offset/size pair locates the destination member inside config_t, so the
 * parse_config_kv() dispatcher can apply every value kind uniformly, without
 * per-key code.
 */
typedef struct {
    const char *key;           /**< Case-insensitive key name (strcasecmp). */
    config_section_t sec;      /**< Section the key belongs to. */
    cfg_val_kind_t kind;       /**< Value handler kind. */
    config_seen_t seen_bit;    /**< Duplicate-tracking bit (CFG_SEEN_BIT()). */
    size_t offset;             /**< offsetof(config_t, destination member). */
    size_t size;               /**< Destination buffer size (string kinds). */
    int min_val;               /**< Inclusive lower bound (CFG_VAL_INT_RANGE). */
    int max_val;               /**< Inclusive upper bound (CFG_VAL_INT_RANGE). */
    const char *reserved_note; /**< "Accepted but unused" INFO note, or NULL. */
} config_key_spec_t;

/** Size of one config_t member, keeping CONFIG_KEYS[] entries in sync with the struct. */
#define CFG_MEMBER_SIZE(member) (sizeof(((config_t *)0)->member))

/**
 * @brief The complete key/section/handler table driving parse_config_kv().
 *
 * Every recognized key is declared here exactly once. The dispatcher rejects
 * anything not in this table — unknown key or right key in the wrong section —
 * and flags repeats via the per-key seen bit. Keep the entries grouped by
 * section, mirroring the documented configuration schema, and keep every
 * config_key_id_t constant paired with exactly one entry.
 */
static const config_key_spec_t CONFIG_KEYS[] = {
    /* [oauth] — Identity provider client credentials, endpoints, and verification. */
    {"client_id", SEC_OAUTH, CFG_VAL_STRING, CFG_SEEN_BIT(CK_CLIENT_ID), offsetof(config_t, client_id),
     CFG_MEMBER_SIZE(client_id), 0, 0, NULL},
    {"client_secret", SEC_OAUTH, CFG_VAL_STRING, CFG_SEEN_BIT(CK_CLIENT_SECRET), offsetof(config_t, client_secret),
     CFG_MEMBER_SIZE(client_secret), 0, 0, NULL},
    {"device_authorization_endpoint", SEC_OAUTH, CFG_VAL_HTTPS_URL, CFG_SEEN_BIT(CK_DEVICE_AUTHORIZATION_ENDPOINT),
     offsetof(config_t, device_authorization_endpoint), CFG_MEMBER_SIZE(device_authorization_endpoint), 0, 0, NULL},
    {"token_endpoint", SEC_OAUTH, CFG_VAL_HTTPS_URL, CFG_SEEN_BIT(CK_TOKEN_ENDPOINT),
     offsetof(config_t, token_endpoint), CFG_MEMBER_SIZE(token_endpoint), 0, 0, NULL},
    {"userinfo_endpoint", SEC_OAUTH, CFG_VAL_HTTPS_URL, CFG_SEEN_BIT(CK_USERINFO_ENDPOINT),
     offsetof(config_t, userinfo_endpoint), CFG_MEMBER_SIZE(userinfo_endpoint), 0, 0, NULL},
    {"scopes", SEC_OAUTH, CFG_VAL_STRING, CFG_SEEN_BIT(CK_SCOPES), offsetof(config_t, scopes), CFG_MEMBER_SIZE(scopes),
     0, 0, NULL},
    {"issuer", SEC_OAUTH, CFG_VAL_STRING, CFG_SEEN_BIT(CK_ISSUER), offsetof(config_t, issuer), CFG_MEMBER_SIZE(issuer),
     0, 0, NULL},
    {"audience", SEC_OAUTH, CFG_VAL_STRING, CFG_SEEN_BIT(CK_AUDIENCE), offsetof(config_t, audience),
     CFG_MEMBER_SIZE(audience), 0, 0, NULL},
    {"jwks_url", SEC_OAUTH, CFG_VAL_HTTPS_URL, CFG_SEEN_BIT(CK_JWKS_URL), offsetof(config_t, jwks_url),
     CFG_MEMBER_SIZE(jwks_url), 0, 0,
     "jwks_url is accepted but unused: JWKS-based JWT signature verification is not currently performed; token "
     "validity is enforced by the UserInfo endpoint"},
    {"introspection_endpoint", SEC_OAUTH, CFG_VAL_HTTPS_URL, CFG_SEEN_BIT(CK_INTROSPECTION_ENDPOINT),
     offsetof(config_t, introspection_endpoint), CFG_MEMBER_SIZE(introspection_endpoint), 0, 0,
     "introspection_endpoint is accepted but unused: RFC 7662 token introspection is not currently performed; "
     "token validity is enforced by the UserInfo endpoint"},
    {"verify_jwt_claims", SEC_OAUTH, CFG_VAL_BOOL, CFG_SEEN_BIT(CK_VERIFY_JWT_CLAIMS),
     offsetof(config_t, verify_jwt_claims), 0, 0, 0, NULL},
    {"clock_skew_leeway", SEC_OAUTH, CFG_VAL_INT_RANGE, CFG_SEEN_BIT(CK_CLOCK_SKEW_LEEWAY),
     offsetof(config_t, clock_skew_leeway), 0, 0, 300, NULL},
    {"require_exp_claim", SEC_OAUTH, CFG_VAL_BOOL, CFG_SEEN_BIT(CK_REQUIRE_EXP_CLAIM),
     offsetof(config_t, require_exp_claim), 0, 0, 0, NULL},
    {"use_pkce", SEC_OAUTH, CFG_VAL_PKCE_MODE, CFG_SEEN_BIT(CK_USE_PKCE), offsetof(config_t, use_pkce), 0, 0, 0, NULL},
    {"discovery_endpoint", SEC_OAUTH, CFG_VAL_HTTPS_URL, CFG_SEEN_BIT(CK_DISCOVERY_ENDPOINT),
     offsetof(config_t, discovery_endpoint), CFG_MEMBER_SIZE(discovery_endpoint), 0, 0, NULL},
    {"proxy", SEC_OAUTH, CFG_VAL_PROXY, CFG_SEEN_BIT(CK_PROXY), offsetof(config_t, proxy), CFG_MEMBER_SIZE(proxy), 0, 0,
     NULL},

    /* [claim] — Identity claim extraction and matching. */
    {"claim_field", SEC_CLAIM, CFG_VAL_STRING, CFG_SEEN_BIT(CK_CLAIM_FIELD), offsetof(config_t, claim_field),
     CFG_MEMBER_SIZE(claim_field), 0, 0, NULL},
    {"claim_regex", SEC_CLAIM, CFG_VAL_STRING, CFG_SEEN_BIT(CK_CLAIM_REGEX), offsetof(config_t, claim_regex),
     CFG_MEMBER_SIZE(claim_regex), 0, 0, NULL},
    {"claim_capture_group", SEC_CLAIM, CFG_VAL_INT_RANGE, CFG_SEEN_BIT(CK_CLAIM_CAPTURE_GROUP),
     offsetof(config_t, claim_capture_group), 0, 0, 32, NULL},
    {"case_sensitive", SEC_CLAIM, CFG_VAL_BOOL, CFG_SEEN_BIT(CK_CASE_SENSITIVE), offsetof(config_t, case_sensitive), 0,
     0, 0, NULL},

    /* [access] — Login authorization policy (user/group allowlists and system-UID denial). */
    {"allow_users", SEC_ACCESS, CFG_VAL_STRING, CFG_SEEN_BIT(CK_ALLOW_USERS), offsetof(config_t, allow_users),
     CFG_MEMBER_SIZE(allow_users), 0, 0, NULL},
    {"deny_users", SEC_ACCESS, CFG_VAL_STRING, CFG_SEEN_BIT(CK_DENY_USERS), offsetof(config_t, deny_users),
     CFG_MEMBER_SIZE(deny_users), 0, 0, NULL},
    {"allow_root", SEC_ACCESS, CFG_VAL_BOOL, CFG_SEEN_BIT(CK_ALLOW_ROOT), offsetof(config_t, allow_root), 0, 0, 0,
     NULL},
    {"deny_system_uids", SEC_ACCESS, CFG_VAL_BOOL, CFG_SEEN_BIT(CK_DENY_SYSTEM_UIDS),
     offsetof(config_t, deny_system_uids), 0, 0, 0, NULL},
    {"system_uid_min", SEC_ACCESS, CFG_VAL_INT_RANGE, CFG_SEEN_BIT(CK_SYSTEM_UID_MIN),
     offsetof(config_t, system_uid_min), 0, 0, INT_MAX, NULL},
    {"system_uid_max", SEC_ACCESS, CFG_VAL_INT_RANGE, CFG_SEEN_BIT(CK_SYSTEM_UID_MAX),
     offsetof(config_t, system_uid_max), 0, 0, INT_MAX, NULL},
    {"allow_groups", SEC_ACCESS, CFG_VAL_STRING, CFG_SEEN_BIT(CK_ALLOW_GROUPS), offsetof(config_t, allow_groups),
     CFG_MEMBER_SIZE(allow_groups), 0, 0, NULL},
    {"deny_groups", SEC_ACCESS, CFG_VAL_STRING, CFG_SEEN_BIT(CK_DENY_GROUPS), offsetof(config_t, deny_groups),
     CFG_MEMBER_SIZE(deny_groups), 0, 0, NULL},
    {"enforce_groups", SEC_ACCESS, CFG_VAL_BOOL, CFG_SEEN_BIT(CK_ENFORCE_GROUPS), offsetof(config_t, enforce_groups), 0,
     0, 0, NULL},
    {"group_claim_field", SEC_ACCESS, CFG_VAL_STRING, CFG_SEEN_BIT(CK_GROUP_CLAIM_FIELD),
     offsetof(config_t, group_claim_field), CFG_MEMBER_SIZE(group_claim_field), 0, 0, NULL},

    /* [prompt] — User-facing prompting presentation. */
    {"init_message", SEC_PROMPT, CFG_VAL_STRING, CFG_SEEN_BIT(CK_INIT_MESSAGE), offsetof(config_t, init_message),
     CFG_MEMBER_SIZE(init_message), 0, 0, NULL},
    {"show_expiry", SEC_PROMPT, CFG_VAL_BOOL, CFG_SEEN_BIT(CK_SHOW_EXPIRY), offsetof(config_t, show_expiry), 0, 0, 0,
     NULL},

    /* [runtime] — Polling and logging behavior. */
    {"max_poll_seconds", SEC_RUNTIME, CFG_VAL_INT_RANGE, CFG_SEEN_BIT(CK_MAX_POLL_SECONDS),
     offsetof(config_t, max_poll_seconds), 0, 10, 3600, NULL},
    {"loglevel", SEC_RUNTIME, CFG_VAL_LOGLEVEL, CFG_SEEN_BIT(CK_LOGLEVEL), offsetof(config_t, loglevel), 0, 0, 0, NULL},

    /* [qr] — Optional QR-code rendering of the verification URI. */
    {"enabled", SEC_QR, CFG_VAL_BOOL, CFG_SEEN_BIT(CK_QR_ENABLED), offsetof(config_t, qr_enabled), 0, 0, 0, NULL},
    {"style", SEC_QR, CFG_VAL_QR_STYLE, CFG_SEEN_BIT(CK_QR_STYLE), offsetof(config_t, qr_style), 0, 0, 0, NULL},
    {"block_char", SEC_QR, CFG_VAL_QR_BLOCK_CHAR, CFG_SEEN_BIT(CK_QR_BLOCK_CHAR), offsetof(config_t, qr_block_char),
     CFG_MEMBER_SIZE(qr_block_char), 0, 0, NULL},
    {"scale", SEC_QR, CFG_VAL_INT_RANGE, CFG_SEEN_BIT(CK_QR_SCALE), offsetof(config_t, qr_scale), 0, 1, 3, NULL},
    {"vertical_quiet_zone", SEC_QR, CFG_VAL_INT_RANGE, CFG_SEEN_BIT(CK_QR_VQUIET),
     offsetof(config_t, qr_vertical_quiet_zone), 0, 0, QR_QUIET_ZONE, NULL},
    {"ec_level", SEC_QR, CFG_VAL_QR_EC_LEVEL, CFG_SEEN_BIT(CK_QR_EC_LEVEL), offsetof(config_t, qr_ec_level), 0, 0, 0,
     NULL},
    {"uri", SEC_QR, CFG_VAL_QR_URI, CFG_SEEN_BIT(CK_QR_URI), offsetof(config_t, qr_uri_complete), 0, 0, 0, NULL},
};

/**
 * @brief Processes a single key-value configuration pair for a given section.
 *
 * Table-driven: looks the (section, key) pair up in CONFIG_KEYS[], then applies
 * the entry's value kind to the destination member located by the table's
 * offset/size pair. Key uniqueness is enforced via the per-key duplicate bit in
 * `seen`; anything not in the table — unknown key, or a known key in the wrong
 * section — is rejected.
 *
 * @param[in,out] cfg  Configuration structure receiving option value.
 * @param[in]     sec  Current configuration section being parsed.
 * @param[in,out] seen Key occurrence tracking bitmask.
 * @param[in]     key  Configuration option name string.
 * @param[in]     val  Configuration option value string.
 * @param[in]     pamh PAM context handle for syslog reporting.
 * @return 0 on success, -1 on parsing, duplication, or format failure.
 */
static int parse_config_kv(config_t *cfg, config_section_t sec, config_seen_t *seen, const char *key, const char *val,
                           pam_handle_t *pamh) {
    for (size_t i = 0; i < (sizeof(CONFIG_KEYS) / sizeof(CONFIG_KEYS[0])); i++) {
        const config_key_spec_t *spec = &CONFIG_KEYS[i];
        if (spec->sec != sec || strcasecmp(key, spec->key) != 0) {
            continue;
        }

        if ((*seen & spec->seen_bit) != 0) {
            if (pamh) {
                pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR, "Duplicate key '%s' in configuration file",
                              key);
            }
            return -1;
        }
        *seen |= spec->seen_bit;

        /* Destination member inside cfg, located by the table's offset. */
        void *dest = (char *)cfg + spec->offset;

        switch (spec->kind) {
        case CFG_VAL_STRING:
            return copy_checked((char *)dest, spec->size, val);
        case CFG_VAL_HTTPS_URL:
        case CFG_VAL_PROXY:
            /* An empty proxy value means "no proxy" (direct routing): accept it
             * without copying; the destination keeps its default empty value. */
            if (spec->kind == CFG_VAL_PROXY && val[0] == '\0') {
                return 0;
            }
            if (!is_valid_https_url(val)) {
                if (pamh) {
                    if (spec->kind == CFG_VAL_PROXY) {
                        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                                      "proxy must be a valid https:// URL (plain-HTTP proxies are not supported)");
                    } else {
                        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR, "%s must be a valid https:// URL",
                                      spec->key);
                    }
                }
                return -1;
            }
            if (spec->reserved_note != NULL && pamh) {
                pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_INFO, LOG_INFO, "%s", spec->reserved_note);
            }
            return copy_checked((char *)dest, spec->size, val);
        case CFG_VAL_BOOL:
            return parse_bool(val, (int *)dest);
        case CFG_VAL_INT_RANGE:
            return parse_int_range(val, spec->min_val, spec->max_val, (int *)dest);
        case CFG_VAL_LOGLEVEL:
            return parse_loglevel(val, (loglevel_t *)dest);
        case CFG_VAL_PKCE_MODE:
            return parse_pkce_mode(val, (int *)dest);
        case CFG_VAL_QR_STYLE:
            return parse_qr_style(val, (qr_style_t *)dest);
        case CFG_VAL_QR_BLOCK_CHAR:
            return parse_qr_block_char(val, (char *)dest);
        case CFG_VAL_QR_EC_LEVEL:
            return parse_qr_ec_level(val, (qr_ec_t *)dest);
        case CFG_VAL_QR_URI:
            return parse_qr_uri(val, (int *)dest);
        }
        /* Unreachable: every table entry names exactly one handled kind. */
        return -1;
    }

    if (pamh) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Key '%s' is invalid or not allowed in current section", key);
    }
    return -1;
}

/**
 * @brief Parses configuration key/value pairs from an open file stream.
 *
 * Pure parsing counterpart of `load_config()`: reads lines from the supplied stream,
 * handles section headers, trims whitespace, rejects overlong lines, and dispatches
 * each key/value pair for validation and duplicate tracking. After the stream is
 * exhausted, verifies that the configured claim regex compiles and that all
 * mandatory provider settings are present. Performs no filesystem checks and no
 * stream lifecycle management (open/fclose) of its own; the caller retains
 * ownership of the stream and must close it.
 *
 * On any failure the `cfg` structure is securely zeroed before returning.
 *
 * @param[in]  fp   Opened configuration stream; the read position may be anywhere in the file.
 * @param[out] cfg  Pointer to configuration structure to populate.
 * @param[in]  pamh PAM handle for syslog logging context (optional, may be NULL).
 * @return 0 on successful parse of a complete and valid configuration, -1 on parse,
 *         validation, duplication, or EOF-with-missing-keys failure.
 */
int parse_config_file(FILE *fp, config_t *cfg, pam_handle_t *pamh) {
    if (!fp || !cfg) {
        return -1;
    }

    config_seen_t seen = 0;
    config_section_t current_sec = SEC_NONE;

    /* The read buffer must comfortably hold the longest legal config line. The largest
     * value is an [access] list field (up to ACCESS_LIST_LEN-1 chars) plus its key and
     * the '=' separator; size it accordingly so a valid long list is not misreported as
     * an overlong line. */
    char line[ACCESS_LIST_LEN + 128];
    int line_num = 0;
    int parse_failed = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        /* Detect overlong lines exceeding buffer size */
        const char *const newline = strchr(line, '\n');
        if (!newline && !feof(fp)) {
            if (pamh) {
                pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR, "Overlong line in config file at line %d",
                              line_num);
            }
            int ch;
            while ((ch = fgetc(fp)) != '\n' && ch != EOF) {
            }
            parse_failed = 1;
            break;
        }

        char *trimmed = trim_whitespace(line);
        if (trimmed[0] == '\0' || trimmed[0] == '#') {
            continue;
        }

        /* Detect section headers [section_name] */
        if (trimmed[0] == '[' && trimmed[strlen(trimmed) - 1] == ']') {
            trimmed[strlen(trimmed) - 1] = '\0';
            char *sec = trim_whitespace(trimmed + 1);
            if (strcasecmp(sec, "oauth") == 0) {
                current_sec = SEC_OAUTH;
            } else if (strcasecmp(sec, "claim") == 0) {
                current_sec = SEC_CLAIM;
            } else if (strcasecmp(sec, "access") == 0) {
                current_sec = SEC_ACCESS;
            } else if (strcasecmp(sec, "prompt") == 0) {
                current_sec = SEC_PROMPT;
            } else if (strcasecmp(sec, "runtime") == 0) {
                current_sec = SEC_RUNTIME;
            } else if (strcasecmp(sec, "qr") == 0) {
                current_sec = SEC_QR;
            } else {
                if (pamh) {
                    pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR, "Unknown section [%s] at line %d", sec,
                                  line_num);
                }
                parse_failed = 1;
                break;
            }
            continue;
        }

        if (current_sec == SEC_NONE) {
            if (pamh) {
                pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                              "Key '%s' found before any section header at line %d", trimmed, line_num);
            }
            parse_failed = 1;
            break;
        }

        char *eq = strchr(trimmed, '=');
        if (!eq) {
            if (pamh) {
                pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR, "Malformed config entry at line %d",
                              line_num);
            }
            parse_failed = 1;
            break;
        }

        *eq = '\0';
        char *key = trim_whitespace(trimmed);
        const char *const val = trim_whitespace(eq + 1);

        if (parse_config_kv(cfg, current_sec, &seen, key, val, pamh) != 0) {
            if (pamh) {
                pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR, "Failed to parse key '%s' at line %d", key,
                              line_num);
            }
            parse_failed = 1;
            break;
        }
    }

    if (ferror(fp)) {
        parse_failed = 1;
    }

    if (parse_failed) {
        secure_memzero(cfg, sizeof(config_t));
        return -1;
    }

    /* claim_regex is an explicit operator decision with no implicit default: an empty
     * value would otherwise match (or behave differently than) the operator intended,
     * and the historical default "^(.*)$" accepted any provider claim equal to the PAM
     * username. Fail the load instead. */
    if (strlen(cfg->claim_regex) == 0) {
        if (pamh) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "claim_regex must be explicitly set in the [claim] section");
        }
        secure_memzero(cfg, sizeof(config_t));
        return -1;
    }

    /* Verify regular expression syntax validity */
    regex_t reg;
    if (regcomp(&reg, cfg->claim_regex, REG_EXTENDED) != 0) {
        if (pamh) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR, "Invalid claim_regex syntax in configuration");
        }
        secure_memzero(cfg, sizeof(config_t));
        return -1;
    }
    regfree(&reg);

    /* Validate presence of mandatory provider settings */
    if (strlen(cfg->client_id) == 0 || strlen(cfg->device_authorization_endpoint) == 0 ||
        strlen(cfg->token_endpoint) == 0 || strlen(cfg->userinfo_endpoint) == 0) {
        if (pamh) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Missing required endpoint/client configuration");
        }
        secure_memzero(cfg, sizeof(config_t));
        return -1;
    }

    /* "auto" mode probes the provider at run time, so a discovery endpoint is mandatory. */
    if (cfg->use_pkce == 2 && strlen(cfg->discovery_endpoint) == 0) {
        if (pamh) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "use_pkce = auto requires a discovery_endpoint in the [oauth] section");
        }
        secure_memzero(cfg, sizeof(config_t));
        return -1;
    }

    /* JWT claim inspection is only meaningful when the expected issuer and audience
     * are both configured: with claims-only inspection (no local signature
     * verification), the iss/aud binding is the defense against tokens minted for
     * a different client or tenant, and verify_token_metadata() fails closed on an
     * unconfigured check. Reject the combination up front instead of failing every
     * authentication attempt at token-verification time. */
    if (cfg->verify_jwt_claims && (strlen(cfg->issuer) == 0 || strlen(cfg->audience) == 0)) {
        if (pamh) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "verify_jwt_claims = true requires both issuer and audience to be configured");
        }
        secure_memzero(cfg, sizeof(config_t));
        return -1;
    }

    /* An inverted system-account UID range is unsatisfiable and a configuration
     * error: reject it up front instead of silently denying (or failing to deny)
     * system accounts at authentication time. */
    if (cfg->system_uid_min > cfg->system_uid_max) {
        if (pamh) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "system_uid_min (%d) must not exceed system_uid_max (%d)", cfg->system_uid_min,
                          cfg->system_uid_max);
        }
        secure_memzero(cfg, sizeof(config_t));
        return -1;
    }

    /* Load-time PKCE advisories (emitted once per load, not per authentication attempt). */
    if (cfg->use_pkce == 1) {
        if (pamh) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_INFO, LOG_INFO,
                          "use_pkce = true: device-flow PKCE is provider-specific; confirm your provider "
                          "accepts code_challenge on the device-authorization endpoint (see "
                          "examples/README.md). Providers without device-flow PKCE support reject the "
                          "device-authorization request; set use_pkce = auto with a discovery_endpoint to "
                          "gate PKCE on live provider metadata instead");
        }
    } else if (strlen(cfg->discovery_endpoint) > 0) {
        if (pamh) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_INFO, LOG_INFO,
                          "discovery_endpoint is set but has no effect unless use_pkce = auto");
        }
    }

    return 0;
}

/**
 * @brief Opens, parses, and validates the configuration file.
 *
 * Implements filesystem hardening checks:
 * 1. Opens descriptor using `O_NOFOLLOW` and `O_CLOEXEC` to prevent symlink attacks and fd leaks.
 * 2. Confirms path refers to a regular file (`S_ISREG`).
 * 3. Enforces root ownership (`uid == 0`).
 * 4. Checks access permissions (`0600` or `0640` with root group `gid == 0`).
 * 5. Delegates line parsing, section validation, duplicate tracking, regex
 *    compilation, and required-field checks to `parse_config_file()`.
 *
 * @param[in]  path Path to configuration file.
 * @param[out] cfg  Pointer to config_t context receiving parsed settings.
 * @param[in]  pamh PAM handle context for syslog logging.
 * @return 0 on successful validation and loading, -1 on security or syntax error.
 */
int load_config(const char *path, config_t *cfg, pam_handle_t *pamh) {
    if (!path || !cfg) {
        return -1;
    }

    /* Step 1: Initialize config defaults */
    memset(cfg, 0, sizeof(config_t));
    (void)copy_checked(cfg->scopes, sizeof(cfg->scopes), "openid");
    (void)copy_checked(cfg->claim_field, sizeof(cfg->claim_field), "sub");
    /* No claim_regex default: the identity-mapping regex is required (an implicit
     * catch-all would let any provider claim that equals the PAM username map to a
     * local account). parse_config_file() rejects a missing/empty value. */
    cfg->claim_capture_group = 1;
    /* Default bounded to the PAM-safe 120 s ceiling (SSH LoginGraceTime and
     * systemd PAM timeouts are typically shorter than RFC 8628 device-code
     * lifetimes; the operator may still raise it explicitly up to 3600). */
    cfg->max_poll_seconds = 120;
    cfg->case_sensitive = 1;
    /* The device-code approval window (provider expires_in, clamped by max_poll_seconds)
     * is shown by default: the built-in default template's trailing status line carries
     * it so the user knows how long they have to complete the approval;
     * [prompt] show_expiry = false hides it. The `{expiry}` template token works in
     * any template regardless of this flag. */
    cfg->show_expiry = 1;
    cfg->loglevel = LOGLEVEL_INFO;
    /* System-account guard: deny local accounts whose numeric UID falls within the
     * conventional system range [0..999] before any provider contact; the operator
     * may disable the guard or narrow/widen the range in [access]. */
    cfg->deny_system_uids = 1;
    cfg->system_uid_min = 0;
    cfg->system_uid_max = 999;
    cfg->verify_jwt_claims = 0;
    cfg->clock_skew_leeway = 60;
    cfg->require_exp_claim = 0;
    cfg->use_pkce = 0;
    (void)copy_checked(cfg->group_claim_field, sizeof(cfg->group_claim_field), "groups");
    /* QR terminal rendering defaults: disabled, compact UTF-8 style, single-scale, medium
     * error correction, the code-embedded complete URI when the provider offers it, and the
     * ISO/IEC 18004 4-module vertical quiet zone (lowerable via vertical_quiet_zone). */
    cfg->qr_enabled = 0;
    cfg->qr_style = QR_STYLE_UTF8;
    (void)copy_checked(cfg->qr_block_char, sizeof(cfg->qr_block_char), "#");
    cfg->qr_scale = 1;
    cfg->qr_ec_level = QR_EC_MEDIUM;
    cfg->qr_uri_complete = 1;
    cfg->qr_vertical_quiet_zone = QR_QUIET_ZONE;

    pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_DEBUG, LOG_DEBUG, "Loading configuration file: %s", path);

    /* Step 2: Open file safely avoiding symlink traversal */
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (pamh) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR, "Unable to open configuration file %s", path);
        }
        return -1;
    }

    /* Step 3: Verify file type is a regular file */
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        if (pamh) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR, "Config file %s must be a regular file", path);
        }
        close(fd);
        return -1;
    }

    /* Step 4: Verify root ownership */
    if (st.st_uid != 0) {
        if (pamh) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR, "Config file %s must be owned by root (uid 0)",
                          path);
        }
        close(fd);
        return -1;
    }

    /* Step 5: Enforce strict file permissions */
    mode_t mode = st.st_mode & (mode_t)0777;
    if (mode != (mode_t)0600 && mode != (mode_t)0640) {
        if (pamh) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Insecure permissions on %s (must be 0600 or 0640)", path);
        }
        close(fd);
        return -1;
    }

    if (mode == (mode_t)0640 && st.st_gid != 0) {
        if (pamh) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Config group owner must be root (gid 0) when mode is 0640");
        }
        close(fd);
        return -1;
    }

    FILE *f = fdopen(fd, "r");
    if (!f) {
        close(fd);
        return -1;
    }

    /* Step 6: Parse, validate, and enforce required fields from the stream */
    int parse_result = parse_config_file(f, cfg, pamh);
    fclose(f);

    if (parse_result != 0) {
        return -1;
    }

    pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                  "Configuration file %s parsed and validated successfully", path);

    return 0;
}
