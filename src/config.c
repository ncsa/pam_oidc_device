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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * @struct config_seen_t
 * @brief Bitfield structure tracking seen configuration keys to reject duplicate key definitions.
 */
typedef struct {
    unsigned int client_id : 1;                     /**< Flag set when client_id key is parsed. */
    unsigned int client_secret : 1;                 /**< Flag set when client_secret key is parsed. */
    unsigned int device_authorization_endpoint : 1; /**< Flag set when device_authorization_endpoint key is parsed. */
    unsigned int token_endpoint : 1;                /**< Flag set when token_endpoint key is parsed. */
    unsigned int userinfo_endpoint : 1;             /**< Flag set when userinfo_endpoint key is parsed. */
    unsigned int scopes : 1;                        /**< Flag set when scopes key is parsed. */
    unsigned int claim_field : 1;                   /**< Flag set when claim_field key is parsed. */
    unsigned int claim_regex : 1;                   /**< Flag set when claim_regex key is parsed. */
    unsigned int claim_capture_group : 1;           /**< Flag set when claim_capture_group key is parsed. */
    unsigned int max_poll_seconds : 1;              /**< Flag set when max_poll_seconds key is parsed. */
    unsigned int init_message : 1;                  /**< Flag set when init_message key is parsed. */
    unsigned int show_countdown : 1;                /**< Flag set when show_countdown key is parsed. */
    unsigned int case_sensitive : 1;                /**< Flag set when case_sensitive key is parsed. */
    unsigned int loglevel : 1;                      /**< Flag set when loglevel key is parsed. */
    unsigned int issuer : 1;                        /**< Flag set when issuer key is parsed. */
    unsigned int audience : 1;                      /**< Flag set when audience key is parsed. */
    unsigned int jwks_url : 1;                      /**< Flag set when jwks_url key is parsed. */
    unsigned int introspection_endpoint : 1;        /**< Flag set when introspection_endpoint key is parsed. */
    unsigned int verify_jwt_claims : 1;             /**< Flag set when verify_jwt_claims key is parsed. */
    unsigned int clock_skew_leeway : 1;             /**< Flag set when clock_skew_leeway key is parsed. */
    unsigned int require_exp_claim : 1;             /**< Flag set when require_exp_claim key is parsed. */
    unsigned int allow_users : 1;                   /**< Flag set when allow_users key is parsed. */
    unsigned int deny_users : 1;                    /**< Flag set when deny_users key is parsed. */
    unsigned int allow_root : 1;                    /**< Flag set when allow_root key is parsed. */
    unsigned int allow_groups : 1;                  /**< Flag set when allow_groups key is parsed. */
    unsigned int deny_groups : 1;                   /**< Flag set when deny_groups key is parsed. */
    unsigned int enforce_groups : 1;                /**< Flag set when enforce_groups key is parsed. */
    unsigned int group_claim_field : 1;             /**< Flag set when group_claim_field key is parsed. */
    unsigned int use_pkce : 1;                      /**< Flag set when use_pkce key is parsed. */
    unsigned int discovery_endpoint : 1;            /**< Flag set when discovery_endpoint key is parsed. */
    unsigned int qr_enabled : 1;                    /**< Flag set when qr `enabled` key is parsed. */
    unsigned int qr_style : 1;                      /**< Flag set when qr `style` key is parsed. */
    unsigned int qr_block_char : 1;                 /**< Flag set when qr `block_char` key is parsed. */
    unsigned int qr_scale : 1;                      /**< Flag set when qr `scale` key is parsed. */
    unsigned int qr_ec_level : 1;                   /**< Flag set when qr `ec_level` key is parsed. */
    unsigned int qr_uri : 1;                        /**< Flag set when qr `uri` key is parsed. */
} config_seen_t;

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
 * @brief Processes a single key-value configuration pair for a given section.
 *
 * Enforces key uniqueness via duplicate detection bitfield flags (`seen`).
 *
 * @param[in,out] cfg  Configuration structure receiving option value.
 * @param[in]     sec  Current configuration section being parsed.
 * @param[in,out] seen Key occurrence tracking structure.
 * @param[in]     key  Configuration option name string.
 * @param[in]     val  Configuration option value string.
 * @param[in]     pamh PAM context handle for syslog reporting.
 * @return 0 on success, -1 on parsing, duplication, or format failure.
 */
static int parse_config_kv(config_t *cfg, config_section_t sec, config_seen_t *seen, const char *key, const char *val,
                           pam_handle_t *pamh) {
    if (sec == SEC_OAUTH) {
        if (strcasecmp(key, "client_id") == 0) {
            if (seen->client_id) {
                goto duplicate_key;
            }
            seen->client_id = 1;
            return copy_checked(cfg->client_id, sizeof(cfg->client_id), val);
        } else if (strcasecmp(key, "client_secret") == 0) {
            if (seen->client_secret) {
                goto duplicate_key;
            }
            seen->client_secret = 1;
            return copy_checked(cfg->client_secret, sizeof(cfg->client_secret), val);
        } else if (strcasecmp(key, "device_authorization_endpoint") == 0) {
            if (seen->device_authorization_endpoint) {
                goto duplicate_key;
            }
            seen->device_authorization_endpoint = 1;
            if (!is_valid_https_url(val)) {
                if (pamh) {
                    pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                                  "device_authorization_endpoint must be a valid https:// URL");
                }
                return -1;
            }
            return copy_checked(cfg->device_authorization_endpoint, sizeof(cfg->device_authorization_endpoint), val);
        } else if (strcasecmp(key, "token_endpoint") == 0) {
            if (seen->token_endpoint) {
                goto duplicate_key;
            }
            seen->token_endpoint = 1;
            if (!is_valid_https_url(val)) {
                if (pamh) {
                    pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                                  "token_endpoint must be a valid https:// URL");
                }
                return -1;
            }
            return copy_checked(cfg->token_endpoint, sizeof(cfg->token_endpoint), val);
        } else if (strcasecmp(key, "userinfo_endpoint") == 0) {
            if (seen->userinfo_endpoint) {
                goto duplicate_key;
            }
            seen->userinfo_endpoint = 1;
            if (!is_valid_https_url(val)) {
                if (pamh) {
                    pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                                  "userinfo_endpoint must be a valid https:// URL");
                }
                return -1;
            }
            return copy_checked(cfg->userinfo_endpoint, sizeof(cfg->userinfo_endpoint), val);
        } else if (strcasecmp(key, "scopes") == 0) {
            if (seen->scopes) {
                goto duplicate_key;
            }
            seen->scopes = 1;
            return copy_checked(cfg->scopes, sizeof(cfg->scopes), val);
        } else if (strcasecmp(key, "issuer") == 0) {
            if (seen->issuer) {
                goto duplicate_key;
            }
            seen->issuer = 1;
            return copy_checked(cfg->issuer, sizeof(cfg->issuer), val);
        } else if (strcasecmp(key, "audience") == 0) {
            if (seen->audience) {
                goto duplicate_key;
            }
            seen->audience = 1;
            return copy_checked(cfg->audience, sizeof(cfg->audience), val);
        } else if (strcasecmp(key, "jwks_url") == 0) {
            if (seen->jwks_url) {
                goto duplicate_key;
            }
            seen->jwks_url = 1;
            if (!is_valid_https_url(val)) {
                if (pamh) {
                    pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                                  "jwks_url must be a valid https:// URL");
                }
                return -1;
            }
            if (pamh) {
                pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_INFO, LOG_INFO,
                              "jwks_url is accepted but unused: JWKS-based JWT signature verification is not currently "
                              "performed; token validity is enforced by the UserInfo endpoint");
            }
            return copy_checked(cfg->jwks_url, sizeof(cfg->jwks_url), val);
        } else if (strcasecmp(key, "introspection_endpoint") == 0) {
            if (seen->introspection_endpoint) {
                goto duplicate_key;
            }
            seen->introspection_endpoint = 1;
            if (!is_valid_https_url(val)) {
                if (pamh) {
                    pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                                  "introspection_endpoint must be a valid https:// URL");
                }
                return -1;
            }
            if (pamh) {
                pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_INFO, LOG_INFO,
                              "introspection_endpoint is accepted but unused: RFC 7662 token introspection is not "
                              "currently performed; token validity is enforced by the UserInfo endpoint");
            }
            return copy_checked(cfg->introspection_endpoint, sizeof(cfg->introspection_endpoint), val);
        } else if (strcasecmp(key, "verify_jwt_claims") == 0) {
            if (seen->verify_jwt_claims) {
                goto duplicate_key;
            }
            seen->verify_jwt_claims = 1;
            return parse_bool(val, &cfg->verify_jwt_claims);
        } else if (strcasecmp(key, "clock_skew_leeway") == 0) {
            if (seen->clock_skew_leeway) {
                goto duplicate_key;
            }
            seen->clock_skew_leeway = 1;
            return parse_int_range(val, 0, 300, &cfg->clock_skew_leeway);
        } else if (strcasecmp(key, "require_exp_claim") == 0) {
            if (seen->require_exp_claim) {
                goto duplicate_key;
            }
            seen->require_exp_claim = 1;
            return parse_bool(val, &cfg->require_exp_claim);
        } else if (strcasecmp(key, "use_pkce") == 0) {
            if (seen->use_pkce) {
                goto duplicate_key;
            }
            seen->use_pkce = 1;
            return parse_pkce_mode(val, &cfg->use_pkce);
        } else if (strcasecmp(key, "discovery_endpoint") == 0) {
            if (seen->discovery_endpoint) {
                goto duplicate_key;
            }
            seen->discovery_endpoint = 1;
            if (!is_valid_https_url(val)) {
                if (pamh) {
                    pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                                  "discovery_endpoint must be a valid https:// URL");
                }
                return -1;
            }
            return copy_checked(cfg->discovery_endpoint, sizeof(cfg->discovery_endpoint), val);
        }
    } else if (sec == SEC_CLAIM) {
        if (strcasecmp(key, "claim_field") == 0) {
            if (seen->claim_field) {
                goto duplicate_key;
            }
            seen->claim_field = 1;
            return copy_checked(cfg->claim_field, sizeof(cfg->claim_field), val);
        } else if (strcasecmp(key, "claim_regex") == 0) {
            if (seen->claim_regex) {
                goto duplicate_key;
            }
            seen->claim_regex = 1;
            return copy_checked(cfg->claim_regex, sizeof(cfg->claim_regex), val);
        } else if (strcasecmp(key, "claim_capture_group") == 0) {
            if (seen->claim_capture_group) {
                goto duplicate_key;
            }
            seen->claim_capture_group = 1;
            return parse_int_range(val, 0, 32, &cfg->claim_capture_group);
        } else if (strcasecmp(key, "case_sensitive") == 0) {
            if (seen->case_sensitive) {
                goto duplicate_key;
            }
            seen->case_sensitive = 1;
            return parse_bool(val, &cfg->case_sensitive);
        }
    } else if (sec == SEC_ACCESS) {
        if (strcasecmp(key, "allow_users") == 0) {
            if (seen->allow_users) {
                goto duplicate_key;
            }
            seen->allow_users = 1;
            return copy_checked(cfg->allow_users, sizeof(cfg->allow_users), val);
        } else if (strcasecmp(key, "deny_users") == 0) {
            if (seen->deny_users) {
                goto duplicate_key;
            }
            seen->deny_users = 1;
            return copy_checked(cfg->deny_users, sizeof(cfg->deny_users), val);
        } else if (strcasecmp(key, "allow_root") == 0) {
            if (seen->allow_root) {
                goto duplicate_key;
            }
            seen->allow_root = 1;
            return parse_bool(val, &cfg->allow_root);
        } else if (strcasecmp(key, "allow_groups") == 0) {
            if (seen->allow_groups) {
                goto duplicate_key;
            }
            seen->allow_groups = 1;
            return copy_checked(cfg->allow_groups, sizeof(cfg->allow_groups), val);
        } else if (strcasecmp(key, "deny_groups") == 0) {
            if (seen->deny_groups) {
                goto duplicate_key;
            }
            seen->deny_groups = 1;
            return copy_checked(cfg->deny_groups, sizeof(cfg->deny_groups), val);
        } else if (strcasecmp(key, "enforce_groups") == 0) {
            if (seen->enforce_groups) {
                goto duplicate_key;
            }
            seen->enforce_groups = 1;
            return parse_bool(val, &cfg->enforce_groups);
        } else if (strcasecmp(key, "group_claim_field") == 0) {
            if (seen->group_claim_field) {
                goto duplicate_key;
            }
            seen->group_claim_field = 1;
            return copy_checked(cfg->group_claim_field, sizeof(cfg->group_claim_field), val);
        }
    } else if (sec == SEC_PROMPT) {
        if (strcasecmp(key, "init_message") == 0) {
            if (seen->init_message) {
                goto duplicate_key;
            }
            seen->init_message = 1;
            return copy_checked(cfg->init_message, sizeof(cfg->init_message), val);
        } else if (strcasecmp(key, "show_countdown") == 0) {
            if (seen->show_countdown) {
                goto duplicate_key;
            }
            seen->show_countdown = 1;
            return parse_bool(val, &cfg->show_countdown);
        }
    } else if (sec == SEC_RUNTIME) {
        if (strcasecmp(key, "max_poll_seconds") == 0) {
            if (seen->max_poll_seconds) {
                goto duplicate_key;
            }
            seen->max_poll_seconds = 1;
            return parse_int_range(val, 10, 3600, &cfg->max_poll_seconds);
        } else if (strcasecmp(key, "loglevel") == 0) {
            if (seen->loglevel) {
                goto duplicate_key;
            }
            seen->loglevel = 1;
            return parse_loglevel(val, &cfg->loglevel);
        }
    } else if (sec == SEC_QR) {
        if (strcasecmp(key, "enabled") == 0) {
            if (seen->qr_enabled) {
                goto duplicate_key;
            }
            seen->qr_enabled = 1;
            return parse_bool(val, &cfg->qr_enabled);
        } else if (strcasecmp(key, "style") == 0) {
            if (seen->qr_style) {
                goto duplicate_key;
            }
            seen->qr_style = 1;
            return parse_qr_style(val, &cfg->qr_style);
        } else if (strcasecmp(key, "block_char") == 0) {
            if (seen->qr_block_char) {
                goto duplicate_key;
            }
            seen->qr_block_char = 1;
            return parse_qr_block_char(val, cfg->qr_block_char);
        } else if (strcasecmp(key, "scale") == 0) {
            if (seen->qr_scale) {
                goto duplicate_key;
            }
            seen->qr_scale = 1;
            return parse_int_range(val, 1, 3, &cfg->qr_scale);
        } else if (strcasecmp(key, "ec_level") == 0) {
            if (seen->qr_ec_level) {
                goto duplicate_key;
            }
            seen->qr_ec_level = 1;
            return parse_qr_ec_level(val, &cfg->qr_ec_level);
        } else if (strcasecmp(key, "uri") == 0) {
            if (seen->qr_uri) {
                goto duplicate_key;
            }
            seen->qr_uri = 1;
            return parse_qr_uri(val, &cfg->qr_uri_complete);
        }
    }

    if (pamh) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Key '%s' is invalid or not allowed in current section", key);
    }
    return -1;

duplicate_key:
    if (pamh) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR, "Duplicate key '%s' in configuration file", key);
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

    config_seen_t seen;
    memset(&seen, 0, sizeof(seen));
    config_section_t current_sec = SEC_NONE;

    char line[MAX_INIT_MSG_LEN + 128];
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
    (void)copy_checked(cfg->claim_regex, sizeof(cfg->claim_regex), "^(.*)$");
    cfg->claim_capture_group = 1;
    cfg->max_poll_seconds = 300;
    cfg->show_countdown = 0;
    cfg->case_sensitive = 1;
    cfg->loglevel = LOGLEVEL_INFO;
    cfg->verify_jwt_claims = 0;
    cfg->clock_skew_leeway = 60;
    cfg->require_exp_claim = 0;
    cfg->use_pkce = 0;
    (void)copy_checked(cfg->group_claim_field, sizeof(cfg->group_claim_field), "groups");
    /* QR terminal rendering defaults: disabled, compact UTF-8 style, single-scale, medium
     * error correction, and the code-embedded complete URI when the provider offers it. */
    cfg->qr_enabled = 0;
    cfg->qr_style = QR_STYLE_UTF8;
    (void)copy_checked(cfg->qr_block_char, sizeof(cfg->qr_block_char), "#");
    cfg->qr_scale = 1;
    cfg->qr_ec_level = QR_EC_MEDIUM;
    cfg->qr_uri_complete = 1;

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
