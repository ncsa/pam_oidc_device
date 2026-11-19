/**
 * @file identity.c
 * @brief User identity claim mapping, level-filtered audit logging, and regular expression verification routines.
 *
 * This module extracts user identifiers from OAuth 2.0 / OpenID Connect claim fields
 * returned by the UserInfo endpoint, applies regular expression capture groups, compares
 * the extracted identity against the requesting PAM local user account name, and enforces group/role membership.
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
#include "device_flow.h"
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * @brief Case-insensitive ASCII string comparison helper.
 *
 * Performs character-by-character comparison converted to lowercase. Avoids locale-dependent behavior
 * of standard `strcasecmp` to enforce deterministic ASCII account matching.
 *
 * @param[in] s1 First string pointer.
 * @param[in] s2 Second string pointer.
 * @return Integer less than, equal to, or greater than zero if s1 is found to be less than, match, or exceed s2.
 */
static int ascii_strcasecmp(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        if (tolower((unsigned char)*s1) != tolower((unsigned char)*s2)) {
            return tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
        }
        s1++;
        s2++;
    }
    return tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
}

/**
 * @brief Tests whether a target string is present in a comma-separated list.
 *
 * Splits `list` on commas, trims surrounding whitespace from each token, and compares
 * against `target` using either exact or case-insensitive ASCII matching. Empty tokens
 * are ignored, so trailing/leading commas do not produce spurious matches.
 *
 * Length handling: `list` is copied into a stack buffer sized to `ACCESS_LIST_LEN`
 * so `strtok_r()` can split it in place without mutating the caller's (const, reused)
 * config string. This buffer is deliberately the same bound as the `config_t` list
 * fields it always feeds (the user/group allow/deny lists), so a validly parsed list
 * always fits here and matching works end to end. A list whose length reaches that
 * bound is REJECTED, not truncated: `copy_checked()` reports the overflow and this
 * function returns 0 (no match), so a partial token can never spuriously match. That
 * is fail-safe for allow lists (an over-long allow list matches nothing, so the
 * account is refused). For a deny list the same bound is, in principle, a fail-open
 * (an over-long deny list is simply not applied) — but every current caller passes one
 * of the `ACCESS_LIST_LEN`-byte `config_t` list fields, which the config loader already
 * bounds to the same length, so the cap is a defense-in-depth backstop that is
 * unreachable through the normal config path; it keeps the function safe even if it
 * were ever called with an arbitrary-length list, and keeps stack usage bounded.
 *
 * @param[in] list           Comma-separated candidate list.
 * @param[in] target         Value to search for.
 * @param[in] case_sensitive 1 for exact comparison, 0 for case-insensitive comparison.
 * @return 1 if `target` matches any token, 0 otherwise.
 */
static int list_contains(const char *list, const char *target, int case_sensitive) {
    if (!list || !target || target[0] == '\0') {
        return 0;
    }
    char buf[ACCESS_LIST_LEN];
    if (copy_checked(buf, sizeof(buf), list) != 0) {
        return 0;
    }
    char *saveptr = NULL;
    char *token = strtok_r(buf, ",", &saveptr);
    while (token) {
        while (isspace((unsigned char)*token)) {
            token++;
        }
        char *end = token + strlen(token) - 1;
        while (end > token && isspace((unsigned char)*end)) {
            *end = '\0';
            end--;
        }
        if (token[0] != '\0' &&
            (case_sensitive ? (strcmp(token, target) == 0) : (ascii_strcasecmp(token, target) == 0))) {
            return 1;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
    return 0;
}

/**
 * @brief Validates whether an OpenID claim matches a target local PAM username.
 *
 * Compiles configured regex rules (`claim_regex`), extracts specified capture group slice (`claim_capture_group`),
 * and compares the result against `pam_user` using configured case sensitivity settings.
 *
 * @param[in] pam_user  Local POSIX user account name requesting authentication.
 * @param[in] raw_claim Identity claim value retrieved from provider UserInfo endpoint.
 * @param[in] cfg       Module configuration parameters containing active log level threshold.
 * @param[in] pamh      PAM handle used for emitting system log errors.
 * @return 1 if identity claim matches PAM user account, 0 otherwise.
 */
int verify_claim(const char *pam_user, const char *raw_claim, const config_t *cfg, pam_handle_t *pamh) {
    /* Step 1: Validate parameter pointers and ensure non-empty inputs */
    if (!pam_user || !raw_claim || !cfg || strlen(pam_user) == 0 || strlen(raw_claim) == 0) {
        return 0;
    }

    /* The raw claim value is PII: log it only at VERBOSE, never at DEBUG, consistent with the
     * redacted (size + claim field) DEBUG-level UserInfo receipt in pam_sm_authenticate(). */
    pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_VERBOSE, LOG_DEBUG,
                  "Verifying claim field '%s' (raw value: '%s') for user '%s'", cfg->claim_field, raw_claim, pam_user);

    /* Step 2: Compile user-specified POSIX extended regular expression pattern */
    regex_t regex;
    int reg_res = regcomp(&regex, cfg->claim_regex, REG_EXTENDED);
    if (reg_res != 0) {
        if (pamh) {
            char err_buf[128];
            regerror(reg_res, &regex, err_buf, sizeof(err_buf));
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR, "Regex compilation failed for pattern '%s': %s",
                          cfg->claim_regex, err_buf);
        }
        return 0;
    }

    /* Step 3: Ensure requested capture group index does not exceed regex pattern capacity */
    if ((size_t)cfg->claim_capture_group > regex.re_nsub) {
        if (pamh) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Configured capture group %d exceeds regex capture group count %zu", cfg->claim_capture_group,
                          regex.re_nsub);
        }
        regfree(&regex);
        return 0;
    }

    /* Step 4: Allocate match array structure to hold target capture group matches */
    size_t max_matches = (size_t)cfg->claim_capture_group + 1U;
    regmatch_t *matches = calloc(max_matches, sizeof(regmatch_t));
    if (!matches) {
        regfree(&regex);
        return 0;
    }

    /* Initialize match offsets to invalid state */
    for (size_t i = 0; i < max_matches; i++) {
        matches[i].rm_so = -1;
        matches[i].rm_eo = -1;
    }

    /* Step 5: Execute regex against raw identity claim */
    if (regexec(&regex, raw_claim, max_matches, matches, 0) != 0) {
        /* PII: below VERBOSE the raw claim value is never logged; its length is. */
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                      "Regex pattern '%s' failed to match claim value (length %zu)", cfg->claim_regex,
                      strlen(raw_claim));
        free(matches);
        regfree(&regex);
        return 0;
    }

    /* Step 6: Verify capture group offset validity and extract matched substring slice */
    int group = cfg->claim_capture_group;
    if (matches[group].rm_so == -1 || matches[group].rm_eo == -1 || matches[group].rm_eo <= matches[group].rm_so) {
        free(matches);
        regfree(&regex);
        return 0;
    }

    size_t extracted_len = (size_t)(matches[group].rm_eo - matches[group].rm_so);
    char extracted_claim[256] = {0};

    /* Protect against destination extraction buffer overflows */
    if (extracted_len >= sizeof(extracted_claim)) {
        free(matches);
        regfree(&regex);
        return 0;
    }

    memcpy(extracted_claim, raw_claim + matches[group].rm_so, extracted_len);
    extracted_claim[extracted_len] = '\0';

    /* Step 7: Release regex resources prior to string comparison */
    free(matches);
    regfree(&regex);

    /* Step 8: Compare extracted identity claim against target PAM user */
    int matched = 0;
    if (cfg->case_sensitive) {
        matched = (strcmp(pam_user, extracted_claim) == 0);
    } else {
        matched = (ascii_strcasecmp(pam_user, extracted_claim) == 0);
    }

    if (matched) {
        /* PII: below VERBOSE the extracted identity value is never logged;
         * its length is (consistent with the policy note at the top of
         * this function). */
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                      "Claim mapping verified: extracted identity (length %zu) matches user '%s'", extracted_len,
                      pam_user);
    } else {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Claim mapping mismatch: extracted identity (length %zu) does not match user '%s'", extracted_len,
                      pam_user);
    }

    return matched;
}

/* The uid lookup in verify_user_access() runs getpwnam_r() against a heap buffer that
 * starts at PWNAM_BUF_INITIAL_LEN (or the platform's _SC_GETPW_R_SIZE_MAX hint, when it is
 * defined and sane) and doubles on ERANGE up to PWNAM_BUF_MAX_LEN, so that accounts whose
 * passwd entry exceeds any fixed buffer (LDAP/SSSD records with long GECOS strings or home
 * paths) are not refused. 1 MiB far exceeds any realistic passwd entry, so the cap also
 * bounds a pathological backend that would otherwise report ERANGE indefinitely; a record
 * that still does not fit there is reported as a genuine lookup error. */
#define PWNAM_BUF_INITIAL_LEN 4096
#define PWNAM_BUF_MAX_LEN 1048576 /* 1 MiB */

/**
 * @brief Enforces local account allow/deny list controls against the requesting PAM username.
 *
 * Evaluates the configured `deny_users` and `allow_users` lists for the requesting local
 * account. Denial lists take precedence over allow lists; empty lists impose no restriction.
 * Any uid-0 account (the account named `root` plus any alternative uid-0 name, e.g. "toor")
 * is additionally denied unless `cfg->allow_root` is explicitly set, independent of the
 * allow/deny lists. Independently, when `cfg->deny_system_uids` is enabled, any local
 * account whose numeric UID falls within [system_uid_min, system_uid_max] is denied
 * regardless of the allow/deny lists (the guard targets the UID, not the name); a uid-0
 * account already exempted via `allow_root` is not re-denied by this range guard.
 *
 * The requesting account is resolved to a numeric UID once, up front. A name that resolves
 * to no local account is simply not subject to the UID gates (it cannot hold a local uid);
 * but if the lookup *itself* fails (out of memory, a backend that keeps reporting `ERANGE`
 * past the buffer-growth cap, or an NSS/DB outage), the uid cannot be established and every
 * active UID gate fails closed with a refusal, rather than being silently skipped.
 *
 * @param[in] pam_user  Target POSIX system username.
 * @param[in] cfg       Module configuration parameters containing the account lists and
 *                      the uid-range guard settings.
 * @param[in] pamh      PAM handle used for emitting system log messages.
 * @return 1 if the account is permitted to authenticate, 0 if it is denied.
 */
int verify_user_access(const char *pam_user, const config_t *cfg, pam_handle_t *pamh) {
    if (!pam_user || !cfg) {
        return 0;
    }
    int cs = cfg->case_sensitive;

    /* Resolve the requesting account to its numeric uid once, up front, so the uid-0 gate
     * and the system-uid range guard below share a single, well-defined result. Three
     * outcomes are distinguished:
     *   PWNAM_FOUND:      the name maps to a local account; acct_uid is valid.
     *   PWNAM_NOT_FOUND:  the name resolves to no local account (getpwnam_r() reported
     *                     success with no record, or an NSS module signalled ENOENT).
     *                     Such a name cannot hold a local uid-0 or in-range uid, so
     *                     neither gate applies and the user lists still decide.
     *   PWNAM_ERROR:      the lookup itself failed (out of memory, persistent ERANGE past
     *                     the buffer cap, an NSS/DB outage, ...). The account's uid cannot
     *                     be established, so each active gate fails closed instead of being
     *                     silently skipped. */
    enum { PWNAM_FOUND, PWNAM_NOT_FOUND, PWNAM_ERROR } pwnam_state;
    uid_t acct_uid = 0;
    int lookup_errno = 0;
    if (strcmp(pam_user, "root") == 0) {
        pwnam_state = PWNAM_FOUND;
        acct_uid = 0;
    } else {
        struct passwd pw;
        struct passwd *pw_res = NULL;
        char *pw_buf = NULL;

        /* NSS backends (LDAP/SSSD) can hold passwd entries larger than any fixed stack
         * buffer can hold: a long GECOS string or home path pushes the record past
         * PWNAM_BUF_INITIAL_LEN and getpwnam_r() reports ERANGE for it. Refusing on that
         * raw error would lock out every legitimate account with a large entry while any
         * uid gate is active, so the lookup starts at the platform's
         * _SC_GETPW_R_SIZE_MAX hint (PWNAM_BUF_INITIAL_LEN where the constant is
         * undefined, e.g. glibc) and retries ERANGE with a doubling heap buffer up to
         * PWNAM_BUF_MAX_LEN. A record that still does not fit there (or a backend that
         * keeps reporting ERANGE) is not a realistic passwd entry: the lookup is
         * reported as a genuine error and each active uid gate keeps its fail-closed
         * behavior. */
        long hint = sysconf(_SC_GETPW_R_SIZE_MAX);
        size_t pw_buf_len = (hint > 0 && hint <= PWNAM_BUF_MAX_LEN) ? (size_t)hint : PWNAM_BUF_INITIAL_LEN;
        pw_buf = malloc(pw_buf_len);
        if (pw_buf == NULL) {
            pwnam_state = PWNAM_ERROR;
            lookup_errno = ENOMEM;
        } else {
            int rc = 0;
            do {
                rc = getpwnam_r(pam_user, &pw, pw_buf, pw_buf_len, &pw_res);
                if (rc != ERANGE || pw_buf_len >= PWNAM_BUF_MAX_LEN) {
                    break;
                }
                size_t next_len = pw_buf_len * 2;
                char *grown = realloc(pw_buf, next_len);
                if (grown == NULL) {
                    rc = ENOMEM;
                    break;
                }
                /* On realloc failure the original allocation is still owned by pw_buf
                 * and is released by the free() below. */
                pw_buf = grown;
                pw_buf_len = next_len;
            } while (1);
            free(pw_buf);
            if (rc == 0) {
                if (pw_res != NULL) {
                    pwnam_state = PWNAM_FOUND;
                    acct_uid = pw_res->pw_uid;
                } else {
                    pwnam_state = PWNAM_NOT_FOUND;
                }
            } else if (rc == ENOENT) {
                /* Some NSS backends report "no such account" via errno instead of a NULL
                 * result; treat it identically to the success-with-no-record case. */
                pwnam_state = PWNAM_NOT_FOUND;
            } else {
                pwnam_state = PWNAM_ERROR;
                lookup_errno = rc;
            }
        }
    }

    /* Denial lists take precedence over allow lists. */
    if (strlen(cfg->deny_users) > 0 && list_contains(cfg->deny_users, pam_user, cs)) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Account '%s' is explicitly denied via deny_users; authentication refused", pam_user);
        return 0;
    }

    /* Root (uid 0) is denied by default and requires an explicit 'allow_root' opt-in. The
     * guard targets uid 0, not the name "root": an alternative uid-0 account (e.g. "toor")
     * is refused identically. This runs regardless of allow_users/deny_users so that
     * listing "root" in allow_users alone never grants root authentication. A name that
     * resolves to no local account cannot be a local uid-0 account (uid-0 accounts always
     * exist in the account database), so it is not refused here; the user lists still
     * apply. If the lookup itself errors, the uid cannot be established and the gate
     * fails closed. */
    if (!cfg->allow_root) {
        int uid0_account = (pwnam_state == PWNAM_FOUND && acct_uid == 0);
        if (uid0_account) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Uid-0 account '%s' is refused: set 'allow_root = true' in [access] to permit root "
                          "authentication via this module",
                          pam_user);
            return 0;
        }
        if (pwnam_state == PWNAM_ERROR) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Cannot verify whether '%s' is a uid-0 account (local account lookup failed, error %d); "
                          "refusing authentication fail-closed: repair the local account database or set "
                          "'allow_root = true' in [access] to disable this gate",
                          pam_user, lookup_errno);
            return 0;
        }
    }

    /* System-account guard: deny local accounts whose numeric uid falls within
     * [system_uid_min, system_uid_max] (default: the conventional system range 0-999)
     * before any provider contact. Like the uid-0 gate above, the guard targets the
     * uid, not the name: any account holding an in-range uid (e.g. a long-lived
     * application or service account) is refused regardless of allow_users. A name
     * that resolves to no local account cannot hold an in-range uid, so it is not
     * refused here; the user lists still apply. A uid-0 account already permitted via
     * the explicit allow_root opt-in is exempt from this second gate. An inverted
     * range is unsatisfiable (load_config() rejects it) and is treated as inactive.
     * If the lookup itself errors, the uid cannot be established and the gate fails
     * closed. */
    if (cfg->deny_system_uids && cfg->system_uid_min <= cfg->system_uid_max) {
        if (pwnam_state == PWNAM_FOUND) {
            if (acct_uid >= (uid_t)cfg->system_uid_min && acct_uid <= (uid_t)cfg->system_uid_max &&
                !(acct_uid == 0 && cfg->allow_root)) {
                pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                              "Account '%s' (uid %u) is refused: uid falls within the denied system-account range "
                              "[%d..%d] (deny_system_uids); adjust the range or set 'deny_system_uids = false' in "
                              "[access] to permit this account",
                              pam_user, (unsigned int)acct_uid, cfg->system_uid_min, cfg->system_uid_max);
                return 0;
            }
        } else if (pwnam_state == PWNAM_ERROR) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Cannot verify '%s''s uid against the denied system-account range [%d..%d] (local account "
                          "lookup failed, error %d); refusing authentication fail-closed: repair the local account "
                          "database or set 'deny_system_uids = false' in [access] to disable this gate",
                          pam_user, cfg->system_uid_min, cfg->system_uid_max, lookup_errno);
            return 0;
        }
        /* PWNAM_NOT_FOUND: the name holds no local uid, so it cannot fall within the
         * denied range; the user lists still apply. */
    }

    if (strlen(cfg->allow_users) > 0 && !list_contains(cfg->allow_users, pam_user, cs)) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Account '%s' is not present in allow_users; authentication refused", pam_user);
        return 0;
    }

    if (strlen(cfg->allow_users) > 0) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                      "Account '%s' passed local allow_users/deny_users access control", pam_user);
    }
    return 1;
}

/**
 * @brief Determines whether a single group/role value matches the configured deny list.
 *
 * @param[in] val            Provider group/role value.
 * @param[in] cfg            Active module configuration settings.
 * @param[in] case_sensitive 1 for exact comparison, 0 for case-insensitive comparison.
 * @return 1 if the value is present in `deny_groups`, 0 otherwise.
 */
static int group_value_denied(const char *val, const config_t *cfg, int case_sensitive) {
    return list_contains(cfg->deny_groups, val, case_sensitive);
}

/**
 * @brief Determines whether a single group/role value satisfies the configured allow set.
 *
 * The allow set is the `allow_groups` list.
 *
 * @param[in] val            Provider group/role value.
 * @param[in] cfg            Active module configuration settings.
 * @param[in] case_sensitive 1 for exact comparison, 0 for case-insensitive comparison.
 * @return 1 if the value is permitted by the allow set, 0 otherwise.
 */
static int group_value_allowed(const char *val, const config_t *cfg, int case_sensitive) {
    if (list_contains(cfg->allow_groups, val, case_sensitive)) {
        return 1;
    }
    return 0;
}

/**
 * @brief Evaluates array or string claims (e.g., `groups` or `roles`) to enforce group authorization.
 *
 * Enforces the configured `allow_groups`/`deny_groups` lists against the UserInfo group/role claim
 * located under `cfg->group_claim_field`. Supports JSON arrays of strings, single strings, and
 * comma-delimited strings. Denial lists take precedence over allow lists.
 *
 * Fail-closed when any group policy is active: if the UserInfo payload is unusable, the claim
 * is absent or JSON null, the claim has an unrecognized type, an array element is not a string
 * (with a deny list configured), or a comma-delimited string cannot be fully parsed, access is
 * refused. Group membership that cannot be established is treated as "no match", which denies
 * under both allow-only and deny-only policies.
 *
 * Group authorization is active when `enforce_groups` is enabled or any group list is populated;
 * otherwise it is bypassed entirely.
 *
 * @param[in] uinfo_json Parsed JSON payload object from provider UserInfo response.
 * @param[in] cfg        Active module configuration settings.
 * @param[in] pamh       PAM handle used for emitting system log messages.
 * @return 1 if group authorization succeeds or is not configured, 0 if permission is denied.
 */
int verify_group_membership(const struct json_object *uinfo_json, const config_t *cfg, pam_handle_t *pamh) {
    if (!cfg) {
        return 0;
    }

    int allow_active = strlen(cfg->allow_groups) > 0;
    int deny_active = strlen(cfg->deny_groups) > 0;
    int active = cfg->enforce_groups || allow_active || deny_active;

    /* No group/role restriction is configured: authorization is bypassed. */
    if (!active) {
        return 1;
    }

    /* Group authorization is enabled but no list is configured to enforce. */
    if (!allow_active && !deny_active) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Group authorization enabled but no group/role lists are configured");
        return 0;
    }

    /* A group policy is active, so the claim must be usable: without a UserInfo JSON
     * object the user's membership cannot be established and the check is fail-closed
     * (an unmatchable deny list must not let unknown membership through). */
    if (!uinfo_json || !json_object_is_type((struct json_object *)uinfo_json, json_type_object)) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Group authorization failed: UserInfo JSON is invalid or missing");
        return 0;
    }

    const char *target_field = (strlen(cfg->group_claim_field) > 0) ? cfg->group_claim_field : "groups";
    int cs = cfg->case_sensitive;

    struct json_object *j_group = NULL;
    /* json-c represents a JSON null value as a NULL pointer, so a null claim reaches
     * the !j_group branch: with a deny list configured, membership that cannot be
     * inspected is refused rather than treated as "nothing to check". */
    if (!json_object_object_get_ex((struct json_object *)uinfo_json, target_field, &j_group) || !j_group) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Group authorization failed: claim field '%s' is missing or null", target_field);
        return 0;
    }

    int matched_deny = 0;
    int matched_allow = 0;

    /* Handle JSON Array claims (e.g., ["admin", "sysadmins", "users"]) */
    if (json_object_is_type(j_group, json_type_array)) {
        size_t arr_len = json_object_array_length(j_group);
        for (size_t i = 0; i < arr_len; i++) {
            struct json_object *item = json_object_array_get_idx(j_group, JSON_ARRAY_IDX(i));
            if (!item || !json_object_is_type(item, json_type_string)) {
                /* A deny list must fail closed on claim content it cannot fully parse;
                 * an allow-only list may skip non-string elements (they simply never
                 * match an allowed group). */
                if (deny_active) {
                    pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                                  "Group authorization failed: claim field '%s' contains a non-string element",
                                  target_field);
                    return 0;
                }
                continue;
            }
            const char *val = json_object_get_string(item);
            if (group_value_denied(val, cfg, cs)) {
                matched_deny = 1;
                break;
            }
            if (group_value_allowed(val, cfg, cs)) {
                matched_allow = 1;
            }
        }
    }
    /* Handle JSON String claims (e.g., "sysadmins" or comma-separated "sysadmins,devs") */
    else if (json_object_is_type(j_group, json_type_string)) {
        const char *val = json_object_get_string(j_group);
        if (group_value_denied(val, cfg, cs)) {
            return 0;
        } else if (group_value_allowed(val, cfg, cs)) {
            return 1;
        } else {
            /* Split in place on a heap copy sized to the input. A fixed-capacity
             * scratch buffer would silently skip the split once the claim grew past
             * the cap, leaving a deny-only policy unable to see any group at all
             * (fail-open). Allocation/copy failure therefore refuses access. */
            size_t val_len = strlen(val);
            char *val_copy = malloc(val_len + 1);
            if (!val_copy || copy_checked(val_copy, val_len + 1, val) != 0) {
                free(val_copy);
                pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                              "Group authorization failed: "
                              "unable to parse claim field '%s' (allocation error)",
                              target_field);
                return 0;
            }
            char *saveptr = NULL;
            char *token = strtok_r(val_copy, ",", &saveptr);
            while (token) {
                while (isspace((unsigned char)*token)) {
                    token++;
                }
                char *end = token + strlen(token) - 1;
                while (end > token && isspace((unsigned char)*end)) {
                    *end = '\0';
                    end--;
                }

                if (group_value_denied(token, cfg, cs)) {
                    matched_deny = 1;
                    break;
                } else if (group_value_allowed(token, cfg, cs)) {
                    matched_allow = 1;
                }
                token = strtok_r(NULL, ",", &saveptr);
            }
            free(val_copy);
        }
    } else {
        /* The claim is present but neither an array nor a string: membership cannot
         * be established, so the check is fail-closed under any active policy. */
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Group authorization failed: claim field '%s' is neither an array nor a string", target_field);
        return 0;
    }

    /* Denial lists take precedence over allow lists. */
    if (matched_deny) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Group authorization failed: user holds a group/role present in deny_groups");
        return 0;
    }

    if (allow_active && !matched_allow) {
        pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Group authorization failed: no group/role in claim '%s' satisfies the allow list", target_field);
        return 0;
    }

    pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_DEBUG, LOG_DEBUG, "Group authorization verified for claim field '%s'",
                  target_field);
    return 1;
}
/*
 * Capacity (bytes, including the terminating NUL) of the stack buffer holding
 * the JWT 'sub' claim for the JWT-sub vs UserInfo-sub consistency check.
 * OIDC Core caps 'sub' at 255 ASCII characters, so 256 = 255 + NUL.
 */
#define JWT_SUB_CLAIM_MAX 256

/**
 * @brief Verifies the provider returned identity claims against the requesting PAM user.
 *
 * Encapsulates the entire post-UserInfo verification block so `pam_sm_authenticate()`
 * (src/pam_module.c) stays focused on orchestration: PII-safe audit logging of the raw
 * claim payload, extraction of the configured claim field, the JWT-`sub` vs UserInfo-`sub`
 * consistency check (token-substitution defense), `verify_claim()` against the local PAM
 * user, and `verify_group_membership()` group/role authorization. Each failure is logged,
 * the matching plain-text notice is delivered to the user, and a distinct PAM status is
 * returned so the caller can branch correctly.
 *
 * `uinfo_json` is borrowed from the caller and is *not* scrubbed or released here — the
 * caller owns it and applies `secure_zero_json_tree()` at its cleanup.
 *
 * @param[in] pamh          PAM framework handle.
 * @param[in] cfg           Module configuration options.
 * @param[in] loglevel      Active runtime log level threshold.
 * @param[in] pam_user      Requesting PAM local user account name.
 * @param[in] uinfo_json    Parsed UserInfo response (JSON object); borrowed, not owned.
 * @param[in] userinfo_size Raw UserInfo payload size in bytes (for the PII-safe audit log).
 * @param[in] access_token  Access token string (for the optional JWT 'sub' extraction).
 * @return PAM_SUCCESS when all checks pass; PAM_AUTH_ERR when the identity claim cannot be
 *         established or verified; PAM_PERM_DENIED when group/role authorization fails.
 */
int verify_userinfo_identity(pam_handle_t *pamh, const config_t *cfg, loglevel_t loglevel, const char *pam_user,
                             struct json_object *uinfo_json, size_t userinfo_size, const char *access_token) {
    /* PII-safe UserInfo audit logging: the raw claim payload contains personal data (emails,
     * phone numbers, group memberships) and must never be persisted to the system log.
     * Routine logging (DEBUG) records only the payload size and the configured claim field;
     * the troubleshooting level (VERBOSE) additionally lists the claim NAMES returned by the
     * provider — enough to debug claim-field configuration — without logging any claim VALUES. */
    pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                  "UserInfo claim payload received: %zu bytes, claim field '%s' present", userinfo_size,
                  cfg->claim_field);
    {
        struct json_object_iter it;
        /* Cap the claim-name listing; larger payloads get a summary line instead.
         * json_object_object_length() returns int on older json-c (EL8/EL9) and size_t on
         * newer releases, so capture through an explicit long and range-check it; both the
         * total and the remaining budget stay opaque runtime values, so the budget check
         * below is not statically foldable. */
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
                pam_oauth_log(pamh, loglevel, LOGLEVEL_VERBOSE, LOG_DEBUG, "UserInfo claim present: '%s'", it.key);
            } else {
                pam_oauth_log(pamh, loglevel, LOGLEVEL_VERBOSE, LOG_DEBUG,
                              "UserInfo claim present: (name contains non-printable bytes; withheld)");
            }
            names_left--;
        }
        if (total_claims > 32) {
            pam_oauth_log(pamh, loglevel, LOGLEVEL_VERBOSE, LOG_DEBUG,
                          "UserInfo claim list truncated: 32 of %zu claim names shown", total_claims);
        }
    }

    struct json_object *j_claim = NULL;
    if (!json_object_object_get_ex(uinfo_json, cfg->claim_field, &j_claim) || !j_claim ||
        !json_object_is_type(j_claim, json_type_string)) {
        pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR, "UserInfo response missing string claim field '%s'",
                      cfg->claim_field);
        return PAM_AUTH_ERR;
    }

    /* JWT-sub vs UserInfo-sub consistency check (token-substitution defense). When local JWT
     * claim inspection is enabled and the access token carries a 'sub' claim, it must match
     * the UserInfo 'sub': the UserInfo exchange is the module's only authoritative token
     * validity/signature check, and on multi-audience IdPs a token minted for a different
     * client could otherwise authorize the wrong subject. A missing 'sub' on either side is
     * skipped (logged; providers differ), while a present-but-mismatched or malformed 'sub'
     * fails closed. */
    if (cfg->verify_jwt_claims) {
        char jwt_sub[JWT_SUB_CLAIM_MAX];
        int sub_rc = jwt_extract_claim_string(access_token, "sub", jwt_sub, sizeof(jwt_sub));
        if (sub_rc == 0) {
            struct json_object *j_uinfo_sub = NULL;
            if (json_object_object_get_ex(uinfo_json, "sub", &j_uinfo_sub) && j_uinfo_sub &&
                json_object_is_type(j_uinfo_sub, json_type_string)) {
                if (strcmp(jwt_sub, json_object_get_string(j_uinfo_sub)) != 0) {
                    pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR,
                                  "JWT subject does not match UserInfo subject for user '%s' "
                                  "(token substitution suspected)",
                                  pam_user);
                    notify_user_failure(pamh, USER_NOTICE_DENIED);
                    secure_memzero(jwt_sub, sizeof(jwt_sub));
                    return PAM_AUTH_ERR;
                }
                pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                              "JWT subject matches UserInfo subject for user '%s'", pam_user);
            } else {
                pam_oauth_log(pamh, loglevel, LOGLEVEL_INFO, LOG_WARNING,
                              "UserInfo response carries no string 'sub' claim; JWT subject consistency "
                              "check skipped");
            }
        } else if (sub_rc == 1) {
            pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                          "Access token carries no 'sub' claim; JWT subject consistency check skipped");
        } else {
            pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Malformed 'sub' claim in access token for user '%s'", pam_user);
            notify_user_failure(pamh, USER_NOTICE_DENIED);
            secure_memzero(jwt_sub, sizeof(jwt_sub));
            return PAM_AUTH_ERR;
        }
        secure_memzero(jwt_sub, sizeof(jwt_sub));
    }

    /* Verify identity claim against requesting PAM user. */
    const char *raw_claim = json_object_get_string(j_claim);
    int valid = verify_claim(pam_user, raw_claim, cfg, pamh);
    if (!valid) {
        pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Authentication failed for user '%s': claim verification failed", pam_user);
        notify_user_failure(pamh, USER_NOTICE_DENIED);
        return PAM_AUTH_ERR;
    }

    /* Enforce Group / Role Authorization (allow/deny group lists). */
    if (!verify_group_membership(uinfo_json, cfg, pamh)) {
        pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR,
                      "Group authorization denied for user '%s': group/role allow/deny lists not satisfied", pam_user);
        notify_user_failure(pamh, USER_NOTICE_DENIED);
        return PAM_PERM_DENIED;
    }
    pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG, "Group authorization succeeded for user '%s'", pam_user);

    return PAM_SUCCESS;
}
