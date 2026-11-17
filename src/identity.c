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
#include <ctype.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
     * apply. */
    if (!cfg->allow_root) {
        int uid0_account = (strcmp(pam_user, "root") == 0);
        if (!uid0_account) {
            struct passwd pw;
            struct passwd *pw_res = NULL;
            char pw_buf[4096];
            if (getpwnam_r(pam_user, &pw, pw_buf, sizeof(pw_buf), &pw_res) == 0 && pw_res != NULL &&
                pw_res->pw_uid == 0) {
                uid0_account = 1;
            }
        }
        if (uid0_account) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Uid-0 account '%s' is refused: set 'allow_root = true' in [access] to permit root "
                          "authentication via this module",
                          pam_user);
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
     * range is unsatisfiable (load_config() rejects it) and is treated as inactive. */
    if (cfg->deny_system_uids && cfg->system_uid_min <= cfg->system_uid_max) {
        uid_t acct_uid = (uid_t)-1;
        int uid_known = 0;
        if (strcmp(pam_user, "root") == 0) {
            acct_uid = 0;
            uid_known = 1;
        } else {
            struct passwd pw;
            struct passwd *pw_res = NULL;
            char pw_buf[4096];
            if (getpwnam_r(pam_user, &pw, pw_buf, sizeof(pw_buf), &pw_res) == 0 && pw_res != NULL) {
                acct_uid = pw_res->pw_uid;
                uid_known = 1;
            }
        }
        if (uid_known && acct_uid >= (uid_t)cfg->system_uid_min && acct_uid <= (uid_t)cfg->system_uid_max &&
            !(acct_uid == 0 && cfg->allow_root)) {
            pam_oauth_log(pamh, cfg->loglevel, LOGLEVEL_ERROR, LOG_ERR,
                          "Account '%s' (uid %u) is refused: uid falls within the denied system-account range "
                          "[%d..%d] (deny_system_uids); adjust the range or set 'deny_system_uids = false' in "
                          "[access] to permit this account",
                          pam_user, (unsigned int)acct_uid, cfg->system_uid_min, cfg->system_uid_max);
            return 0;
        }
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
