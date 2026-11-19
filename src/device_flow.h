/*
 * Internal device-flow contract shared by src/pam_module.c, src/message.c,
 * src/identity.c and tests/test_suite.c.
 *
 * NOT part of the public API: include/pam_oidc_device.h intentionally does not
 * expose the per-attempt device-authorization session state, the terminal
 * prompt/user-notice symbols, or the test-exported helpers declared here. Keep
 * this header in sync with src/pam_module.c, src/message.c and src/identity.c only.
 */
#ifndef PAM_OIDC_DEVICE_FLOW_H
#define PAM_OIDC_DEVICE_FLOW_H

#include <time.h>

#include "../include/pam_oidc_device.h"

/*
 * Maximum length (bytes, including the terminating NUL) of the provider-issued
 * RFC 8628 device_code.
 */
#define DEVICE_CODE_MAX_LEN 2048

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

/*
 * Classification of a FAILED token-polling outcome (poll_for_access_token()),
 * mapped to the user-visible notice in pam_sm_authenticate(). The PAM status
 * code alone cannot carry this distinction — token-phase failures collapse
 * into PAM_AUTH_ERR, so without it the user would see the same notice for an
 * expired code, a declined sign-in, and a broken network path.
 */
typedef enum {
    TOKEN_PHASE_EXPIRED = 0, /* Poll deadline reached, or the provider reported expired_token. */
    TOKEN_PHASE_DENIED,      /* The provider reported access_denied (sign-in not approved). */
    TOKEN_PHASE_UNAVAILABLE  /* Everything else: network failure, malformed/oversized token,
                                 unexpected status, allocation error. */
} token_phase_t;

/*
 * One poll-loop scheduling decision, computed by poll_loop_schedule() from an
 * injected clock reading so the timing rules are unit-testable without sleeping.
 */
typedef enum {
    POLL_SCHED_RUN_NOW = 0, /* First poll: request immediately, no leading sleep. */
    POLL_SCHED_SLEEP,       /* Sleep until the absolute `next_poll` time, then request. */
    POLL_SCHED_EXPIRED      /* The next poll would land at/after the device deadline: stop. */
} poll_sched_action_t;

/*
 * Test-exported poll-loop helpers. These are declared here (not in
 * include/pam_oidc_device.h) solely so tests/test_suite.c can drive them
 * through the fake cURL transport and the injected clock; src/pam_module.c
 * remains their only production caller.
 */

/** RFC 8628 s3.5 `slow_down` poll-interval adjustment (see src/pam_module.c). */
int poll_interval_after_slow_down(int interval);

/** Transient-error (HTTP 429/5xx, cURL transport error) poll-interval backoff. */
int poll_interval_after_transient(int interval);

/** Pure scheduling decision for one token-poll loop iteration (see src/pam_module.c). */
poll_sched_action_t poll_loop_schedule(int first_poll, int interval, const struct timespec *now,
                                       const struct timespec *deadline, struct timespec *next_poll);

/** Pure per-request deadline budget for one token poll (see src/pam_module.c). */
int poll_request_budget(const struct timespec *now, const struct timespec *deadline, long *timeout_ms);

/** Bounded form-field table append (see src/pam_module.c): 0 on success, -1 once
 *  `*count` reaches `capacity` (the overflow the callers map to PAM_BUF_ERR). */
int form_field_append(const char **keys, const char **vals, size_t *count, size_t capacity, const char *key,
                      const char *val);

/** RFC 8628 s3.1/s3.2 device-authorization request phase (see src/pam_module.c). */
int request_device_authorization(pam_handle_t *pamh, const config_t *cfg, loglevel_t loglevel, int pkce_active,
                                 const char *code_challenge, CURL *curl, device_auth_t *dev, http_response_t *resp,
                                 struct json_object **dev_json, char **postfields);

/** RFC 8628 s3.5 token-poll loop (see src/pam_module.c). */
int poll_for_access_token(pam_handle_t *pamh, const config_t *cfg, loglevel_t loglevel, const char *pam_user,
                          const device_auth_t *dev, const char *code_verifier, int pkce_active, CURL *curl,
                          http_response_t *token_resp, struct json_object **tok_json, char **access_token,
                          char **token_postfields, token_phase_t *phase);

/*
 * Terminal-prompt / user-notice family. The notice strings are compile-time macros
 * (plain, printable-ASCII string literals) so they inline at every call site in the
 * PIC shared-object build. An exported `const char *const` data symbol referenced
 * from other translation units (src/pam_module.c, src/identity.c) can make gcc emit
 * a non-PIC `R_X86_64_PC32` relocation that bfd rejects when the `.so` is linked --
 * a build failure seen across the distro package CI. Inlining the literal avoids the
 * cross-TU data symbol entirely, on every toolchain.
 */
#define USER_NOTICE_SERVICE                                                                                            \
    "Sign-in could not be completed: the identity provider service is unavailable.\n"                                  \
    "Please try again, or contact your system administrator if the problem persists.\n"
#define USER_NOTICE_DENIED                                                                                             \
    "Authentication was denied for this account.\n"                                                                    \
    "Please contact your system administrator if you believe this is an error.\n"
#define USER_NOTICE_EXPIRED                                                                                            \
    "Sign-in was not approved in time: the sign-in code expired or the identity provider\n"                            \
    "service became unavailable. Please sign in again to start a new session.\n"
#define USER_NOTICE_NOT_APPROVED                                                                                       \
    "Sign-in was declined: the sign-in request was not approved at the identity provider.\n"                           \
    "Please sign in again to start a new session.\n"

/** Best-effort PAM_TEXT_INFO delivery of a plain-text failure notice (see src/message.c). */
void notify_user_failure(pam_handle_t *pamh, const char *msg);

/** Render + present the sign-in prompt (steps 4/4b/4c); returns a PAM status (see src/message.c). */
int present_signin_prompt(pam_handle_t *pamh, const config_t *cfg, loglevel_t loglevel, const device_auth_t *dev);

/** Post-UserInfo identity verification (claim extraction, JWT-sub check, claim + group
 *  verification); returns PAM_SUCCESS / PAM_AUTH_ERR / PAM_PERM_DENIED (see src/identity.c). */
int verify_userinfo_identity(pam_handle_t *pamh, const config_t *cfg, loglevel_t loglevel, const char *pam_user,
                             struct json_object *uinfo_json, size_t userinfo_size, const char *access_token);

#endif /* PAM_OIDC_DEVICE_FLOW_H */
