/**
 * @file message.c
 * @brief Terminal prompt templating and user-facing failure notices.
 *
 * Owns the terminal-messaging layer of the RFC 8628 device flow: template
 * rendering ({url}/{url_complete}/{code}/{expiry} substitution plus the
 * built-in default), the optional QR-code presentation, the PAM_TEXT_INFO
 * instruction delivery, the "Press [Enter] to begin..." confirmation, and the
 * plain-text failure notices routed through the PAM conversation. Extracted
 * from src/pam_module.c so the prompt path is one reviewable unit.
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
#include "device_flow.h"
#include <stdio.h>
#include <string.h>
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
 * @brief Formats a device-code approval window (seconds) as a compact duration string.
 *
 * Renders the RFC 8628 `expires_in` value for the prompt's `{expiry}` template token and the
 * `[prompt] show_expiry` status-line clause in compact units: whole seconds under a minute
 * ("45s"), whole minutes (rounded up) up to an hour ("15m"), and "Nh [Mm]" at or above it
 * ("1h", "1h 5m"). The duration text is static-ASCII-derived (only digits, a space, and the
 * fixed unit letters), so it requires no separate terminal-safety check.
 *
 * @param[in]  expires_in Approval window in seconds (0 or negative = unknown).
 * @param[out] out        Buffer receiving the NUL-terminated duration text.
 * @param[in]  out_len    Output buffer byte capacity.
 * @return 0 on success, -1 when the window is unknown or the output buffer is too small.
 */
static int format_expiry_seconds(int expires_in, char *out, size_t out_len) {
    if (out == NULL || out_len == 0) {
        return -1;
    }
    if (expires_in <= 0) {
        out[0] = '\0';
        return -1;
    }
    int w = 0;
    if (expires_in < 60) {
        w = snprintf(out, out_len, "%ds", expires_in);
    } else if (expires_in < 3600) {
        int minutes = (expires_in + 59) / 60;
        w = snprintf(out, out_len, "%dm", minutes);
    } else {
        int total_minutes = (expires_in + 59) / 60;
        int hours = total_minutes / 60;
        int minutes = total_minutes % 60;
        if (minutes == 0) {
            w = snprintf(out, out_len, "%dh", hours);
        } else {
            w = snprintf(out, out_len, "%dh %dm", hours, minutes);
        }
    }
    return (w >= 0 && (size_t)w < out_len) ? 0 : -1;
}
/**
 * Renders the user prompt message for SSH / PAM interactive auth. Replaces
 * {url}/{url_complete}/{code}/{expiry} tokens and \n escapes, or emits the built-in
 * default template. Terminal-injection-safe line-by-line on completion.
 */
int render_prompt_message(const config_t *cfg, const char *url, const char *url_complete, const char *code,
                          int expires_in, char *out, size_t out_len) {
    if (!cfg || !url || !code || !out || out_len == 0) {
        return -1;
    }

    const char *tpl = cfg->init_message;
    if (tpl[0] == '\0') {
        /* Default template: leading blank line only when QR is off; status line carries
         * the compact approval window when show_expiry is set and the window is known. */
        const char *lead = cfg->qr_enabled ? "" : "\n";
        char status_clause[32] = "";
        if (cfg->show_expiry) {
            char expiry_text[32];
            if (format_expiry_seconds(expires_in, expiry_text, sizeof(expiry_text)) == 0) {
                int elen = snprintf(status_clause, sizeof(status_clause), " (expires in %s)", expiry_text);
                if (elen < 0 || (size_t)elen >= sizeof(status_clause)) {
                    return -1;
                }
            }
        }
        int w = 0;
        if (url_complete && strcmp(url, url_complete) != 0) {
            w = snprintf(out, out_len,
                         "%sSign in via browser:\n  %s\n\n"
                         "Manual entry: %s  |  Code: %s\n"
                         "Waiting for approval%s.\n",
                         lead, url_complete, url, code, status_clause);
        } else {
            w = snprintf(out, out_len,
                         "%sSign in via browser:\n  URL:  %s\n  Code: %s\n\n"
                         "Waiting for approval%s.\n",
                         lead, url, code, status_clause);
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
        } else if (strncmp(tpl + i, "{expiry}", 8) == 0) {
            /* {expiry} expands to the human-readable device-code approval window; when the
             * window is unknown the token expands to an empty string. */
            char expiry_text[32];
            if (format_expiry_seconds(expires_in, expiry_text, sizeof(expiry_text)) == 0) {
                size_t vlen = strlen(expiry_text);
                if (out_pos + vlen >= out_len) {
                    return -1;
                }
                memcpy(out + out_pos, expiry_text, vlen);
                out_pos += vlen;
            }
            i += 7;
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
/* Delivery of the plain-text failure notices is best-effort (a `pam_prompt`
 * failure is intentionally ignored): on a degraded conversation the notice is
 * simply not shown, and it must never change the authentication outcome. OpenSSH
 * keyboard-interactive clients may additionally buffer PAM_TEXT_INFO until a prompt
 * round-trip, so SSH clients are not guaranteed to display a notice; local console
 * logins are.
 *
 * The notice strings themselves (USER_NOTICE_*) are compile-time macros defined in
 * src/device_flow.h so they inline at every call site (see there for why macros
 * rather than exported const globals). */

void notify_user_failure(pam_handle_t *pamh, const char *msg) {
    if (pamh && msg != NULL) {
        (void)pam_prompt(pamh, PAM_TEXT_INFO, NULL, "%s", msg);
    }
}

/**
 * @brief Renders and presents the terminal sign-in prompt to the client.
 *
 * Orchestrates Steps 4/4b/4c of the RFC 8628 flow in one reviewable unit: templated
 * prompt rendering, the optional scannable QR code, delivery via PAM_TEXT_INFO, and the
 * key-press confirmation that flushes the buffered text to keyboard-interactive (OpenSSH)
 * clients before polling begins.
 *
 * The prompt deliberately carries no host identification. In the device-code phishing
 * attack (docs/threat-model.md §8) this prompt is delivered to whoever ran ssh — the
 * attacker — while the phishing victim only sees the identity provider's approval page;
 * showing the target host (or the connecting client's host, readable from PAM_RHOST via
 * pam_get_item()) here cannot reach the approver. Machine context therefore belongs in the
 * registered OAuth client name shown on the IdP's approval page (register one descriptive
 * client per host or cluster) and in source-network limits on device-flow approvals, not in
 * this prompt. The device-code approval window (provider expires_in, clamped by [runtime]
 * max_poll_seconds — the module's effective wait limit) reaches the prompt as dev->expires_in:
 * by default it appears in the built-in default template's trailing status line, [prompt]
 * show_expiry = false omits it, and any {expiry} template token expands it regardless.
 *
 * @param[in] pamh     PAM framework handle.
 * @param[in] cfg      Module configuration options.
 * @param[in] loglevel Active runtime log level threshold.
 * @param[in] dev      Successful device-authorization result (verification URIs, user code).
 * @return PAM_SUCCESS to proceed, or the PAM status code of the failing step (PAM_SERVICE_ERR
 *         on rendering failure, the conversation result on delivery failure, PAM_ABORT on
 *         user-initiated cancellation).
 */
int present_signin_prompt(pam_handle_t *pamh, const config_t *cfg, loglevel_t loglevel, const device_auth_t *dev) {
    int retval = PAM_SUCCESS;
    char prompt_buf[MAX_INIT_MSG_LEN];

    if (render_prompt_message(cfg, dev->verification_uri, dev->verification_uri_complete, dev->user_code,
                              dev->expires_in, prompt_buf, sizeof(prompt_buf)) != 0) {
        if (pamh) {
            pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR, "Failed to render prompt message");
        }
        notify_user_failure(pamh, USER_NOTICE_SERVICE);
        retval = PAM_SERVICE_ERR;
        goto out;
    }

    /* Step 4b: Optionally present the verification URI as a scannable terminal QR code so
     * the user can open the page with a phone camera instead of typing. The block is
     * informational (PAM_TEXT_INFO); any rendering failure is logged at debug level and
     * non-fatal, because the text prompt below always carries the URL and user code. */
    if (cfg->qr_enabled) {
        char qr_buf[QR_RENDER_BUF_MAX];
        if (qr_render_verification_code(cfg, loglevel, dev->verification_uri, dev->verification_uri_complete, qr_buf,
                                        sizeof(qr_buf), pamh) == 0) {
            int qr_res = pam_prompt(pamh, PAM_TEXT_INFO, NULL, "%s", qr_buf);
            if (qr_res != PAM_SUCCESS) {
                pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                              "QR code prompt not displayed (conversation returned %d); text prompt follows", qr_res);
            }
        }
    }

    pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG, "Prompting user with verification code instructions");

    /* Deliver the instructions as an informational message (PAM_TEXT_INFO), the same
     * primitive used for the QR code. OpenSSH (keyboard-interactive) buffers PAM_TEXT_INFO
     * and flushes it only when a subsequent prompt triggers a USERINFO round-trip; the
     * mandatory PAM_PROMPT_ECHO_ON "Press [Enter] to begin..." confirmation (Step 4c) forces
     * that flush so the URL / user code are reliably visible before polling begins. */
    int prompt_res = pam_prompt(pamh, PAM_TEXT_INFO, NULL, "%s", prompt_buf);
    if (prompt_res != PAM_SUCCESS) {
        pam_oauth_log(pamh, loglevel, LOGLEVEL_ERROR, LOG_ERR, "User prompt delivery failed or was cancelled");
        retval = prompt_res;
        goto out;
    }

    /* Step 4c: Sign-in confirmation. Wait for a single Enter before polling begins. This
     * reliably flushes the PAM_TEXT_INFO sign-in prompt (URL / QR / user code) to OpenSSH
     * keyboard-interactive clients, which otherwise buffer it until a prompt triggers a
     * USERINFO round-trip. The keystroke is intentionally ignored — the device-code flow is
     * already in progress. */
    if (pamh) {
        int flush_rc = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, NULL, "Press [Enter] to begin... ");
        if (flush_rc == PAM_ABORT) {
            pam_oauth_log(pamh, loglevel, LOGLEVEL_INFO, LOG_INFO, "Authentication aborted by user");
            retval = PAM_ABORT;
            goto out;
        }
        if (flush_rc != PAM_SUCCESS) {
            /* Best-effort: the URL / user code above were already sent as PAM_TEXT_INFO. Log
             * and continue polling rather than hard-failing on a degraded conversation. */
            pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                          "Key-press prompt returned %d; proceeding to polling", flush_rc);
        }
    }
    retval = PAM_SUCCESS;

out:
    /* prompt_buf embeds the user code and verification URIs; scrub it on every exit path. */
    secure_memzero(prompt_buf, sizeof(prompt_buf));
    return retval;
}
