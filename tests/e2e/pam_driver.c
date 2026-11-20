/*
 * pam_driver.c -- deterministic PAM test driver for the pam_oidc_device
 * end-to-end sandbox (tests/e2e).
 *
 * Usage:
 *   pam_driver <pam-service> <user>
 *
 * Runs pam_authenticate() against /etc/pam.d/<pam-service> for <user> and
 * exits with the PAM return value (0 = PAM_SUCCESS, 3 = PAM_SERVICE_ERR,
 * 6 = PAM_PERM_DENIED, 7 = PAM_AUTH_ERR, ...) so the e2e harness can
 * assert on exact module outcomes.
 *
 * Why not plain pamtester?  The module emits a PAM_TEXT_INFO block followed
 * by a PAM_PROMPT_ECHO_ON "Press [Enter] to begin..." synchronization
 * prompt.  This driver's conv() function answers that prompt deterministically
 * (simulating the Enter keypress) and prints every PAM_TEXT_INFO /
 * PAM_ERROR_MSG message to the terminal, so the flow behaves exactly as it
 * does under an interactive keyboard-interactive SSH session.
 *
 * Build (from the repository root; needs PAM headers):
 *   cc -O2 -Wall -Wextra -Werror -Iinclude tests/e2e/pam_driver.c \
 *       -o tests/e2e/pam_driver -lpam
 *
 * Must run as root (PAM auth modules run with privilege).
 */

#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * PAM conversation function (classical multi-message signature used by the
 * pam_conv structure).  Informational and error messages are echoed to the
 * test terminal; every prompt is answered with a single newline so the module
 * proceeds past its "Press [Enter] to begin..." barrier instead of hanging on
 * a headless terminal.  The response array is intentionally not freed: the
 * PAM library consumes it after this function returns (the driver process
 * exits shortly after, so it is reclaimed with the process).
 */
static int conv_func(int num_messages, const struct pam_message **message, struct pam_response **response,
                     void *appdata_ptr) {
    (void)appdata_ptr;
    *response = NULL;

    if (num_messages <= 0 || message == NULL) {
        return PAM_BUF_ERR;
    }

    struct pam_response *entries = calloc((size_t)num_messages, sizeof(*entries));
    if (entries == NULL) {
        return PAM_BUF_ERR;
    }

    for (int i = 0; i < num_messages; i++) {
        const char *text = (message[i] != NULL && message[i]->msg != NULL) ? message[i]->msg : "";

        switch (message[i]->msg_style) {
            case PAM_TEXT_INFO:
                printf("%s", text);
                fflush(stdout);
                break;
            case PAM_ERROR_MSG:
                fprintf(stderr, "[pam-error] %s", text);
                if (strchr(text, '\n') == NULL) {
                    fputc('\n', stderr);
                }
                fflush(stderr);
                break;
            case PAM_PROMPT_ECHO_ON:
                printf("%s", text);
                fflush(stdout);
                break;
            case PAM_PROMPT_ECHO_OFF:
                fprintf(stderr, "[prompt-hidden]");
                break;
        }

        entries[i].resp = strdup("\n");
        if (entries[i].resp == NULL) {
            free(entries);
            return PAM_BUF_ERR;
        }
    }

    *response = entries;
    return PAM_SUCCESS;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <pam-service> <user>\n", argv[0]);
        return 125;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "pam_driver: must run as root (PAM auth modules run privileged)\n");
        return 125;
    }

    const char *service = argv[1];
    const char *user = argv[2];
    static struct pam_conv conversation = { &conv_func, NULL };
    pam_handle_t *pamh = NULL;

    int rc = pam_start(service, user, &conversation, &pamh);
    if (rc != PAM_SUCCESS) {
        fprintf(stderr, "pam_start(%s, %s) failed: %s\n", service, user, pam_strerror(NULL, rc));
        return rc;
    }

    rc = pam_authenticate(pamh, 0);
    fprintf(stderr, "[pam-driver] pam_authenticate(%s, %s) -> %d (%s)\n", service, user, rc,
            pam_strerror(pamh, rc));

    int end_rc = pam_end(pamh, rc);
    (void)end_rc;
    return rc;
}
