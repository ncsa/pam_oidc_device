/*
 * @file qr_render_check.c
 * Standalone harness for independent-scanner verification of the terminal QR
 * rendering (consumed by the `qr-scan-audit` job in .github/workflows/build.yml
 * and usable ad hoc: ./qr_render_check <uri> <utf8_art_path> <ascii_art_path>
 * [scale]).
 *
 * It renders the verification-URI symbol through the exact production code
 * path (qr_encode_uri + qr_render_matrix from src/qr.c, over the vendored
 * Nayuki encoder) and writes both terminal styles to files for rasterization
 * (tests/qr_scan/art2png.py) and decoding with an independent scanner
 * (zbarimg). It additionally prints scale-1 ASCII art to stdout so the art
 * published in the CI workflow summary can be scanned manually with a phone
 * camera — the "real terminal conditions" leg of the verification.
 *
 * The harness links only src/qr.c + third_party/qrcodegen/qrcodegen.c and
 * therefore supplies the single logging sink qr.c calls on error paths (the
 * real implementation lives in the PAM module). No PAM/curl/json-c linkage
 * is needed; the PAM headers are only used for the types.
 *
 * Build (Linux, matching the CI qr-scan-audit job):
 *   gcc -O2 -Iinclude -D_GNU_SOURCE -Wall -Wextra -Werror \
 *       src/qr.c third_party/qrcodegen/qrcodegen.c \
 *       tests/qr_scan/qr_render_check.c -o build/qr_render_check
 *
 * @project     pam_oidc_device
 * @license     MIT License
 * @see         ISO/IEC 18004 (QR Code), RFC 8628 (OAuth 2.0 Device Authorization Grant)
 *
 * Copyright (c) 2026 The Board of Trustees of the University of Illinois.
 * SPDX-License-Identifier: MIT
 */

#include "pam_oidc_device.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void pam_oauth_log(pam_handle_t *pamh, loglevel_t cfg_level, loglevel_t msg_level, int priority, const char *fmt, ...) {
    (void)pamh;
    (void)cfg_level;
    (void)msg_level;
    (void)priority;
    if (!fmt) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static int write_art_file(const char *path, const char *art) {
    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "error: cannot write %s\n", path);
        return -1;
    }
    fputs(art, f);
    fclose(f);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <uri> <utf8_art_path> <ascii_art_path> [scale 1-3]\n", argv[0]);
        return 2;
    }
    const char *const uri = argv[1];
    const char *const utf8_path = argv[2];
    const char *const ascii_path = argv[3];
    const int scale = (argc > 4) ? atoi(argv[4]) : 3;
    if (scale < 1 || scale > 3 || uri[0] == '\0') {
        fprintf(stderr, "error: bad arguments (uri must be non-empty, scale must be 1-3)\n");
        return 2;
    }

    uint8_t qr[QR_MATRIX_BYTES_MAX];
    int size = 0;
    if (qr_encode_uri(uri, QR_EC_MEDIUM, qr, sizeof(qr), &size) != 0) {
        fprintf(stderr, "error: URI (%zu bytes) does not fit a version-%d symbol at EC MEDIUM\n", strlen(uri),
                QR_MAX_VERSION);
        return 1;
    }

    char art[QR_RENDER_BUF_MAX];
    if (qr_render_matrix(qr, size, QR_STYLE_UTF8, scale, '#', art, sizeof(art)) != 0) {
        fprintf(stderr, "error: UTF-8 rendering failed\n");
        return 1;
    }
    if (write_art_file(utf8_path, art) != 0) {
        return 1;
    }
    if (qr_render_matrix(qr, size, QR_STYLE_ASCII, scale, '#', art, sizeof(art)) != 0) {
        fprintf(stderr, "error: ASCII rendering failed\n");
        return 1;
    }
    if (write_art_file(ascii_path, art) != 0) {
        return 1;
    }

    /* Scale-1 ASCII art on stdout: compact enough for the CI job summary and
     * readable/scannable by a phone camera when printed to a terminal. */
    if (qr_render_matrix(qr, size, QR_STYLE_ASCII, 1, '#', art, sizeof(art)) != 0) {
        fprintf(stderr, "error: summary ASCII rendering failed\n");
        return 1;
    }
    printf("QR symbol: %dx%d modules, payload %zu bytes\n", size, size, strlen(uri));
    printf("Decode target: %s\n", uri);
    fputs(art, stdout);
    return 0;
}
