/**
 * @file qr.c
 * @brief Terminal rendering of the OAuth 2.0 verification URI as a scannable QR code.
 *
 * Wraps the vendored ISO/IEC 18004 encoder (third_party/qrcodegen/qrcodegen.c) with two
 * module-owned layers:
 *  - URI encoding with the configured error-correction level and a bounded symbol version
 *    range suitable for terminal display (qr_encode_uri), and
 *  - text rendering of the module matrix with a quiet zone, two font-robust styles
 *    (UTF-8 half-blocks or single-character ASCII), and integer module scaling
 *    (qr_render_matrix), plus a config-aware convenience entry point
 *    (qr_render_verification_code) used by the PAM prompt flow.
 *
 * The rendered output is module-generated from config-validated inputs (the QR_STYLE_ASCII
 * block character is range-checked at config load time; the UTF-8 glyphs are fixed constants),
 * so no user/provider data can inject escape sequences into the QR block itself.
 *
 * @project     pam_oidc_device
 * @repository  https://github.com/ncsa/pam_oidc_device
 * @maintainer  National Center for Supercomputing Applications (NCSA)
 * @license     MIT License
 * @see         ISO/IEC 18004 (QR Code), RFC 8628 (OAuth 2.0 Device Authorization Grant)
 *
 * Copyright (c) 2026 The Board of Trustees of the University of Illinois.
 * SPDX-License-Identifier: MIT
 */

#include "../include/pam_oidc_device.h"
#include "../third_party/qrcodegen/qrcodegen.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/** Maximum symbol width in modules for QR_MAX_VERSION (21 + 4 * version). */
#define QR_MAX_SIZE (QR_MAX_VERSION * 4 + 17)

/** Worst-case bytes per rendered line: QR_MAX_SIZE modules * 3 (UTF-8 glyph width) * 3 (max scale). */
#define QR_LINE_BUF_MAX ((3 * 3 * (QR_MAX_VERSION * 4 + 17)) + 1)

/** Instruction line prefixed to the rendered QR block. */
#define QR_HEADER_LINE "Scan this QR code with your phone's camera to open the verification page:"

/**
 * @brief Reports whether the module at (x, y) of the quiet-zone-padded symbol grid is dark.
 *
 * @param[in] qrdata Packed QR module grid (no quiet zone).
 * @param[in] size   Symbol width/height in modules.
 * @param[in] x      Grid column, 0..size+2*QR_QUIET_ZONE-1.
 * @param[in] y      Grid row, 0..size+2*vquiet-1.
 * @param[in] vquiet Vertical quiet zone in module rows (0..QR_QUIET_ZONE).
 * @return 1 if the module is dark, 0 if light (including quiet-zone positions).
 */
static int qr_module_is_dark(const uint8_t *qrdata, int size, int x, int y, int vquiet) {
    int mx = x - QR_QUIET_ZONE;
    int my = y - vquiet;
    if (mx < 0 || my < 0 || mx >= size || my >= size) {
        return 0;
    }
    return qrcodegen_getModule(qrdata, mx, my) ? 1 : 0;
}

int qr_encode_uri(const char *url, qr_ec_t ec, uint8_t *qrdata, size_t qrdata_cap, int *out_size) {
    if (!url || url[0] == '\0' || !qrdata || qrdata_cap < QR_MATRIX_BYTES_MAX || !out_size) {
        return -1;
    }
    if (ec > QR_EC_HIGH) {
        return -1;
    }

    /* The scratch codeword buffer is stack-allocated per call (bounded by QR_MAX_VERSION),
     * so concurrent PAM invocations never share mutable state. */
    uint8_t temp[QR_MATRIX_BYTES_MAX];
    bool ok = qrcodegen_encodeText(url, temp, qrdata, (enum qrcodegen_Ecc)ec, qrcodegen_VERSION_MIN, QR_MAX_VERSION,
                                   qrcodegen_Mask_AUTO, false);
    if (!ok) {
        *out_size = 0;
        return -1;
    }

    *out_size = qrcodegen_getSize(qrdata);
    return 0;
}

/**
 * @brief Appends a fully built output line (plus its newline) to the render buffer.
 *
 * @param[out] out      Render buffer.
 * @param[in]  out_len  Byte capacity of out.
 * @param[out] out_pos  Current write position (updated on success).
 * @param[in]  line     Built line content (no newline).
 * @param[in]  line_len Byte length of line.
 * @return 0 on success, -1 if the line would not fit.
 */
static int qr_append_line(char *out, size_t out_len, size_t *out_pos, const char *line, size_t line_len) {
    if (*out_pos + line_len + 2 > out_len) {
        return -1;
    }
    memcpy(out + *out_pos, line, line_len);
    out[*out_pos + line_len] = '\n';
    *out_pos += line_len + 1;
    return 0;
}

/**
 * @brief Renders one module row (or one paired row, for the UTF-8 style) as a text line.
 *
 * @param[out] line        Line buffer (at least QR_LINE_BUF_MAX bytes).
 * @param[out] line_len    Byte length of the rendered line.
 * @param[in]  qrdata      Packed QR module grid.
 * @param[in]  size        Symbol width/height in modules.
 * @param[in]  width       Padded grid width (size + 2 * QR_QUIET_ZONE).
 * @param[in]  y0          First module row index (the UTF-8 style pairs rows y0 and y0+1).
 * @param[in]  single_row  1 when y0+1 is outside the grid (odd padded height, UTF-8 style).
 * @param[in]  style       Rendering style.
 * @param[in]  scale       Enlargement factor.
 * @param[in]  vquiet      Vertical quiet zone in module rows (0..QR_QUIET_ZONE).
 * @param[in]  block_char  Dark-module character (QR_STYLE_ASCII only).
 * @return 0 on success, -1 on an unexpected rendering error.
 */
static int qr_render_line(char *line, size_t *line_len, const uint8_t *qrdata, int size, int width, int y0,
                          int single_row, qr_style_t style, int scale, int vquiet, char block_char) {
    size_t pos = 0;
    for (int x = 0; x < width; x++) {
        int dark = qr_module_is_dark(qrdata, size, x, y0, vquiet);
        if (style == QR_STYLE_ASCII) {
            for (int s = 0; s < scale; s++) {
                if (pos + 2 >= QR_LINE_BUF_MAX) {
                    return -1;
                }
                line[pos++] = (char)(dark ? (unsigned char)block_char : ' ');
            }
        } else {
            int dark2 = single_row ? 0 : qr_module_is_dark(qrdata, size, x, y0 + 1, vquiet);
            const char *glyph = " ";
            if (dark && dark2) {
                glyph = "\342\226\210"; /* U+2588 FULL BLOCK */
            } else if (dark) {
                glyph = "\342\226\200"; /* U+2580 UPPER HALF BLOCK */
            } else if (dark2) {
                glyph = "\342\226\204"; /* U+2584 LOWER HALF BLOCK */
            }
            for (int s = 0; s < scale; s++) {
                size_t g = 0;
                while (glyph[g] != '\0') {
                    if (pos + 2 >= QR_LINE_BUF_MAX) {
                        return -1;
                    }
                    line[pos++] = glyph[g];
                    g++;
                }
            }
        }
    }
    if (pos + 1 >= QR_LINE_BUF_MAX) {
        return -1;
    }
    line[pos] = '\0';
    *line_len = pos;
    return 0;
}

int qr_render_matrix(const uint8_t *qrdata, int size, qr_style_t style, int scale, char block_char, int vquiet,
                     char *out, size_t out_len) {
    if (!qrdata || !out || out_len == 0 || size < 21 || size > QR_MAX_SIZE || style > QR_STYLE_ASCII || scale < 1 ||
        scale > 3 || vquiet < 0 || vquiet > QR_QUIET_ZONE) {
        return -1;
    }
    /* The ASCII block character must be a single printable, non-space character so dark
     * modules cannot blend into prompt text or form escape sequences. */
    if (style == QR_STYLE_ASCII && ((unsigned char)block_char < 0x21U || (unsigned char)block_char > 0x7EU)) {
        return -1;
    }

    /* The horizontal quiet zone always keeps the ISO/IEC 18004 4-module minimum (it separates the symbol
     * from the surrounding terminal text); only the vertical zone is configurable, for compactness. */
    int width = size + (2 * QR_QUIET_ZONE);
    int height = size + (2 * vquiet);
    size_t out_pos = 0;
    char line[QR_LINE_BUF_MAX];
    size_t line_len = 0;

    if (style == QR_STYLE_UTF8) {
        for (int y = 0; y < height; y += 2) {
            if (qr_render_line(line, &line_len, qrdata, size, width, y, y + 1 >= height, QR_STYLE_UTF8, scale, vquiet,
                               block_char) != 0) {
                return -1;
            }
            if (qr_append_line(out, out_len, &out_pos, line, line_len) != 0) {
                return -1;
            }
        }
    } else {
        for (int y = 0; y < height; y++) {
            if (qr_render_line(line, &line_len, qrdata, size, width, y, 1, QR_STYLE_ASCII, scale, vquiet, block_char) !=
                0) {
                return -1;
            }
            for (int s = 0; s < scale; s++) {
                if (qr_append_line(out, out_len, &out_pos, line, line_len) != 0) {
                    return -1;
                }
            }
        }
    }

    out[out_pos] = '\0';
    return 0;
}

int qr_render_verification_code(const config_t *cfg, loglevel_t loglevel, const char *url_plain,
                                const char *url_complete, char *out, size_t out_len, pam_handle_t *pamh) {
    /* Reject undersized buffers before the `out_len - 1` size arithmetic below can underflow
     * (out_len == 0 would wrap to SIZE_MAX and make snprintf() effectively unbounded):
     * the smallest renderable output still needs the header line, its newline, and a NUL. */
    if (!cfg || !url_plain || url_plain[0] == '\0' || !out || out_len < strlen(QR_HEADER_LINE) + 2) {
        return -1;
    }

    /* Prefer the complete URI (user code embedded, so nothing is typed on the second device)
     * unless the operator chose manual code entry or the provider did not supply it. */
    const char *uri = (cfg->qr_uri_complete && url_complete) ? url_complete : url_plain;

    uint8_t qrdata[QR_MATRIX_BYTES_MAX];
    int size = 0;
    if (qr_encode_uri(uri, cfg->qr_ec_level, qrdata, sizeof(qrdata), &size) != 0) {
        if (pamh) {
            pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                          "QR code skipped: verification URI does not fit in a version-%d symbol at the configured "
                          "error-correction level",
                          QR_MAX_VERSION);
        }
        return -1;
    }

    /* Reserve one byte for the NUL terminator. No trailing separator blank line is appended: the bottom
     * quiet zone already separates the rendered art from the text prompt that follows it. */
    int header_len = snprintf(out, out_len - 1, "%s\n", QR_HEADER_LINE);
    if (header_len < 0 || (size_t)header_len >= out_len - 1) {
        return -1;
    }
    size_t art_cap = out_len - (size_t)header_len - 1;
    if (qr_render_matrix(qrdata, size, cfg->qr_style, cfg->qr_scale, cfg->qr_block_char[0], cfg->qr_vertical_quiet_zone,
                         out + header_len, art_cap) != 0) {
        if (pamh) {
            pam_oauth_log(pamh, loglevel, LOGLEVEL_DEBUG, LOG_DEBUG,
                          "QR code skipped: rendered output exceeds the terminal buffer capacity");
        }
        return -1;
    }
    /* qr_render_matrix() NUL-terminates the art after its final newline, so the block is complete. */
    return 0;
}
