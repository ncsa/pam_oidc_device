/**
 * @file pkce.c
 * @brief RFC 7636 Proof Key for Code Exchange (PKCE) code verifier generation and S256 challenge computation.
 *
 * Extends the RFC 8628 device authorization grant with the PKCE mechanism: a
 * high-entropy `code_verifier` drawn from the OpenSSL CSPRNG is derived per
 * authentication attempt, its S256 `code_challenge` is sent with the device
 * authorization request, and the verifier itself is presented at the token
 * endpoint. Binds the token exchange to the originating device flow, so a
 * stolen `device_code` cannot by itself be converted into tokens.
 *
 * @project     pam_oidc_device
 * @repository  https://github.com/ncsa/pam_oidc_device
 * @maintainer  National Center for Supercomputing Applications (NCSA)
 * @license     MIT License
 * @see         RFC 7636 (Proof Key for Code Exchange by Authenticated Public Key Clients)
 *
 * Copyright (c) 2026 The Board of Trustees of the University of Illinois.
 * SPDX-License-Identifier: MIT
 */

#include "../include/pam_oidc_device.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <string.h>

/**
 * @brief Unpadded Base64URL alphabet per RFC 4648 §5 (`+` -> `-`, `/` -> `_`).
 *
 * Sized 65 so the 64-character alphabet is NUL-terminated in memory; the
 * encoder indexes positions 0..63 only.
 */
static const char B64URL_ALPHABET[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * @brief Encodes raw bytes as unpadded Base64URL (RFC 4648 §5, no `=` padding).
 *
 * Standard three-octet-to-four-character grouping with the URL-safe alphabet;
 * the one- and two-character groups at the end of a non-multiple-of-three
 * input omit their padding characters.
 *
 * @param[in]  data    Raw input bytes.
 * @param[in]  len     Input length in bytes.
 * @param[out] out     Buffer receiving the NUL-terminated encoded string.
 * @param[in]  out_len Output buffer capacity in bytes.
 * @return 0 on success, -1 on NULL inputs, empty capacity, or a buffer too small
 *         for the encoded result.
 */
static int base64url_encode_nopad(const unsigned char *data, size_t len, char *out, size_t out_len) {
    if (!data || !out || out_len == 0) {
        return -1;
    }

    size_t encoded_len = ((len + 2) / 3) * 4;
    if (len % 3 == 1) {
        encoded_len -= 2;
    } else if (len % 3 == 2) {
        encoded_len -= 1;
    }
    if (encoded_len + 1 > out_len) {
        return -1;
    }

    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t acc = (uint32_t)data[i] << 16;
        if (i + 1 < len) {
            acc |= (uint32_t)data[i + 1] << 8;
        }
        if (i + 2 < len) {
            acc |= (uint32_t)data[i + 2];
        }
        out[o++] = B64URL_ALPHABET[(acc >> 18) & 0x3F];
        out[o++] = B64URL_ALPHABET[(acc >> 12) & 0x3F];
        if (i + 1 < len) {
            out[o++] = B64URL_ALPHABET[(acc >> 6) & 0x3F];
        }
        if (i + 2 < len) {
            out[o++] = B64URL_ALPHABET[acc & 0x3F];
        }
    }
    out[o] = '\0';
    return 0;
}

/**
 * @brief Generates a high-entropy RFC 7636 PKCE code verifier from the OpenSSL CSPRNG.
 *
 * Reads 48 random bytes from `RAND_bytes()` and encodes them as unpadded
 * Base64URL, yielding a 64-character verifier within the RFC 7636 §4.2
 * 43-128 character bound. The raw CSPRNG buffer is scrubbed before return.
 *
 * The caller owns `out` and is expected to scrub it with `secure_memzero()` on
 * every termination path; this function never logs or returns the verifier.
 *
 * @param[out] out    Buffer receiving the NUL-terminated verifier.
 * @param[in]  out_len Buffer capacity in bytes (must be at least PKCE_VERIFIER_LEN + 1).
 * @return 0 on success, -1 on NULL inputs, undersized buffer, or CSPRNG failure.
 */
int pkce_generate_code_verifier(char *out, size_t out_len) {
    unsigned char raw[PKCE_VERIFIER_BYTES];

    if (!out || out_len < PKCE_VERIFIER_LEN + 1) {
        return -1;
    }
    if (RAND_bytes(raw, sizeof(raw)) != 1) {
        return -1;
    }
    int rc = base64url_encode_nopad(raw, sizeof(raw), out, out_len);
    secure_memzero(raw, sizeof(raw));
    return rc;
}

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
int pkce_compute_s256_challenge(const char *verifier, char *out, size_t out_len) {
    if (!verifier || *verifier == '\0' || !out || out_len < PKCE_S256_CHALLENGE_LEN + 1) {
        return -1;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return -1;
    }
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, verifier, strlen(verifier)) == 1 &&
             EVP_DigestFinal_ex(ctx, digest, &digest_len) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) {
        return -1;
    }

    return base64url_encode_nopad(digest, digest_len, out, out_len);
}
