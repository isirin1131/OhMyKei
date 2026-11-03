/*
 * AES-256 (FIPS 197), CBC mode (NIST SP 800-38A) and the omk_ct_equal /
 * omk_memzero utilities.
 *
 * Byte-oriented implementation: compact and easy to audit.  Performance is
 * more than sufficient for CTAP (a few blocks per operation on a 150 MHz
 * Cortex-M33).
 */

#include "crypto/omk_crypto.h"

#include <string.h>

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
};

static uint8_t rsbox[256];
static bool rsbox_ready;

static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80u) ? 0x1Bu : 0x00u));
}

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b != 0) {
        if (b & 1u) {
            r ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    return r;
}

static void init_rsbox(void) {
    if (rsbox_ready) {
        return;
    }
    for (unsigned i = 0; i < 256; i++) {
        rsbox[sbox[i]] = (uint8_t)i;
    }
    rsbox_ready = true;
}

bool omk_aes256_set_encrypt_key(omk_aes256_ctx *ctx,
                                const uint8_t key[OMK_AES256_KEY_LEN]) {
    static const uint8_t rcon[8] = {0x01, 0x02, 0x04, 0x08,
                                    0x10, 0x20, 0x40, 0x80};
    if (ctx == NULL || key == NULL) {
        return false;
    }
    for (unsigned i = 0; i < 8; i++) {
        ctx->rk[i] = ((uint32_t)key[4 * i] << 24) |
                     ((uint32_t)key[4 * i + 1] << 16) |
                     ((uint32_t)key[4 * i + 2] << 8) |
                     (uint32_t)key[4 * i + 3];
    }
    for (unsigned i = 8; i < 60; i++) {
        uint32_t t = ctx->rk[i - 1];
        if (i % 8 == 0) {
            t = ((t << 8) | (t >> 24));
            t = ((uint32_t)sbox[(t >> 24) & 0xFF] << 24) |
                ((uint32_t)sbox[(t >> 16) & 0xFF] << 16) |
                ((uint32_t)sbox[(t >> 8) & 0xFF] << 8) |
                (uint32_t)sbox[t & 0xFF];
            t ^= (uint32_t)rcon[i / 8 - 1] << 24;
        } else if (i % 8 == 4) {
            t = ((uint32_t)sbox[(t >> 24) & 0xFF] << 24) |
                ((uint32_t)sbox[(t >> 16) & 0xFF] << 16) |
                ((uint32_t)sbox[(t >> 8) & 0xFF] << 8) |
                (uint32_t)sbox[t & 0xFF];
        }
        ctx->rk[i] = ctx->rk[i - 8] ^ t;
    }
    return true;
}

bool omk_aes256_set_decrypt_key(omk_aes256_ctx *ctx,
                                const uint8_t key[OMK_AES256_KEY_LEN]) {
    if (!omk_aes256_set_encrypt_key(ctx, key)) {
        return false;
    }
    init_rsbox();
    return true;
}

static void add_round_key(uint8_t s[16], const uint32_t *rk) {
    for (unsigned c = 0; c < 4; c++) {
        s[4 * c] ^= (uint8_t)(rk[c] >> 24);
        s[4 * c + 1] ^= (uint8_t)(rk[c] >> 16);
        s[4 * c + 2] ^= (uint8_t)(rk[c] >> 8);
        s[4 * c + 3] ^= (uint8_t)rk[c];
    }
}

static void sub_bytes(uint8_t s[16]) {
    for (unsigned i = 0; i < 16; i++) {
        s[i] = sbox[s[i]];
    }
}

static void inv_sub_bytes(uint8_t s[16]) {
    for (unsigned i = 0; i < 16; i++) {
        s[i] = rsbox[s[i]];
    }
}

static void shift_rows(uint8_t s[16]) {
    uint8_t t;
    /* row 1 left by 1 */
    t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;
    /* row 2 left by 2 */
    t = s[2];
    s[2] = s[10];
    s[10] = t;
    t = s[6];
    s[6] = s[14];
    s[14] = t;
    /* row 3 left by 3 (right by 1) */
    t = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t;
}

static void inv_shift_rows(uint8_t s[16]) {
    uint8_t t;
    t = s[13];
    s[13] = s[9];
    s[9] = s[5];
    s[5] = s[1];
    s[1] = t;
    t = s[2];
    s[2] = s[10];
    s[10] = t;
    t = s[6];
    s[6] = s[14];
    s[14] = t;
    t = s[3];
    s[3] = s[7];
    s[7] = s[11];
    s[11] = s[15];
    s[15] = t;
}

static void mix_columns(uint8_t s[16]) {
    for (unsigned c = 0; c < 4; c++) {
        uint8_t *p = s + 4 * c;
        uint8_t a = p[0], b = p[1], d = p[2], e = p[3];
        p[0] = (uint8_t)(gmul(a, 2) ^ gmul(b, 3) ^ d ^ e);
        p[1] = (uint8_t)(a ^ gmul(b, 2) ^ gmul(d, 3) ^ e);
        p[2] = (uint8_t)(a ^ b ^ gmul(d, 2) ^ gmul(e, 3));
        p[3] = (uint8_t)(gmul(a, 3) ^ b ^ d ^ gmul(e, 2));
    }
}

static void inv_mix_columns(uint8_t s[16]) {
    for (unsigned c = 0; c < 4; c++) {
        uint8_t *p = s + 4 * c;
        uint8_t a = p[0], b = p[1], d = p[2], e = p[3];
        p[0] = (uint8_t)(gmul(a, 14) ^ gmul(b, 11) ^ gmul(d, 13) ^ gmul(e, 9));
        p[1] = (uint8_t)(gmul(a, 9) ^ gmul(b, 14) ^ gmul(d, 11) ^ gmul(e, 13));
        p[2] = (uint8_t)(gmul(a, 13) ^ gmul(b, 9) ^ gmul(d, 14) ^ gmul(e, 11));
        p[3] = (uint8_t)(gmul(a, 11) ^ gmul(b, 13) ^ gmul(d, 9) ^ gmul(e, 14));
    }
}

void omk_aes256_encrypt_block(const omk_aes256_ctx *ctx,
                              const uint8_t in[OMK_AES_BLOCK_LEN],
                              uint8_t out[OMK_AES_BLOCK_LEN]) {
    uint8_t s[16];
    memcpy(s, in, 16);
    add_round_key(s, ctx->rk);
    for (unsigned round = 1; round <= 13; round++) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        add_round_key(s, ctx->rk + 4 * round);
    }
    sub_bytes(s);
    shift_rows(s);
    add_round_key(s, ctx->rk + 56);
    memcpy(out, s, 16);
}

void omk_aes256_decrypt_block(const omk_aes256_ctx *ctx,
                              const uint8_t in[OMK_AES_BLOCK_LEN],
                              uint8_t out[OMK_AES_BLOCK_LEN]) {
    uint8_t s[16];
    init_rsbox();
    memcpy(s, in, 16);
    add_round_key(s, ctx->rk + 56);
    for (unsigned round = 13; round > 0; round--) {
        inv_shift_rows(s);
        inv_sub_bytes(s);
        add_round_key(s, ctx->rk + 4 * round);
        inv_mix_columns(s);
        if (round == 1) {
            break;
        }
    }
    inv_shift_rows(s);
    inv_sub_bytes(s);
    add_round_key(s, ctx->rk);
    memcpy(out, s, 16);
}

void omk_aes256_cbc_encrypt(const uint8_t key[OMK_AES256_KEY_LEN],
                            const uint8_t iv[OMK_AES_BLOCK_LEN],
                            const uint8_t *in, size_t len, uint8_t *out) {
    omk_aes256_ctx ctx;
    uint8_t chain[16];
    uint8_t block[16];

    if (len == 0 || len % 16 != 0 || !omk_aes256_set_encrypt_key(&ctx, key)) {
        return;
    }
    memcpy(chain, iv, 16);
    for (size_t off = 0; off < len; off += 16) {
        for (unsigned i = 0; i < 16; i++) {
            block[i] = (uint8_t)(in[off + i] ^ chain[i]);
        }
        omk_aes256_encrypt_block(&ctx, block, chain);
        memcpy(out + off, chain, 16);
    }
    omk_memzero(&ctx, sizeof ctx);
    omk_memzero(block, sizeof block);
}

void omk_aes256_cbc_decrypt(const uint8_t key[OMK_AES256_KEY_LEN],
                            const uint8_t iv[OMK_AES_BLOCK_LEN],
                            const uint8_t *in, size_t len, uint8_t *out) {
    omk_aes256_ctx ctx;
    uint8_t chain[16];
    uint8_t saved[16];
    uint8_t block[16];

    if (len == 0 || len % 16 != 0 || !omk_aes256_set_decrypt_key(&ctx, key)) {
        return;
    }
    memcpy(chain, iv, 16);
    for (size_t off = 0; off < len; off += 16) {
        memcpy(saved, in + off, 16);
        omk_aes256_decrypt_block(&ctx, saved, block);
        for (unsigned i = 0; i < 16; i++) {
            out[off + i] = (uint8_t)(block[i] ^ chain[i]);
        }
        memcpy(chain, saved, 16);
    }
    omk_memzero(&ctx, sizeof ctx);
    omk_memzero(block, sizeof block);
}

bool omk_ct_equal(const void *a, const void *b, size_t len) {
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    uint8_t diff = 0;

    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    }
    return diff == 0;
}

void omk_memzero(void *p, size_t len) {
    volatile uint8_t *vp = (volatile uint8_t *)p;

    if (p == NULL) {
        return;
    }
    while (len-- != 0) {
        *vp++ = 0;
    }
}
