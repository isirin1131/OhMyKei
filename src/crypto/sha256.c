/*
 * SHA-256 (FIPS 180-4), HMAC-SHA-256 (FIPS 198-1) and HKDF-SHA-256
 * (RFC 5869).  Self-contained C17 with no heap use, so the identical code
 * runs on the RP2350 and in the host test suite.
 */

#include "crypto/omk_crypto.h"

#include <string.h>

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static const uint32_t sha256_iv[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

static uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

static uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void store_be64(uint8_t *p, uint64_t v) {
    store_be32(p, (uint32_t)(v >> 32));
    store_be32(p + 4, (uint32_t)v);
}

static void sha256_compress(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, hh;
    unsigned i;

    for (i = 0; i < 16; i++) {
        w[i] = load_be32(block + 4 * i);
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^
                      (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^
                      (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = h[0];
    b = h[1];
    c = h[2];
    d = h[3];
    e = h[4];
    f = h[5];
    g = h[6];
    hh = h[7];

    for (i = 0; i < 64; i++) {
        uint32_t big_s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + big_s1 + ch + sha256_k[i] + w[i];
        uint32_t big_s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = big_s0 + maj;

        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
}

void omk_sha256_init(omk_sha256_ctx *ctx) {
    unsigned i;

    for (i = 0; i < 8; i++) {
        ctx->h[i] = sha256_iv[i];
    }
    ctx->total_len = 0;
    ctx->buf_len = 0;
    memset(ctx->buf, 0, sizeof ctx->buf);
}

void omk_sha256_update(omk_sha256_ctx *ctx, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    size_t take;

    if (len == 0) {
        return;
    }
    ctx->total_len += (uint64_t)len;

    if (ctx->buf_len != 0) {
        take = sizeof ctx->buf - ctx->buf_len;
        if (take > len) {
            take = len;
        }
        memcpy(ctx->buf + ctx->buf_len, p, take);
        ctx->buf_len += take;
        p += take;
        len -= take;
        if (ctx->buf_len < sizeof ctx->buf) {
            return;
        }
        sha256_compress(ctx->h, ctx->buf);
        ctx->buf_len = 0;
    }

    while (len >= sizeof ctx->buf) {
        sha256_compress(ctx->h, p);
        p += sizeof ctx->buf;
        len -= sizeof ctx->buf;
    }

    if (len != 0) {
        memcpy(ctx->buf, p, len);
        ctx->buf_len = len;
    }
}

void omk_sha256_final(omk_sha256_ctx *ctx, uint8_t out[OMK_SHA256_LEN]) {
    /* Padding is 0x80, zeros, then the 64-bit big-endian bit count.  With the
     * block size as a compile-time constant no VLA is involved. */
    uint8_t pad[72];
    uint8_t lenbuf[8];
    size_t pad_len;
    unsigned i;

    store_be64(lenbuf, ctx->total_len * 8);

    pad[0] = 0x80;
    pad_len = (ctx->buf_len < 56) ? 56 - ctx->buf_len : 120 - ctx->buf_len;
    memset(pad + 1, 0, pad_len - 1);
    omk_sha256_update(ctx, pad, pad_len);
    omk_sha256_update(ctx, lenbuf, sizeof lenbuf);

    for (i = 0; i < 8; i++) {
        store_be32(out + 4 * i, ctx->h[i]);
    }
    omk_memzero(ctx, sizeof *ctx);
}

void omk_sha256(const void *data, size_t len, uint8_t out[OMK_SHA256_LEN]) {
    omk_sha256_ctx ctx;

    omk_sha256_init(&ctx);
    omk_sha256_update(&ctx, data, len);
    omk_sha256_final(&ctx, out);
}

void omk_hmac_sha256_init(omk_sha256_ctx *inner, uint8_t opad[64],
                          const uint8_t *key, size_t key_len) {
    uint8_t k[64];
    uint8_t ipad[64];
    unsigned i;

    if (key_len > sizeof k) {
        omk_sha256(key, key_len, k);
        memset(k + OMK_SHA256_LEN, 0, sizeof k - OMK_SHA256_LEN);
    } else {
        if (key_len != 0) {
            memcpy(k, key, key_len);
        }
        memset(k + key_len, 0, sizeof k - key_len);
    }

    for (i = 0; i < sizeof k; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }

    omk_sha256_init(inner);
    omk_sha256_update(inner, ipad, sizeof ipad);

    omk_memzero(k, sizeof k);
    omk_memzero(ipad, sizeof ipad);
}

void omk_hmac_sha256_update(omk_sha256_ctx *inner, const void *data,
                            size_t len) {
    omk_sha256_update(inner, data, len);
}

void omk_hmac_sha256_final(omk_sha256_ctx *inner, uint8_t opad[64],
                           uint8_t out[OMK_HMAC256_LEN]) {
    omk_sha256_ctx outer;
    uint8_t ihash[OMK_SHA256_LEN];

    omk_sha256_final(inner, ihash);
    omk_sha256_init(&outer);
    omk_sha256_update(&outer, opad, 64);
    omk_sha256_update(&outer, ihash, sizeof ihash);
    omk_sha256_final(&outer, out);
    omk_memzero(ihash, sizeof ihash);
    /* opad is derived from the HMAC key and this context is finished with
     * it: don't leave a keyed pad in the caller's frame.  Callers that reuse
     * opad must call init() again first. */
    omk_memzero(opad, 64);
}

void omk_hmac_sha256(const uint8_t *key, size_t key_len,
                     const void *msg, size_t msg_len,
                     uint8_t out[OMK_HMAC256_LEN]) {
    omk_sha256_ctx inner;
    uint8_t opad[64];

    omk_hmac_sha256_init(&inner, opad, key, key_len);
    omk_hmac_sha256_update(&inner, msg, msg_len);
    omk_hmac_sha256_final(&inner, opad, out);
    omk_memzero(opad, sizeof opad);
}

void omk_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                     const uint8_t *ikm, size_t ikm_len,
                     const uint8_t *info, size_t info_len,
                     uint8_t *out, size_t out_len) {
    uint8_t prk[OMK_SHA256_LEN];
    uint8_t t[OMK_SHA256_LEN];
    uint8_t opad[64];
    omk_sha256_ctx inner;
    uint8_t counter = 1;
    size_t done = 0;
    size_t t_len = 0;
    size_t chunk;

    if (out_len == 0) {
        goto done;
    }
    if (out_len > 255u * OMK_SHA256_LEN) {
        /* Contract: RFC 5869 caps the output at 255 blocks.  Clamp rather
         * than wrap the block counter. */
        out_len = 255u * OMK_SHA256_LEN;
    }

    /* Extract: PRK = HMAC-SHA-256(salt, IKM).  A zero-length salt hashes as a
     * 64-byte zero pad, which is exactly the RFC 5869 default. */
    omk_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);

    /* Expand: T(i) = HMAC(PRK, T(i-1) || info || i), i = 1.. */
    while (done < out_len) {
        omk_hmac_sha256_init(&inner, opad, prk, sizeof prk);
        if (t_len != 0) {
            omk_hmac_sha256_update(&inner, t, t_len);
        }
        if (info_len != 0) {
            omk_hmac_sha256_update(&inner, info, info_len);
        }
        omk_hmac_sha256_update(&inner, &counter, 1);
        omk_hmac_sha256_final(&inner, opad, t);
        t_len = sizeof t;
        counter++;

        chunk = out_len - done;
        if (chunk > sizeof t) {
            chunk = sizeof t;
        }
        memcpy(out + done, t, chunk);
        done += chunk;
    }

done:
    /* Every exit path wipes the extracted key, the block state and the
     * keyed outer pad.  inner is normally wiped by HMAC final(); wipe it
     * defensively so the zero-length early exit is covered as well. */
    omk_memzero(prk, sizeof prk);
    omk_memzero(t, sizeof t);
    omk_memzero(opad, sizeof opad);
    omk_memzero(&inner, sizeof inner);
}
