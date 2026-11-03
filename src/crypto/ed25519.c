/*
 * Ed25519 (RFC 8032 section 5.1) -- self-contained C17 implementation.
 *
 * Everything lives in this file: SHA-512 (FIPS 180-4), field arithmetic
 * modulo p = 2^255 - 19, the edwards25519 group in extended coordinates and
 * scalar arithmetic modulo L.  No heap, no VLAs, no __int128 and no
 * 64x64 -> 128 multiplication, so the same source compiles for the
 * Cortex-M33 (32-bit) and for the host test suite.
 *
 * Field elements use the ref10 10-limb representation
 *
 *     value = sum h[i] * 2^w[i],  w = 0,26,51,77,102,128,153,179,204,230
 *
 * i.e. alternating widths of 26 and 25 bits ("25.5 bits").  Limbs are
 * int32_t and are kept in [0, 2^26) by fe_normalize(), so every product is a
 * 32x32 -> 64 bit multiplication and a 10x10 convolution fits comfortably
 * in int64_t.
 *
 * Side-channel scope: ge_scalarmult() is a fixed double-and-add loop whose
 * accumulator update uses a mask, so there are no secret-indexed tables and
 * no explicit branch on a scalar bit.  sc_reduce()/sc_muladd() likewise use
 * mask-based conditional subtraction.  That is a source-level property only:
 * the compiler may turn a mask select into a branch, and helpers that run on
 * public input (ge_frombytes(), sc_is_canonical(), the final canonicalisation
 * in fe_tobytes(), and SHA-512 length handling) do contain data-dependent
 * branches.  No timing or power-analysis guarantee is made.
 *
 * Seed-derived hashes, secret scalars and the main signing buffers are wiped
 * on every return.  The field arithmetic and SHA-512 compression scratch is
 * not individually wiped at every layer, so transient copies can remain on
 * the stack.
 */

#include "crypto/omk_crypto.h"

#include <string.h>

/* Defined with the field helpers below; declared here because SHA-512
 * finalisation also wipes its context. */
static void ed_zero(void *p, size_t n);

/* ====================================================================== */
/* SHA-512 (FIPS 180-4)                                                    */
/* ====================================================================== */

typedef struct {
    uint64_t h[8];
    uint64_t total; /* number of bytes hashed so far */
    uint8_t buf[128];
    size_t buf_len;
} ed_sha512_ctx;

/* First 64 bits of the fractional parts of the cube roots of the first 80
 * primes.  Generated with exact integer arithmetic, not transcribed. */
static const uint64_t ed_sha512_k[80] = {
    UINT64_C(0x428a2f98d728ae22), UINT64_C(0x7137449123ef65cd),
    UINT64_C(0xb5c0fbcfec4d3b2f), UINT64_C(0xe9b5dba58189dbbc),
    UINT64_C(0x3956c25bf348b538), UINT64_C(0x59f111f1b605d019),
    UINT64_C(0x923f82a4af194f9b), UINT64_C(0xab1c5ed5da6d8118),
    UINT64_C(0xd807aa98a3030242), UINT64_C(0x12835b0145706fbe),
    UINT64_C(0x243185be4ee4b28c), UINT64_C(0x550c7dc3d5ffb4e2),
    UINT64_C(0x72be5d74f27b896f), UINT64_C(0x80deb1fe3b1696b1),
    UINT64_C(0x9bdc06a725c71235), UINT64_C(0xc19bf174cf692694),
    UINT64_C(0xe49b69c19ef14ad2), UINT64_C(0xefbe4786384f25e3),
    UINT64_C(0x0fc19dc68b8cd5b5), UINT64_C(0x240ca1cc77ac9c65),
    UINT64_C(0x2de92c6f592b0275), UINT64_C(0x4a7484aa6ea6e483),
    UINT64_C(0x5cb0a9dcbd41fbd4), UINT64_C(0x76f988da831153b5),
    UINT64_C(0x983e5152ee66dfab), UINT64_C(0xa831c66d2db43210),
    UINT64_C(0xb00327c898fb213f), UINT64_C(0xbf597fc7beef0ee4),
    UINT64_C(0xc6e00bf33da88fc2), UINT64_C(0xd5a79147930aa725),
    UINT64_C(0x06ca6351e003826f), UINT64_C(0x142929670a0e6e70),
    UINT64_C(0x27b70a8546d22ffc), UINT64_C(0x2e1b21385c26c926),
    UINT64_C(0x4d2c6dfc5ac42aed), UINT64_C(0x53380d139d95b3df),
    UINT64_C(0x650a73548baf63de), UINT64_C(0x766a0abb3c77b2a8),
    UINT64_C(0x81c2c92e47edaee6), UINT64_C(0x92722c851482353b),
    UINT64_C(0xa2bfe8a14cf10364), UINT64_C(0xa81a664bbc423001),
    UINT64_C(0xc24b8b70d0f89791), UINT64_C(0xc76c51a30654be30),
    UINT64_C(0xd192e819d6ef5218), UINT64_C(0xd69906245565a910),
    UINT64_C(0xf40e35855771202a), UINT64_C(0x106aa07032bbd1b8),
    UINT64_C(0x19a4c116b8d2d0c8), UINT64_C(0x1e376c085141ab53),
    UINT64_C(0x2748774cdf8eeb99), UINT64_C(0x34b0bcb5e19b48a8),
    UINT64_C(0x391c0cb3c5c95a63), UINT64_C(0x4ed8aa4ae3418acb),
    UINT64_C(0x5b9cca4f7763e373), UINT64_C(0x682e6ff3d6b2b8a3),
    UINT64_C(0x748f82ee5defb2fc), UINT64_C(0x78a5636f43172f60),
    UINT64_C(0x84c87814a1f0ab72), UINT64_C(0x8cc702081a6439ec),
    UINT64_C(0x90befffa23631e28), UINT64_C(0xa4506cebde82bde9),
    UINT64_C(0xbef9a3f7b2c67915), UINT64_C(0xc67178f2e372532b),
    UINT64_C(0xca273eceea26619c), UINT64_C(0xd186b8c721c0c207),
    UINT64_C(0xeada7dd6cde0eb1e), UINT64_C(0xf57d4f7fee6ed178),
    UINT64_C(0x06f067aa72176fba), UINT64_C(0x0a637dc5a2c898a6),
    UINT64_C(0x113f9804bef90dae), UINT64_C(0x1b710b35131c471b),
    UINT64_C(0x28db77f523047d84), UINT64_C(0x32caab7b40c72493),
    UINT64_C(0x3c9ebe0a15c9bebc), UINT64_C(0x431d67c49c100d4c),
    UINT64_C(0x4cc5d4becb3e42b6), UINT64_C(0x597f299cfc657e2a),
    UINT64_C(0x5fcb6fab3ad6faec), UINT64_C(0x6c44198c4a475817),
};

static const uint64_t ed_sha512_iv[8] = {
    UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
    UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
    UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179),
};

static uint64_t ed_rotr64(uint64_t x, unsigned n)
{
    return (x >> n) | (x << (64 - n));
}

static uint32_t ed_load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void ed_store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void ed_store_be64(uint8_t *p, uint64_t v)
{
    ed_store_be32(p, (uint32_t)(v >> 32));
    ed_store_be32(p + 4, (uint32_t)v);
}

static void ed_sha512_compress(uint64_t h[8], const uint8_t blk[128])
{
    uint64_t w[80];
    uint64_t a, b, c, d, e, f, g, hh, t1, t2;
    unsigned i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint64_t)ed_load_be32(blk + 8 * i) << 32) |
               ed_load_be32(blk + 8 * i + 4);
    }
    for (i = 16; i < 80; i++) {
        uint64_t s0 = ed_rotr64(w[i - 15], 1) ^ ed_rotr64(w[i - 15], 8) ^
                      (w[i - 15] >> 7);
        uint64_t s1 = ed_rotr64(w[i - 2], 19) ^ ed_rotr64(w[i - 2], 61) ^
                      (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];

    for (i = 0; i < 80; i++) {
        uint64_t bsig1 = ed_rotr64(e, 14) ^ ed_rotr64(e, 18) ^
                         ed_rotr64(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t bsig0 = ed_rotr64(a, 28) ^ ed_rotr64(a, 34) ^
                         ed_rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);

        t1 = hh + bsig1 + ch + ed_sha512_k[i] + w[i];
        t2 = bsig0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void ed_sha512_init(ed_sha512_ctx *c)
{
    memcpy(c->h, ed_sha512_iv, sizeof(c->h));
    c->total = 0;
    c->buf_len = 0;
}

static void ed_sha512_update(ed_sha512_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;

    if (len == 0) {
        return;
    }
    c->total += (uint64_t)len;
    if (c->buf_len != 0) {
        size_t n = sizeof(c->buf) - c->buf_len;
        if (n > len) {
            n = len;
        }
        memcpy(c->buf + c->buf_len, p, n);
        c->buf_len += n;
        p += n;
        len -= n;
        if (c->buf_len < sizeof(c->buf)) {
            return;
        }
        ed_sha512_compress(c->h, c->buf);
        c->buf_len = 0;
    }
    while (len >= sizeof(c->buf)) {
        ed_sha512_compress(c->h, p);
        p += sizeof(c->buf);
        len -= sizeof(c->buf);
    }
    if (len != 0) {
        memcpy(c->buf, p, len);
        c->buf_len = len;
    }
}

static void ed_sha512_final(ed_sha512_ctx *c, uint8_t out[OMK_SHA512_LEN])
{
    size_t i = c->buf_len;

    c->buf[i++] = 0x80;
    if (i > 112) {
        memset(c->buf + i, 0, sizeof(c->buf) - i);
        ed_sha512_compress(c->h, c->buf);
        i = 0;
    }
    memset(c->buf + i, 0, 112 - i);
    ed_store_be64(c->buf + 112, c->total >> 61); /* length in bits, hi word */
    ed_store_be64(c->buf + 120, c->total << 3);
    ed_sha512_compress(c->h, c->buf);

    for (i = 0; i < 8; i++) {
        ed_store_be64(out + 8 * i, c->h[i]);
    }
    /* The context holds the chaining state and the final message block; it
     * may be seed- or nonce-derived, so do not leave it on the stack. */
    ed_zero(c, sizeof *c);
}

static void ed_sha512(const void *data, size_t len,
                      uint8_t out[OMK_SHA512_LEN])
{
    ed_sha512_ctx c;

    ed_sha512_init(&c);
    ed_sha512_update(&c, data, len);
    ed_sha512_final(&c, out);
}

/* ====================================================================== */
/* Field arithmetic modulo p = 2^255 - 19                                  */
/* ====================================================================== */

typedef int32_t fe[10];

/* d = -121665/121666 mod p, 2d, and sqrt(-1) = 2^((p-1)/4) mod p. */
static const fe ed_d = {
    56195235, 13857412, 51736253, 6949390, 114729,
    24766616, 60832955, 30306712, 48412415, 21499315,
};
static const fe ed_d2 = {
    45281625, 27714825, 36363642, 13898781, 229458,
    15978800, 54557047, 27058993, 29715967, 9444199,
};
static const fe ed_sqrtm1 = {
    34513072, 25610706, 9377949, 3500415, 12389472,
    33281959, 41962654, 31548777, 326685, 11406482,
};

/* ed25519 base point, y coordinate with the sign bit of x (x is even). */
static const uint8_t ed_base_enc[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
};

static uint32_t ed_load_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t ed_load_le24(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}

static void ed_store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* Constant-time equality of two byte strings. */
static int ed_ct_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    size_t i;

    for (i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

/* Best-effort wipe of secret material. */
static void ed_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;

    while (n-- != 0) {
        *v++ = 0;
    }
}

/*
 * Reduce an int64 limb vector to the canonical limb range: every limb is
 * non-negative and narrower than its weight (26 bits on even positions,
 * 25 bits on odd ones).  The represented value changes only by multiples
 * of p because 2^255 == 19 (mod p).
 *
 * Four fixed passes always reach a fixed point, even when the input limbs
 * are as large as a product of two reduced limbs: after the first pass the
 * limbs 1..9 are in range and the wrap carry into limb 0 is small; after
 * the third pass every limb is in range, so the fourth pass does nothing.
 * The loop count is fixed so the timing is independent of the input.
 *
 * Negative limbs are handled by the floor division of an arithmetic
 * right shift; multiplication by 2^b is used instead of a left shift
 * because shifting a negative value is undefined in C.
 */
static void fe_normalize(int64_t t[10])
{
    int pass, i;

    for (pass = 0; pass < 4; pass++) {
        int64_t c;

        for (i = 0; i < 9; i++) {
            int b = (i & 1) ? 25 : 26;
            c = t[i] >> b;
            t[i] -= c * (INT64_C(1) << b);
            t[i + 1] += c;
        }
        c = t[9] >> 25;
        t[9] -= c * (INT64_C(1) << 25);
        t[0] += 19 * c;
    }
}

static void fe_0(fe h)
{
    memset(h, 0, sizeof(fe));
}

static void fe_1(fe h)
{
    fe_0(h);
    h[0] = 1;
}

static void fe_copy(fe h, const fe f)
{
    memcpy(h, f, sizeof(fe));
}

static void fe_add(fe h, const fe f, const fe g)
{
    int64_t t[10];
    int i;

    for (i = 0; i < 10; i++) {
        t[i] = (int64_t)f[i] + (int64_t)g[i];
    }
    fe_normalize(t);
    for (i = 0; i < 10; i++) {
        h[i] = (int32_t)t[i];
    }
}

static void fe_sub(fe h, const fe f, const fe g)
{
    int64_t t[10];
    int i;

    for (i = 0; i < 10; i++) {
        t[i] = (int64_t)f[i] - (int64_t)g[i];
    }
    fe_normalize(t);
    for (i = 0; i < 10; i++) {
        h[i] = (int32_t)t[i];
    }
}

static void fe_neg(fe h, const fe f)
{
    int64_t t[10];
    int i;

    for (i = 0; i < 10; i++) {
        t[i] = -(int64_t)f[i];
    }
    fe_normalize(t);
    for (i = 0; i < 10; i++) {
        h[i] = (int32_t)t[i];
    }
}

/*
 * h = f * g.  A pair of odd limbs has weight w[i] + w[j] = w[i+j] + 1, so
 * odd*odd products are doubled before being folded at index i+j.  Terms
 * with i+j >= 10 fold back by 19 because 2^255 == 19 (mod p).
 */
static void fe_mul(fe h, const fe f, const fe g)
{
    int64_t t[20] = {0};
    int64_t u[10];
    int i, j;

    for (i = 0; i < 10; i++) {
        for (j = 0; j < 10; j++) {
            /* 32x32 -> 64 bit multiply; limbs are non-negative. */
            int64_t p = (int64_t)((uint64_t)(uint32_t)f[i] *
                                  (uint64_t)(uint32_t)g[j]);
            if ((i & 1) && (j & 1)) {
                p *= 2;
            }
            t[i + j] += p;
        }
    }
    for (i = 0; i < 10; i++) {
        u[i] = t[i] + 19 * t[i + 10];
    }
    fe_normalize(u);
    for (i = 0; i < 10; i++) {
        h[i] = (int32_t)u[i];
    }
}

static void fe_sq(fe h, const fe f)
{
    fe_mul(h, f, f);
}

/* h = f when bit != 0, h unchanged otherwise.  The select is written with a
 * mask rather than a branch; C does not require the compiler to keep it
 * branch-free. */
static void fe_cmov(fe h, const fe f, unsigned bit)
{
    uint32_t mask = (uint32_t)0 - (uint32_t)(bit & 1u);
    int i;

    for (i = 0; i < 10; i++) {
        uint32_t x = (uint32_t)h[i];
        uint32_t d = (x ^ (uint32_t)f[i]) & mask;
        h[i] = (int32_t)(x ^ d);
    }
}

static void fe_frombytes(fe h, const uint8_t s[32])
{
    int64_t t[10];
    int i;

    t[0] = (int64_t)ed_load_le32(s);
    t[1] = (int64_t)ed_load_le24(s + 4) << 6;
    t[2] = (int64_t)ed_load_le24(s + 7) << 5;
    t[3] = (int64_t)ed_load_le24(s + 10) << 3;
    t[4] = (int64_t)ed_load_le24(s + 13) << 2;
    t[5] = (int64_t)ed_load_le32(s + 16);
    t[6] = (int64_t)ed_load_le24(s + 20) << 7;
    t[7] = (int64_t)ed_load_le24(s + 23) << 5;
    t[8] = (int64_t)ed_load_le24(s + 26) << 4;
    t[9] = (int64_t)(ed_load_le24(s + 29) & 0x7fffffu) << 2;

    fe_normalize(t);
    for (i = 0; i < 10; i++) {
        h[i] = (int32_t)t[i];
    }
}

/*
 * Canonical little-endian encoding: reduce limbs to [0, 2^255), pack, then
 * conditionally subtract p.  Adding 19 first is the standard trick: the
 * result is >= p exactly when the addition carries into bit 255, and
 * clearing that bit performs the subtraction.
 */
static void fe_tobytes(uint8_t s[32], const fe f)
{
    int64_t t[10];
    uint8_t v[32], w[32];
    uint64_t acc = 0;
    unsigned accbits = 0, o = 0;
    uint32_t carry;
    int i;

    for (i = 0; i < 10; i++) {
        t[i] = f[i];
    }
    fe_normalize(t); /* all limbs are now in [0, 2^26) / [0, 2^25) */

    for (i = 0; i < 10; i++) {
        unsigned b = (i & 1) ? 25u : 26u;
        acc |= (uint64_t)(uint32_t)t[i] << accbits;
        accbits += b;
        while (accbits >= 8) {
            v[o++] = (uint8_t)acc;
            acc >>= 8;
            accbits -= 8;
        }
    }
    if (o < 32) {
        v[o++] = (uint8_t)acc; /* the final 7 bits */
    }
    while (o < 32) {
        v[o++] = 0;
    }

    memcpy(s, v, 32);
    carry = 19;
    for (i = 0; i < 32; i++) {
        carry += s[i];
        w[i] = (uint8_t)carry;
        carry >>= 8;
    }
    if ((w[31] & 0x80u) != 0) { /* f + 19 >= 2^255, so f >= p */
        w[31] &= 0x7fu;
        memcpy(s, w, 32);
    }
}

static int fe_isnegative(const fe f)
{
    uint8_t s[32];

    fe_tobytes(s, f);
    return (int)(s[0] & 1u);
}

static int fe_iszero(const fe f)
{
    uint8_t s[32], z[32];

    fe_tobytes(s, f);
    memset(z, 0, sizeof(z));
    return ed_ct_eq(s, z, 32);
}

static int fe_isequal(const fe f, const fe g)
{
    uint8_t a[32], b[32];

    fe_tobytes(a, f);
    fe_tobytes(b, g);
    return ed_ct_eq(a, b, 32);
}

/* h = a^e for a public 32-byte little-endian exponent e. */
static void fe_pow(fe h, const fe a, const uint8_t e[32])
{
    fe r, t;
    int i;

    fe_1(r);
    for (i = 255; i >= 0; i--) {
        unsigned bit = (unsigned)((e[i >> 3] >> (i & 7)) & 1);

        fe_sq(r, r);
        fe_mul(t, r, a);
        fe_cmov(r, t, bit);
    }
    fe_copy(h, r);
    ed_zero(r, sizeof r);
    ed_zero(t, sizeof t);
}

/* h = a^-1 = a^(p-2). */
static void fe_invert(fe h, const fe a)
{
    uint8_t e[32];

    memset(e, 0xff, sizeof(e));
    e[0] = 0xeb; /* p - 2 = 2^255 - 21 */
    e[31] = 0x7f;
    fe_pow(h, a, e);
}

/* h = a^((p-5)/8) = a^(2^252-3), used for square roots. */
static void fe_pow22523(fe h, const fe a)
{
    uint8_t e[32];

    memset(e, 0xff, sizeof(e));
    e[0] = 0xfd; /* (p-5)/8 = 2^252 - 3 */
    e[31] = 0x0f;
    fe_pow(h, a, e);
}

/* ====================================================================== */
/* edwards25519 group, extended coordinates (X:Y:Z:T)                      */
/* ====================================================================== */

typedef struct {
    fe x, y, z, t;
} ge;

static void ge_identity(ge *r)
{
    fe_0(r->x);
    fe_1(r->y);
    fe_1(r->z);
    fe_0(r->t);
}

/* add-2008-hwcd-3: r = p + q, complete for a = -1 and non-square d. */
static void ge_add(ge *r, const ge *p, const ge *q)
{
    fe a, b, c, d, e, f, g, h, t0, t1;

    fe_sub(t0, p->y, p->x);
    fe_sub(t1, q->y, q->x);
    fe_mul(a, t0, t1);
    fe_add(t0, p->y, p->x);
    fe_add(t1, q->y, q->x);
    fe_mul(b, t0, t1);
    fe_mul(c, p->t, q->t);
    fe_mul(c, c, ed_d2);
    fe_mul(d, p->z, q->z);
    fe_add(d, d, d);
    fe_sub(e, b, a);
    fe_sub(f, d, c);
    fe_add(g, d, c);
    fe_add(h, b, a);

    fe_mul(r->x, e, f);
    fe_mul(r->y, g, h);
    fe_mul(r->t, e, h);
    fe_mul(r->z, f, g);
}

/* dbl-2008-hwcd with a = -1: r = 2p. */
static void ge_double(ge *r, const ge *p)
{
    fe a, b, c, d, e, f, g, h, t0;

    fe_sq(a, p->x);
    fe_sq(b, p->y);
    fe_sq(c, p->z);
    fe_add(c, c, c);
    fe_add(t0, p->x, p->y);
    fe_sq(e, t0);
    fe_sub(e, e, a);
    fe_sub(e, e, b);
    fe_neg(d, a);
    fe_add(g, d, b);
    fe_sub(f, g, c);
    fe_sub(h, d, b);

    fe_mul(r->x, e, f);
    fe_mul(r->y, g, h);
    fe_mul(r->t, e, h);
    fe_mul(r->z, f, g);
}

static void ge_neg(ge *r, const ge *p)
{
    fe_neg(r->x, p->x);
    fe_copy(r->y, p->y);
    fe_copy(r->z, p->z);
    fe_neg(r->t, p->t);
}

/* r = q when bit != 0, r unchanged otherwise; mask-based select. */
static void ge_cmov(ge *r, const ge *q, unsigned bit)
{
    fe_cmov(r->x, q->x, bit);
    fe_cmov(r->y, q->y, bit);
    fe_cmov(r->z, q->z, bit);
    fe_cmov(r->t, q->t, bit);
}

/*
 * Fixed double-and-add r = scalar * p: always double, always add, then
 * select with a mask.  The scalar is secret (clamped a, or the nonce r), so
 * no explicit branch depends on one of its bits; the mask select is only a
 * source-level construct and is not a hardware timing guarantee.
 */
static void ge_scalarmult(ge *r, const ge *p, const uint8_t scalar[32])
{
    ge acc, sum;
    int i;

    ge_identity(&acc);
    for (i = 255; i >= 0; i--) {
        unsigned bit = (unsigned)((scalar[i >> 3] >> (i & 7)) & 1);

        ge_double(&acc, &acc);
        ge_add(&sum, &acc, p);
        ge_cmov(&acc, &sum, bit);
    }
    *r = acc;
    ed_zero(&acc, sizeof acc);
    ed_zero(&sum, sizeof sum);
}

static void ge_tobytes(uint8_t s[32], const ge *p)
{
    fe zi, x, y;

    fe_invert(zi, p->z);
    fe_mul(x, p->x, zi);
    fe_mul(y, p->y, zi);
    fe_tobytes(s, y);
    s[31] ^= (uint8_t)(fe_isnegative(x) << 7);
}

static int ge_isidentity(const ge *p)
{
    uint8_t enc[32], id[32];

    memset(id, 0, sizeof(id));
    id[0] = 1;
    ge_tobytes(enc, p);
    return ed_ct_eq(enc, id, 32);
}

/* Decode y || sign(x).  Rejects non-canonical y, non-square u/v and a
 * "negative zero" x, exactly as RFC 8032 section 5.1.3 requires. */
static int ge_frombytes(ge *r, const uint8_t s[32])
{
    fe y, u, v, v2, v3, v4, v7, x, t, nequ;
    uint8_t in[32], out[32];
    unsigned sign = (unsigned)(s[31] >> 7);
    int ok;

    memcpy(in, s, 32);
    in[31] &= 0x7fu;
    fe_frombytes(y, in);
    fe_tobytes(out, y);
    if (!ed_ct_eq(in, out, 32)) {
        return 0; /* y >= p */
    }

    fe_1(t);
    fe_sq(u, y);
    fe_sub(u, u, t);          /* u = y^2 - 1 */
    fe_sq(v, y);
    fe_mul(v, v, ed_d);
    fe_add(v, v, t);          /* v = d*y^2 + 1 */

    fe_sq(v2, v);
    fe_mul(v3, v2, v);
    fe_sq(v4, v2);
    fe_mul(v7, v3, v4);

    fe_mul(t, u, v7);
    fe_pow22523(t, t);        /* (u*v^7)^((p-5)/8) */
    fe_mul(x, u, v3);
    fe_mul(x, x, t);          /* x = u*v^3*(u*v^7)^((p-5)/8) */

    fe_sq(t, x);
    fe_mul(t, t, v);          /* v*x^2 */
    ok = fe_isequal(t, u);
    if (!ok) {
        fe_neg(nequ, u);
        if (!fe_isequal(t, nequ)) {
            return 0;
        }
        fe_mul(x, x, ed_sqrtm1);
    }

    if (fe_iszero(x) && sign != 0) {
        return 0;
    }
    if (fe_isnegative(x) != (int)sign) {
        fe_neg(x, x);
    }

    fe_copy(r->x, x);
    fe_copy(r->y, y);
    fe_1(r->z);
    fe_mul(r->t, x, y);
    return 1;
}

static int ge_base(ge *b)
{
    return ge_frombytes(b, ed_base_enc);
}

/* True for the identity and the other seven points of order dividing 8. */
static int ge_small_order(const ge *p)
{
    ge q = *p;
    int i;

    for (i = 0; i < 3; i++) {
        ge_double(&q, &q);
    }
    return ge_isidentity(&q);
}

/* ====================================================================== */
/* Scalars modulo L = 2^252 + 27742317777372353535851937790883648493       */
/* ====================================================================== */

/* L in 32-bit little-endian limbs. */
static const uint32_t ed_L32[8] = {
    0x5cf5d3edu, 0x5812631au, 0xa2f79cd6u, 0x14def9deu,
    0x00000000u, 0x00000000u, 0x00000000u, 0x10000000u,
};

/* Reduction of a little-endian byte string modulo L: one shift/add step per
 * input bit, using 32-bit limbs so that no 128-bit multiplication is needed
 * and the borrow can be extracted with a shift rather than a comparison (the
 * conditional subtraction is a mask select, not a branch). */
static void sc_reduce(uint8_t out[32], const uint8_t *in, size_t in_len)
{
    uint32_t r[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t t[8];
    size_t bit;
    int j;

    for (bit = in_len * 8; bit-- > 0;) {
        uint32_t carry = (uint32_t)((in[bit >> 3] >> (bit & 7)) & 1);

        for (j = 0; j < 8; j++) {
            uint32_t next = r[j] >> 31;
            r[j] = (r[j] << 1) | carry;
            carry = next;
        }
        /* r < 2L after the shift, so one conditional subtraction of L
         * restores r < L.  t = r - L; the borrow is bit 63 of the 64-bit
         * difference because the operands are 32-bit values. */
        {
            uint64_t borrow = 0;

            for (j = 0; j < 8; j++) {
                uint64_t sub = (uint64_t)ed_L32[j] + borrow;
                uint64_t cur = (uint64_t)r[j] - sub;
                t[j] = (uint32_t)cur;
                borrow = cur >> 63;
            }
            {
                /* borrow == 1 means r < L, so keep r; otherwise take r - L.
                 * The XOR-select avoids an explicit branch here. */
                uint32_t mask = (uint32_t)0 - (uint32_t)(borrow ^ 1u);
                for (j = 0; j < 8; j++) {
                    r[j] ^= (r[j] ^ t[j]) & mask;
                }
            }
        }
    }
    for (j = 0; j < 8; j++) {
        ed_store_le32(out + 4 * j, r[j]);
    }
    ed_zero(r, sizeof r);
    ed_zero(t, sizeof t);
}

/* Return 1 when the encoded scalar is < L (RFC 8032 requires S < L). */
static int sc_is_canonical(const uint8_t s[32])
{
    uint32_t w[8];
    int j;

    for (j = 0; j < 8; j++) {
        w[j] = ed_load_le32(s + 4 * j);
    }
    for (j = 7; j >= 0; j--) {
        if (w[j] < ed_L32[j]) {
            return 1;
        }
        if (w[j] > ed_L32[j]) {
            return 0;
        }
    }
    return 0;
}

/*
 * out = (a*b + c) mod L.  The product is built with 32x32 -> 64 bit
 * multiplications (a, b < L < 2^253) and then reduced by sc_reduce().
 */
static void sc_muladd(uint8_t out[32], const uint8_t a[32], const uint8_t b[32],
                      const uint8_t c[32])
{
    uint32_t t[17];
    uint8_t wide[68];
    uint64_t carry;
    int i, j;

    for (i = 0; i < 17; i++) {
        t[i] = 0;
    }
    for (i = 0; i < 8; i++) {
        uint32_t ai = ed_load_le32(a + 4 * i);
        carry = 0;
        for (j = 0; j < 8; j++) {
            uint64_t cur = (uint64_t)t[i + j] +
                           (uint64_t)ai * ed_load_le32(b + 4 * j) + carry;
            t[i + j] = (uint32_t)cur;
            carry = cur >> 32;
        }
        t[i + 8] = (uint32_t)carry;
    }
    carry = 0;
    for (i = 0; i < 17; i++) {
        uint64_t cur = (uint64_t)t[i] +
                       (i < 8 ? (uint64_t)ed_load_le32(c + 4 * i) : 0) + carry;
        t[i] = (uint32_t)cur;
        carry = cur >> 32;
    }
    for (i = 0; i < 17; i++) {
        ed_store_le32(wide + 4 * i, t[i]);
    }
    sc_reduce(out, wide, sizeof(wide));
    ed_zero(t, sizeof t);
    ed_zero(wide, sizeof wide);
}

/* RFC 8032 section 5.1.5: clamp the first half of the key hash. */
static void sc_clamp(uint8_t a[32])
{
    a[0] &= 248u;
    a[31] &= 127u;
    a[31] |= 64u;
}

/* ====================================================================== */
/* Public API                                                             */
/* ====================================================================== */

bool omk_ed25519_public_from_seed(const uint8_t seed[OMK_ED25519_SEED_LEN],
                                  uint8_t pub[OMK_ED25519_PUBLIC_LEN])
{
    bool ok = false;
    uint8_t h[OMK_SHA512_LEN], a[32];
    ge base, A;

    ed_sha512(seed, OMK_ED25519_SEED_LEN, h);
    memcpy(a, h, 32);
    sc_clamp(a);

    if (!ge_base(&base)) {
        goto done; /* cannot happen: the base point is valid */
    }
    ge_scalarmult(&A, &base, a);
    ge_tobytes(pub, &A);
    ok = true;

done:
    ed_zero(h, sizeof(h));
    ed_zero(a, sizeof(a));
    return ok;
}

bool omk_ed25519_sign(const uint8_t seed[OMK_ED25519_SEED_LEN],
                      const void *msg, size_t msg_len,
                      uint8_t sig[OMK_ED25519_SIG_LEN])
{
    bool ok = false;
    uint8_t h[OMK_SHA512_LEN], a[32], prefix[32], r[32], k[32], pub[32];
    ge base, A, R;
    ed_sha512_ctx ctx;

    /* a and prefix come from the seed, never from the message. */
    ed_sha512(seed, OMK_ED25519_SEED_LEN, h);
    memcpy(a, h, 32);
    sc_clamp(a);
    memcpy(prefix, h + 32, 32);

    if (!ge_base(&base)) {
        goto done;
    }
    ge_scalarmult(&A, &base, a);
    ge_tobytes(pub, &A);

    /* r = H(prefix || M) mod L, R = r*B */
    ed_sha512_init(&ctx);
    ed_sha512_update(&ctx, prefix, 32);
    ed_sha512_update(&ctx, msg, msg_len);
    ed_sha512_final(&ctx, h);
    sc_reduce(r, h, sizeof(h));

    ge_scalarmult(&R, &base, r);
    ge_tobytes(sig, &R);

    /* k = H(R || A || M) mod L, S = (r + k*a) mod L */
    ed_sha512_init(&ctx);
    ed_sha512_update(&ctx, sig, 32);
    ed_sha512_update(&ctx, pub, 32);
    ed_sha512_update(&ctx, msg, msg_len);
    ed_sha512_final(&ctx, h);
    sc_reduce(k, h, sizeof(h));

    sc_muladd(sig + 32, k, a, r);
    ok = true;

done:
    /* h holds the seed hash and signing hashes, a/r/k the secret scalars and
     * nonce; ctx holds SHA-512 state derived from them. */
    ed_zero(h, sizeof(h));
    ed_zero(a, sizeof(a));
    ed_zero(prefix, sizeof(prefix));
    ed_zero(r, sizeof(r));
    ed_zero(k, sizeof(k));
    ed_zero(&ctx, sizeof(ctx));
    return ok;
}

bool omk_ed25519_verify(const uint8_t pub[OMK_ED25519_PUBLIC_LEN],
                        const void *msg, size_t msg_len,
                        const uint8_t sig[OMK_ED25519_SIG_LEN])
{
    ge A, R, base, sB, kA, sum;
    uint8_t h[OMK_SHA512_LEN], k[32], enc[32];
    ed_sha512_ctx ctx;

    /* S must be canonical: reject S >= L. */
    if (!sc_is_canonical(sig + 32)) {
        return false;
    }
    /* A and R must be canonically encoded curve points; reject the
     * identity and all small-order ("weak") public keys. */
    if (!ge_frombytes(&A, pub) || ge_small_order(&A)) {
        return false;
    }
    if (!ge_frombytes(&R, sig)) {
        return false;
    }

    ed_sha512_init(&ctx);
    ed_sha512_update(&ctx, sig, 32);
    ed_sha512_update(&ctx, pub, 32);
    ed_sha512_update(&ctx, msg, msg_len);
    ed_sha512_final(&ctx, h);
    sc_reduce(k, h, sizeof(h));

    if (!ge_base(&base)) {
        return false;
    }
    ge_scalarmult(&sB, &base, sig + 32); /* [S]B */
    ge_scalarmult(&kA, &A, k);           /* [k]A */
    ge_neg(&kA, &kA);
    ge_add(&sum, &sB, &kA);              /* [S]B - [k]A */

    ge_tobytes(enc, &sum);
    return ed_ct_eq(enc, sig, 32);       /* must equal ENC(R) */
}
