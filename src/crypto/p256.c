/*
 * NIST P-256 (secp256r1): field/scalar arithmetic, ECDSA and ECDH.
 *
 * 8x32-bit limbs, Montgomery multiplication with uint64_t intermediates, so
 * the same code builds for 32-bit Cortex-M33 and 64-bit hosts without
 * __int128.
 *
 * Side-channel scope: point_mul() walks all 256 scalar bits and selects the
 * accumulated point with a mask, so the scalar-bit loop itself does not
 * branch.  The field and point helpers it calls are NOT constant-time:
 * point_add()/point_double() branch on infinity and equality tests,
 * fp_add()/fp_sub() branch on carries, and the inversion chains behave
 * differently for different operands.  P-256 (and in particular ECDSA
 * nonce/scalar handling) therefore has no constant-time or side-channel
 * resistance guarantee.
 *
 * Signatures are r || s (32 bytes each, big-endian) with low-S normalisation.
 * When rng is NULL, ECDSA nonces come from RFC 6979 (HMAC-SHA-256 DRBG).
 * Secret scalars, nonces and the API-boundary signing buffers are wiped on
 * every return; the field/point arithmetic below does not wipe its own
 * temporaries.
 */

#include "crypto/omk_crypto.h"

#include <string.h>

typedef struct {
    uint32_t v[8];
} u256;

static const u256 P = {{0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u,
                        0x00000000u, 0x00000000u, 0x00000001u, 0xFFFFFFFFu}};
static const u256 N = {{0xFC632551u, 0xF3B9CAC2u, 0xA7179E84u, 0xBCE6FAADu,
                        0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u, 0xFFFFFFFFu}};
static const u256 B = {{0x27D2604Bu, 0x3BCE3C3Eu, 0xCC53B0F6u, 0x651D06B0u,
                        0x769886BCu, 0xB3EBBD55u, 0xAA3A93E7u, 0x5AC635D8u}};
static const u256 GX = {{0xD898C296u, 0xF4A13945u, 0x2DEB33A0u, 0x77037D81u,
                         0x63A440F2u, 0xF8BCE6E5u, 0xE12C4247u, 0x6B17D1F2u}};
static const u256 GY = {{0x37BF51F5u, 0xCBB64068u, 0x6B315ECEu, 0x2BCE3357u,
                         0x7C0F9E16u, 0x8EE7EB4Au, 0xFE1A7F9Bu, 0x4FE342E2u}};
static const u256 R2_P = {{0x00000003u, 0x00000000u, 0xFFFFFFFFu, 0xFFFFFFFBu,
                           0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFDu, 0x00000004u}};
static const u256 R2_N = {{0xBE79EEA2u, 0x83244C95u, 0x49BD6FA6u, 0x4699799Cu,
                           0x2B6BEC59u, 0x2845B239u, 0xF3D95620u, 0x66E12D94u}};
static const u256 HALF_N = {{0x7E3192A8u, 0x79DCE561u, 0xD38BCF42u, 0xDE737D56u,
                             0xFFFFFFFFu, 0x7FFFFFFFu, 0x80000000u,
                             0x7FFFFFFFu}};
static const u256 P_MINUS_2 = {{0xFFFFFFFDu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                                0x00000000u, 0x00000000u, 0x00000000u,
                                0x00000001u, 0xFFFFFFFFu}};
static const u256 N_MINUS_2 = {{0xFC63254Fu, 0xF3B9CAC2u, 0xA7179E84u,
                                0xBCE6FAADu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                                0x00000000u, 0xFFFFFFFFu}};
static const u256 ZERO = {{0}};
static const u256 ONE = {{1, 0, 0, 0, 0, 0, 0, 0}};
/* Montgomery representation of 1: 2^256 mod p / 2^256 mod n. */
static const u256 R_ONE_P = {{0x00000001u, 0x00000000u, 0x00000000u,
                              0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                              0xFFFFFFFEu, 0x00000000u}};
static const u256 R_ONE_N = {{0x039CDAAFu, 0x0C46353Du, 0x58E8617Bu,
                              0x43190552u, 0x00000000u, 0x00000000u,
                              0xFFFFFFFFu, 0x00000000u}};

#define P_N0INV 0x00000001u
#define N_N0INV 0xEE00BC4Fu

static int u256_cmp(const u256 *a, const u256 *b) {
    for (int i = 7; i >= 0; i--) {
        if (a->v[i] != b->v[i]) {
            return a->v[i] > b->v[i] ? 1 : -1;
        }
    }
    return 0;
}

static bool u256_is_zero(const u256 *a) {
    uint32_t acc = 0;
    for (int i = 0; i < 8; i++) {
        acc |= a->v[i];
    }
    return acc == 0;
}

static bool u256_equal(const u256 *a, const u256 *b) {
    return u256_cmp(a, b) == 0;
}

static uint32_t u256_add_raw(u256 *r, const u256 *a, const u256 *b) {
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        const uint64_t t = (uint64_t)a->v[i] + b->v[i] + carry;
        r->v[i] = (uint32_t)t;
        carry = t >> 32;
    }
    return (uint32_t)carry;
}

static uint32_t u256_sub_raw(u256 *r, const u256 *a, const u256 *b) {
    uint64_t borrow = 0;
    for (int i = 0; i < 8; i++) {
        const uint64_t t = (uint64_t)a->v[i] - b->v[i] - borrow;
        r->v[i] = (uint32_t)t;
        borrow = (t >> 63) & 1u;
    }
    return (uint32_t)borrow;
}

/* r = a * b * 2^-256 mod m, CIOS. */
static void mont_mul(u256 *r, const u256 *a, const u256 *b, const u256 *m,
                     uint32_t n0inv) {
    uint32_t t[18];
    memset(t, 0, sizeof t);

    for (int i = 0; i < 8; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; j++) {
            const uint64_t cur =
                (uint64_t)t[i + j] + (uint64_t)a->v[i] * b->v[j] + carry;
            t[i + j] = (uint32_t)cur;
            carry = cur >> 32;
        }
        int k = i + 8;
        while (carry != 0) {
            const uint64_t cur = (uint64_t)t[k] + carry;
            t[k] = (uint32_t)cur;
            carry = cur >> 32;
            k++;
        }
    }
    for (int i = 0; i < 8; i++) {
        const uint32_t mm = t[i] * n0inv;
        uint64_t carry = 0;
        for (int j = 0; j < 8; j++) {
            const uint64_t cur = (uint64_t)t[i + j] +
                                 (uint64_t)mm * m->v[j] + carry;
            t[i + j] = (uint32_t)cur;
            carry = cur >> 32;
        }
        int k = i + 8;
        while (carry != 0) {
            const uint64_t cur = (uint64_t)t[k] + carry;
            t[k] = (uint32_t)cur;
            carry = cur >> 32;
            k++;
        }
    }

    u256 out;
    for (int i = 0; i < 8; i++) {
        out.v[i] = t[8 + i];
    }
    u256 high = ONE;
    high.v[0] = t[16];
    high.v[1] = t[17];
    uint32_t borrow = u256_sub_raw(&out, &out, m);
    if (high.v[0] != 0 || high.v[1] != 0) {
        /* Overflow limb: the subtraction wrapped, so the true result is
         * out + 2^256 - m, which the wrapped subtraction already produced
         * plus 2^256; because the value is < 2m this is < m. */
    } else if (borrow != 0) {
        u256_add_raw(&out, &out, m);
    }
    *r = out;
}

static void fp_to_mont(u256 *r, const u256 *a) {
    mont_mul(r, a, &R2_P, &P, P_N0INV);
}

static void fp_from_mont(u256 *r, const u256 *a) {
    static const u256 one = {{1, 0, 0, 0, 0, 0, 0, 0}};
    mont_mul(r, a, &one, &P, P_N0INV);
}

static void fp_add(u256 *r, const u256 *a, const u256 *b) {
    u256 t;
    const uint32_t carry = u256_add_raw(&t, a, b);
    if (carry != 0 || u256_cmp(&t, &P) >= 0) {
        u256_sub_raw(&t, &t, &P);
    }
    *r = t;
}

static void fp_sub(u256 *r, const u256 *a, const u256 *b) {
    u256 t;
    const uint32_t borrow = u256_sub_raw(&t, a, b);
    if (borrow != 0) {
        u256_add_raw(&t, &t, &P);
    }
    *r = t;
}

static void fp_mul(u256 *r, const u256 *a, const u256 *b) {
    mont_mul(r, a, b, &P, P_N0INV);
}

static void fp_sqr(u256 *r, const u256 *a) {
    fp_mul(r, a, a);
}


static void fp_inv(u256 *r, const u256 *a) {
    u256 result = R_ONE_P;
    u256 base = *a;
    for (int i = 255; i >= 0; i--) {
        fp_sqr(&result, &result);
        if ((P_MINUS_2.v[i / 32] >> (i % 32)) & 1u) {
            fp_mul(&result, &result, &base);
        }
    }
    *r = result;
    omk_memzero(&result, sizeof result);
    omk_memzero(&base, sizeof base);
}


/* ---------------------------- scalar mod n ----------------------------- */

static void fn_to_mont(u256 *r, const u256 *a) {
    mont_mul(r, a, &R2_N, &N, N_N0INV);
}

static void fn_from_mont(u256 *r, const u256 *a) {
    mont_mul(r, a, &ONE, &N, N_N0INV);
}

static void fn_add(u256 *r, const u256 *a, const u256 *b) {
    u256 t;
    const uint32_t carry = u256_add_raw(&t, a, b);
    if (carry != 0 || u256_cmp(&t, &N) >= 0) {
        u256_sub_raw(&t, &t, &N);
    }
    *r = t;
}


static void fn_mul(u256 *r, const u256 *a, const u256 *b) {
    mont_mul(r, a, b, &N, N_N0INV);
}

static void fn_inv(u256 *r, const u256 *a) {
    u256 result = R_ONE_N;
    u256 base = *a;
    for (int i = 255; i >= 0; i--) {
        fn_mul(&result, &result, &result);
        if ((N_MINUS_2.v[i / 32] >> (i % 32)) & 1u) {
            fn_mul(&result, &result, &base);
        }
    }
    *r = result;
    omk_memzero(&result, sizeof result);
    omk_memzero(&base, sizeof base);
}

static void u256_from_be(u256 *r, const uint8_t in[32]) {
    for (int i = 0; i < 8; i++) {
        r->v[7 - i] = ((uint32_t)in[4 * i] << 24) |
                      ((uint32_t)in[4 * i + 1] << 16) |
                      ((uint32_t)in[4 * i + 2] << 8) | in[4 * i + 3];
    }
}

static void u256_to_be(uint8_t out[32], const u256 *a) {
    for (int i = 0; i < 8; i++) {
        const uint32_t w = a->v[7 - i];
        out[4 * i] = (uint8_t)(w >> 24);
        out[4 * i + 1] = (uint8_t)(w >> 16);
        out[4 * i + 2] = (uint8_t)(w >> 8);
        out[4 * i + 3] = (uint8_t)w;
    }
}

/* ---------------------------- point arithmetic ------------------------- */

typedef struct {
    u256 x, y, z; /* Jacobian, Montgomery form; z == 0 is infinity */
} jac_point;

static void point_set_infinity(jac_point *p) {
    p->x = ZERO;
    p->y = ZERO;
    p->z = ZERO;
}

static bool point_is_infinity(const jac_point *p) {
    return u256_is_zero(&p->z);
}

static void point_double(jac_point *r, const jac_point *p) {
    if (point_is_infinity(p)) {
        point_set_infinity(r);
        return;
    }
    u256 delta, gamma, beta, alpha, t1, t2, x3, y3, z3;
    fp_sqr(&delta, &p->z);
    fp_sqr(&gamma, &p->y);
    fp_mul(&beta, &p->x, &gamma);

    fp_sub(&t1, &p->x, &delta);
    fp_add(&t2, &p->x, &delta);
    fp_mul(&alpha, &t1, &t2);
    fp_add(&t1, &alpha, &alpha);
    fp_add(&alpha, &t1, &alpha); /* alpha = 3*(x-delta)*(x+delta) */

    fp_sqr(&x3, &alpha);
    fp_add(&t1, &beta, &beta);
    fp_add(&t2, &t1, &t1);
    fp_add(&t1, &t2, &t2); /* 8*beta */
    fp_sub(&x3, &x3, &t1);

    fp_add(&t1, &p->y, &p->z);
    fp_sqr(&z3, &t1);
    fp_sub(&z3, &z3, &gamma);
    fp_sub(&z3, &z3, &delta);

    fp_add(&t1, &beta, &beta);
    fp_add(&t1, &t1, &t1); /* 4*beta */
    fp_sub(&t1, &t1, &x3);
    fp_mul(&y3, &alpha, &t1);
    fp_sqr(&t2, &gamma);
    fp_add(&t2, &t2, &t2);
    fp_add(&t2, &t2, &t2);
    fp_add(&t2, &t2, &t2); /* 8*gamma^2 */
    fp_sub(&y3, &y3, &t2);

    r->x = x3;
    r->y = y3;
    r->z = z3;
}

static void point_add(jac_point *r, const jac_point *p, const jac_point *q) {
    if (point_is_infinity(p)) {
        *r = *q;
        return;
    }
    if (point_is_infinity(q)) {
        *r = *p;
        return;
    }

    u256 z1z1, z2z2, u1, u2, s1, s2, h, rr, i, j, v, x3, y3, z3, t1, t2;
    fp_sqr(&z1z1, &p->z);
    fp_sqr(&z2z2, &q->z);
    fp_mul(&u1, &p->x, &z2z2);
    fp_mul(&u2, &q->x, &z1z1);
    fp_mul(&t1, &q->z, &z2z2);
    fp_mul(&s1, &p->y, &t1);
    fp_mul(&t1, &p->z, &z1z1);
    fp_mul(&s2, &q->y, &t1);
    fp_sub(&h, &u2, &u1);
    fp_sub(&t1, &s2, &s1);
    fp_add(&rr, &t1, &t1);

    if (u256_is_zero(&h)) {
        if (u256_is_zero(&rr)) {
            point_double(r, p);
        } else {
            point_set_infinity(r);
        }
        return;
    }

    fp_add(&t1, &h, &h);
    fp_sqr(&i, &t1);
    fp_mul(&j, &h, &i);
    fp_mul(&v, &u1, &i);

    fp_sqr(&x3, &rr);
    fp_sub(&x3, &x3, &j);
    fp_add(&t1, &v, &v);
    fp_sub(&x3, &x3, &t1);

    fp_sub(&t1, &v, &x3);
    fp_mul(&y3, &rr, &t1);
    fp_mul(&t2, &s1, &j);
    fp_add(&t2, &t2, &t2);
    fp_sub(&y3, &y3, &t2);

    fp_add(&t1, &p->z, &q->z);
    fp_sqr(&t1, &t1);
    fp_sub(&t1, &t1, &z1z1);
    fp_sub(&t1, &t1, &z2z2);
    fp_mul(&z3, &t1, &h);

    r->x = x3;
    r->y = y3;
    r->z = z3;
}

static void point_cmov(jac_point *r, const jac_point *a, uint32_t mask) {
    /* mask is 0 (keep r) or 0xFFFFFFFF (select a). */
    for (int i = 0; i < 8; i++) {
        r->x.v[i] = (r->x.v[i] & ~mask) | (a->x.v[i] & mask);
        r->y.v[i] = (r->y.v[i] & ~mask) | (a->y.v[i] & mask);
        r->z.v[i] = (r->z.v[i] & ~mask) | (a->z.v[i] & mask);
    }
}

static void point_mul(jac_point *r, const u256 *scalar,
                      const jac_point *point) {
    jac_point acc, sum, doubled;
    point_set_infinity(&acc);
    for (int i = 255; i >= 0; i--) {
        point_double(&doubled, &acc);
        point_add(&sum, &doubled, point);
        const uint32_t bit = (scalar->v[i / 32] >> (i % 32)) & 1u;
        const uint32_t mask = (uint32_t)0 - bit;
        acc = doubled;
        point_cmov(&acc, &sum, mask);
    }
    *r = acc;
    /* acc/sum/doubled hold secret-derived points; wipe the locals. */
    omk_memzero(&acc, sizeof acc);
    omk_memzero(&sum, sizeof sum);
    omk_memzero(&doubled, sizeof doubled);
}

static void point_to_affine(u256 *x, u256 *y, const jac_point *p) {
    u256 zinv, zinv2, zinv3;
    fp_inv(&zinv, &p->z);
    fp_sqr(&zinv2, &zinv);
    fp_mul(&zinv3, &zinv2, &zinv);
    fp_mul(x, &p->x, &zinv2);
    fp_mul(y, &p->y, &zinv3);
    fp_from_mont(x, x);
    fp_from_mont(y, y);
    /* The inverse of Z is secret-derived on the ECDH/ECDSA paths. */
    omk_memzero(&zinv, sizeof zinv);
    omk_memzero(&zinv2, sizeof zinv2);
    omk_memzero(&zinv3, sizeof zinv3);
}

static void point_from_affine(jac_point *r, const u256 *x, const u256 *y) {
    fp_to_mont(&r->x, x);
    fp_to_mont(&r->y, y);
    fp_to_mont(&r->z, &ONE);
}

static bool scalar_is_valid(const u256 *d) {
    return !u256_is_zero(d) && u256_cmp(d, &N) < 0;
}

static bool scalar_mul_normal(u256 *r, const u256 *a, const u256 *b) {
    u256 am, bm, rm;
    fn_to_mont(&am, a);
    fn_to_mont(&bm, b);
    fn_mul(&rm, &am, &bm);
    fn_from_mont(r, &rm);
    return true;
}

static bool point_on_curve(const u256 *x, const u256 *y) {
    if (u256_cmp(x, &P) >= 0 || u256_cmp(y, &P) >= 0) {
        return false;
    }
    u256 xm, ym, bm, lhs, rhs, t;
    fp_to_mont(&xm, x);
    fp_to_mont(&ym, y);
    fp_to_mont(&bm, &B);
    fp_sqr(&lhs, &ym);
    fp_sqr(&t, &xm);
    fp_mul(&rhs, &t, &xm); /* x^3 */
    fp_add(&t, &xm, &xm);
    fp_add(&t, &t, &xm); /* 3x */
    fp_sub(&rhs, &rhs, &t);
    fp_add(&rhs, &rhs, &bm);
    return u256_equal(&lhs, &rhs);
}

static bool parse_public_key(jac_point *r, const uint8_t pub[65]) {
    if (pub[0] != 0x04) {
        return false;
    }
    u256 x, y;
    u256_from_be(&x, pub + 1);
    u256_from_be(&y, pub + 33);
    if (!point_on_curve(&x, &y)) {
        return false;
    }
    point_from_affine(r, &x, &y);
    return true;
}

static const jac_point *generator(void) {
    static jac_point g;
    static bool ready;
    if (!ready) {
        point_from_affine(&g, &GX, &GY);
        ready = true;
    }
    return &g;
}

/* ------------------------------ RFC 6979 ------------------------------- */

static void hmac32(const uint8_t key[32], const uint8_t *msg, size_t len,
                   uint8_t out[32]) {
    omk_hmac_sha256(key, 32, msg, len, out);
}

static void rfc6979_k(const u256 *d, const u256 *z, u256 *k) {
    uint8_t V[32], K[32], buf[97];
    uint8_t x[32], h[32];
    u256_to_be(x, d);
    u256_to_be(h, z);

    memset(V, 0x01, sizeof V);
    memset(K, 0x00, sizeof K);

    memcpy(buf, V, 32);
    buf[32] = 0x00;
    memcpy(buf + 33, x, 32);
    memcpy(buf + 65, h, 32);
    hmac32(K, buf, sizeof buf, K);
    hmac32(K, V, sizeof V, V);

    memcpy(buf, V, 32);
    buf[32] = 0x01;
    memcpy(buf + 33, x, 32);
    memcpy(buf + 65, h, 32);
    hmac32(K, buf, sizeof buf, K);
    hmac32(K, V, sizeof V, V);

    for (;;) {
        hmac32(K, V, sizeof V, V);
        u256_from_be(k, V);
        if (scalar_is_valid(k)) {
            break;
        }
        memcpy(buf, V, 32);
        buf[32] = 0x00;
        hmac32(K, buf, 33, K);
        hmac32(K, V, sizeof V, V);
    }

    /* V/K are the DRBG state and x is the private scalar; buf and h carry
     * copies of both.  None may outlive this call. */
    omk_memzero(V, sizeof V);
    omk_memzero(K, sizeof K);
    omk_memzero(buf, sizeof buf);
    omk_memzero(x, sizeof x);
    omk_memzero(h, sizeof h);
}

/* ------------------------------- public API ---------------------------- */

bool omk_p256_point_valid(const uint8_t pub[OMK_P256_PUBLIC_LEN]) {
    jac_point p;
    return parse_public_key(&p, pub);
}

bool omk_p256_keypair_from_scalar(const uint8_t d[OMK_P256_SCALAR_LEN],
                                  omk_p256_keypair *out) {
    bool ok = false;
    u256 scalar, x, y;
    jac_point r;

    u256_from_be(&scalar, d);
    if (!scalar_is_valid(&scalar)) {
        goto done;
    }
    point_mul(&r, &scalar, generator());
    if (point_is_infinity(&r)) {
        goto done;
    }
    point_to_affine(&x, &y, &r);
    memmove(out->d, d, OMK_P256_SCALAR_LEN);
    out->pub[0] = 0x04;
    u256_to_be(out->pub + 1, &x);
    u256_to_be(out->pub + 33, &y);
    ok = true;

done:
    omk_memzero(&scalar, sizeof scalar);
    omk_memzero(&x, sizeof x);
    omk_memzero(&y, sizeof y);
    omk_memzero(&r, sizeof r);
    return ok;
}

bool omk_p256_keygen(bool (*rng)(void *ctx, void *out, size_t len),
                     void *ctx, omk_p256_keypair *out) {
    bool ok = false;
    uint8_t d[32];
    u256 scalar;

    if (rng == NULL) {
        goto done;
    }
    for (unsigned attempt = 0; attempt < 64; attempt++) {
        if (!rng(ctx, d, sizeof d)) {
            goto done;
        }
        u256_from_be(&scalar, d);
        if (!scalar_is_valid(&scalar)) {
            continue;
        }
        ok = omk_p256_keypair_from_scalar(d, out);
        break;
    }

done:
    omk_memzero(d, sizeof d);
    omk_memzero(&scalar, sizeof scalar);
    return ok;
}

bool omk_p256_ecdh(const uint8_t d[OMK_P256_SCALAR_LEN],
                   const uint8_t peer_pub[OMK_P256_PUBLIC_LEN],
                   uint8_t out_x[32]) {
    bool ok = false;
    u256 scalar, x, y;
    jac_point peer, r;

    u256_from_be(&scalar, d);
    if (!scalar_is_valid(&scalar)) {
        goto done;
    }
    if (!parse_public_key(&peer, peer_pub)) {
        goto done;
    }
    point_mul(&r, &scalar, &peer);
    if (point_is_infinity(&r)) {
        goto done;
    }
    point_to_affine(&x, &y, &r);
    u256_to_be(out_x, &x);
    ok = true;

done:
    omk_memzero(&scalar, sizeof scalar);
    omk_memzero(&x, sizeof x);
    omk_memzero(&y, sizeof y);
    omk_memzero(&peer, sizeof peer);
    omk_memzero(&r, sizeof r);
    return ok;
}

static void hash_to_scalar(u256 *z, const uint8_t hash[32]) {
    u256_from_be(z, hash);
    if (u256_cmp(z, &N) >= 0) {
        u256_sub_raw(z, z, &N);
    }
}

bool omk_p256_ecdsa_sign(const uint8_t d[OMK_P256_SCALAR_LEN],
                         const uint8_t hash[OMK_SHA256_LEN],
                         uint8_t sig[OMK_P256_SIG_LEN],
                         bool (*rng)(void *ctx, void *out, size_t len),
                         void *ctx) {
    bool ok = false;
    u256 scalar, z, k, rx, ry, r, km, dm, rm, zm, t, inv, sm, s;
    jac_point rp;

    u256_from_be(&scalar, d);
    if (!scalar_is_valid(&scalar)) {
        goto done;
    }
    hash_to_scalar(&z, hash);

    for (unsigned attempt = 0; attempt < 64; attempt++) {
        if (rng != NULL) {
            uint8_t kb[32];
            if (!rng(ctx, kb, sizeof kb)) {
                omk_memzero(kb, sizeof kb);
                goto done;
            }
            u256_from_be(&k, kb);
            omk_memzero(kb, sizeof kb);
        } else {
            rfc6979_k(&scalar, &z, &k);
        }
        if (!scalar_is_valid(&k)) {
            if (rng == NULL) {
                goto done;
            }
            continue;
        }

        point_mul(&rp, &k, generator());
        if (point_is_infinity(&rp)) {
            continue;
        }
        point_to_affine(&rx, &ry, &rp);
        r = rx;
        if (u256_cmp(&r, &N) >= 0) {
            u256_sub_raw(&r, &r, &N);
        }
        if (u256_is_zero(&r)) {
            continue;
        }

        fn_to_mont(&km, &k);
        fn_inv(&inv, &km);
        fn_to_mont(&dm, &scalar);
        fn_to_mont(&rm, &r);
        fn_to_mont(&zm, &z);
        fn_mul(&t, &rm, &dm);
        fn_add(&t, &t, &zm);
        fn_mul(&sm, &inv, &t);
        fn_from_mont(&s, &sm);
        if (u256_is_zero(&s)) {
            continue;
        }
        if (u256_cmp(&s, &HALF_N) > 0) {
            u256_sub_raw(&s, &N, &s);
        }

        u256_to_be(sig, &r);
        u256_to_be(sig + 32, &s);
        ok = true;
        break;
    }

done:
    /* Wipe the private key, nonce, DRBG output and every intermediate that
     * contains them, no matter which path reached this point. */
    omk_memzero(&scalar, sizeof scalar);
    omk_memzero(&z, sizeof z);
    omk_memzero(&k, sizeof k);
    omk_memzero(&rx, sizeof rx);
    omk_memzero(&ry, sizeof ry);
    omk_memzero(&r, sizeof r);
    omk_memzero(&km, sizeof km);
    omk_memzero(&dm, sizeof dm);
    omk_memzero(&rm, sizeof rm);
    omk_memzero(&zm, sizeof zm);
    omk_memzero(&t, sizeof t);
    omk_memzero(&inv, sizeof inv);
    omk_memzero(&sm, sizeof sm);
    omk_memzero(&s, sizeof s);
    omk_memzero(&rp, sizeof rp);
    return ok;
}

bool omk_p256_ecdsa_verify(const uint8_t pub[OMK_P256_PUBLIC_LEN],
                           const uint8_t hash[OMK_SHA256_LEN],
                           const uint8_t sig[OMK_P256_SIG_LEN]) {
    jac_point q;
    if (!parse_public_key(&q, pub)) {
        return false;
    }
    u256 r, s;
    u256_from_be(&r, sig);
    u256_from_be(&s, sig + 32);
    if (!scalar_is_valid(&r) || !scalar_is_valid(&s)) {
        return false;
    }
    u256 z;
    hash_to_scalar(&z, hash);

    u256 sm, invm, w;
    fn_to_mont(&sm, &s);
    fn_inv(&invm, &sm);
    fn_from_mont(&w, &invm);

    u256 u1, u2;
    scalar_mul_normal(&u1, &z, &w);
    scalar_mul_normal(&u2, &r, &w);

    jac_point p1, p2, sum;
    point_mul(&p1, &u1, generator());
    point_mul(&p2, &u2, &q);
    point_add(&sum, &p1, &p2);
    if (point_is_infinity(&sum)) {
        return false;
    }
    u256 x, y;
    point_to_affine(&x, &y, &sum);
    if (u256_cmp(&x, &N) >= 0) {
        u256_sub_raw(&x, &x, &N);
    }
    return u256_equal(&x, &r);
}

