/* P-256 known-answer tests: key derivation, ECDH, ECDSA (RFC 6979). */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto/omk_crypto.h"

static int g_failures;

static void check(bool cond, const char *what) {
    if (!cond) {
        printf("FAIL: %s\n", what);
        g_failures++;
    }
}

static void from_hex(const char *hex, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void expect_hex(const uint8_t *got, size_t len, const char *want,
                       const char *what) {
    uint8_t buf[128];
    from_hex(want, buf, len);
    if (memcmp(got, buf, len) != 0) {
        printf("FAIL: %s\n  got  ", what);
        for (size_t i = 0; i < len; i++) {
            printf("%02x", got[i]);
        }
        printf("\n  want %s\n", want);
        g_failures++;
    }
}

static void scalar_from_hex(uint8_t out[32], const char *hex) {
    from_hex(hex, out, 32);
}

static void test_key_derivation(void) {
    struct {
        const char *d;
        const char *x;
        const char *y;
    } cases[] = {
        {"0000000000000000000000000000000000000000000000000000000000000001",
         "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
         "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"},
        {"0000000000000000000000000000000000000000000000000000000000000002",
         "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
         "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"},
        {"0000000000000000000000000000000000000000000000000000000000000003",
         "5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c",
         "8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032"},
        {"0000000000000000000000000000000000000000000000001234567890abcdef",
         "9fad84aeae08bbef7f010014d82cef6a09de2b0cf871b5ce0c4f1d13a59a5934",
         "07cb45769f1070e2c2470fe5b1bfe63133c0b0cdc64ea4bf3791a8ec2a07fd4f"},
        {"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f",
         "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
         "f888aaee24712fc0d6c26539608bcf244582521ac3167dd661fb4862dd878c2e"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        uint8_t d[32];
        scalar_from_hex(d, cases[i].d);
        omk_p256_keypair kp;
        check(omk_p256_keypair_from_scalar(d, &kp), "derive keypair");
        expect_hex(kp.pub + 1, 32, cases[i].x, "pub x");
        expect_hex(kp.pub + 33, 32, cases[i].y, "pub y");
        check(omk_p256_point_valid(kp.pub), "derived point valid");
    }

    /* Reject 0 and n. */
    uint8_t d[32] = {0};
    omk_p256_keypair kp;
    check(!omk_p256_keypair_from_scalar(d, &kp), "reject d=0");
    scalar_from_hex(d, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    check(!omk_p256_keypair_from_scalar(d, &kp), "reject d=n");
}

static void test_ecdh(void) {
    struct {
        const char *da;
        const char *db;
        const char *shared;
    } cases[] = {
        {"0000000000000000000000000000000000000000000000000000000000000001",
         "0000000000000000000000000000000000000000000000000000000000000001",
         "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"},
        {"0000000000000000000000000000000000000000000000000000000000000002",
         "0000000000000000000000000000000000000000000000000000000000000003",
         "b01a172a76a4602c92d3242cb897dde3024c740debb215b4c6b0aae93c2291a9"},
        {"0000000000000000000000000000000000000000000000000000000000001111",
         "0000000000000000000000000000000000000000000000000000000000002222",
         "19cfbcaa5b6f16b6d0d45634acd7aaa05b764a17e520771158a8db8688ba1f87"},
        {"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f",
         "0000000000000000000000000000000000000000000000000000000000000005",
         "cef66d6b2a3a993e591214d1ea223fb545ca6c471c48306e4c36069404c5723f"},
        {"00000000000000000000000000000000000000000000000000000000deadbeef",
         "00000000000000000000000000000000000000000000000000000000cafebabe",
         "dc0affa04b0b07f9f22e76de58b2e205c1774acba809092077516c380faea0a1"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        uint8_t da[32], db[32], shared[32];
        scalar_from_hex(da, cases[i].da);
        scalar_from_hex(db, cases[i].db);
        omk_p256_keypair peer;
        check(omk_p256_keypair_from_scalar(db, &peer), "ecdh peer key");
        check(omk_p256_ecdh(da, peer.pub, shared), "ecdh works");
        expect_hex(shared, 32, cases[i].shared, "ecdh shared");
    }

    /* Invalid peer points are rejected. */
    uint8_t d[32];
    scalar_from_hex(d, "0000000000000000000000000000000000000000000000000000000000000001");
    uint8_t bad[65] = {0};
    bad[0] = 0x04;
    check(!omk_p256_ecdh(d, bad, (uint8_t[32]){0}), "ecdh zero point rejected");
    (void)omk_p256_point_valid;
    uint8_t pub[65];
    from_hex("04"
             "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
             "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f6",
             pub, 65);
    check(!omk_p256_point_valid(pub), "off-curve point rejected");
    pub[0] = 0x05;
    check(!omk_p256_point_valid(pub), "bad prefix rejected");
}

static void test_ecdsa(void) {
    struct {
        const char *d;
        const char *msg;
        const char *hash;
        const char *r;
        const char *s;
    } cases[] = {
        {"0000000000000000000000000000000000000000000000000000000000000001",
         "OhMyKei P-256 test",
         "16bf7dc896fb1a90cbc3423b2b9cbb22e76e5beb30dfd0dbb759c0bdfddf7deb",
         "447c402aecfc0ae0cb1bcf8d4aa40e061e32ba6e677fba7333d952782e59f487",
         "2739e2227cb4ba40771f7c7e7f115a75275a260d85de840ef8b3161731da1bf8"},
        {"0000000000000000000000000000000000000000000000001234567890abcdef",
         "second vector",
         "80976a6512137ee6191d6749e786d35a6ce1ca855be1885502fbeb366b4413f6",
         "219ccfaeac459ba38a6e7bc94fa3cff9444a3346e1908e6c108d9677fa4f39d0",
         "5dc06d4858136b144570e95630027391be73df7961d457f2264bf5c213f07f9c"},
        {"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f",
         "edge scalar",
         "9e8ae8c353139138ea577640f3f1f7cebcf2f0c5ebcac70c3a8a6b498ac3193e",
         "7d035adeb34371403ac76485f0821d6d3c6f1b38d9b6a990ce76162b31d13580",
         "6369e346feb2f40edcd6bce304b99271e9562303a28e37f4293039e2e25366bc"},
        /* RFC 6979 A.2.5 (P-256/SHA-256, message "sample").  The RFC lists
         * the high-S value f7cb...cd a8; this implementation emits the
         * equivalent low-S form used by CTAP. */
        {"c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
         "sample",
         "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
         "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
         "0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        uint8_t d[32], hash[32], sig[64];
        scalar_from_hex(d, cases[i].d);
        from_hex(cases[i].hash, hash, 32);
        omk_p256_keypair kp;
        check(omk_p256_keypair_from_scalar(d, &kp), "sign keypair");
        check(omk_p256_ecdsa_sign(d, hash, sig, NULL, NULL), "ecdsa sign");
        uint8_t want[64];
        from_hex(cases[i].r, want, 32);
        from_hex(cases[i].s, want + 32, 32);
        check(memcmp(sig, want, 64) == 0, "rfc6979 signature matches");
        check(omk_p256_ecdsa_verify(kp.pub, hash, sig), "ecdsa verify");

        /* High-S form must also verify (verification is permissive). */
        uint8_t high[64];
        memcpy(high, sig, 64);
        uint8_t n_bytes[32];
        from_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                 n_bytes, 32);
        unsigned borrow = 0;
        for (int k = 31; k >= 0; k--) {
            int v = (int)n_bytes[k] - (int)high[32 + k] - (int)borrow;
            borrow = v < 0 ? 1u : 0u;
            high[32 + k] = (uint8_t)v;
        }
        check(omk_p256_ecdsa_verify(kp.pub, hash, high),
              "high-s signature verifies");

        /* Tampering must fail. */
        high[10] ^= 0x01;
        check(!omk_p256_ecdsa_verify(kp.pub, hash, high), "tampered sig rejected");
        uint8_t badhash[32];
        memcpy(badhash, hash, 32);
        badhash[0] ^= 0x80;
        check(!omk_p256_ecdsa_verify(kp.pub, badhash, sig),
              "tampered hash rejected");
    }

    /* r = 0 and s = 0 must be rejected. */
    uint8_t hash[32] = {0};
    uint8_t sig[64] = {0};
    uint8_t d[32];
    scalar_from_hex(d, "0000000000000000000000000000000000000000000000000000000000000001");
    omk_p256_keypair kp;
    omk_p256_keypair_from_scalar(d, &kp);
    check(!omk_p256_ecdsa_verify(kp.pub, hash, sig), "r=s=0 rejected");
}

static bool fake_rng(void *ctx, void *out, size_t len) {
    uint8_t *state = (uint8_t *)ctx;
    uint8_t *p = (uint8_t *)out;
    for (size_t i = 0; i < len; i++) {
        *state = (uint8_t)(*state * 31u + 7u);
        p[i] = *state;
    }
    return true;
}

static bool always_fail_rng(void *ctx, void *out, size_t len) {
    (void)ctx;
    (void)out;
    (void)len;
    return false;
}

/* Fill the output before reporting failure, like a broken/detected RNG. */
static bool fill_then_fail_rng(void *ctx, void *out, size_t len) {
    (void)ctx;
    memset(out, 0xa5, len);
    return false;
}

static bool zero_rng(void *ctx, void *out, size_t len) {
    (void)ctx;
    memset(out, 0, len);
    return true;
}

typedef struct {
    unsigned calls;
} retry_rng_state;

/* First output is zero (invalid scalar); later outputs are in range. */
static bool zero_then_valid_rng(void *ctx, void *out, size_t len) {
    retry_rng_state *st = (retry_rng_state *)ctx;
    uint8_t *p = (uint8_t *)out;

    st->calls++;
    if (st->calls == 1) {
        memset(p, 0, len);
        return true;
    }
    for (size_t i = 0; i < len; i++) {
        p[i] = (uint8_t)(0x11u + (unsigned)i + st->calls);
    }
    return true;
}

/* Failure and retry paths must be clean under ASan/UBSan and must not
 * accept invalid nonces or scalars. */
static void test_failure_and_retry_paths(void) {
    uint8_t d[32], hash[32], sig[64], pub[65], shared[32];
    scalar_from_hex(d, "0000000000000000000000000000000000000000000000000000000000000001");
    memset(hash, 0x5a, sizeof hash);

    omk_p256_keypair kp;
    check(omk_p256_keypair_from_scalar(d, &kp), "retry keypair");

    check(!omk_p256_ecdsa_sign(d, hash, sig, always_fail_rng, NULL),
          "sign rejects failing rng");
    check(!omk_p256_ecdsa_sign(d, hash, sig, fill_then_fail_rng, NULL),
          "sign rejects failing rng after writing");
    check(!omk_p256_ecdsa_sign(d, hash, sig, zero_rng, NULL),
          "sign rejects always-invalid rng");
    check(!omk_p256_keygen(always_fail_rng, NULL, &kp),
          "keygen rejects failing rng");

    retry_rng_state st = {0};
    check(omk_p256_ecdsa_sign(d, hash, sig, zero_then_valid_rng, &st),
          "sign retries invalid rng nonce");
    check(st.calls >= 2, "invalid nonce was retried");
    check(omk_p256_ecdsa_verify(kp.pub, hash, sig),
          "retried rng signature verifies");

    retry_rng_state st_keygen = {0};
    omk_p256_keypair kp2;
    check(omk_p256_keygen(zero_then_valid_rng, &st_keygen, &kp2),
          "keygen retries invalid rng scalar");
    check(st_keygen.calls >= 2, "invalid keygen scalar was retried");
    check(omk_p256_point_valid(kp2.pub), "retried keygen point valid");

    /* Invalid private scalars are rejected on every entry point. */
    memset(d, 0, 32);
    check(!omk_p256_ecdsa_sign(d, hash, sig, NULL, NULL), "sign rejects d=0");
    check(!omk_p256_keypair_from_scalar(d, &kp), "keypair rejects d=0");
    scalar_from_hex(d, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    check(!omk_p256_ecdsa_sign(d, hash, sig, NULL, NULL), "sign rejects d=n");

    /* ECDH must reject an invalid scalar and an off-curve peer. */
    from_hex("04"
             "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
             "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
             pub, sizeof pub);
    memset(d, 0, 32);
    check(!omk_p256_ecdh(d, pub, shared), "ecdh rejects d=0");
    scalar_from_hex(d, "0000000000000000000000000000000000000000000000000000000000000001");
    pub[64] ^= 0x01; /* no longer on the curve */
    check(!omk_p256_ecdh(d, pub, shared), "ecdh rejects off-curve peer");
}

int main(void) {
    test_key_derivation();
    test_ecdh();
    test_ecdsa();
    test_failure_and_retry_paths();

    /* Random-key round trip using a (deterministic) RNG. */
    uint8_t state = 1;
    for (int i = 0; i < 8; i++) {
        omk_p256_keypair kp;
        check(omk_p256_keygen(fake_rng, &state, &kp), "keygen");
        uint8_t hash[32];
        for (int j = 0; j < 32; j++) {
            hash[j] = (uint8_t)(i * 32 + j);
        }
        uint8_t sig[64];
        state = (uint8_t)(state + i);
        check(omk_p256_ecdsa_sign(kp.d, hash, sig, fake_rng, &state),
              "rng sign");
        check(omk_p256_ecdsa_verify(kp.pub, hash, sig), "rng sign verify");
    }

    if (g_failures != 0) {
        printf("%d p256 test(s) failed\n", g_failures);
        return 1;
    }
    printf("p256: all tests passed\n");
    return 0;
}
