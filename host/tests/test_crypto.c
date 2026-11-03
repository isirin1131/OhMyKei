/* Known-answer tests for the portable crypto primitives (host only). */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto/omk_crypto.h"

static int g_failures;

static void check_true(bool cond, const char *what) {
    if (!cond) {
        printf("FAIL: %s\n", what);
        g_failures++;
    }
}

static void from_hex(const char *hex, uint8_t *out, size_t out_len) {
    for (size_t i = 0; i < out_len; i++) {
        unsigned v = 0;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void expect_hex(const uint8_t *got, const char *want_hex,
                       const char *what) {
    uint8_t want[128];
    size_t n = strlen(want_hex) / 2;
    from_hex(want_hex, want, n);
    if (memcmp(got, want, n) != 0) {
        printf("FAIL: %s\n  got ", what);
        for (size_t i = 0; i < n; i++) {
            printf("%02x", got[i]);
        }
        printf("\n  want %s\n", want_hex);
        g_failures++;
    }
}

static void test_sha256(void) {
    uint8_t out[32];
    omk_sha256("", 0, out);
    expect_hex(out,
               "e3b0c44298fc1c149afbf4c8996fb924"
               "27ae41e4649b934ca495991b7852b855",
               "sha256 empty");
    omk_sha256("abc", 3, out);
    expect_hex(out,
               "ba7816bf8f01cfea414140de5dae2223"
               "b00361a396177a9cb410ff61f20015ad",
               "sha256 abc");

    /* Streaming with an awkward split must match the one-shot result. */
    static uint8_t buf[1000];
    for (size_t i = 0; i < sizeof buf; i++) {
        buf[i] = (uint8_t)(i * 7u + 3u);
    }
    uint8_t one[32], streamed[32];
    omk_sha256(buf, sizeof buf, one);
    omk_sha256_ctx ctx;
    omk_sha256_init(&ctx);
    omk_sha256_update(&ctx, buf, 1);
    omk_sha256_update(&ctx, buf + 1, 63);
    omk_sha256_update(&ctx, buf + 64, 137);
    omk_sha256_update(&ctx, buf + 201, sizeof buf - 201);
    omk_sha256_final(&ctx, streamed);
    check_true(memcmp(one, streamed, 32) == 0, "sha256 streaming");
}

static void test_hmac(void) {
    uint8_t key[20], out[32];
    memset(key, 0x0b, sizeof key);
    omk_hmac_sha256(key, sizeof key, "Hi There", 8, out);
    expect_hex(out,
               "b0344c61d8db38535ca8afceaf0bf12b"
               "881dc200c9833da726e9376c2e32cff7",
               "hmac rfc4231 tc1");

    static const char jefe[] = "Jefe";
    static const char data[] = "what do ya want for nothing?";
    omk_hmac_sha256((const uint8_t *)jefe, 4, data, sizeof data - 1, out);
    expect_hex(out,
               "5bdcc146bf60754e6a042426089575c7"
               "5a003f089d2739839dec58b964ec3843",
               "hmac rfc4231 tc2");
}

/* RFC 4231 TC6: key longer than the SHA-256 block size, streamed in two
 * pieces.  Also checks that final() leaves no keyed outer pad behind. */
static void test_hmac_long_key(void) {
    static const char data[] =
        "Test Using Larger Than Block-Size Key - Hash Key First";
    uint8_t key[131];
    uint8_t one[32], streamed[32], opad[64];
    omk_sha256_ctx inner;

    memset(key, 0xaa, sizeof key);
    omk_hmac_sha256(key, sizeof key, data, sizeof data - 1, one);
    expect_hex(one,
               "60e431591ee0b67f0d8a26aacbf5b77f"
               "8e0bc6213728c5140546040f0ee37f54",
               "hmac rfc4231 tc6");

    omk_hmac_sha256_init(&inner, opad, key, sizeof key);
    omk_hmac_sha256_update(&inner, data, 20);
    omk_hmac_sha256_update(&inner, data + 20, sizeof data - 1 - 20);
    omk_hmac_sha256_final(&inner, opad, streamed);
    check_true(memcmp(one, streamed, sizeof one) == 0,
               "hmac streaming equals one-shot");

    uint8_t acc = 0;
    for (size_t i = 0; i < sizeof opad; i++) {
        acc |= opad[i];
    }
    check_true(acc == 0, "hmac final wipes opad");
}

static void test_hkdf(void) {
    uint8_t ikm[22], salt[13], info[10], out[42], want[42];
    memset(ikm, 0x0b, sizeof ikm);
    from_hex("000102030405060708090a0b0c", salt, sizeof salt);
    from_hex("f0f1f2f3f4f5f6f7f8f9", info, sizeof info);
    omk_hkdf_sha256(salt, sizeof salt, ikm, sizeof ikm, info, sizeof info, out,
                    sizeof out);
    from_hex("3cb25f25faacd57a90434f64d0362f2a"
             "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
             "34007208d5b887185865",
             want, sizeof want);
    check_true(memcmp(out, want, sizeof out) == 0, "hkdf rfc5869 tc1");

    /* RFC 5869 TC3: zero-length salt and info. */
    uint8_t out3[42], want3[42];
    omk_hkdf_sha256(NULL, 0, ikm, sizeof ikm, NULL, 0, out3, sizeof out3);
    from_hex("8da4e775a563c18f715f802a063c5a31"
             "b8a11f5c5ee1879ec3454e5f3c738d2d"
             "9d201395faa4b61a96c8",
             want3, sizeof want3);
    check_true(memcmp(out3, want3, sizeof out3) == 0, "hkdf rfc5869 tc3");

    /* Zero-length output is a no-op and must not write to out. */
    uint8_t canary = 0x5a;
    omk_hkdf_sha256(NULL, 0, ikm, sizeof ikm, NULL, 0, &canary, 0);
    check_true(canary == 0x5a, "hkdf zero length writes nothing");
}

static void test_aes(void) {
    uint8_t key[32], pt[16], ct[16], back[16];
    from_hex("000102030405060708090a0b0c0d0e0f"
             "101112131415161718191a1b1c1d1e1f",
             key, sizeof key);
    from_hex("00112233445566778899aabbccddeeff", pt, 16);
    omk_aes256_ctx ctx;
    check_true(omk_aes256_set_encrypt_key(&ctx, key), "aes set enc key");
    omk_aes256_encrypt_block(&ctx, pt, ct);
    expect_hex(ct, "8ea2b7ca516745bfeafc49904b496089", "aes256 fips197");
    check_true(omk_aes256_set_decrypt_key(&ctx, key), "aes set dec key");
    omk_aes256_decrypt_block(&ctx, ct, back);
    check_true(memcmp(back, pt, 16) == 0, "aes256 decrypt");

    /* NIST SP 800-38A F.2.5 AES-256-CBC */
    from_hex("603deb1015ca71be2b73aef0857d7781"
             "1f352c073b6108d72d9810a30914dff4",
             key, sizeof key);
    uint8_t iv[16];
    from_hex("000102030405060708090a0b0c0d0e0f", iv, 16);
    uint8_t plain[64], cipher[64];
    from_hex("6bc1bee22e409f96e93d7e117393172a"
             "ae2d8a571e03ac9c9eb76fac45af8e51"
             "30c81c46a35ce411e5fbc1191a0a52ef"
             "f69f2445df4f9b17ad2b417be66c3710",
             plain, sizeof plain);
    omk_aes256_cbc_encrypt(key, iv, plain, sizeof plain, cipher);
    expect_hex(cipher,
               "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
               "9cfc4e967edb808d679f777bc6702c7d"
               "39f23369a9d9bacfa530e26304231461"
               "b2eb05e2c39be9fcda6c19078c6a9d1b",
               "aes256-cbc sp800-38a");
    omk_aes256_cbc_decrypt(key, iv, cipher, sizeof cipher, plain);
    expect_hex(plain,
               "6bc1bee22e409f96e93d7e117393172a"
               "ae2d8a571e03ac9c9eb76fac45af8e51"
               "30c81c46a35ce411e5fbc1191a0a52ef"
               "f69f2445df4f9b17ad2b417be66c3710",
               "aes256-cbc decrypt");

    check_true(omk_ct_equal("abc", "abc", 3), "ct_equal equal");
    check_true(!omk_ct_equal("abc", "abd", 3), "ct_equal diff");
}

int main(void) {
    test_sha256();
    test_hmac();
    test_hmac_long_key();
    test_hkdf();
    test_aes();
    if (g_failures != 0) {
        printf("%d crypto test(s) failed\n", g_failures);
        return 1;
    }
    printf("crypto: all known-answer tests passed\n");
    return 0;
}
