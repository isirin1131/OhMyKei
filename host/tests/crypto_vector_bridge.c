/* Host-only bridge for offline public vectors. No crypto implementation here. */
#include "crypto/omk_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BYTES 16384
#define MAX_LINE 65536

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool decode_hex(const char *s, uint8_t *out, size_t *len) {
    if (strcmp(s, "-") == 0) {
        *len = 0;
        return true;
    }
    size_t n = strlen(s);
    if ((n & 1u) != 0 || n / 2 > MAX_BYTES) return false;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hex_value(s[2 * i]);
        int lo = hex_value(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *len = n / 2;
    return true;
}

static void encode_hex(const uint8_t *in, size_t len) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        putchar(digits[in[i] >> 4]);
        putchar(digits[in[i] & 0xf]);
    }
}

static char *next_token(char **cursor) {
    char *s = *cursor;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '\0' || *s == '\n') {
        *cursor = s;
        return NULL;
    }
    char *end = s;
    while (*end != '\0' && *end != ' ' && *end != '\t' && *end != '\n') end++;
    if (*end != '\0') *end++ = '\0';
    *cursor = end;
    return s;
}

static bool parse_size(const char *s, size_t *out) {
    char *end = NULL;
    unsigned long long value = strtoull(s, &end, 10);
    if (end == s || *end != '\0' || value > SIZE_MAX) return false;
    *out = (size_t)value;
    return true;
}

static void reply_error(void) {
    fputs("ERR\n", stdout);
}

int main(void) {
    char line[MAX_LINE];
    uint8_t a[MAX_BYTES], b[MAX_BYTES], c[MAX_BYTES];
    uint8_t out[MAX_BYTES];
    setvbuf(stdout, NULL, _IOLBF, 0);
    while (fgets(line, sizeof line, stdin) != NULL) {
        if (strchr(line, '\n') == NULL) return 2;
        char *cursor = line;
        char *op = next_token(&cursor);
        if (op == NULL) continue;

        if (strcmp(op, "sha256") == 0 || strcmp(op, "sha256_monte") == 0) {
            char *msg_s = next_token(&cursor);
            size_t len;
            if (msg_s == NULL || !decode_hex(msg_s, a, &len)) return 2;
            if (strcmp(op, "sha256_monte") == 0) {
                if (len != 32) return 2;
                memcpy(a + 32, a, 32);
                memcpy(a + 64, a, 32);
                /* SHAVS 6.4: MD[i] = SHA(MD[i-3] || MD[i-2] || MD[i-1]). */
                for (unsigned i = 0; i < 1000; i++) {
                    omk_sha256(a, 96, out);
                    memmove(a, a + 32, 64);
                    memcpy(a + 64, out, 32);
                }
            } else {
                omk_sha256(a, len, out);
                /* Also exercise incremental updates around block boundaries. */
                const size_t chunks[] = {1, 63, 64, 65};
                for (size_t j = 0; j < sizeof chunks / sizeof chunks[0]; j++) {
                    omk_sha256_ctx ctx;
                    omk_sha256_init(&ctx);
                    omk_sha256_update(&ctx, a, 0);
                    for (size_t pos = 0; pos < len;) {
                        size_t n = len - pos;
                        if (n > chunks[j]) n = chunks[j];
                        omk_sha256_update(&ctx, a + pos, n);
                        pos += n;
                    }
                    omk_sha256_final(&ctx, b);
                    if (memcmp(b, out, 32) != 0) return 2;
                }
            }
            fputs("OK ", stdout);
            encode_hex(out, 32);
            putchar('\n');
            continue;
        }

        if (strcmp(op, "ecb_enc") == 0 || strcmp(op, "ecb_dec") == 0 ||
            strcmp(op, "cbc_enc") == 0 || strcmp(op, "cbc_dec") == 0) {
            char *key_s = next_token(&cursor);
            char *iv_s = next_token(&cursor);
            char *data_s = next_token(&cursor);
            size_t key_len, iv_len, len;
            if (key_s == NULL || iv_s == NULL || data_s == NULL ||
                !decode_hex(key_s, a, &key_len) || key_len != 32 ||
                !decode_hex(iv_s, b, &iv_len) || iv_len != 16 ||
                !decode_hex(data_s, c, &len) || len % 16 != 0) return 2;
            bool encrypt = strcmp(op + 4, "enc") == 0;
            if (op[0] == 'e') {
                omk_aes256_ctx ctx;
                if (!(encrypt ? omk_aes256_set_encrypt_key(&ctx, a)
                              : omk_aes256_set_decrypt_key(&ctx, a))) return 2;
                for (size_t pos = 0; pos < len; pos += 16) {
                    if (encrypt) omk_aes256_encrypt_block(&ctx, c + pos, out + pos);
                    else omk_aes256_decrypt_block(&ctx, c + pos, out + pos);
                    if (encrypt) omk_aes256_encrypt_block(&ctx, c + pos, c + pos);
                    else omk_aes256_decrypt_block(&ctx, c + pos, c + pos);
                }
            } else {
                uint8_t iv[16];
                memcpy(iv, b, sizeof iv);
                if (encrypt) omk_aes256_cbc_encrypt(a, b, c, len, out);
                else omk_aes256_cbc_decrypt(a, b, c, len, out);
                if (memcmp(iv, b, sizeof iv) != 0) return 2;
                if (encrypt) omk_aes256_cbc_encrypt(a, b, c, len, c);
                else omk_aes256_cbc_decrypt(a, b, c, len, c);
                if (memcmp(iv, b, sizeof iv) != 0) return 2;
            }
            if (memcmp(c, out, len) != 0) return 2;
            fputs("OK ", stdout);
            encode_hex(out, len);
            putchar('\n');
            continue;
        }

        if (strcmp(op, "hmac") == 0) {
            char *key_s = next_token(&cursor);
            char *msg_s = next_token(&cursor);
            char *tag_s = next_token(&cursor);
            size_t key_len, msg_len, tag_len;
            if (key_s == NULL || msg_s == NULL || tag_s == NULL ||
                !decode_hex(key_s, a, &key_len) ||
                !decode_hex(msg_s, b, &msg_len) ||
                !decode_hex(tag_s, c, &tag_len) || tag_len != OMK_HMAC256_LEN) {
                return 2;
            }
            omk_hmac_sha256(a, key_len, b, msg_len, out);
            printf("%s\n", omk_ct_equal(out, c, tag_len) ? "VALID" : "INVALID");
            continue;
        }

        if (strcmp(op, "hkdf") == 0) {
            char *salt_s = next_token(&cursor);
            char *ikm_s = next_token(&cursor);
            char *info_s = next_token(&cursor);
            char *size_s = next_token(&cursor);
            size_t salt_len, ikm_len, info_len, out_len;
            if (salt_s == NULL || ikm_s == NULL || info_s == NULL || size_s == NULL ||
                !decode_hex(salt_s, a, &salt_len) ||
                !decode_hex(ikm_s, b, &ikm_len) ||
                !decode_hex(info_s, c, &info_len) ||
                !parse_size(size_s, &out_len) || out_len > sizeof out) {
                return 2;
            }
            memset(out, 0xa5, sizeof out);
            if (!omk_hkdf_sha256(a, salt_len, b, ikm_len, c, info_len, out, out_len)) {
                for (size_t i = 0; i < sizeof out; i++) {
                    if (out[i] != 0xa5) return 2;
                }
                reply_error();
                continue;
            }
            fputs("OK ", stdout);
            encode_hex(out, out_len);
            putchar('\n');
            continue;
        }

        if (strcmp(op, "ecdsa") == 0) {
            char *pub_s = next_token(&cursor);
            char *hash_s = next_token(&cursor);
            char *sig_s = next_token(&cursor);
            size_t pub_len, hash_len, sig_len;
            if (pub_s == NULL || hash_s == NULL || sig_s == NULL ||
                !decode_hex(pub_s, a, &pub_len) ||
                !decode_hex(hash_s, b, &hash_len) ||
                !decode_hex(sig_s, c, &sig_len) ||
                pub_len != OMK_P256_PUBLIC_LEN || hash_len != OMK_SHA256_LEN ||
                sig_len != OMK_P256_SIG_LEN) {
                return 2;
            }
            printf("%s\n", omk_p256_ecdsa_verify(a, b, c) ? "VALID" : "INVALID");
            continue;
        }

        if (strcmp(op, "ed25519") == 0) {
            char *pub_s = next_token(&cursor);
            char *msg_s = next_token(&cursor);
            char *sig_s = next_token(&cursor);
            size_t pub_len, msg_len, sig_len;
            if (pub_s == NULL || msg_s == NULL || sig_s == NULL ||
                !decode_hex(pub_s, a, &pub_len) ||
                !decode_hex(msg_s, b, &msg_len) ||
                !decode_hex(sig_s, c, &sig_len) ||
                pub_len != OMK_ED25519_PUBLIC_LEN || sig_len != OMK_ED25519_SIG_LEN) {
                return 2;
            }
            printf("%s\n", omk_ed25519_verify(a, b, msg_len, c) ? "VALID" : "INVALID");
            continue;
        }

        if (strcmp(op, "ecdh") == 0) {
            char *d_s = next_token(&cursor);
            char *pub_s = next_token(&cursor);
            size_t d_len, pub_len;
            if (d_s == NULL || pub_s == NULL ||
                !decode_hex(d_s, a, &d_len) || !decode_hex(pub_s, b, &pub_len) ||
                d_len != OMK_P256_SCALAR_LEN || pub_len != OMK_P256_PUBLIC_LEN) {
                return 2;
            }
            if (!omk_p256_ecdh(a, b, out)) {
                reply_error();
                continue;
            }
            fputs("OK ", stdout);
            encode_hex(out, OMK_P256_SCALAR_LEN);
            putchar('\n');
            continue;
        }

        return 2;
    }
    return ferror(stdin) || ferror(stdout) ? 1 : 0;
}
