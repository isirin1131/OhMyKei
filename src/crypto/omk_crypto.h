/*
 * OhMyKei portable cryptographic primitives.
 *
 * This is the only crypto interface used by the CTAP core.  Everything here
 * is plain C17 with no heap allocation and no platform dependencies so the
 * same code runs on the RP2350 and in the host test suite.
 *
 * All 32-byte scalars and coordinates are big-endian, matching the FIDO/CTAP
 * wire format.  Public keys are uncompressed SEC1 points: 0x04 || X || Y.
 */
#ifndef OMK_CRYPTO_H
#define OMK_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define OMK_SHA256_LEN 32
#define OMK_SHA512_LEN 64
#define OMK_AES256_KEY_LEN 32
#define OMK_AES_BLOCK_LEN 16
#define OMK_HMAC256_LEN 32

/* ---------------------------------------------------------------------- */
/* SHA-256                                                                 */
/* ---------------------------------------------------------------------- */

typedef struct {
    uint32_t h[8];
    uint64_t total_len;
    uint8_t buf[64];
    size_t buf_len;
} omk_sha256_ctx;

void omk_sha256_init(omk_sha256_ctx *ctx);
void omk_sha256_update(omk_sha256_ctx *ctx, const void *data, size_t len);
void omk_sha256_final(omk_sha256_ctx *ctx, uint8_t out[OMK_SHA256_LEN]);
void omk_sha256(const void *data, size_t len, uint8_t out[OMK_SHA256_LEN]);

/* HMAC-SHA-256 (FIPS 198-1).  init() fills opad with the key-derived outer
 * pad; final() consumes it, writes the MAC and zeroes opad before returning.
 * out must not alias opad. */
void omk_hmac_sha256_init(omk_sha256_ctx *inner, uint8_t opad[64],
                          const uint8_t *key, size_t key_len);
void omk_hmac_sha256_update(omk_sha256_ctx *inner, const void *data, size_t len);
void omk_hmac_sha256_final(omk_sha256_ctx *inner, uint8_t opad[64],
                           uint8_t out[OMK_HMAC256_LEN]);
void omk_hmac_sha256(const uint8_t *key, size_t key_len,
                     const void *msg, size_t msg_len,
                     uint8_t out[OMK_HMAC256_LEN]);

/* HKDF-SHA-256 (RFC 5869).  out_len is limited to 255 * 32 bytes. */
void omk_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                     const uint8_t *ikm, size_t ikm_len,
                     const uint8_t *info, size_t info_len,
                     uint8_t *out, size_t out_len);

/* ---------------------------------------------------------------------- */
/* AES-256 (FIPS 197) and CBC mode                                         */
/* ---------------------------------------------------------------------- */

typedef struct {
    uint32_t rk[60];
} omk_aes256_ctx;

bool omk_aes256_set_encrypt_key(omk_aes256_ctx *ctx,
                                const uint8_t key[OMK_AES256_KEY_LEN]);
bool omk_aes256_set_decrypt_key(omk_aes256_ctx *ctx,
                                const uint8_t key[OMK_AES256_KEY_LEN]);
void omk_aes256_encrypt_block(const omk_aes256_ctx *ctx,
                              const uint8_t in[OMK_AES_BLOCK_LEN],
                              uint8_t out[OMK_AES_BLOCK_LEN]);
void omk_aes256_decrypt_block(const omk_aes256_ctx *ctx,
                              const uint8_t in[OMK_AES_BLOCK_LEN],
                              uint8_t out[OMK_AES_BLOCK_LEN]);

/* CBC with PKCS#7 padding is deliberately *not* provided: callers must pass
 * data whose length is a multiple of 16 bytes.  PIN protocol 1 and credential
 * ID sealing both require caller-controlled padding. */
void omk_aes256_cbc_encrypt(const uint8_t key[OMK_AES256_KEY_LEN],
                            const uint8_t iv[OMK_AES_BLOCK_LEN],
                            const uint8_t *in, size_t len, uint8_t *out);
void omk_aes256_cbc_decrypt(const uint8_t key[OMK_AES256_KEY_LEN],
                            const uint8_t iv[OMK_AES_BLOCK_LEN],
                            const uint8_t *in, size_t len, uint8_t *out);

/* ---------------------------------------------------------------------- */
/* Utilities                                                               */
/* ---------------------------------------------------------------------- */

/* Constant-time comparison: returns true when the buffers are equal. */
bool omk_ct_equal(const void *a, const void *b, size_t len);

/* Zero memory in a way the compiler may not elide. */
void omk_memzero(void *p, size_t len);

/* ---------------------------------------------------------------------- */
/* NIST P-256 (secp256r1)                                                  */
/* ---------------------------------------------------------------------- */

#define OMK_P256_SCALAR_LEN 32
#define OMK_P256_PUBLIC_LEN 65
#define OMK_P256_SIG_LEN 64

typedef struct {
    uint8_t d[OMK_P256_SCALAR_LEN];
    uint8_t pub[OMK_P256_PUBLIC_LEN];
} omk_p256_keypair;

/* Generate a fresh key pair from rng. */
bool omk_p256_keygen(bool (*rng)(void *ctx, void *out, size_t len), void *ctx,
                     omk_p256_keypair *out);

/* Derive the public key for a private scalar.  Returns false if d is not in
 * [1, n-1]. */
bool omk_p256_keypair_from_scalar(const uint8_t d[OMK_P256_SCALAR_LEN],
                                  omk_p256_keypair *out);

/* Check [1, n-1] without deriving a public key. */
bool omk_p256_scalar_valid(const uint8_t d[OMK_P256_SCALAR_LEN]);

/* Validate an uncompressed point: prefix, curve membership, not infinity. */
bool omk_p256_point_valid(const uint8_t pub[OMK_P256_PUBLIC_LEN]);

/* ECDSA-SHA-256 signature over a 32-byte digest.  Produces r || s with the
 * low-S normalization used by CTAP.  rng may be NULL to use a deterministic
 * RFC 6979 nonce. */
bool omk_p256_ecdsa_sign(const uint8_t d[OMK_P256_SCALAR_LEN],
                         const uint8_t hash[OMK_SHA256_LEN],
                         uint8_t sig[OMK_P256_SIG_LEN],
                         bool (*rng)(void *ctx, void *out, size_t len),
                         void *ctx);
bool omk_p256_ecdsa_verify(const uint8_t pub[OMK_P256_PUBLIC_LEN],
                           const uint8_t hash[OMK_SHA256_LEN],
                           const uint8_t sig[OMK_P256_SIG_LEN]);

/* ECDH: out receives the 32-byte big-endian X coordinate of d * peer_pub. */
bool omk_p256_ecdh(const uint8_t d[OMK_P256_SCALAR_LEN],
                   const uint8_t peer_pub[OMK_P256_PUBLIC_LEN],
                   uint8_t out_x[32]);

/* ---------------------------------------------------------------------- */
/* Ed25519 (RFC 8032, pure Ed25519, empty context)                         */
/* ---------------------------------------------------------------------- */

#define OMK_ED25519_SEED_LEN 32
#define OMK_ED25519_PUBLIC_LEN 32
#define OMK_ED25519_SIG_LEN 64

bool omk_ed25519_public_from_seed(const uint8_t seed[OMK_ED25519_SEED_LEN],
                                  uint8_t pub[OMK_ED25519_PUBLIC_LEN]);
bool omk_ed25519_sign(const uint8_t seed[OMK_ED25519_SEED_LEN],
                      const void *msg, size_t msg_len,
                      uint8_t sig[OMK_ED25519_SIG_LEN]);
bool omk_ed25519_verify(const uint8_t pub[OMK_ED25519_PUBLIC_LEN],
                        const void *msg, size_t msg_len,
                        const uint8_t sig[OMK_ED25519_SIG_LEN]);

#endif /* OMK_CRYPTO_H */
