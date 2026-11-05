#include <string.h>

#include "crypto/omk_crypto.h"
#include "fido/omk_pin_protocol.h"

bool omk_pin_protocol_derive(const omk_cbor_doc *doc,
                             const omk_cbor_val *cose, uint32_t protocol,
                             const uint8_t private_key[32], uint8_t aes[32],
                             uint8_t hmac[32]) {
    memset(aes, 0, 32);
    memset(hmac, 0, 32);
    if (cose == NULL || cose->type != OMK_CBOR_MAP) {
        return false;
    }
    const omk_cbor_val *crv = omk_cbor_map_get_int(doc, cose, -1);
    const omk_cbor_val *x = omk_cbor_map_get_int(doc, cose, -2);
    const omk_cbor_val *y = omk_cbor_map_get_int(doc, cose, -3);
    if (crv == NULL || x == NULL || y == NULL || crv->type != OMK_CBOR_UINT ||
        crv->num != 1 || x->type != OMK_CBOR_BYTES || x->len != 32 ||
        y->type != OMK_CBOR_BYTES || y->len != 32) {
        return false;
    }
    uint8_t pub[65];
    pub[0] = 0x04;
    memcpy(pub + 1, x->data, 32);
    memcpy(pub + 33, y->data, 32);
    uint8_t shared[32] = {0};
    /* ECDH validates the point before scalar multiplication. */
    if (!omk_p256_ecdh(private_key, pub, shared)) {
        omk_memzero(shared, sizeof shared);
        return false;
    }
    if (protocol == 1) {
        omk_sha256(shared, 32, aes);
        memcpy(hmac, aes, 32);
    } else {
        const uint8_t salt[32] = {0};
        omk_hkdf_sha256(salt, 32, shared, 32, (const uint8_t *)"CTAP2 AES key",
                        13, aes, 32);
        omk_hkdf_sha256(salt, 32, shared, 32, (const uint8_t *)"CTAP2 HMAC key",
                        14, hmac, 32);
    }
    omk_memzero(shared, sizeof shared);
    return true;
}

bool omk_pin_protocol_decrypt(const uint8_t aes[32], uint32_t protocol,
                              const uint8_t *in, size_t in_len,
                              uint8_t *out, size_t plain_len) {
    const size_t prefix = protocol == 1 ? 0 : 16;
    if (plain_len == 0 || plain_len % 16 != 0 || in_len < prefix ||
        in_len - prefix != plain_len) {
        return false;
    }
    const uint8_t zero_iv[16] = {0};
    const uint8_t *iv = protocol == 1 ? zero_iv : in;
    omk_aes256_cbc_decrypt(aes, iv, in + prefix, plain_len, out);
    return true;
}

bool omk_pin_protocol_encrypt(const omk_port *port, const uint8_t aes[32],
                              uint32_t protocol, const uint8_t *in,
                              size_t in_len, uint8_t *out, size_t *out_len) {
    if (in_len % 16 != 0) {
        return false;
    }
    uint8_t iv[16] = {0};
    const size_t prefix = protocol == 1 ? 0 : 16;
    if (prefix != 0) {
        if (!port->random_bytes(port->ctx, iv, sizeof iv)) {
            omk_memzero(iv, sizeof iv);
            return false;
        }
        memcpy(out, iv, sizeof iv);
    }
    omk_aes256_cbc_encrypt(aes, iv, in, in_len, out + prefix);
    omk_memzero(iv, sizeof iv);
    *out_len = in_len + prefix;
    return true;
}
