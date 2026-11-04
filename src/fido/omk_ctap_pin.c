#include <string.h>

#include "crypto/omk_crypto.h"
#include "fido/omk_cbor.h"
#include "fido/omk_ctap_internal.h"

/* ---------------------------------------------------------------------- */
/* PUAT state                                                              */
/* ---------------------------------------------------------------------- */

void omk_ctap_puat_invalidate(omk_ctap *ct) {
    ct->pin.token_valid = false;
    ct->pin.permissions = 0;
    ct->pin.rp_bound = false;
    ct->pin.user_verified = false;
    ct->pin.used_once = false;
    ct->pin.created_ms = 0;
    ct->pin.used_ms = 0;
    omk_memzero(ct->pin.token, sizeof ct->pin.token);
    omk_memzero(ct->pin.rp_hash, sizeof ct->pin.rp_hash);
}

static uint8_t puat_check(omk_ctap *ct, uint8_t permissions,
                          const uint8_t *rp_hash, bool *uv_out) {
    if (!ct->pin.token_valid) {
        return OMK_CTAP2_ERR_PIN_AUTH_INVALID;
    }
    const uint64_t now = omk_ctap_now_ms(ct);
    /* Token expiry, missing permissions and an RP-bound token presented for a
     * different RP are all an authentication failure at use time.  Only the
     * issuance request itself may report UNAUTHORIZED_PERMISSION. */
    const uint64_t activity_ms =
        ct->pin.used_once ? ct->pin.used_ms : ct->pin.created_ms;
    if (now - ct->pin.created_ms > OMK_CTAP_PUAT_TOTAL_MS ||
        now - activity_ms > OMK_CTAP_PUAT_INITIAL_MS) {
        omk_ctap_puat_invalidate(ct);
        return OMK_CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if ((ct->pin.permissions & permissions) != permissions) {
        return OMK_CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (ct->pin.rp_bound) {
        if (rp_hash == NULL || memcmp(ct->pin.rp_hash, rp_hash, 32) != 0) {
            return OMK_CTAP2_ERR_PIN_AUTH_INVALID;
        }
    }
    ct->pin.used_once = true;
    ct->pin.used_ms = now;
    if (uv_out != NULL) {
        *uv_out = ct->pin.user_verified;
    }
    return OMK_CTAP2_OK;
}

uint8_t omk_ctap_authorize_raw(omk_ctap *ct, const omk_cbor_val *param,
                               uint32_t protocol, const uint8_t *msg,
                               size_t msg_len, uint8_t permissions,
                               const uint8_t *rp_hash, bool *uv_out) {
    if (param == NULL) {
        return ct->store.pin_set ? OMK_CTAP2_ERR_PIN_REQUIRED : OMK_CTAP2_OK;
    }
    if (param->type != OMK_CBOR_BYTES) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    if (param->len == 0) {
        return OMK_CTAP_PIN_PROBE;
    }
    if (!ct->store.pin_set) {
        return OMK_CTAP2_ERR_PIN_NOT_SET;
    }
    if (protocol != 1 && protocol != 2) {
        return OMK_CTAP1_ERR_INVALID_PARAMETER;
    }
    if (param->len != (protocol == 1 ? 16u : 32u)) {
        return OMK_CTAP2_ERR_PIN_AUTH_INVALID;
    }
    uint8_t mac[32];
    omk_hmac_sha256(ct->pin.token, 32, msg, msg_len, mac);
    if (!omk_ct_equal(mac, param->data, param->len)) {
        return OMK_CTAP2_ERR_PIN_AUTH_INVALID;
    }
    bool uv = false;
    const uint8_t status = puat_check(ct, permissions, rp_hash, &uv);
    if (status != OMK_CTAP2_OK) {
        return status;
    }
    if (uv_out != NULL) {
        *uv_out = uv;
    }
    return OMK_CTAP2_OK;
}

uint8_t omk_ctap_authorize(omk_ctap *ct, const omk_cbor_doc *doc,
                           const omk_cbor_val *req, uint32_t protocol,
                           const uint8_t *msg, size_t msg_len,
                           uint8_t permissions, const uint8_t *rp_hash,
                           bool *uv_out) {
    return omk_ctap_authorize_raw(ct, omk_cbor_map_get_int(doc, req, 0x04),
                                  protocol, msg, msg_len, permissions, rp_hash,
                                  uv_out);
}

/* ---------------------------------------------------------------------- */
/* PIN protocol cryptography                                               */
/* ---------------------------------------------------------------------- */

static bool pin_rng(void *ctx, void *out, size_t len) {
    omk_ctap *ct = (omk_ctap *)ctx;
    return ct->port->random_bytes(ct->port->ctx, out, len);
}

/* Rotate the PIN key agreement after a failed comparison so a platform that
 * learned (or tried to brute-force) the old shared secret cannot reuse it.
 * A failed RNG never installs a partial key pair; the old agreement key is
 * kept but every derived shared secret is discarded and the caller fails
 * closed instead of continuing with stale or zeroed key material. */
static bool pin_regenerate_agreement(omk_ctap *ct) {
    omk_p256_keypair kp;
    memset(&kp, 0, sizeof kp);
    if (!omk_p256_keygen(pin_rng, ct, &kp)) {
        omk_memzero(&kp, sizeof kp);
        omk_ctap_pin_shared_clear(ct);
        return false;
    }
    memcpy(ct->pin.key_priv, kp.d, 32);
    memcpy(ct->pin.key_pub, kp.pub, 65);
    omk_memzero(&kp, sizeof kp);
    omk_ctap_pin_shared_clear(ct);
    return true;
}

static uint8_t pin_verify_hash(omk_ctap *ct, const uint8_t hash[16]) {
    if (ct->pin_store_fault) {
        return OMK_CTAP2_ERR_OTHER;
    }
    if (!ct->store.pin_set) {
        return OMK_CTAP2_ERR_PIN_NOT_SET;
    }
    /* Existing lock state is authoritative; a locked authenticator does not
     * touch the persistent retry counter. */
    if (ct->store.pin_retries == 0) {
        return OMK_CTAP2_ERR_PIN_BLOCKED;
    }
    if (ct->consecutive_pin_failures >= 3) {
        return OMK_CTAP2_ERR_PIN_AUTH_BLOCKED;
    }
    /* Reserve a retry on flash *before* comparing.  The store persists the
     * decremented count together with the candidate hash; if the write fails
     * the comparison never happens and the authenticator fails closed instead
     * of reporting an ordinary PIN_INVALID. */
    if (omk_store_pin_attempt(&ct->store, hash) != 0) {
        ct->pin_store_fault = true;
        return OMK_CTAP2_ERR_OTHER;
    }
    if (omk_ct_equal(hash, ct->store.pin_hash, 16)) {
        ct->consecutive_pin_failures = 0;
        if (omk_store_pin_success(&ct->store) != 0) {
            /* The correct PIN could not be persisted as restored. */
            ct->pin_store_fault = true;
            return OMK_CTAP2_ERR_OTHER;
        }
        return OMK_CTAP2_OK;
    }
    ct->consecutive_pin_failures++;
    /* Persist the fact that this attempt was wrong (keep the decrement)
     * before doing any further work.  If that write fails, fail closed; the
     * attempt record itself still keeps the decrease durable across a
     * reboot. */
    if (omk_store_pin_reject(&ct->store) != 0) {
        ct->pin_store_fault = true;
        return OMK_CTAP2_ERR_OTHER;
    }
    if (!pin_regenerate_agreement(ct)) {
        return OMK_CTAP2_ERR_OTHER;
    }
    /* Retries exhausted by *this* wrong PIN wins over the per-boot
     * consecutive-failure limit: report PIN_BLOCKED, not PIN_AUTH_BLOCKED. */
    if (ct->store.pin_retries == 0) {
        return OMK_CTAP2_ERR_PIN_BLOCKED;
    }
    if (ct->consecutive_pin_failures >= 3) {
        return OMK_CTAP2_ERR_PIN_AUTH_BLOCKED;
    }
    return OMK_CTAP2_ERR_PIN_INVALID;
}

static void pin_hash(const uint8_t *pin, size_t len, uint8_t out[16]) {
    uint8_t full[32];
    omk_sha256(pin, len, full);
    memcpy(out, full, 16);
    omk_memzero(full, sizeof full);
}

static size_t utf8_codepoints(const uint8_t *s, size_t len) {
    size_t n = 0;
    for (size_t i = 0; i < len;) {
        const uint8_t c = s[i];
        size_t step = 0;
        if (c <= 0x7Fu) {
            step = 1;
        } else if (c >= 0xC2u && c <= 0xDFu) {
            step = 2;
            if (i + step > len || (s[i + 1] & 0xC0u) != 0x80u) {
                return 0;
            }
        } else if (c >= 0xE0u && c <= 0xEFu) {
            step = 3;
            if (i + step > len || (s[i + 1] & 0xC0u) != 0x80u ||
                (s[i + 2] & 0xC0u) != 0x80u ||
                (c == 0xE0u && s[i + 1] < 0xA0u) ||
                (c == 0xEDu && s[i + 1] >= 0xA0u)) {
                return 0;
            }
        } else if (c >= 0xF0u && c <= 0xF4u) {
            step = 4;
            if (i + step > len || (s[i + 1] & 0xC0u) != 0x80u ||
                (s[i + 2] & 0xC0u) != 0x80u ||
                (s[i + 3] & 0xC0u) != 0x80u ||
                (c == 0xF0u && s[i + 1] < 0x90u) ||
                (c == 0xF4u && s[i + 1] >= 0x90u)) {
                return 0;
            }
        } else {
            return 0;
        }
        i += step;
        n++;
    }
    return n;
}

static uint8_t pin_check_policy(const uint8_t *pin, size_t len) {
    if (len < OMK_CTAP_MIN_PIN_LENGTH || len > 63) {
        return OMK_CTAP2_ERR_PIN_POLICY_VIOLATION;
    }
    if (utf8_codepoints(pin, len) < OMK_CTAP_MIN_PIN_LENGTH) {
        return OMK_CTAP2_ERR_PIN_POLICY_VIOLATION;
    }
    return OMK_CTAP2_OK;
}

static bool cose_to_pub(const omk_cbor_doc *doc, const omk_cbor_val *cose,
                        uint8_t pub[65]) {
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
    pub[0] = 0x04;
    memcpy(pub + 1, x->data, 32);
    memcpy(pub + 33, y->data, 32);
    /* ECDH validates the assembled point before scalar multiplication. */
    return true;
}

static void zero32(uint8_t out[32]) {
    memset(out, 0, 32);
}

static bool pin_derive_shared(omk_ctap *ct, const omk_cbor_doc *doc,
                              uint32_t protocol,
                              const omk_cbor_val *cose) {
    uint8_t pub[65];
    if (!cose_to_pub(doc, cose, pub)) {
        return false;
    }
    uint8_t shared[32];
    memset(shared, 0, sizeof shared);
    if (!omk_p256_ecdh(ct->pin.key_priv, pub, shared)) {
        omk_memzero(shared, sizeof shared);
        return false;
    }
    if (protocol == 1) {
        omk_sha256(shared, 32, ct->pin.shared_aes);
        memcpy(ct->pin.shared_hmac, ct->pin.shared_aes, 32);
    } else {
        uint8_t salt[32];
        zero32(salt);
        omk_hkdf_sha256(salt, 32, shared, 32, (const uint8_t *)"CTAP2 AES key",
                        13, ct->pin.shared_aes, 32);
        omk_hkdf_sha256(salt, 32, shared, 32, (const uint8_t *)"CTAP2 HMAC key",
                        14, ct->pin.shared_hmac, 32);
        omk_memzero(salt, sizeof salt);
    }
    ct->pin.protocol = (uint8_t)protocol;
    omk_memzero(shared, sizeof shared);
    return true;
}

/* Decrypt into a caller buffer only after proving that the ciphertext has
 * exactly the length the caller expects and that the plaintext fits. */
static bool pin_decrypt(omk_ctap *ct, const uint8_t *in, size_t in_len,
                        uint8_t *out, size_t out_cap, size_t expected) {
    if (expected == 0 || expected % 16 != 0 || expected > out_cap) {
        return false;
    }
    if (ct->pin.protocol == 1) {
        if (in_len != expected) {
            return false;
        }
        uint8_t iv[16] = {0};
        omk_aes256_cbc_decrypt(ct->pin.shared_aes, iv, in, in_len, out);
        return true;
    }
    if (in_len < 16 || in_len - 16 != expected) {
        return false;
    }
    omk_aes256_cbc_decrypt(ct->pin.shared_aes, in, in + 16, expected, out);
    return true;
}

static bool pin_encrypt(omk_ctap *ct, const uint8_t *in, size_t in_len,
                        uint8_t *out, size_t *out_len) {
    if (in_len % 16 != 0) {
        return false;
    }
    if (ct->pin.protocol == 1) {
        uint8_t iv[16] = {0};
        omk_aes256_cbc_encrypt(ct->pin.shared_aes, iv, in, in_len, out);
        *out_len = in_len;
        return true;
    }
    uint8_t iv[16];
    memset(iv, 0, sizeof iv);
    if (!ct->port->random_bytes(ct->port->ctx, iv, sizeof iv)) {
        omk_memzero(iv, sizeof iv);
        return false;
    }
    memcpy(out, iv, 16);
    omk_aes256_cbc_encrypt(ct->pin.shared_aes, iv, in, in_len, out + 16);
    omk_memzero(iv, sizeof iv);
    *out_len = in_len + 16;
    return true;
}

static size_t pin_auth_len(const omk_ctap *ct) {
    return ct->pin.protocol == 1 ? 16 : 32;
}

static bool pin_check_auth2(omk_ctap *ct, const uint8_t *param,
                            size_t param_len, const uint8_t *m1, size_t n1,
                            const uint8_t *m2, size_t n2) {
    uint8_t opad[64];
    uint8_t mac[32];
    omk_sha256_ctx inner;
    omk_hmac_sha256_init(&inner, opad, ct->pin.shared_hmac, 32);
    if (n1 != 0) {
        omk_hmac_sha256_update(&inner, m1, n1);
    }
    if (n2 != 0) {
        omk_hmac_sha256_update(&inner, m2, n2);
    }
    omk_hmac_sha256_final(&inner, opad, mac);
    const size_t n = pin_auth_len(ct);
    const bool ok = param_len == n && omk_ct_equal(mac, param, n);
    omk_memzero(mac, sizeof mac);
    return ok;
}

static bool pin_check_auth(omk_ctap *ct, const uint8_t *param,
                           size_t param_len, const uint8_t *msg,
                           size_t msg_len) {
    return pin_check_auth2(ct, param, param_len, msg, msg_len, NULL, 0);
}

static bool pin_unpad(const uint8_t *buf, size_t len, size_t *out_len) {
    size_t n = 0;
    while (n < len && buf[n] != 0) {
        n++;
    }
    for (size_t i = n; i < len; i++) {
        if (buf[i] != 0) {
            return false;
        }
    }
    *out_len = n;
    return true;
}

/* ---------------------------------------------------------------------- */
/* ClientPIN                                                               */
/* ---------------------------------------------------------------------- */

static uint8_t resp_empty(omk_ctap *ct) {
    /* setPIN/changePIN have no response parameters. */
    ct->response_len = 0;
    return OMK_CTAP2_OK;
}

static uint8_t sub_get_retries(omk_ctap *ct) {
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, ct->response, sizeof ct->response);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_uint(&e, ct->store.pin_retries);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bool(&e, ct->consecutive_pin_failures >= 3);
    ct->response_len = e.len;
    return e.overflow ? OMK_CTAP2_ERR_REQUEST_TOO_LARGE : OMK_CTAP2_OK;
}

/* The PIN/UV key agreement key is an ECDH-ES+HKDF-256 key (COSE alg -25),
 * never an ES256 credential key (-7).  The two key types share the EC2
 * encoding but not the algorithm identifier. */
static size_t build_key_agreement_cose(uint8_t *out, size_t cap,
                                       const uint8_t pub[65]) {
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, out, cap);
    omk_cbor_put_map(&e, 5);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 2); /* kty: EC2 */
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_nint(&e, -25); /* alg: ECDH-ES + HKDF-256 */
    omk_cbor_put_nint(&e, -1);
    omk_cbor_put_uint(&e, 1); /* crv: P-256 */
    omk_cbor_put_nint(&e, -2);
    omk_cbor_put_bytes(&e, pub + 1, 32);
    omk_cbor_put_nint(&e, -3);
    omk_cbor_put_bytes(&e, pub + 33, 32);
    return e.overflow ? 0 : e.len;
}

static uint8_t sub_get_key_agreement(omk_ctap *ct) {
    uint8_t cose[128];
    const size_t n = build_key_agreement_cose(cose, sizeof cose,
                                               ct->pin.key_pub);
    if (n == 0) {
        return OMK_CTAP2_ERR_OTHER;
    }
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, ct->response, sizeof ct->response);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_uint(&e, 1);
    for (size_t i = 0; i < n; i++) {
        /* Append the pre-encoded COSE key. */
        if (e.len >= e.cap) {
            e.overflow = true;
            break;
        }
        e.buf[e.len++] = cose[i];
    }
    ct->response_len = e.len;
    return e.overflow ? OMK_CTAP2_ERR_REQUEST_TOO_LARGE : OMK_CTAP2_OK;
}

static uint8_t sub_set_pin(omk_ctap *ct, const omk_cbor_doc *doc,
                           const omk_cbor_val *req, uint32_t protocol) {
    const omk_cbor_val *ka = omk_cbor_map_get_int(doc, req, 0x03);
    const omk_cbor_val *auth = omk_cbor_map_get_int(doc, req, 0x04);
    const omk_cbor_val *enc = omk_cbor_map_get_int(doc, req, 0x05);
    uint8_t plain[64] = {0};
    uint8_t hash[16] = {0};
    uint8_t status;

    if (ka == NULL || auth == NULL || enc == NULL) {
        return OMK_CTAP2_ERR_MISSING_PARAMETER;
    }
    if (auth->type != OMK_CBOR_BYTES || enc->type != OMK_CBOR_BYTES) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    if (ct->store.pin_set) {
        return OMK_CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (!pin_derive_shared(ct, doc, protocol, ka)) {
        return OMK_CTAP1_ERR_INVALID_PARAMETER;
    }
    if (!pin_check_auth(ct, auth->data, auth->len, enc->data, enc->len)) {
        return OMK_CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (!pin_decrypt(ct, enc->data, enc->len, plain, sizeof plain,
                     sizeof plain)) {
        status = OMK_CTAP1_ERR_INVALID_PARAMETER;
        goto done;
    }
    size_t pin_len = 0;
    if (!pin_unpad(plain, sizeof plain, &pin_len)) {
        status = OMK_CTAP1_ERR_INVALID_PARAMETER;
        goto done;
    }
    status = pin_check_policy(plain, pin_len);
    if (status == OMK_CTAP2_OK) {
        pin_hash(plain, pin_len, hash);
        if (omk_store_set_pin(&ct->store, hash) != 0) {
            status = OMK_CTAP2_ERR_OTHER;
            goto done;
        }
        ct->consecutive_pin_failures = 0;
        omk_ctap_puat_invalidate(ct);
        status = resp_empty(ct);
    }

done:
    omk_memzero(plain, sizeof plain);
    omk_memzero(hash, sizeof hash);
    return status;
}

static uint8_t sub_change_pin(omk_ctap *ct, const omk_cbor_doc *doc,
                              const omk_cbor_val *req, uint32_t protocol) {
    const omk_cbor_val *ka = omk_cbor_map_get_int(doc, req, 0x03);
    const omk_cbor_val *auth = omk_cbor_map_get_int(doc, req, 0x04);
    const omk_cbor_val *enc = omk_cbor_map_get_int(doc, req, 0x05);
    const omk_cbor_val *cur = omk_cbor_map_get_int(doc, req, 0x06);
    uint8_t current[32] = {0};
    uint8_t plain[64] = {0};
    uint8_t hash[16] = {0};
    uint8_t status;

    if (ka == NULL || auth == NULL || enc == NULL || cur == NULL) {
        return OMK_CTAP2_ERR_MISSING_PARAMETER;
    }
    if (auth->type != OMK_CBOR_BYTES || enc->type != OMK_CBOR_BYTES ||
        cur->type != OMK_CBOR_BYTES) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    if (!ct->store.pin_set) {
        return OMK_CTAP2_ERR_PIN_NOT_SET;
    }
    if (!pin_derive_shared(ct, doc, protocol, ka)) {
        return OMK_CTAP1_ERR_INVALID_PARAMETER;
    }
    /* Authenticate the concatenated ciphertext before looking at its shape.
     * Verify it incrementally so an oversized parameter is still checked
     * without a scratch buffer and then rejected as an invalid parameter. */
    if (!pin_check_auth2(ct, auth->data, auth->len, enc->data, enc->len,
                         cur->data, cur->len)) {
        return OMK_CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (!pin_decrypt(ct, cur->data, cur->len, current, sizeof current, 16)) {
        status = OMK_CTAP1_ERR_INVALID_PARAMETER;
        goto done;
    }
    status = pin_verify_hash(ct, current);
    if (status != OMK_CTAP2_OK) {
        goto done;
    }
    if (!pin_decrypt(ct, enc->data, enc->len, plain, sizeof plain,
                     sizeof plain)) {
        status = OMK_CTAP1_ERR_INVALID_PARAMETER;
        goto done;
    }
    size_t pin_len = 0;
    if (!pin_unpad(plain, sizeof plain, &pin_len)) {
        status = OMK_CTAP1_ERR_INVALID_PARAMETER;
        goto done;
    }
    status = pin_check_policy(plain, pin_len);
    if (status == OMK_CTAP2_OK) {
        pin_hash(plain, pin_len, hash);
        if (omk_store_set_pin(&ct->store, hash) != 0) {
            status = OMK_CTAP2_ERR_OTHER;
            goto done;
        }
        ct->consecutive_pin_failures = 0;
        omk_ctap_puat_invalidate(ct);
        status = resp_empty(ct);
    }

done:
    omk_memzero(current, sizeof current);
    omk_memzero(plain, sizeof plain);
    omk_memzero(hash, sizeof hash);
    return status;
}

static uint8_t issue_token(omk_ctap *ct, uint8_t permissions,
                           const uint8_t *rp_id, size_t rp_id_len) {
    uint8_t token[32] = {0};
    uint8_t enc[64] = {0};
    size_t enc_len = 0;
    uint8_t status = OMK_CTAP2_ERR_OTHER;

    /* A failed issuance must not leave the previous token usable. */
    omk_ctap_puat_invalidate(ct);

    if (!ct->port->random_bytes(ct->port->ctx, token, sizeof token)) {
        goto done;
    }
    if (!pin_encrypt(ct, token, sizeof token, enc, &enc_len)) {
        goto done;
    }

    memcpy(ct->pin.token, token, sizeof token);
    ct->pin.token_valid = true;
    ct->pin.permissions = permissions;
    ct->pin.user_verified = true;
    ct->pin.created_ms = omk_ctap_now_ms(ct);
    ct->pin.used_once = false;
    if (rp_id != NULL) {
        omk_sha256(rp_id, rp_id_len, ct->pin.rp_hash);
        ct->pin.rp_bound = true;
    } else {
        omk_memzero(ct->pin.rp_hash, sizeof ct->pin.rp_hash);
        ct->pin.rp_bound = false;
    }

    omk_cbor_enc e;
    omk_cbor_enc_init(&e, ct->response, sizeof ct->response);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_bytes(&e, enc, enc_len);
    ct->response_len = e.len;
    status = e.overflow ? OMK_CTAP2_ERR_REQUEST_TOO_LARGE : OMK_CTAP2_OK;

done:
    omk_memzero(token, sizeof token);
    omk_memzero(enc, sizeof enc);
    return status;
}

static uint8_t sub_get_token(omk_ctap *ct, const omk_cbor_doc *doc,
                             const omk_cbor_val *req, uint32_t protocol) {
    /* getPinToken predates the permissions/rpId parameters; a client that
     * sends them is using the wrong subcommand and must not silently get a
     * token with unintended scope. */
    if (omk_cbor_map_get_int(doc, req, 0x09) != NULL ||
        omk_cbor_map_get_int(doc, req, 0x0A) != NULL) {
        return OMK_CTAP1_ERR_INVALID_PARAMETER;
    }
    const omk_cbor_val *ka = omk_cbor_map_get_int(doc, req, 0x03);
    const omk_cbor_val *enc = omk_cbor_map_get_int(doc, req, 0x06);
    if (ka == NULL || enc == NULL) {
        return OMK_CTAP2_ERR_MISSING_PARAMETER;
    }
    if (enc->type != OMK_CBOR_BYTES) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    if (!ct->store.pin_set) {
        return OMK_CTAP2_ERR_PIN_NOT_SET;
    }
    if (!pin_derive_shared(ct, doc, protocol, ka)) {
        return OMK_CTAP1_ERR_INVALID_PARAMETER;
    }
    uint8_t plain[32] = {0};
    if (!pin_decrypt(ct, enc->data, enc->len, plain, sizeof plain, 16)) {
        omk_memzero(plain, sizeof plain);
        return OMK_CTAP1_ERR_INVALID_PARAMETER;
    }
    const uint8_t status = pin_verify_hash(ct, plain);
    omk_memzero(plain, sizeof plain);
    if (status != OMK_CTAP2_OK) {
        return status;
    }
    return issue_token(ct, OMK_PERM_MC | OMK_PERM_GA, NULL, 0);
}

static uint8_t sub_get_token_permissions(omk_ctap *ct,
                                         const omk_cbor_doc *doc,
                                         const omk_cbor_val *req,
                                         uint32_t protocol) {
    const omk_cbor_val *ka = omk_cbor_map_get_int(doc, req, 0x03);
    const omk_cbor_val *enc = omk_cbor_map_get_int(doc, req, 0x06);
    const omk_cbor_val *perm = omk_cbor_map_get_int(doc, req, 0x09);
    const omk_cbor_val *rp = omk_cbor_map_get_int(doc, req, 0x0A);
    if (ka == NULL || enc == NULL || perm == NULL) {
        return OMK_CTAP2_ERR_MISSING_PARAMETER;
    }
    if (enc->type != OMK_CBOR_BYTES) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    uint32_t permissions = 0;
    if (!omk_ctap_val_uint(perm, &permissions)) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    if (permissions == 0) {
        return OMK_CTAP1_ERR_INVALID_PARAMETER;
    }
    if ((permissions & ~(OMK_PERM_MC | OMK_PERM_GA | OMK_PERM_CM)) != 0) {
        return OMK_CTAP2_ERR_UNAUTHORIZED_PERMISSION;
    }
    const uint8_t *rp_id = NULL;
    size_t rp_len = 0;
    if (rp != NULL) {
        if (!omk_ctap_val_text(rp, &rp_id, &rp_len) || rp_len == 0 ||
            rp_len > OMK_RP_ID_MAX) {
            return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
    }
    if ((permissions & (OMK_PERM_MC | OMK_PERM_GA)) != 0 && rp_id == NULL) {
        return OMK_CTAP2_ERR_MISSING_PARAMETER;
    }
    if (!ct->store.pin_set) {
        return OMK_CTAP2_ERR_PIN_NOT_SET;
    }
    if (!pin_derive_shared(ct, doc, protocol, ka)) {
        return OMK_CTAP1_ERR_INVALID_PARAMETER;
    }
    uint8_t plain[32] = {0};
    if (!pin_decrypt(ct, enc->data, enc->len, plain, sizeof plain, 16)) {
        omk_memzero(plain, sizeof plain);
        return OMK_CTAP1_ERR_INVALID_PARAMETER;
    }
    const uint8_t status = pin_verify_hash(ct, plain);
    omk_memzero(plain, sizeof plain);
    if (status != OMK_CTAP2_OK) {
        return status;
    }
    return issue_token(ct, (uint8_t)permissions, rp_id, rp_len);
}

uint8_t omk_ctap_cmd_clientpin(omk_ctap *ct, const omk_cbor_doc *doc,
                               const omk_cbor_val *req, uint32_t cid) {
    (void)cid;
    const omk_cbor_val *sub = omk_cbor_map_get_int(doc, req, 0x02);
    uint32_t subcommand = 0;
    if (!omk_ctap_val_uint(sub, &subcommand)) {
        return sub == NULL ? OMK_CTAP2_ERR_MISSING_PARAMETER
                           : OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    uint32_t protocol = 1;
    const omk_cbor_val *pv = omk_cbor_map_get_int(doc, req, 0x01);
    if (pv == NULL && omk_cbor_map_get_int(doc, req, 0x04) != NULL) {
        return OMK_CTAP2_ERR_MISSING_PARAMETER;
    }
    if (pv != NULL && !omk_ctap_val_uint(pv, &protocol)) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    if (protocol != 1 && protocol != 2) {
        return OMK_CTAP1_ERR_INVALID_PARAMETER;
    }

    switch (subcommand) {
    case 0x01:
        return sub_get_retries(ct);
    case 0x02:
        return sub_get_key_agreement(ct);
    case 0x03:
        return sub_set_pin(ct, doc, req, protocol);
    case 0x04:
        return sub_change_pin(ct, doc, req, protocol);
    case 0x05:
        return sub_get_token(ct, doc, req, protocol);
    case 0x09:
        return sub_get_token_permissions(ct, doc, req, protocol);
    case 0x06:
    case 0x07:
    default:
        return OMK_CTAP2_ERR_INVALID_SUBCOMMAND;
    }
}
