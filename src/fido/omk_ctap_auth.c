#include <string.h>

#include "crypto/omk_crypto.h"
#include "fido/omk_cbor.h"
#include "fido/omk_ctap_internal.h"

#define AUTH_FLAG_UP 0x01
#define AUTH_FLAG_UV 0x04
#define AUTH_FLAG_AT 0x40
#define AUTH_FLAG_ED 0x80

/* ---------------------------------------------------------------------- */
/* Credential keys                                                         */
/* ---------------------------------------------------------------------- */

bool omk_ctap_cred_public_key(uint8_t alg, const uint8_t seed[32],
                              uint8_t pub[65], size_t *pub_len) {
    if (alg == OMK_ALG_ES256) {
        omk_p256_keypair kp;
        memset(&kp, 0, sizeof kp);
        if (!omk_p256_keypair_from_scalar(seed, &kp)) {
            omk_memzero(&kp, sizeof kp);
            return false;
        }
        memcpy(pub, kp.pub, 65);
        omk_memzero(&kp, sizeof kp);
        *pub_len = 65;
        return true;
    }
    if (alg == OMK_ALG_EDDSA) {
        memset(pub, 0, 65);
        if (!omk_ed25519_public_from_seed(seed, pub)) {
            return false;
        }
        *pub_len = 32;
        return true;
    }
    return false;
}

bool omk_ctap_sign(omk_ctap *ct, uint8_t alg, const uint8_t seed[32],
                   const uint8_t *data, size_t len, uint8_t *sig,
                   size_t *sig_len) {
    (void)ct;
    if (alg == OMK_ALG_ES256) {
        uint8_t hash[32];
        omk_sha256(data, len, hash);
        if (!omk_p256_ecdsa_sign(seed, hash, sig, NULL, NULL)) {
            return false;
        }
        *sig_len = 64;
        return true;
    }
    if (alg == OMK_ALG_EDDSA) {
        if (!omk_ed25519_sign(seed, data, len, sig)) {
            return false;
        }
        *sig_len = 64;
        return true;
    }
    return false;
}

/* ---------------------------------------------------------------------- */
/* hmac-secret                                                             */
/* ---------------------------------------------------------------------- */

bool omk_ctap_hmac_secret_output(const omk_ctap *ct, const uint8_t seed[32],
                                 bool uv, const uint8_t *salt, size_t salt_len,
                                 uint8_t *out, size_t *out_len) {
    (void)ct;
    if (salt_len != 32 && salt_len != 64) {
        return false;
    }
    static const char info_base[] = "OMK hmac-secret v1";
    uint8_t info[19];
    memcpy(info, info_base, sizeof info_base - 1);
    info[18] = uv ? 1 : 0;
    uint8_t cred_random[32];
    omk_hkdf_sha256(NULL, 0, seed, 32, info, sizeof info, cred_random, 32);

    if (salt_len == 32) {
        omk_hmac_sha256(cred_random, 32, salt, 32, out);
        *out_len = 32;
    } else {
        omk_hmac_sha256(cred_random, 32, salt, 32, out);
        omk_hmac_sha256(cred_random, 32, salt + 32, 32, out + 32);
        *out_len = 64;
    }
    omk_memzero(cred_random, sizeof cred_random);
    return true;
}

static bool ext_shared(omk_ctap *ct, const omk_cbor_doc *doc,
                       const omk_cbor_val *cose, uint32_t protocol,
                       uint8_t aes[32], uint8_t hmac[32]) {
    memset(aes, 0, 32);
    memset(hmac, 0, 32);
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
    if (!omk_p256_point_valid(pub)) {
        return false;
    }
    uint8_t shared[32];
    memset(shared, 0, sizeof shared);
    if (!omk_p256_ecdh(ct->pin.key_priv, pub, shared)) {
        omk_memzero(shared, sizeof shared);
        memset(aes, 0, 32);
        memset(hmac, 0, 32);
        return false;
    }
    if (protocol == 1) {
        omk_sha256(shared, 32, aes);
        memcpy(hmac, aes, 32);
    } else {
        uint8_t salt[32] = {0};
        omk_hkdf_sha256(salt, 32, shared, 32, (const uint8_t *)"CTAP2 AES key",
                        13, aes, 32);
        omk_hkdf_sha256(salt, 32, shared, 32, (const uint8_t *)"CTAP2 HMAC key",
                        14, hmac, 32);
    }
    omk_memzero(shared, sizeof shared);
    return true;
}

/* hmac-secret accepts only 32- or 64-byte plaintexts.  Reject every other
 * ciphertext shape before touching the caller's output buffer. */
static bool ext_decrypt(const uint8_t aes[32], uint32_t protocol,
                        const uint8_t *in, size_t in_len, uint8_t *out,
                        size_t out_cap, size_t *out_len) {
    if (protocol == 1) {
        if ((in_len != 32 && in_len != 64) || in_len > out_cap) {
            return false;
        }
        uint8_t iv[16] = {0};
        omk_aes256_cbc_decrypt(aes, iv, in, in_len, out);
        *out_len = in_len;
        return true;
    }
    if (in_len < 16) {
        return false;
    }
    const size_t plain_len = in_len - 16;
    if ((plain_len != 32 && plain_len != 64) || plain_len > out_cap) {
        return false;
    }
    omk_aes256_cbc_decrypt(aes, in, in + 16, plain_len, out);
    *out_len = plain_len;
    return true;
}

static bool ext_encrypt(const omk_port *port, const uint8_t aes[32],
                        uint32_t protocol, const uint8_t *in, size_t in_len,
                        uint8_t *out, size_t *out_len) {
    if (in_len % 16 != 0) {
        return false;
    }
    if (protocol == 1) {
        uint8_t iv[16] = {0};
        omk_aes256_cbc_encrypt(aes, iv, in, in_len, out);
        *out_len = in_len;
        return true;
    }
    uint8_t iv[16];
    memset(iv, 0, sizeof iv);
    if (!port->random_bytes(port->ctx, iv, sizeof iv)) {
        omk_memzero(iv, sizeof iv);
        return false;
    }
    memcpy(out, iv, 16);
    omk_aes256_cbc_encrypt(aes, iv, in, in_len, out + 16);
    omk_memzero(iv, sizeof iv);
    *out_len = in_len + 16;
    return true;
}

static uint8_t ext_parse_request(omk_ctap *ct, const omk_cbor_doc *doc,
                                 const omk_cbor_val *ext, uint8_t *salt,
                                 size_t salt_cap, size_t *salt_len,
                                 uint8_t aes[32], uint8_t hmac[32],
                                 uint32_t *protocol) {
    const omk_cbor_val *ka = omk_cbor_map_get_int(doc, ext, 0x01);
    const omk_cbor_val *salt_enc = omk_cbor_map_get_int(doc, ext, 0x02);
    const omk_cbor_val *salt_auth = omk_cbor_map_get_int(doc, ext, 0x03);
    const omk_cbor_val *proto = omk_cbor_map_get_int(doc, ext, 0x04);
    if (ka == NULL || salt_enc == NULL || salt_auth == NULL) {
        return OMK_CTAP2_ERR_MISSING_PARAMETER;
    }
    if (salt_enc->type != OMK_CBOR_BYTES || salt_auth->type != OMK_CBOR_BYTES) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    uint32_t p = 1;
    if (proto != NULL) {
        if (!omk_ctap_val_uint(proto, &p)) {
            return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
    }
    if (p != 1 && p != 2) {
        return OMK_CTAP1_ERR_INVALID_PARAMETER;
    }
    if (salt_auth->len != (p == 1 ? 16u : 32u)) {
        return OMK_CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (!ext_shared(ct, doc, ka, p, aes, hmac)) {
        return OMK_CTAP1_ERR_INVALID_PARAMETER;
    }
    uint8_t mac[32];
    omk_hmac_sha256(hmac, 32, salt_enc->data, salt_enc->len, mac);
    const bool auth_ok = omk_ct_equal(mac, salt_auth->data, salt_auth->len);
    omk_memzero(mac, sizeof mac);
    if (!auth_ok) {
        return OMK_CTAP2_ERR_PIN_AUTH_INVALID;
    }
    size_t plain_len = 0;
    if (!ext_decrypt(aes, p, salt_enc->data, salt_enc->len, salt, salt_cap,
                     &plain_len)) {
        /* The authenticator has already verified saltAuth, so a ciphertext
         * that does not decrypt to exactly 32 or 64 bytes is a malformed
         * parameter rather than an authentication failure. */
        return OMK_CTAP1_ERR_INVALID_PARAMETER;
    }
    if (plain_len != 32 && plain_len != 64) {
        return OMK_CTAP1_ERR_INVALID_PARAMETER;
    }
    *salt_len = plain_len;
    *protocol = p;
    return OMK_CTAP2_OK;
}

/* ---------------------------------------------------------------------- */
/* Parsing helpers                                                         */
/* ---------------------------------------------------------------------- */

static uint8_t parse_rp(const omk_cbor_doc *doc, const omk_cbor_val *rp,
                        const uint8_t **id, size_t *id_len) {
    if (rp == NULL) {
        return OMK_CTAP2_ERR_MISSING_PARAMETER;
    }
    if (rp->type != OMK_CBOR_MAP) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    const omk_cbor_val *vid = omk_cbor_map_get_text(doc, rp, "id", 2);
    if (vid == NULL) {
        return OMK_CTAP2_ERR_MISSING_PARAMETER;
    }
    if (!omk_ctap_val_text(vid, id, id_len) || *id_len == 0 ||
        *id_len > OMK_RP_ID_MAX) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    return OMK_CTAP2_OK;
}

static uint8_t parse_user(const omk_cbor_doc *doc, const omk_cbor_val *user,
                          const uint8_t **id, size_t *id_len,
                          const uint8_t **name, size_t *name_len,
                          const uint8_t **display, size_t *display_len) {
    if (user == NULL) {
        return OMK_CTAP2_ERR_MISSING_PARAMETER;
    }
    if (user->type != OMK_CBOR_MAP) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    const omk_cbor_val *vid = omk_cbor_map_get_text(doc, user, "id", 2);
    if (vid == NULL) {
        return OMK_CTAP2_ERR_MISSING_PARAMETER;
    }
    if (!omk_ctap_val_bytes(vid, id, id_len) || *id_len == 0 ||
        *id_len > OMK_USER_ID_MAX) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    *name = NULL;
    *name_len = 0;
    *display = NULL;
    *display_len = 0;
    const omk_cbor_val *vname = omk_cbor_map_get_text(doc, user, "name", 4);
    if (vname != NULL) {
        if (!omk_ctap_val_text(vname, name, name_len) ||
            *name_len > OMK_USER_NAME_MAX) {
            return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
    }
    const omk_cbor_val *vdisp =
        omk_cbor_map_get_text(doc, user, "displayName", 11);
    if (vdisp != NULL) {
        if (!omk_ctap_val_text(vdisp, display, display_len) ||
            *display_len > OMK_USER_NAME_MAX) {
            return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
    }
    return OMK_CTAP2_OK;
}

static uint8_t parse_options(const omk_cbor_doc *doc, const omk_cbor_val *opt,
                             bool *rk, bool *up, bool *uv) {
    *rk = false;
    *up = true;
    *uv = false;
    if (opt == NULL) {
        return OMK_CTAP2_OK;
    }
    if (opt->type != OMK_CBOR_MAP) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    const char *keys[] = {"rk", "up", "uv"};
    bool *slots[] = {rk, up, uv};
    for (size_t i = 0; i < 3; i++) {
        const omk_cbor_val *v =
            omk_cbor_map_get_text(doc, opt, keys[i], strlen(keys[i]));
        if (v == NULL) {
            continue;
        }
        if (v->type != OMK_CBOR_BOOL) {
            return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        *slots[i] = v->boolean;
    }
    return OMK_CTAP2_OK;
}

static uint8_t parse_cred_protect(const omk_cbor_doc *doc,
                                  const omk_cbor_val *ext, uint8_t *out,
                                  bool *requested) {
    *out = 1;
    *requested = false;
    if (ext == NULL) {
        return OMK_CTAP2_OK;
    }
    if (ext->type != OMK_CBOR_MAP) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    const omk_cbor_val *cp = omk_cbor_map_get_text(doc, ext, "credProtect", 11);
    if (cp == NULL) {
        return OMK_CTAP2_OK;
    }
    *requested = true;
    uint32_t v = 0;
    if (!omk_ctap_val_uint(cp, &v)) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    if (v < 1 || v > 3) {
        return OMK_CTAP1_ERR_INVALID_PARAMETER;
    }
    *out = (uint8_t)v;
    return OMK_CTAP2_OK;
}

static uint8_t choose_algorithm(const omk_cbor_doc *doc,
                                const omk_cbor_val *params, uint8_t *alg) {
    if (params == NULL) {
        return OMK_CTAP2_ERR_MISSING_PARAMETER;
    }
    if (params->type != OMK_CBOR_ARRAY || params->count == 0) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    for (uint16_t i = 0; i < params->count; i++) {
        const omk_cbor_val *p = omk_cbor_array_get(doc, params, i);
        if (p == NULL || p->type != OMK_CBOR_MAP) {
            return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        const omk_cbor_val *a = omk_cbor_map_get_text(doc, p, "alg", 3);
        const omk_cbor_val *t = omk_cbor_map_get_text(doc, p, "type", 4);
        /* Every parameter must name the credential type.  A missing required
         * member is MISSING_PARAMETER; a known member with the wrong CBOR
         * type is CBOR_UNEXPECTED_TYPE.  Text values we do not implement are
         * skipped so a later supported entry can still win. */
        if (t == NULL) {
            return OMK_CTAP2_ERR_MISSING_PARAMETER;
        }
        if (t->type != OMK_CBOR_TEXT) {
            return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        if (t->len != 10 || memcmp(t->data, "public-key", 10) != 0) {
            continue;
        }
        if (a == NULL) {
            return OMK_CTAP2_ERR_MISSING_PARAMETER;
        }
        if (a->type != OMK_CBOR_NINT && a->type != OMK_CBOR_UINT) {
            return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        if (a->num == -7) {
            *alg = OMK_ALG_ES256;
            return OMK_CTAP2_OK;
        }
        if (a->num == -8) {
            *alg = OMK_ALG_EDDSA;
            return OMK_CTAP2_OK;
        }
    }
    return OMK_CTAP2_ERR_UNSUPPORTED_ALGORITHM;
}

/* ---------------------------------------------------------------------- */
/* Credential matching                                                     */
/* ---------------------------------------------------------------------- */

typedef struct {
    uint8_t seed[32];
    uint8_t alg;
    uint8_t cred_protect;
    bool resident;
    const omk_credential *record;
} match_t;

static bool match_descriptor(omk_ctap *ct, const omk_cbor_doc *doc,
                             const omk_cbor_val *desc,
                             const uint8_t rp_hash[32], bool uv, match_t *out) {
    if (desc == NULL || desc->type != OMK_CBOR_MAP) {
        return false;
    }
    const omk_cbor_val *idv = omk_cbor_map_get_text(doc, desc, "id", 2);
    const omk_cbor_val *type = omk_cbor_map_get_text(doc, desc, "type", 4);
    if (idv == NULL || idv->type != OMK_CBOR_BYTES || idv->len == 0 ||
        idv->len > OMK_CRED_ID_MAX) {
        return false;
    }
    if (type != NULL &&
        (type->type != OMK_CBOR_TEXT || type->len != 10 ||
         memcmp(type->data, "public-key", 10) != 0)) {
        return false;
    }

    const omk_credential *rec = omk_store_find_id(&ct->store, idv->data,
                                                   idv->len);
    if (rec != NULL) {
        if (memcmp(rec->rp_id_hash, rp_hash, 32) != 0) {
            return false;
        }
        if (rec->cred_protect >= 3 && !uv) {
            return false;
        }
        if (!omk_store_open_credential(&ct->store, rp_hash, rec->id,
                                       rec->id_len, out->seed, &out->alg,
                                       &out->cred_protect, &out->resident)) {
            return false;
        }
        out->record = rec;
        return true;
    }

    uint8_t alg = 0, cp = 0;
    bool resident = false;
    if (!omk_store_open_credential(&ct->store, rp_hash, idv->data, idv->len,
                                   out->seed, &alg, &cp, &resident)) {
        return false;
    }
    if (resident) {
        /* Deleted resident credential: the self-contained ID alone is not
         * sufficient (CTAP 2.3 §6.1.3). */
        return false;
    }
    if (cp >= 3 && !uv) {
        return false;
    }
    out->alg = alg;
    out->cred_protect = cp;
    out->resident = false;
    out->record = NULL;
    return true;
}

static bool excluded(omk_ctap *ct, const omk_cbor_doc *doc,
                     const omk_cbor_val *list, const uint8_t rp_hash[32],
                     bool uv) {
    if (list == NULL || list->type != OMK_CBOR_ARRAY) {
        return false;
    }
    for (uint16_t i = 0; i < list->count; i++) {
        match_t m;
        memset(&m, 0, sizeof m);
        const bool matched =
            match_descriptor(ct, doc, omk_cbor_array_get(doc, list, i),
                             rp_hash, uv, &m);
        omk_memzero(&m, sizeof m);
        if (matched) {
            return true;
        }
    }
    return false;
}

/* ---------------------------------------------------------------------- */
/* MakeCredential                                                          */
/* ---------------------------------------------------------------------- */

static bool makecred_rng(void *ctx, void *out, size_t len) {
    omk_ctap *ct = (omk_ctap *)ctx;
    return ct->port->random_bytes(ct->port->ctx, out, len);
}

static uint8_t build_mc_ext_map(uint8_t *out, size_t cap, bool hmac_bool,
                                const uint8_t *hmac_mc, size_t hmac_mc_len,
                                bool cred_protect_requested,
                                uint8_t cred_protect) {
    if (!hmac_bool && hmac_mc_len == 0 && !cred_protect_requested) {
        return 0;
    }
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, out, cap);
    const size_t pairs = (hmac_bool ? 1u : 0u) +
                         (hmac_mc_len != 0 ? 1u : 0u) +
                         (cred_protect_requested ? 1u : 0u);
    omk_cbor_put_map(&e, pairs);
    if (cred_protect_requested) {
        omk_cbor_put_text(&e, "credProtect", 11);
        omk_cbor_put_uint(&e, cred_protect);
    }
    if (hmac_bool) {
        omk_cbor_put_text(&e, "hmac-secret", 11);
        omk_cbor_put_bool(&e, true);
    }
    if (hmac_mc_len != 0) {
        omk_cbor_put_text(&e, "hmac-secret-mc", 14);
        omk_cbor_put_bytes(&e, hmac_mc, hmac_mc_len);
    }
    return e.overflow ? 0 : (uint8_t)e.len;
}

uint8_t omk_ctap_cmd_makecredential(omk_ctap *ct, const omk_cbor_doc *doc,
                                    const omk_cbor_val *req, uint32_t cid) {
    (void)cid;
    const omk_cbor_val *cdh = omk_cbor_map_get_int(doc, req, 0x01);
    const omk_cbor_val *rpv = omk_cbor_map_get_int(doc, req, 0x02);
    const omk_cbor_val *userv = omk_cbor_map_get_int(doc, req, 0x03);
    const omk_cbor_val *paramsv = omk_cbor_map_get_int(doc, req, 0x04);
    const omk_cbor_val *exclude = omk_cbor_map_get_int(doc, req, 0x05);
    const omk_cbor_val *extv = omk_cbor_map_get_int(doc, req, 0x06);
    const omk_cbor_val *optv = omk_cbor_map_get_int(doc, req, 0x07);

    const uint8_t *client_data_hash = NULL;
    size_t cdh_len = 0;
    if (cdh == NULL) {
        return OMK_CTAP2_ERR_MISSING_PARAMETER;
    }
    if (!omk_ctap_val_bytes(cdh, &client_data_hash, &cdh_len) || cdh_len != 32) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    const uint8_t *rp_id = NULL;
    size_t rp_id_len = 0;
    uint8_t status = parse_rp(doc, rpv, &rp_id, &rp_id_len);
    if (status != OMK_CTAP2_OK) {
        return status;
    }
    const uint8_t *user_id = NULL, *user_name = NULL, *display = NULL;
    size_t user_id_len = 0, user_name_len = 0, display_len = 0;
    status = parse_user(doc, userv, &user_id, &user_id_len, &user_name,
                        &user_name_len, &display, &display_len);
    if (status != OMK_CTAP2_OK) {
        return status;
    }
    uint8_t alg = 0;
    status = choose_algorithm(doc, paramsv, &alg);
    if (status != OMK_CTAP2_OK) {
        return status;
    }
    bool rk = false, up = true, uv_opt = false;
    status = parse_options(doc, optv, &rk, &up, &uv_opt);
    if (status != OMK_CTAP2_OK) {
        return status;
    }
    if (!up || uv_opt) {
        return OMK_CTAP2_ERR_INVALID_OPTION;
    }
    uint8_t cred_protect = 1;
    bool cred_protect_requested = false;
    status = parse_cred_protect(doc, extv, &cred_protect,
                                &cred_protect_requested);
    if (status != OMK_CTAP2_OK) {
        return status;
    }
    uint8_t rp_hash[32];
    omk_sha256(rp_id, rp_id_len, rp_hash);

    /* Validate the extension envelope and the hmac-secret-mc dependency
     * before any user interaction or credential creation. */
    bool hmac_bool = false;
    const omk_cbor_val *mc_ext = NULL;
    if (extv != NULL) {
        if (extv->type != OMK_CBOR_MAP) {
            return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        const omk_cbor_val *hs =
            omk_cbor_map_get_text(doc, extv, "hmac-secret", 11);
        if (hs != NULL) {
            if (hs->type != OMK_CBOR_BOOL) {
                return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            hmac_bool = hs->boolean;
        }
        mc_ext = omk_cbor_map_get_text(doc, extv, "hmac-secret-mc", 14);
        if (mc_ext != NULL && !hmac_bool) {
            return OMK_CTAP2_ERR_MISSING_PARAMETER;
        }
    }

    bool token_uv = false;
    const omk_cbor_val *pin_param = omk_cbor_map_get_int(doc, req, 0x08);
    if (pin_param != NULL) {
        uint32_t pin_protocol = 0;
        const omk_cbor_val *ppv = omk_cbor_map_get_int(doc, req, 0x09);
        if (ppv == NULL) {
            return OMK_CTAP2_ERR_MISSING_PARAMETER;
        }
        if (!omk_ctap_val_uint(ppv, &pin_protocol)) {
            return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        status = omk_ctap_authorize_raw(ct, pin_param, pin_protocol,
                                        client_data_hash, 32, OMK_PERM_MC,
                                        rp_hash, &token_uv);
        if (status == OMK_CTAP_PIN_PROBE) {
            const uint8_t up_status = omk_ctap_wait_up(ct);
            if (up_status == OMK_CTAP_ABORTED) {
                return OMK_CTAP_ABORTED;
            }
            if (up_status != OMK_CTAP2_OK) {
                return up_status;
            }
            omk_ctap_consume_up(ct);
            return ct->store.pin_set ? OMK_CTAP2_ERR_PIN_INVALID
                                     : OMK_CTAP2_ERR_PIN_NOT_SET;
        }
        if (status != OMK_CTAP2_OK) {
            return status;
        }
    } else if (ct->store.pin_set && rk) {
        return OMK_CTAP2_ERR_PIN_REQUIRED;
    }

    if (excluded(ct, doc, exclude, rp_hash, token_uv)) {
        const uint8_t up_status = omk_ctap_wait_up(ct);
        if (up_status == OMK_CTAP_ABORTED) {
            return OMK_CTAP_ABORTED;
        }
        /* The exclusion decision is already final; a missing touch must not
         * turn it into a user-action timeout. */
        if (up_status == OMK_CTAP2_ERR_USER_ACTION_TIMEOUT) {
            return OMK_CTAP2_ERR_CREDENTIAL_EXCLUDED;
        }
        if (up_status != OMK_CTAP2_OK) {
            return up_status;
        }
        omk_ctap_consume_up(ct);
        return OMK_CTAP2_ERR_CREDENTIAL_EXCLUDED;
    }

    {
        const uint8_t up_status = omk_ctap_wait_up(ct);
        if (up_status == OMK_CTAP_ABORTED) {
            return OMK_CTAP_ABORTED;
        }
        if (up_status != OMK_CTAP2_OK) {
            return up_status;
        }
    }
    omk_ctap_consume_up(ct);
    const bool uv_done = token_uv;

    uint8_t seed[32] = {0};
    uint8_t pub[65] = {0};
    uint8_t cred_id[OMK_CRED_ID_MAX] = {0};
    size_t cred_id_len = 0;
    uint8_t hmac_mc[128] = {0};
    size_t hmac_mc_len = 0;
    uint8_t hmac_salt[64] = {0};
    uint8_t hmac_aes[32] = {0};
    uint8_t hmac_key[32] = {0};
    uint8_t hs_out[64] = {0};
    uint8_t ext_data[200] = {0};
    size_t ext_len = 0;

    if (alg == OMK_ALG_ES256) {
        omk_p256_keypair kp;
        memset(&kp, 0, sizeof kp);
        if (!omk_p256_keygen(makecred_rng, ct, &kp)) {
            omk_memzero(&kp, sizeof kp);
            status = OMK_CTAP2_ERR_OTHER;
            goto done;
        }
        memcpy(seed, kp.d, 32);
        memcpy(pub, kp.pub, 65);
        omk_memzero(&kp, sizeof kp);
    } else {
        if (!ct->port->random_bytes(ct->port->ctx, seed, 32)) {
            status = OMK_CTAP2_ERR_OTHER;
            goto done;
        }
        if (!omk_ed25519_public_from_seed(seed, pub)) {
            status = OMK_CTAP2_ERR_OTHER;
            goto done;
        }
    }

    cred_id_len = omk_store_seal_credential(
        &ct->store, rp_hash, seed, alg, cred_protect, rk, cred_id);
    if (cred_id_len == 0) {
        status = OMK_CTAP2_ERR_OTHER;
        goto done;
    }

    if (mc_ext != NULL) {
        size_t salt_len = 0;
        uint32_t protocol = 1;
        status = ext_parse_request(ct, doc, mc_ext, hmac_salt,
                                   sizeof hmac_salt, &salt_len, hmac_aes,
                                   hmac_key, &protocol);
        if (status != OMK_CTAP2_OK) {
            goto done;
        }
        size_t hs_len = 0;
        if (!omk_ctap_hmac_secret_output(ct, seed, uv_done, hmac_salt,
                                         salt_len, hs_out, &hs_len)) {
            status = OMK_CTAP1_ERR_INVALID_PARAMETER;
            goto done;
        }
        size_t enc_len = 0;
        if (!ext_encrypt(ct->port, hmac_aes, protocol, hs_out, hs_len,
                         hmac_mc, &enc_len)) {
            status = OMK_CTAP2_ERR_OTHER;
            goto done;
        }
        hmac_mc_len = enc_len;
    }
    if (hmac_bool || hmac_mc_len != 0 || cred_protect_requested) {
        ext_len = build_mc_ext_map(ext_data, sizeof ext_data, hmac_bool,
                                   hmac_mc, hmac_mc_len,
                                   cred_protect_requested, cred_protect);
        if (ext_len == 0) {
            status = OMK_CTAP2_ERR_OTHER;
            goto done;
        }
    }

    uint8_t flags = AUTH_FLAG_UP | AUTH_FLAG_AT;
    if (uv_done) {
        flags |= AUTH_FLAG_UV;
    }
    if (ext_len != 0) {
        flags |= AUTH_FLAG_ED;
    }
    /* The counter is consumed only after every random operation (key
     * generation, credential sealing, hmac-secret IV) has succeeded. */
    const uint32_t counter = omk_store_next_counter(&ct->store);
    if (counter == 0) {
        status = OMK_CTAP2_ERR_OTHER;
        goto done;
    }
    uint8_t auth_data[640];
    const size_t auth_len = omk_ctap_build_auth_data(
        ct, auth_data, sizeof auth_data, rp_hash, flags, counter, alg, cred_id,
        cred_id_len, pub, ext_data, ext_len);
    if (auth_len == 0) {
        status = OMK_CTAP2_ERR_REQUEST_TOO_LARGE;
        goto done;
    }

    bool want_attestation = true;
    const omk_cbor_val *pref = omk_cbor_map_get_int(doc, req, 0x0A);
    if (pref != NULL) {
        if (pref->type != OMK_CBOR_ARRAY) {
            status = OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            goto done;
        }
        want_attestation = false;
        for (uint16_t i = 0; i < pref->count; i++) {
            const omk_cbor_val *f = omk_cbor_array_get(doc, pref, i);
            if (f == NULL || f->type != OMK_CBOR_TEXT) {
                continue;
            }
            if (f->len == 6 && memcmp(f->data, "packed", 6) == 0) {
                want_attestation = true;
                break;
            }
            if (f->len == 4 && memcmp(f->data, "none", 4) == 0) {
                break;
            }
        }
    }

    if (rk) {
        omk_credential c;
        memset(&c, 0, sizeof c);
        memcpy(c.id, cred_id, cred_id_len);
        c.id_len = (uint8_t)cred_id_len;
        c.alg = alg;
        c.cred_protect = cred_protect;
        memcpy(c.rp_id_hash, rp_hash, 32);
        memcpy(c.rp_id, rp_id, rp_id_len);
        c.rp_id_len = (uint16_t)rp_id_len;
        memcpy(c.user_id, user_id, user_id_len);
        c.user_id_len = (uint8_t)user_id_len;
        if (user_name != NULL) {
            memcpy(c.user_name, user_name, user_name_len);
            c.user_name_len = (uint8_t)user_name_len;
        }
        if (display != NULL) {
            memcpy(c.display_name, display, display_len);
            c.display_name_len = (uint8_t)display_len;
        }
        const int store_rc = omk_store_put_credential(&ct->store, &c);
        if (store_rc != 0) {
            status = omk_ctap_store_error(ct, store_rc);
            goto done;
        }
    }

    omk_cbor_enc e;
    omk_cbor_enc_init(&e, ct->response, sizeof ct->response);
    omk_cbor_put_map(&e, 3);
    omk_cbor_put_uint(&e, 1);
    if (want_attestation) {
        omk_cbor_put_text(&e, "packed", 6);
    } else {
        omk_cbor_put_text(&e, "none", 4);
    }
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_bytes(&e, auth_data, auth_len);
    omk_cbor_put_uint(&e, 3);
    if (want_attestation) {
        omk_cbor_put_map(&e, 2);
        omk_cbor_put_text(&e, "alg", 3);
        omk_cbor_put_nint(&e, alg == OMK_ALG_ES256 ? -7 : -8);
        omk_cbor_put_text(&e, "sig", 3);
        uint8_t att_input[768];
        if (auth_len + 32 > sizeof att_input) {
            status = OMK_CTAP2_ERR_REQUEST_TOO_LARGE;
            goto done;
        }
        memcpy(att_input, auth_data, auth_len);
        memcpy(att_input + auth_len, client_data_hash, 32);
        uint8_t sig[64];
        size_t sig_len = 0;
        if (!omk_ctap_sign(ct, alg, seed, att_input, auth_len + 32, sig,
                           &sig_len)) {
            status = OMK_CTAP2_ERR_OTHER;
            goto done;
        }
        omk_cbor_put_bytes(&e, sig, sig_len);
    } else {
        omk_cbor_put_map(&e, 0);
    }
    ct->response_len = e.len;
    status = e.overflow ? OMK_CTAP2_ERR_REQUEST_TOO_LARGE : OMK_CTAP2_OK;

done:
    omk_memzero(seed, sizeof seed);
    omk_memzero(hmac_salt, sizeof hmac_salt);
    omk_memzero(hmac_aes, sizeof hmac_aes);
    omk_memzero(hmac_key, sizeof hmac_key);
    omk_memzero(hs_out, sizeof hs_out);
    omk_memzero(hmac_mc, sizeof hmac_mc);
    omk_memzero(ext_data, sizeof ext_data);
    return status;
}

/* ---------------------------------------------------------------------- */
/* GetAssertion / GetNextAssertion                                         */
/* ---------------------------------------------------------------------- */

static uint8_t open_record(omk_ctap *ct, const omk_credential *rec,
                           const uint8_t rp_hash[32], match_t *m) {
    if (memcmp(rec->rp_id_hash, rp_hash, 32) != 0) {
        return OMK_CTAP2_ERR_NO_CREDENTIALS;
    }
    if (!omk_store_open_credential(&ct->store, rp_hash, rec->id, rec->id_len,
                                   m->seed, &m->alg, &m->cred_protect,
                                   &m->resident)) {
        return OMK_CTAP2_ERR_INVALID_CREDENTIAL;
    }
    m->record = rec;
    return OMK_CTAP2_OK;
}

static void collect_residents(omk_ctap *ct, const uint8_t rp_hash[32], bool uv,
                              uint8_t *idxs, uint8_t *count) {
    *count = 0;
    for (uint8_t i = 0; i < ct->store.cred_count; i++) {
        const omk_credential *c = &ct->store.creds[i];
        if (memcmp(c->rp_id_hash, rp_hash, 32) != 0) {
            continue;
        }
        if (c->cred_protect >= 2 && !uv) {
            continue;
        }
        if (*count < OMK_MAX_CREDENTIALS) {
            idxs[(*count)++] = i;
        }
    }
    for (uint8_t i = 1; i < *count; i++) {
        const uint8_t v = idxs[i];
        int j = (int)i - 1;
        while (j >= 0 &&
               ct->store.creds[idxs[j]].seq < ct->store.creds[v].seq) {
            idxs[j + 1] = idxs[j];
            j--;
        }
        idxs[j + 1] = v;
    }
}

static uint8_t emit_assertion(omk_ctap *ct, const match_t *m,
                              const uint8_t *cred_id, size_t cred_id_len,
                              const uint8_t client_data_hash[32],
                              const uint8_t rp_hash[32], bool up, bool uv,
                              const uint8_t *ext_data, size_t ext_len,
                              bool include_number, uint32_t number) {
    uint8_t pub[65];
    size_t pub_len = 0;
    if (!omk_ctap_cred_public_key(m->alg, m->seed, pub, &pub_len)) {
        return OMK_CTAP2_ERR_INVALID_CREDENTIAL;
    }
    (void)pub_len;
    uint8_t flags = 0;
    if (up) {
        flags |= AUTH_FLAG_UP;
    }
    if (uv) {
        flags |= AUTH_FLAG_UV;
    }
    if (ext_len != 0) {
        flags |= AUTH_FLAG_ED;
    }
    const uint32_t counter = omk_store_next_counter(&ct->store);
    if (counter == 0) {
        return OMK_CTAP2_ERR_OTHER;
    }

    uint8_t ad[512];
    size_t ad_len = 0;
    memcpy(ad + ad_len, rp_hash, 32);
    ad_len += 32;
    ad[ad_len++] = flags;
    ad[ad_len++] = (uint8_t)(counter >> 24);
    ad[ad_len++] = (uint8_t)(counter >> 16);
    ad[ad_len++] = (uint8_t)(counter >> 8);
    ad[ad_len++] = (uint8_t)counter;
    if (ext_len != 0) {
        memcpy(ad + ad_len, ext_data, ext_len);
        ad_len += ext_len;
    }

    uint8_t sign_input[640];
    if (ad_len + 32 > sizeof sign_input) {
        return OMK_CTAP2_ERR_REQUEST_TOO_LARGE;
    }
    memcpy(sign_input, ad, ad_len);
    memcpy(sign_input + ad_len, client_data_hash, 32);
    uint8_t sig[64];
    size_t sig_len = 0;
    if (!omk_ctap_sign(ct, m->alg, m->seed, sign_input, ad_len + 32, sig,
                       &sig_len)) {
        return OMK_CTAP2_ERR_OTHER;
    }

    const bool with_user = m->resident && m->record != NULL;
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, ct->response, sizeof ct->response);
    omk_cbor_put_map(&e, (size_t)3 + (with_user ? 1u : 0u) +
                             (include_number ? 1u : 0u));
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_bytes(&e, cred_id, cred_id_len);
    omk_cbor_put_text(&e, "type", 4);
    omk_cbor_put_text(&e, "public-key", 10);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_bytes(&e, ad, ad_len);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_bytes(&e, sig, sig_len);
    if (with_user) {
        omk_cbor_put_uint(&e, 4);
        const omk_credential *c = m->record;
        size_t pairs = 1;
        if (uv && c->user_name_len != 0) {
            pairs++;
        }
        if (uv && c->display_name_len != 0) {
            pairs++;
        }
        omk_cbor_put_map(&e, pairs);
        omk_cbor_put_text(&e, "id", 2);
        omk_cbor_put_bytes(&e, c->user_id, c->user_id_len);
        if (uv && c->user_name_len != 0) {
            omk_cbor_put_text(&e, "name", 4);
            omk_cbor_put_text(&e, (const char *)c->user_name, c->user_name_len);
        }
        if (uv && c->display_name_len != 0) {
            omk_cbor_put_text(&e, "displayName", 11);
            omk_cbor_put_text(&e, (const char *)c->display_name,
                              c->display_name_len);
        }
    }
    if (include_number) {
        omk_cbor_put_uint(&e, 5);
        omk_cbor_put_uint(&e, number);
    }
    if (e.overflow) {
        return OMK_CTAP2_ERR_REQUEST_TOO_LARGE;
    }
    ct->response_len = e.len;
    return OMK_CTAP2_OK;
}

typedef struct {
    match_t m;
    uint8_t cred_id[OMK_CRED_ID_MAX];
    uint8_t cred_id_len;
} full_match;

static uint8_t match_allow_entry(omk_ctap *ct, const omk_cbor_doc *doc,
                                 const omk_cbor_val *desc,
                                 const uint8_t rp_hash[32], bool uv,
                                 full_match *out) {
    if (!match_descriptor(ct, doc, desc, rp_hash, uv, &out->m)) {
        return OMK_CTAP2_ERR_NO_CREDENTIALS;
    }
    const omk_cbor_val *idv = omk_cbor_map_get_text(doc, desc, "id", 2);
    if (out->m.record != NULL) {
        memcpy(out->cred_id, out->m.record->id, out->m.record->id_len);
        out->cred_id_len = out->m.record->id_len;
    } else {
        memcpy(out->cred_id, idv->data, idv->len);
        out->cred_id_len = (uint8_t)idv->len;
    }
    return OMK_CTAP2_OK;
}

static uint8_t hmac_ext_output(omk_ctap *ct, const uint8_t seed[32], bool uv,
                               uint8_t *out, size_t *out_len) {
    uint8_t hs[64] = {0};
    uint8_t enc[128] = {0};
    uint8_t status = OMK_CTAP2_OK;
    size_t hs_len = 0;
    size_t enc_len = 0;

    *out_len = 0;
    if (!ct->ga.hmac_secret) {
        goto done;
    }
    if (!omk_ctap_hmac_secret_output(ct, seed, uv, ct->ga.hmac_salt,
                                     ct->ga.hmac_salt_len, hs, &hs_len)) {
        status = OMK_CTAP1_ERR_INVALID_LENGTH;
        goto done;
    }
    if (!ext_encrypt(ct->port, ct->ga.hmac_aes, ct->ga.hmac_protocol, hs,
                     hs_len, enc, &enc_len)) {
        status = OMK_CTAP2_ERR_OTHER;
        goto done;
    }
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, out, 200);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "hmac-secret", 11);
    omk_cbor_put_bytes(&e, enc, enc_len);
    if (e.overflow) {
        status = OMK_CTAP2_ERR_REQUEST_TOO_LARGE;
        goto done;
    }
    *out_len = e.len;

done:
    omk_memzero(hs, sizeof hs);
    omk_memzero(enc, sizeof enc);
    return status;
}

static uint8_t parse_hmac_extension(omk_ctap *ct, const omk_cbor_doc *doc,
                                    const omk_cbor_val *extv, bool up) {
    ct->ga.hmac_secret = false;
    ct->ga.hmac_salt_len = 0;
    ct->ga.hmac_protocol = 0;
    omk_memzero(ct->ga.hmac_salt, sizeof ct->ga.hmac_salt);
    omk_memzero(ct->ga.hmac_aes, sizeof ct->ga.hmac_aes);
    omk_memzero(ct->ga.hmac_hmac, sizeof ct->ga.hmac_hmac);
    if (extv == NULL) {
        return OMK_CTAP2_OK;
    }
    if (extv->type != OMK_CBOR_MAP) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    const omk_cbor_val *hs =
        omk_cbor_map_get_text(doc, extv, "hmac-secret", 11);
    if (hs == NULL) {
        return OMK_CTAP2_OK;
    }
    if (!up) {
        return OMK_CTAP2_ERR_UNSUPPORTED_OPTION;
    }
    if (hs->type != OMK_CBOR_MAP) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    uint32_t protocol = 1;
    const uint8_t status = ext_parse_request(
        ct, doc, hs, ct->ga.hmac_salt, sizeof ct->ga.hmac_salt,
        &ct->ga.hmac_salt_len, ct->ga.hmac_aes, ct->ga.hmac_hmac, &protocol);
    if (status != OMK_CTAP2_OK) {
        return status;
    }
    ct->ga.hmac_protocol = (uint8_t)protocol;
    ct->ga.hmac_secret = true;
    return OMK_CTAP2_OK;
}

/* A request that finds no applicable credential did not perform an
 * authenticated operation, so it must not consume (age) the PUAT. */
static void restore_puat_use(omk_ctap *ct, bool used_once, uint64_t used_ms) {
    if (ct->pin.token_valid) {
        ct->pin.used_once = used_once;
        ct->pin.used_ms = used_ms;
    }
}

uint8_t omk_ctap_cmd_getassertion(omk_ctap *ct, const omk_cbor_doc *doc,
                                  const omk_cbor_val *req, uint32_t cid) {
    (void)cid;
    omk_ctap_ga_clear(ct);
    const bool puat_was_used = ct->pin.used_once;
    const uint64_t puat_used_ms = ct->pin.used_ms;
    const omk_cbor_val *rpv = omk_cbor_map_get_int(doc, req, 0x01);
    const omk_cbor_val *cdh = omk_cbor_map_get_int(doc, req, 0x02);
    const omk_cbor_val *allow = omk_cbor_map_get_int(doc, req, 0x03);
    const omk_cbor_val *extv = omk_cbor_map_get_int(doc, req, 0x04);
    const omk_cbor_val *optv = omk_cbor_map_get_int(doc, req, 0x05);

    if (rpv == NULL || cdh == NULL) {
        return OMK_CTAP2_ERR_MISSING_PARAMETER;
    }
    if (rpv->type != OMK_CBOR_TEXT || rpv->len == 0 ||
        rpv->len > OMK_RP_ID_MAX) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    const uint8_t *client_data_hash = NULL;
    size_t cdh_len = 0;
    if (!omk_ctap_val_bytes(cdh, &client_data_hash, &cdh_len) ||
        cdh_len != 32) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    if (allow != NULL && allow->type != OMK_CBOR_ARRAY) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    bool rk = false, up = true, uv_opt = false;
    uint8_t status = parse_options(doc, optv, &rk, &up, &uv_opt);
    if (status != OMK_CTAP2_OK) {
        return status;
    }
    if (rk) {
        return OMK_CTAP2_ERR_UNSUPPORTED_OPTION;
    }
    if (uv_opt) {
        return OMK_CTAP2_ERR_INVALID_OPTION;
    }
    uint8_t rp_hash[32];
    omk_sha256(rpv->data, rpv->len, rp_hash);

    bool uv = false;
    const omk_cbor_val *pin_param = omk_cbor_map_get_int(doc, req, 0x06);
    if (pin_param != NULL) {
        uint32_t pin_protocol = 0;
        const omk_cbor_val *ppv = omk_cbor_map_get_int(doc, req, 0x07);
        if (ppv == NULL) {
            return OMK_CTAP2_ERR_MISSING_PARAMETER;
        }
        if (!omk_ctap_val_uint(ppv, &pin_protocol)) {
            return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        status = omk_ctap_authorize_raw(ct, pin_param, pin_protocol,
                                        client_data_hash, 32, OMK_PERM_GA,
                                        rp_hash, &uv);
        if (status == OMK_CTAP_PIN_PROBE) {
            const uint8_t up_status = omk_ctap_wait_up(ct);
            if (up_status == OMK_CTAP_ABORTED) {
                return OMK_CTAP_ABORTED;
            }
            if (up_status != OMK_CTAP2_OK) {
                return up_status;
            }
            omk_ctap_consume_up(ct);
            return ct->store.pin_set ? OMK_CTAP2_ERR_PIN_INVALID
                                     : OMK_CTAP2_ERR_PIN_NOT_SET;
        }
        if (status != OMK_CTAP2_OK) {
            return status;
        }
    } else if (ct->store.pin_set && allow == NULL) {
        /* No pinUvAuthParam, no allowList, PIN set: PIN_REQUIRED regardless of
         * the up option.  The up:false pre-flight path only skips user
         * presence, it does not bypass PIN protection. */
        return OMK_CTAP2_ERR_PIN_REQUIRED;
    }

    status = parse_hmac_extension(ct, doc, extv, up);
    if (status != OMK_CTAP2_OK) {
        omk_ctap_ga_clear(ct);
        return status;
    }

    if (allow != NULL) {
        full_match fm;
        memset(&fm, 0, sizeof fm);
        bool found = false;
        for (uint16_t i = 0; i < allow->count; i++) {
            if (match_allow_entry(ct, doc, omk_cbor_array_get(doc, allow, i),
                                  rp_hash, uv, &fm) == OMK_CTAP2_OK) {
                found = true;
                break;
            }
        }
        if (!found) {
            /* No applicable credential: report it without a user-presence
             * wait and without consuming the PUAT. */
            if (pin_param != NULL) {
                restore_puat_use(ct, puat_was_used, puat_used_ms);
            }
            omk_memzero(&fm, sizeof fm);
            omk_ctap_ga_clear(ct);
            return OMK_CTAP2_ERR_NO_CREDENTIALS;
        }
        if (up) {
            const uint8_t up_status = omk_ctap_wait_up(ct);
            if (up_status == OMK_CTAP_ABORTED) {
                omk_memzero(&fm, sizeof fm);
                omk_ctap_ga_clear(ct);
                return OMK_CTAP_ABORTED;
            }
            if (up_status != OMK_CTAP2_OK) {
                omk_memzero(&fm, sizeof fm);
                omk_ctap_ga_clear(ct);
                return up_status;
            }
            omk_ctap_consume_up(ct);
        }
        uint8_t ext_data[200] = {0};
        size_t ext_len = 0;
        status = hmac_ext_output(ct, fm.m.seed, uv, ext_data, &ext_len);
        if (status == OMK_CTAP2_OK) {
            status = emit_assertion(ct, &fm.m, fm.cred_id, fm.cred_id_len,
                                    client_data_hash, rp_hash, up, uv,
                                    ext_data, ext_len, false, 0);
        }
        omk_memzero(&fm, sizeof fm);
        omk_memzero(ext_data, sizeof ext_data);
        omk_ctap_ga_clear(ct);
        return status;
    }

    uint8_t idxs[OMK_MAX_CREDENTIALS];
    uint8_t count = 0;
    collect_residents(ct, rp_hash, uv, idxs, &count);
    if (count == 0) {
        /* No applicable credential: report it without a user-presence wait
         * and without consuming the PUAT. */
        if (pin_param != NULL) {
            restore_puat_use(ct, puat_was_used, puat_used_ms);
        }
        omk_ctap_ga_clear(ct);
        return OMK_CTAP2_ERR_NO_CREDENTIALS;
    }
    if (up) {
        const uint8_t up_status = omk_ctap_wait_up(ct);
        if (up_status == OMK_CTAP_ABORTED) {
            omk_ctap_ga_clear(ct);
            return OMK_CTAP_ABORTED;
        }
        if (up_status != OMK_CTAP2_OK) {
            omk_ctap_ga_clear(ct);
            return up_status;
        }
        omk_ctap_consume_up(ct);
    }

    match_t m;
    memset(&m, 0, sizeof m);
    status = open_record(ct, &ct->store.creds[idxs[0]], rp_hash, &m);
    if (status != OMK_CTAP2_OK) {
        omk_memzero(&m, sizeof m);
        omk_ctap_ga_clear(ct);
        return status;
    }
    uint8_t ext_data[200] = {0};
    size_t ext_len = 0;
    status = hmac_ext_output(ct, m.seed, uv, ext_data, &ext_len);
    if (status != OMK_CTAP2_OK) {
        omk_memzero(&m, sizeof m);
        omk_memzero(ext_data, sizeof ext_data);
        omk_ctap_ga_clear(ct);
        return status;
    }
    status = emit_assertion(ct, &m, m.record->id, m.record->id_len,
                            client_data_hash, rp_hash, up, uv, ext_data,
                            ext_len, count > 1, count);
    omk_memzero(&m, sizeof m);
    omk_memzero(ext_data, sizeof ext_data);
    if (status != OMK_CTAP2_OK) {
        omk_ctap_ga_clear(ct);
        return status;
    }

    if (count > 1) {
        ct->ga.valid = true;
        memcpy(ct->ga.client_data_hash, client_data_hash, 32);
        memcpy(ct->ga.rp_hash, rp_hash, 32);
        ct->ga.up = up;
        ct->ga.uv = uv;
        ct->ga.count = count;
        ct->ga.next = 1;
        memcpy(ct->ga.indices, idxs, count);
        ct->ga.expires_ms = omk_ctap_now_ms(ct) + OMK_CTAP_GA_STATE_MS;
    } else {
        /* No continuation exists, so the extension keys are not retained. */
        omk_ctap_ga_clear(ct);
    }
    return OMK_CTAP2_OK;
}

uint8_t omk_ctap_cmd_getnextassertion(omk_ctap *ct, uint32_t cid) {
    (void)cid;
    if (!ct->ga.valid || ct->ga.next >= ct->ga.count ||
        omk_ctap_now_ms(ct) > ct->ga.expires_ms) {
        omk_ctap_ga_clear(ct);
        return OMK_CTAP2_ERR_NOT_ALLOWED;
    }
    const uint8_t idx = ct->ga.indices[ct->ga.next++];
    if (idx >= ct->store.cred_count) {
        omk_ctap_ga_clear(ct);
        return OMK_CTAP2_ERR_NOT_ALLOWED;
    }
    match_t m;
    memset(&m, 0, sizeof m);
    const uint8_t status =
        open_record(ct, &ct->store.creds[idx], ct->ga.rp_hash, &m);
    if (status != OMK_CTAP2_OK) {
        omk_memzero(&m, sizeof m);
        omk_ctap_ga_clear(ct);
        return status;
    }
    uint8_t ext_data[200] = {0};
    size_t ext_len = 0;
    uint8_t hs =
        hmac_ext_output(ct, m.seed, ct->ga.uv, ext_data, &ext_len);
    if (hs != OMK_CTAP2_OK) {
        omk_memzero(&m, sizeof m);
        omk_memzero(ext_data, sizeof ext_data);
        omk_ctap_ga_clear(ct);
        return hs;
    }
    const uint8_t result =
        emit_assertion(ct, &m, m.record->id, m.record->id_len,
                       ct->ga.client_data_hash, ct->ga.rp_hash, ct->ga.up,
                       ct->ga.uv, ext_data, ext_len, false, 0);
    omk_memzero(&m, sizeof m);
    omk_memzero(ext_data, sizeof ext_data);
    if (ct->ga.next >= ct->ga.count || result != OMK_CTAP2_OK) {
        omk_ctap_ga_clear(ct);
    } else {
        /* Each successful iteration gets a fresh 30 s window. */
        ct->ga.expires_ms = omk_ctap_now_ms(ct) + OMK_CTAP_GA_STATE_MS;
    }
    return result;
}
