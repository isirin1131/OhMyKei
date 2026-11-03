#include <string.h>

#include "crypto/omk_crypto.h"
#include "fido/omk_cbor.h"
#include "fido/omk_ctap_internal.h"

static void put_user(omk_cbor_enc *e, const omk_credential *c) {
    size_t pairs = 1;
    if (c->user_name_len != 0) {
        pairs++;
    }
    if (c->display_name_len != 0) {
        pairs++;
    }
    omk_cbor_put_map(e, pairs);
    omk_cbor_put_text(e, "id", 2);
    omk_cbor_put_bytes(e, c->user_id, c->user_id_len);
    if (c->user_name_len != 0) {
        omk_cbor_put_text(e, "name", 4);
        omk_cbor_put_text(e, (const char *)c->user_name, c->user_name_len);
    }
    if (c->display_name_len != 0) {
        omk_cbor_put_text(e, "displayName", 11);
        omk_cbor_put_text(e, (const char *)c->display_name,
                          c->display_name_len);
    }
}

static void put_rp(omk_cbor_enc *e, const uint8_t *rp_id, size_t rp_id_len) {
    omk_cbor_put_map(e, 2);
    omk_cbor_put_text(e, "id", 2);
    omk_cbor_put_text(e, (const char *)rp_id, rp_id_len);
    omk_cbor_put_text(e, "name", 4);
    omk_cbor_put_text(e, (const char *)rp_id, rp_id_len);
}

static const omk_credential *find_by_rp_hash(omk_ctap *ct,
                                             const uint8_t *rp_hash) {
    for (uint8_t i = 0; i < ct->store.cred_count; i++) {
        if (memcmp(ct->store.creds[i].rp_id_hash, rp_hash, 32) == 0) {
            return &ct->store.creds[i];
        }
    }
    return NULL;
}

static void sort_indices(omk_ctap *ct, uint8_t *idxs, uint8_t count) {
    for (uint8_t i = 1; i < count; i++) {
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

static uint8_t collect_rp_credentials(omk_ctap *ct, const uint8_t *rp_hash,
                                      uint8_t *idxs, uint8_t *count) {
    *count = 0;
    for (uint8_t i = 0; i < ct->store.cred_count; i++) {
        if (memcmp(ct->store.creds[i].rp_id_hash, rp_hash, 32) == 0) {
            if (*count < OMK_MAX_CREDENTIALS) {
                idxs[(*count)++] = i;
            }
        }
    }
    sort_indices(ct, idxs, *count);
    return *count;
}

static uint8_t auth_message(const omk_cbor_doc *doc, uint8_t subcommand,
                            const omk_cbor_val *params, uint8_t *out,
                            size_t cap, size_t *len) {
    *len = 0;
    if (cap < 1) {
        return OMK_CTAP2_ERR_REQUEST_TOO_LARGE;
    }
    out[(*len)++] = subcommand;
    if (params != NULL) {
        if (params->raw_len == 0 || params->raw_len > cap - *len) {
            return OMK_CTAP2_ERR_REQUEST_TOO_LARGE;
        }
        memcpy(out + *len, doc->buf + params->raw_off, params->raw_len);
        *len += params->raw_len;
    }
    return OMK_CTAP2_OK;
}

static uint8_t check_cm_auth(omk_ctap *ct, const omk_cbor_doc *doc,
                             const omk_cbor_val *req, uint8_t subcommand,
                             const omk_cbor_val *params,
                             const uint8_t *rp_hash, bool *uv) {
    if (!ct->store.pin_set) {
        return OMK_CTAP2_ERR_PIN_NOT_SET;
    }
    const omk_cbor_val *auth = omk_cbor_map_get_int(doc, req, 0x04);
    if (auth == NULL) {
        return OMK_CTAP2_ERR_PIN_REQUIRED;
    }
    uint32_t protocol = 0;
    const omk_cbor_val *pv = omk_cbor_map_get_int(doc, req, 0x03);
    if (pv == NULL) {
        return OMK_CTAP2_ERR_MISSING_PARAMETER;
    }
    if (!omk_ctap_val_uint(pv, &protocol)) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    uint8_t msg[512];
    size_t msg_len = 0;
    uint8_t status = auth_message(doc, subcommand, params, msg, sizeof msg,
                                  &msg_len);
    if (status != OMK_CTAP2_OK) {
        return status;
    }
    status = omk_ctap_authorize_raw(ct, auth, protocol, msg, msg_len,
                                    OMK_PERM_CM, rp_hash, uv);
    if (status == OMK_CTAP_PIN_PROBE) {
        /* A zero-length pinUvAuthParam is a CTAP 2.0 discovery probe, not a
         * CTAP status code.  It must never escape a CredentialManagement
         * response: with a PIN configured it is simply an invalid
         * authenticator, and without one the earlier check already returned
         * PIN_NOT_SET. */
        return ct->store.pin_set ? OMK_CTAP2_ERR_PIN_AUTH_INVALID
                                 : OMK_CTAP2_ERR_PIN_NOT_SET;
    }
    return status;
}

static uint8_t sub_metadata(omk_ctap *ct) {
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, ct->response, sizeof ct->response);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, ct->store.cred_count);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, OMK_MAX_CREDENTIALS - ct->store.cred_count);
    ct->response_len = e.len;
    return e.overflow ? OMK_CTAP2_ERR_REQUEST_TOO_LARGE : OMK_CTAP2_OK;
}

static uint8_t sub_enum_rps_begin(omk_ctap *ct) {
    uint8_t count = 0;
    for (uint8_t i = 0; i < ct->store.cred_count; i++) {
        bool seen = false;
        for (uint8_t j = 0; j < count; j++) {
            if (memcmp(ct->cm.rp_hashes[j], ct->store.creds[i].rp_id_hash,
                       32) == 0) {
                seen = true;
                break;
            }
        }
        if (!seen && count < OMK_MAX_CREDENTIALS) {
            memcpy(ct->cm.rp_hashes[count++], ct->store.creds[i].rp_id_hash,
                   32);
        }
    }
    if (count == 0) {
        return OMK_CTAP2_ERR_NO_CREDENTIALS;
    }
    ct->cm.valid = true;
    ct->cm.kind = 1;
    ct->cm.count = count;
    ct->cm.next = 1;
    ct->cm.expires_ms = omk_ctap_now_ms(ct) + OMK_CTAP_GA_STATE_MS;

    const omk_credential *c = find_by_rp_hash(ct, ct->cm.rp_hashes[0]);
    if (c == NULL) {
        omk_ctap_cm_clear(ct);
        return OMK_CTAP2_ERR_OTHER;
    }
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, ct->response, sizeof ct->response);
    omk_cbor_put_map(&e, 3);
    omk_cbor_put_uint(&e, 3);
    put_rp(&e, c->rp_id, c->rp_id_len);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, c->rp_id_hash, 32);
    omk_cbor_put_uint(&e, 5);
    omk_cbor_put_uint(&e, count);
    ct->response_len = e.len;
    if (e.overflow) {
        omk_ctap_cm_clear(ct);
        return OMK_CTAP2_ERR_REQUEST_TOO_LARGE;
    }
    return OMK_CTAP2_OK;
}

static uint8_t sub_enum_rps_next(omk_ctap *ct) {
    if (!ct->cm.valid || ct->cm.kind != 1 ||
        omk_ctap_now_ms(ct) > ct->cm.expires_ms ||
        ct->cm.next >= ct->cm.count) {
        omk_ctap_cm_clear(ct);
        return OMK_CTAP2_ERR_NOT_ALLOWED;
    }
    const omk_credential *c = NULL;
    while (ct->cm.next < ct->cm.count) {
        const uint8_t *hash = ct->cm.rp_hashes[ct->cm.next++];
        c = find_by_rp_hash(ct, hash);
        if (c != NULL) {
            break;
        }
    }
    if (c == NULL) {
        omk_ctap_cm_clear(ct);
        return OMK_CTAP2_ERR_NOT_ALLOWED;
    }
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, ct->response, sizeof ct->response);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_uint(&e, 3);
    put_rp(&e, c->rp_id, c->rp_id_len);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, c->rp_id_hash, 32);
    ct->response_len = e.len;
    if (ct->cm.next >= ct->cm.count || e.overflow) {
        omk_ctap_cm_clear(ct);
    }
    return e.overflow ? OMK_CTAP2_ERR_REQUEST_TOO_LARGE : OMK_CTAP2_OK;
}

static uint8_t sub_enum_creds_begin(omk_ctap *ct, const omk_cbor_doc *doc,
                                    const omk_cbor_val *params) {
    uint8_t seed[32] = {0};
    uint8_t pub[65] = {0};
    uint8_t cose[128] = {0};
    uint8_t status = OMK_CTAP2_OK;

    if (params == NULL || params->type != OMK_CBOR_MAP) {
        return OMK_CTAP2_ERR_MISSING_PARAMETER;
    }
    const omk_cbor_val *hash = omk_cbor_map_get_int(doc, params, 0x01);
    if (hash == NULL) {
        return OMK_CTAP2_ERR_MISSING_PARAMETER;
    }
    if (hash->type != OMK_CBOR_BYTES || hash->len != 32) {
        return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    uint8_t idxs[OMK_MAX_CREDENTIALS];
    uint8_t count = 0;
    collect_rp_credentials(ct, hash->data, idxs, &count);
    if (count == 0) {
        return OMK_CTAP2_ERR_NO_CREDENTIALS;
    }
    ct->cm.valid = true;
    ct->cm.kind = 2;
    memcpy(ct->cm.rp_hash, hash->data, 32);
    for (uint8_t i = 0; i < count; i++) {
        ct->cm.cred_seqs[i] = ct->store.creds[idxs[i]].seq;
    }
    ct->cm.count = count;
    ct->cm.next = 1;
    ct->cm.expires_ms = omk_ctap_now_ms(ct) + OMK_CTAP_GA_STATE_MS;

    /* The record does not carry the private seed: open the sealed ID. */
    const omk_credential *c = &ct->store.creds[idxs[0]];
    uint8_t alg = 0, cp = 0;
    bool resident = false;
    if (!omk_store_open_credential(&ct->store, hash->data, c->id, c->id_len,
                                   seed, &alg, &cp, &resident)) {
        status = OMK_CTAP2_ERR_INVALID_CREDENTIAL;
        goto done;
    }
    size_t pub_len = 0;
    if (!omk_ctap_cred_public_key(alg, seed, pub, &pub_len)) {
        status = OMK_CTAP2_ERR_OTHER;
        goto done;
    }
    const size_t n = omk_ctap_build_cose_key(cose, sizeof cose, alg, pub);
    if (n == 0) {
        status = OMK_CTAP2_ERR_OTHER;
        goto done;
    }
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, ct->response, sizeof ct->response);
    omk_cbor_put_map(&e, 5);
    omk_cbor_put_uint(&e, 6);
    put_user(&e, c);
    omk_cbor_put_uint(&e, 7);
    omk_cbor_put_bytes(&e, c->id, c->id_len);
    omk_cbor_put_uint(&e, 8);
    omk_cbor_put_raw(&e, cose, n);
    omk_cbor_put_uint(&e, 9);
    omk_cbor_put_uint(&e, count);
    omk_cbor_put_uint(&e, 10);
    omk_cbor_put_uint(&e, cp);
    ct->response_len = e.len;
    status = e.overflow ? OMK_CTAP2_ERR_REQUEST_TOO_LARGE : OMK_CTAP2_OK;

done:
    omk_memzero(seed, sizeof seed);
    omk_memzero(pub, sizeof pub);
    omk_memzero(cose, sizeof cose);
    if (status != OMK_CTAP2_OK) {
        omk_ctap_cm_clear(ct);
    }
    return status;
}

static uint8_t sub_enum_creds_next(omk_ctap *ct) {
    uint8_t seed[32] = {0};
    uint8_t pub[65] = {0};
    uint8_t cose[128] = {0};
    uint8_t status = OMK_CTAP2_OK;

    if (!ct->cm.valid || ct->cm.kind != 2 ||
        omk_ctap_now_ms(ct) > ct->cm.expires_ms ||
        ct->cm.next >= ct->cm.count) {
        omk_ctap_cm_clear(ct);
        return OMK_CTAP2_ERR_NOT_ALLOWED;
    }
    const omk_credential *c = NULL;
    /* Deletion shifts the RAM index array.  Resolve each snapshot sequence
     * against current records and skip entries deleted since enumeration
     * began instead of returning the wrong credential or a stale index. */
    while (c == NULL && ct->cm.next < ct->cm.count) {
        const uint32_t seq = ct->cm.cred_seqs[ct->cm.next++];
        for (uint8_t i = 0; i < ct->store.cred_count; i++) {
            if (ct->store.creds[i].seq == seq &&
                memcmp(ct->store.creds[i].rp_id_hash, ct->cm.rp_hash, 32) == 0) {
                c = &ct->store.creds[i];
                break;
            }
        }
    }
    if (c == NULL) {
        status = OMK_CTAP2_ERR_NOT_ALLOWED;
        goto done;
    }
    uint8_t alg = 0, cp = 0;
    bool resident = false;
    if (!omk_store_open_credential(&ct->store, ct->cm.rp_hash, c->id, c->id_len,
                                   seed, &alg, &cp, &resident)) {
        status = OMK_CTAP2_ERR_INVALID_CREDENTIAL;
        goto done;
    }
    size_t pub_len = 0;
    if (!omk_ctap_cred_public_key(alg, seed, pub, &pub_len)) {
        status = OMK_CTAP2_ERR_OTHER;
        goto done;
    }
    const size_t n = omk_ctap_build_cose_key(cose, sizeof cose, alg, pub);
    if (n == 0) {
        status = OMK_CTAP2_ERR_OTHER;
        goto done;
    }
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, ct->response, sizeof ct->response);
    omk_cbor_put_map(&e, 4);
    omk_cbor_put_uint(&e, 6);
    put_user(&e, c);
    omk_cbor_put_uint(&e, 7);
    omk_cbor_put_bytes(&e, c->id, c->id_len);
    omk_cbor_put_uint(&e, 8);
    omk_cbor_put_raw(&e, cose, n);
    omk_cbor_put_uint(&e, 10);
    omk_cbor_put_uint(&e, cp);
    ct->response_len = e.len;
    status = e.overflow ? OMK_CTAP2_ERR_REQUEST_TOO_LARGE : OMK_CTAP2_OK;

done:
    omk_memzero(seed, sizeof seed);
    omk_memzero(pub, sizeof pub);
    omk_memzero(cose, sizeof cose);
    if (status != OMK_CTAP2_OK || ct->cm.next >= ct->cm.count) {
        omk_ctap_cm_clear(ct);
    }
    return status;
}

uint8_t omk_ctap_cmd_credmgmt(omk_ctap *ct, const omk_cbor_doc *doc,
                              const omk_cbor_val *req, uint32_t cid) {
    (void)cid;
    const omk_cbor_val *sub = omk_cbor_map_get_int(doc, req, 0x01);
    uint32_t subcommand = 0;
    if (!omk_ctap_val_uint(sub, &subcommand)) {
        return sub == NULL ? OMK_CTAP2_ERR_MISSING_PARAMETER
                           : OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    const omk_cbor_val *params = omk_cbor_map_get_int(doc, req, 0x02);
    bool uv = false;

    /* Enumerators 0x03/0x05 continue an existing state and carry no auth. */
    if (subcommand == 0x03) {
        return sub_enum_rps_next(ct);
    }
    if (subcommand == 0x05) {
        return sub_enum_creds_next(ct);
    }

    uint8_t status;
    switch (subcommand) {
    case 0x01:
        status = check_cm_auth(ct, doc, req, 0x01, params, NULL, &uv);
        return status == OMK_CTAP2_OK ? sub_metadata(ct) : status;
    case 0x02:
        status = check_cm_auth(ct, doc, req, 0x02, params, NULL, &uv);
        return status == OMK_CTAP2_OK ? sub_enum_rps_begin(ct) : status;
    case 0x04: {
        if (params == NULL || params->type != OMK_CBOR_MAP) {
            return OMK_CTAP2_ERR_MISSING_PARAMETER;
        }
        const omk_cbor_val *rp = omk_cbor_map_get_int(doc, params, 0x01);
        if (rp == NULL) {
            return OMK_CTAP2_ERR_MISSING_PARAMETER;
        }
        if (rp->type != OMK_CBOR_BYTES || rp->len != 32) {
            return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        status = check_cm_auth(ct, doc, req, 0x04, params, rp->data, &uv);
        return status == OMK_CTAP2_OK ? sub_enum_creds_begin(ct, doc, params)
                                      : status;
    }
    case 0x06: {
        if (params == NULL || params->type != OMK_CBOR_MAP) {
            return OMK_CTAP2_ERR_MISSING_PARAMETER;
        }
        const omk_cbor_val *id = omk_cbor_map_get_int(doc, params, 0x02);
        if (id == NULL) {
            return OMK_CTAP2_ERR_MISSING_PARAMETER;
        }
        if (id->type != OMK_CBOR_BYTES || id->len == 0 ||
            id->len > OMK_CRED_ID_MAX) {
            return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        const omk_credential *c =
            omk_store_find_id(&ct->store, id->data, id->len);
        status = check_cm_auth(ct, doc, req, 0x06, params,
                               c != NULL ? c->rp_id_hash : NULL, &uv);
        if (status != OMK_CTAP2_OK) {
            return status;
        }
        if (c == NULL) {
            return OMK_CTAP2_ERR_NO_CREDENTIALS;
        }
        const int store_rc =
            omk_store_delete_credential(&ct->store, id->data, id->len);
        if (store_rc != 0) {
            return omk_ctap_store_error(ct, store_rc);
        }
        /* No response parameters: status-only success. */
        ct->response_len = 0;
        return OMK_CTAP2_OK;
    }
    case 0x07: {
        if (params == NULL || params->type != OMK_CBOR_MAP) {
            return OMK_CTAP2_ERR_MISSING_PARAMETER;
        }
        const omk_cbor_val *id = omk_cbor_map_get_int(doc, params, 0x02);
        const omk_cbor_val *user = omk_cbor_map_get_int(doc, params, 0x03);
        if (id == NULL || user == NULL) {
            return OMK_CTAP2_ERR_MISSING_PARAMETER;
        }
        if (id->type != OMK_CBOR_BYTES || id->len == 0 ||
            id->len > OMK_CRED_ID_MAX || user->type != OMK_CBOR_MAP) {
            return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        const omk_credential *c =
            omk_store_find_id(&ct->store, id->data, id->len);
        status = check_cm_auth(ct, doc, req, 0x07, params,
                               c != NULL ? c->rp_id_hash : NULL, &uv);
        if (status != OMK_CTAP2_OK) {
            return status;
        }
        if (c == NULL) {
            return OMK_CTAP2_ERR_NO_CREDENTIALS;
        }
        const omk_cbor_val *uid = omk_cbor_map_get_text(doc, user, "id", 2);
        const omk_cbor_val *name = omk_cbor_map_get_text(doc, user, "name", 4);
        const omk_cbor_val *display =
            omk_cbor_map_get_text(doc, user, "displayName", 11);
        if (uid == NULL) {
            return OMK_CTAP2_ERR_MISSING_PARAMETER;
        }
        if (uid->type != OMK_CBOR_BYTES || uid->len == 0 ||
            uid->len > OMK_USER_ID_MAX) {
            return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        if (name != NULL &&
            (name->type != OMK_CBOR_TEXT || name->len > OMK_USER_NAME_MAX)) {
            return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        if (display != NULL &&
            (display->type != OMK_CBOR_TEXT ||
             display->len > OMK_USER_NAME_MAX)) {
            return OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        /* user.id identifies the account: it cannot be edited in place.  A
         * request that tries to change it is rejected and the stored handle
         * is left untouched. */
        if (uid->len != c->user_id_len ||
            memcmp(uid->data, c->user_id, uid->len) != 0) {
            return OMK_CTAP1_ERR_INVALID_PARAMETER;
        }
        const int store_rc = omk_store_update_user(
            &ct->store, id->data, id->len, uid->data, uid->len,
            name != NULL ? name->data : NULL, name != NULL ? name->len : 0,
            display != NULL ? display->data : NULL,
            display != NULL ? display->len : 0);
        if (store_rc != 0) {
            /* The credential was resolved above; a failure here is a flash/
             * serialization/cancel fault, not a missing-credential response. */
            return omk_ctap_store_error(ct, store_rc);
        }
        /* No response parameters: status-only success. */
        ct->response_len = 0;
        return OMK_CTAP2_OK;
    }
    default:
        return OMK_CTAP2_ERR_INVALID_SUBCOMMAND;
    }
}
