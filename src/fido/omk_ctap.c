#include "fido/omk_ctap.h"

#include <string.h>

#include "crypto/omk_crypto.h"
#include "fido/omk_cbor.h"
#include "fido/omk_ctap_internal.h"

/* ---------------------------------------------------------------------- */
/* Small helpers                                                           */
/* ---------------------------------------------------------------------- */

uint64_t omk_ctap_now_ms(const omk_ctap *ct) {
    return ct->port->now_ms(ct->port->ctx);
}

void omk_ctap_delay(omk_ctap *ct, uint32_t ms) {
    if (ct->port->delay_ms != NULL) {
        ct->port->delay_ms(ct->port->ctx, ms);
    }
}

void omk_ctap_send_status(omk_ctap *ct, uint32_t cid, uint8_t status) {
    uint8_t b = status;
    omk_ctaphid_send(ct->hid, cid, &b, 1);
}

uint8_t omk_ctap_store_error(const omk_ctap *ct, int store_rc) {
    if (store_rc == OMK_STORE_ERR_CANCELLED) {
        if (ct->hid != NULL && omk_ctaphid_aborted(ct->hid)) {
            return OMK_CTAP_ABORTED;
        }
        return OMK_CTAP2_ERR_KEEPALIVE_CANCEL;
    }
    if (store_rc == OMK_STORE_ERR_FULL) {
        return OMK_CTAP2_ERR_KEY_STORE_FULL;
    }
    return OMK_CTAP2_ERR_OTHER;
}

bool omk_ctap_val_uint(const omk_cbor_val *v, uint32_t *out) {
    if (v == NULL || v->type != OMK_CBOR_UINT || v->num < 0 ||
        v->num > 0xFFFFFFFFLL) {
        return false;
    }
    *out = (uint32_t)v->num;
    return true;
}

bool omk_ctap_val_bytes(const omk_cbor_val *v, const uint8_t **data,
                        size_t *len) {
    if (v == NULL || v->type != OMK_CBOR_BYTES) {
        return false;
    }
    *data = v->data;
    *len = v->len;
    return true;
}

bool omk_ctap_val_text(const omk_cbor_val *v, const uint8_t **data,
                       size_t *len) {
    if (v == NULL || v->type != OMK_CBOR_TEXT) {
        return false;
    }
    *data = v->data;
    *len = v->len;
    return true;
}

uint8_t omk_ctap_wait_up(omk_ctap *ct) {
    const uint64_t start = omk_ctap_now_ms(ct);
    if (ct->port->up_pressed(ct->port->ctx)) {
        /* Ignore a button that was already held when the command started. */
        ct->up_latched = true;
    }
    for (;;) {
        if (ct->hid != NULL) {
            omk_ctaphid_poll(ct->hid);
            if (omk_ctaphid_aborted(ct->hid)) {
                return OMK_CTAP_ABORTED;
            }
            if (omk_ctaphid_cancel_pending(ct->hid)) {
                return OMK_CTAP2_ERR_KEEPALIVE_CANCEL;
            }
            omk_ctaphid_send_keepalive(ct->hid, OMK_KEEPALIVE_UP_NEEDED);
        }
        const bool pressed = ct->port->up_pressed(ct->port->ctx);
        if (!ct->up_latched && pressed) {
            ct->up_latched = true;
            return OMK_CTAP2_OK;
        }
        if (ct->up_latched && !pressed) {
            ct->up_latched = false;
        }
        if (omk_ctap_now_ms(ct) - start >= OMK_CTAP_UP_TIMEOUT_MS) {
            return OMK_CTAP2_ERR_USER_ACTION_TIMEOUT;
        }
        omk_ctap_delay(ct, 10);
    }
}

void omk_ctap_consume_up(omk_ctap *ct) {
    /* A new UP consumes every PUAT permission except large-blob write. */
    omk_ctap_puat_invalidate(ct);
}

void omk_ctap_ga_clear(omk_ctap *ct) {
    /* Clears match seeds, hmac-secret salts/keys and enumeration cursors. */
    omk_memzero(&ct->ga, sizeof ct->ga);
}

void omk_ctap_cm_clear(omk_ctap *ct) {
    omk_memzero(&ct->cm, sizeof ct->cm);
}

void omk_ctap_pin_shared_clear(omk_ctap *ct) {
    omk_memzero(ct->pin.shared_aes, sizeof ct->pin.shared_aes);
    omk_memzero(ct->pin.shared_hmac, sizeof ct->pin.shared_hmac);
    ct->pin.protocol = 0;
}

size_t omk_ctap_build_cose_key(uint8_t *out, size_t cap, uint8_t alg,
                               const uint8_t pub[65]) {
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, out, cap);
    if (alg == OMK_ALG_ES256) {
        omk_cbor_put_map(&e, 5);
        omk_cbor_put_uint(&e, 1);
        omk_cbor_put_uint(&e, 2); /* kty: EC2 */
        omk_cbor_put_uint(&e, 3);
        omk_cbor_put_nint(&e, -7); /* alg: ES256 */
        omk_cbor_put_nint(&e, -1);
        omk_cbor_put_uint(&e, 1); /* crv: P-256 */
        omk_cbor_put_nint(&e, -2);
        omk_cbor_put_bytes(&e, pub + 1, 32);
        omk_cbor_put_nint(&e, -3);
        omk_cbor_put_bytes(&e, pub + 33, 32);
    } else if (alg == OMK_ALG_EDDSA) {
        omk_cbor_put_map(&e, 4);
        omk_cbor_put_uint(&e, 1);
        omk_cbor_put_uint(&e, 1); /* kty: OKP */
        omk_cbor_put_uint(&e, 3);
        omk_cbor_put_nint(&e, -8); /* alg: EdDSA */
        omk_cbor_put_nint(&e, -1);
        omk_cbor_put_uint(&e, 6); /* crv: Ed25519 */
        omk_cbor_put_nint(&e, -2);
        omk_cbor_put_bytes(&e, pub, 32);
    } else {
        e.overflow = true;
    }
    return e.overflow ? 0 : e.len;
}

size_t omk_ctap_build_auth_data(const omk_ctap *ct, uint8_t *out, size_t cap,
                                const uint8_t rp_hash[32], uint8_t flags,
                                uint32_t counter, uint8_t alg,
                                const uint8_t *cred_id, size_t cred_id_len,
                                const uint8_t pub[65], const uint8_t *ext_data,
                                size_t ext_len) {
    size_t need = 32 + 1 + 4;
    if ((flags & 0x40u) != 0) {
        need += 16 + 2 + cred_id_len + 128;
    }
    if ((flags & 0x80u) != 0) {
        need += ext_len;
    }
    if (need > cap) {
        return 0;
    }
    size_t o = 0;
    memcpy(out + o, rp_hash, 32);
    o += 32;
    out[o++] = flags;
    out[o++] = (uint8_t)(counter >> 24);
    out[o++] = (uint8_t)(counter >> 16);
    out[o++] = (uint8_t)(counter >> 8);
    out[o++] = (uint8_t)counter;
    if ((flags & 0x40u) != 0) {
        memcpy(out + o, ct->store.aaguid, 16);
        o += 16;
        out[o++] = (uint8_t)(cred_id_len >> 8);
        out[o++] = (uint8_t)cred_id_len;
        memcpy(out + o, cred_id, cred_id_len);
        o += cred_id_len;
        const size_t cose = omk_ctap_build_cose_key(out + o, cap - o, alg, pub);
        if (cose == 0) {
            return 0;
        }
        o += cose;
    }
    if ((flags & 0x80u) != 0) {
        memcpy(out + o, ext_data, ext_len);
        o += ext_len;
    }
    return o;
}

/* ---------------------------------------------------------------------- */
/* authenticatorGetInfo                                                    */
/* ---------------------------------------------------------------------- */

static uint8_t cmd_get_info(omk_ctap *ct) {
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, ct->response, sizeof ct->response);
    omk_cbor_put_map(&e, 12);

    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_array(&e, 3);
    omk_cbor_put_text(&e, "FIDO_2_0", 8);
    omk_cbor_put_text(&e, "FIDO_2_1", 8);
    omk_cbor_put_text(&e, "FIDO_2_3", 8);

    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_array(&e, 3);
    omk_cbor_put_text(&e, "credProtect", 11);
    omk_cbor_put_text(&e, "hmac-secret", 11);
    omk_cbor_put_text(&e, "hmac-secret-mc", 14);

    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_bytes(&e, ct->store.aaguid, 16);

    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_map(&e, 7);
    omk_cbor_put_text(&e, "rk", 2);
    omk_cbor_put_bool(&e, true);
    omk_cbor_put_text(&e, "up", 2);
    omk_cbor_put_bool(&e, true);
    omk_cbor_put_text(&e, "plat", 4);
    omk_cbor_put_bool(&e, false);
    omk_cbor_put_text(&e, "credMgmt", 8);
    omk_cbor_put_bool(&e, true);
    omk_cbor_put_text(&e, "clientPin", 9);
    omk_cbor_put_bool(&e, ct->store.pin_set);
    omk_cbor_put_text(&e, "pinUvAuthToken", 14);
    omk_cbor_put_bool(&e, true);
    omk_cbor_put_text(&e, "makeCredUvNotRqd", 16);
    omk_cbor_put_bool(&e, true);

    omk_cbor_put_uint(&e, 5);
    omk_cbor_put_uint(&e, OMK_CTAPHID_MAX_MESSAGE);

    omk_cbor_put_uint(&e, 6);
    omk_cbor_put_array(&e, 2);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 1);

    omk_cbor_put_uint(&e, 7);
    omk_cbor_put_uint(&e, 32);
    omk_cbor_put_uint(&e, 8);
    omk_cbor_put_uint(&e, OMK_CRED_ID_MAX);

    omk_cbor_put_uint(&e, 9);
    omk_cbor_put_array(&e, 1);
    omk_cbor_put_text(&e, "usb", 3);

    omk_cbor_put_uint(&e, 10);
    omk_cbor_put_array(&e, 2);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_text(&e, "alg", 3);
    omk_cbor_put_nint(&e, -7);
    omk_cbor_put_text(&e, "type", 4);
    omk_cbor_put_text(&e, "public-key", 10);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_text(&e, "alg", 3);
    omk_cbor_put_nint(&e, -8);
    omk_cbor_put_text(&e, "type", 4);
    omk_cbor_put_text(&e, "public-key", 10);

    omk_cbor_put_uint(&e, 14);
    omk_cbor_put_uint(&e, OMK_CTAP_FIRMWARE_VERSION);

    omk_cbor_put_uint(&e, 20);
    omk_cbor_put_uint(&e, OMK_MAX_CREDENTIALS - ct->store.cred_count);

    if (e.overflow) {
        return OMK_CTAP2_ERR_REQUEST_TOO_LARGE;
    }
    ct->response_len = e.len;
    return OMK_CTAP2_OK;
}

/* ---------------------------------------------------------------------- */
/* Reset / Selection                                                       */
/* ---------------------------------------------------------------------- */

static uint8_t cmd_reset(omk_ctap *ct) {
    if (omk_ctap_now_ms(ct) - ct->boot_ms > OMK_CTAP_RESET_WINDOW_MS) {
        return OMK_CTAP2_ERR_NOT_ALLOWED;
    }
    const uint8_t up = omk_ctap_wait_up(ct);
    if (up != OMK_CTAP2_OK) {
        return up;
    }
    const int store_rc = omk_store_reset(&ct->store);
    if (store_rc != 0) {
        return omk_ctap_store_error(ct, store_rc);
    }
    /* The store was rebuilt, so a PIN flash fault latched before Reset no
     * longer applies.  A failed Reset above keeps it latched.  Invalidate the
     * whole live authorization/extension state, not just token_valid: a
     * pre-Reset PUAT, GA continuation, CredentialManagement cursor or
     * hmac-secret key must not survive into the fresh store. */
    ct->pin_store_fault = false;
    omk_ctap_puat_invalidate(ct);
    omk_ctap_pin_shared_clear(ct);
    omk_ctap_ga_clear(ct);
    omk_ctap_cm_clear(ct);
    ct->consecutive_pin_failures = 0;
    /* Reset has no response parameters: status-only success. */
    ct->response_len = 0;
    return OMK_CTAP2_OK;
}

static uint8_t cmd_selection(omk_ctap *ct) {
    const uint8_t up = omk_ctap_wait_up(ct);
    if (up == OMK_CTAP2_ERR_KEEPALIVE_CANCEL) {
        return OMK_CTAP2_ERR_OPERATION_DENIED;
    }
    if (up != OMK_CTAP2_OK) {
        return up;
    }
    /* Selection has no response parameters: status-only success. */
    ct->response_len = 0;
    return OMK_CTAP2_OK;
}

/* ---------------------------------------------------------------------- */
/* Dispatcher                                                              */
/* ---------------------------------------------------------------------- */

static uint8_t dispatch(omk_ctap *ct, uint8_t cmd, const omk_cbor_doc *doc,
                        const omk_cbor_val *req, uint32_t cid) {
    switch (cmd) {
    case 0x01:
        return omk_ctap_cmd_makecredential(ct, doc, req, cid);
    case 0x02:
        return omk_ctap_cmd_getassertion(ct, doc, req, cid);
    case 0x04:
        return cmd_get_info(ct);
    case 0x06:
        return omk_ctap_cmd_clientpin(ct, doc, req, cid);
    case 0x07:
        return cmd_reset(ct);
    case 0x08:
        return omk_ctap_cmd_getnextassertion(ct, cid);
    case 0x0A:
        return omk_ctap_cmd_credmgmt(ct, doc, req, cid);
    case 0x0B:
        return cmd_selection(ct);
    default:
        return OMK_CTAP1_ERR_INVALID_COMMAND;
    }
}

void omk_ctap_handle(void *ctx, uint32_t cid, const uint8_t *msg, size_t len) {
    omk_ctap *ct = (omk_ctap *)ctx;
    ct->response_len = 0;

    if (len < 1) {
        omk_ctap_send_status(ct, cid, OMK_CTAP1_ERR_INVALID_LENGTH);
        return;
    }
    const uint8_t cmd = msg[0];
    if (cmd != 0x08) {
        omk_ctap_ga_clear(ct);
    }
    if (cmd != 0x0A) {
        omk_ctap_cm_clear(ct);
    }

    /* Kept out of the (small) embedded stack: the arena is ~18 KiB. */
    static omk_cbor_doc doc;
    const omk_cbor_val *req = NULL;
    if (cmd == 0x04 || cmd == 0x07 || cmd == 0x08 || cmd == 0x0B) {
        memset(&doc, 0, sizeof doc);
    } else {
        omk_cbor_decode(&doc, msg + 1, len - 1);
        req = omk_cbor_root(&doc);
        if (req == NULL) {
            omk_ctap_send_status(ct, cid, OMK_CTAP2_ERR_INVALID_CBOR);
            return;
        }
        if (req->type != OMK_CBOR_MAP) {
            omk_ctap_send_status(ct, cid,
                                 OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            return;
        }
    }

    uint8_t status = dispatch(ct, cmd, &doc, req, cid);
    if (status == OMK_CTAP_ABORTED) {
        return;
    }
    if (status != OMK_CTAP2_OK) {
        omk_ctap_send_status(ct, cid, status);
        return;
    }
    /* Every CTAP response starts with a status byte.  A successful command
     * with no response parameters (Reset, Selection, PIN set/change,
     * CredentialManagement delete/update) is exactly one 0x00 byte; commands
     * with response parameters are 0x00 || CBOR. */
    if (ct->response_len == 0) {
        omk_ctap_send_status(ct, cid, OMK_CTAP2_OK);
        return;
    }
    if (ct->response_len >= sizeof ct->response) {
        /* No room for the status byte: the response cannot be framed. */
        omk_ctap_send_status(ct, cid, OMK_CTAP2_ERR_REQUEST_TOO_LARGE);
        return;
    }
    memmove(ct->response + 1, ct->response, ct->response_len);
    ct->response[0] = OMK_CTAP2_OK;
    ct->response_len++;
    omk_ctaphid_send(ct->hid, cid, ct->response, ct->response_len);
}

/* ---------------------------------------------------------------------- */
/* Init                                                                    */
/* ---------------------------------------------------------------------- */

static bool port_rng(void *ctx, void *out, size_t len) {
    omk_ctap *ct = (omk_ctap *)ctx;
    return ct->port->random_bytes(ct->port->ctx, out, len);
}

int omk_ctap_init(omk_ctap *ct, const omk_port *port, omk_ctaphid *hid) {
    memset(ct, 0, sizeof(*ct));
    ct->port = port;
    ct->hid = hid;
    if (omk_store_init(&ct->store, port) != 0) {
        return -1;
    }
    omk_p256_keypair kp;
    memset(&kp, 0, sizeof kp);
    if (!omk_p256_keygen(port_rng, ct, &kp)) {
        omk_memzero(&kp, sizeof kp);
        memset(ct, 0, sizeof(*ct));
        return -1;
    }
    memcpy(ct->pin.key_priv, kp.d, 32);
    memcpy(ct->pin.key_pub, kp.pub, 65);
    omk_memzero(&kp, sizeof kp);
    ct->boot_ms = port->now_ms(port->ctx);
    return 0;
}
