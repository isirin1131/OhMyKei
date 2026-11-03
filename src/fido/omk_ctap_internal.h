/* Internal interfaces shared by the CTAP command handlers. */
#ifndef OMK_FIDO_CTAP_INTERNAL_H
#define OMK_FIDO_CTAP_INTERNAL_H

#include "fido/omk_ctap.h"
#include "fido/omk_cbor.h"

#define OMK_CTAP_ABORTED 0xFE
#define OMK_CTAP_PIN_PROBE 0xFD

/* ---- common helpers (omk_ctap.c) ---- */
uint64_t omk_ctap_now_ms(const omk_ctap *ct);
void omk_ctap_delay(omk_ctap *ct, uint32_t ms);
uint8_t omk_ctap_wait_up(omk_ctap *ct);
void omk_ctap_consume_up(omk_ctap *ct);
void omk_ctap_send_status(omk_ctap *ct, uint32_t cid, uint8_t status);
uint8_t omk_ctap_store_error(const omk_ctap *ct, int store_rc);
/* Full live-state invalidation, including seeds/salts/enumeration cursors. */
void omk_ctap_ga_clear(omk_ctap *ct);
void omk_ctap_cm_clear(omk_ctap *ct);
void omk_ctap_pin_shared_clear(omk_ctap *ct);

bool omk_ctap_val_uint(const omk_cbor_val *v, uint32_t *out);
bool omk_ctap_val_bytes(const omk_cbor_val *v, const uint8_t **data,
                        size_t *len);
bool omk_ctap_val_text(const omk_cbor_val *v, const uint8_t **data,
                       size_t *len);
size_t omk_ctap_build_cose_key(uint8_t *out, size_t cap, uint8_t alg,
                               const uint8_t pub[65]);
size_t omk_ctap_build_auth_data(const omk_ctap *ct, uint8_t *out, size_t cap,
                                const uint8_t rp_hash[32], uint8_t flags,
                                uint32_t counter, uint8_t alg,
                                const uint8_t *cred_id, size_t cred_id_len,
                                const uint8_t pub[65],
                                const uint8_t *ext_data, size_t ext_len);

/* ---- PIN/UV (omk_ctap_pin.c) ---- */
uint8_t omk_ctap_authorize(omk_ctap *ct, const omk_cbor_doc *doc,
                           const omk_cbor_val *req, uint32_t protocol,
                           const uint8_t *msg, size_t msg_len, uint8_t perm,
                           const uint8_t *rp_hash, bool *uv_out);
uint8_t omk_ctap_authorize_raw(omk_ctap *ct, const omk_cbor_val *param,
                               uint32_t protocol, const uint8_t *msg,
                               size_t msg_len, uint8_t perm,
                               const uint8_t *rp_hash, bool *uv_out);
bool omk_ctap_puat_valid(const omk_ctap *ct, uint8_t perm,
                         const uint8_t *rp_hash, bool *uv_out);
void omk_ctap_puat_invalidate(omk_ctap *ct);
uint8_t omk_ctap_cmd_clientpin(omk_ctap *ct, const omk_cbor_doc *doc,
                               const omk_cbor_val *req, uint32_t cid);

/* ---- credentials ---- */
uint8_t omk_ctap_cmd_makecredential(omk_ctap *ct, const omk_cbor_doc *doc,
                                    const omk_cbor_val *req, uint32_t cid);
uint8_t omk_ctap_cmd_getassertion(omk_ctap *ct, const omk_cbor_doc *doc,
                                  const omk_cbor_val *req, uint32_t cid);
uint8_t omk_ctap_cmd_getnextassertion(omk_ctap *ct, uint32_t cid);

/* ---- credential management ---- */
uint8_t omk_ctap_cmd_credmgmt(omk_ctap *ct, const omk_cbor_doc *doc,
                              const omk_cbor_val *req, uint32_t cid);

/* ---- extensions ---- */
bool omk_ctap_hmac_secret_output(const omk_ctap *ct,
                                 const uint8_t seed[32], bool uv,
                                 const uint8_t *salt, size_t salt_len,
                                 uint8_t *out, size_t *out_len);

/* Derive the credential public key from its stored seed. */
bool omk_ctap_cred_public_key(uint8_t alg, const uint8_t seed[32],
                              uint8_t pub[65], size_t *pub_len);
bool omk_ctap_sign(omk_ctap *ct, uint8_t alg, const uint8_t seed[32],
                   const uint8_t *data, size_t len, uint8_t *sig,
                   size_t *sig_len);

#endif /* OMK_FIDO_CTAP_INTERNAL_H */
