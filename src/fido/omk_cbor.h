/*
 * Strict CTAP2 CBOR decoding and canonical encoding.
 *
 * Decoder:
 *  - definite lengths only (indefinite length arrays/maps/strings are
 *    rejected), minimal-form integer heads required,
 *  - duplicate map keys are rejected (CTAP2_ERR_INVALID_CBOR),
 *  - any map key order is accepted on input (real clients do not always
 *    emit canonical map ordering), unknown keys are preserved so callers
 *    can skip them,
 *  - nesting depth is bounded (OMK_CBOR_MAX_DEPTH),
 *  - every node lives in a fixed-size arena inside the doc: no heap.
 *
 * Encoder: canonical CTAP2 encoding (minimal heads, definite lengths).
 * Map keys must be emitted by the caller in canonical order: integer keys
 * ascending, text keys by (length, bytes).
 */
#ifndef OMK_FIDO_CBOR_H
#define OMK_FIDO_CBOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define OMK_CBOR_MAX_DEPTH 8
#define OMK_CBOR_MAX_NODES 384

typedef enum {
    OMK_CBOR_UINT = 0,
    OMK_CBOR_NINT,
    OMK_CBOR_BYTES,
    OMK_CBOR_TEXT,
    OMK_CBOR_ARRAY,
    OMK_CBOR_MAP,
    OMK_CBOR_BOOL,
    OMK_CBOR_NULL,
} omk_cbor_type;

typedef struct {
    uint8_t type;
    bool boolean;
    /* UINT: value, NINT: -1 - value (as int64). */
    int64_t num;
    /* BYTES/TEXT payload (points into the input buffer). */
    const uint8_t *data;
    size_t len;
    /* ARRAY/MAP: index of first child; MAP children alternate key/value. */
    uint16_t first_child;
    /* Next sibling node index; 0xFFFF terminates. */
    uint16_t next;
    /* ARRAY: element count; MAP: pair count * 2. */
    uint16_t count;
    /* Raw encoded span of this item inside the input buffer. */
    uint32_t raw_off;
    uint32_t raw_len;
} omk_cbor_val;

typedef struct {
    const uint8_t *buf;
    size_t buf_len;
    omk_cbor_val vals[OMK_CBOR_MAX_NODES];
    size_t used;
    /* true when the decode rejected the input. */
    bool bad;
    bool has_root;
} omk_cbor_doc;

/* Decode a complete CBOR item; trailing bytes after the root item are an
 * error.  Every call initialises doc.  Returns true only for a valid item;
 * on rejection doc->bad is true, doc->has_root is false and the root is NULL. */
bool omk_cbor_decode(omk_cbor_doc *doc, const uint8_t *buf, size_t len);

/* Decode a single item and report how many bytes it consumed; trailing bytes
 * are allowed.  Returns true only for a valid item and then sets *used (when
 * non-NULL).  Rejection has the same doc state as omk_cbor_decode and reports
 * zero bytes used.  Used for structures embedded inside binary blobs. */
bool omk_cbor_decode_prefix(omk_cbor_doc *doc, const uint8_t *buf, size_t len,
                            size_t *used);

/* Root value; NULL if nothing was decoded. */
const omk_cbor_val *omk_cbor_root(const omk_cbor_doc *doc);

/* Map lookups: return NULL when the key is absent. */
const omk_cbor_val *omk_cbor_map_get_int(const omk_cbor_doc *doc,
                                         const omk_cbor_val *map, int64_t key);
const omk_cbor_val *omk_cbor_map_get_text(const omk_cbor_doc *doc,
                                          const omk_cbor_val *map,
                                          const char *key, size_t key_len);
/* Array element; NULL when out of bounds. */
const omk_cbor_val *omk_cbor_array_get(const omk_cbor_doc *doc,
                                       const omk_cbor_val *arr, size_t idx);

/* ---------------------------------------------------------------------- */
/* Encoder                                                                 */
/* ---------------------------------------------------------------------- */

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t len;
    bool overflow;
} omk_cbor_enc;

void omk_cbor_enc_init(omk_cbor_enc *e, uint8_t *buf, size_t cap);
void omk_cbor_put_uint(omk_cbor_enc *e, uint64_t v);
void omk_cbor_put_nint(omk_cbor_enc *e, int64_t v); /* v < 0 */
void omk_cbor_put_bytes(omk_cbor_enc *e, const void *data, size_t len);
void omk_cbor_put_text(omk_cbor_enc *e, const char *s, size_t len);
void omk_cbor_put_bool(omk_cbor_enc *e, bool b);
void omk_cbor_put_array(omk_cbor_enc *e, size_t count);
void omk_cbor_put_map(omk_cbor_enc *e, size_t pairs);
/* Append an already-encoded CBOR value without adding a byte-string header. */
void omk_cbor_put_raw(omk_cbor_enc *e, const void *data, size_t len);

#endif /* OMK_FIDO_CBOR_H */
