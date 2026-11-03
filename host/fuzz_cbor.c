/* libFuzzer harness for the CTAP CBOR parser. */
#include <stddef.h>
#include <stdint.h>

#include "fido/omk_cbor.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static omk_cbor_doc doc;
    omk_cbor_decode(&doc, data, size);
    const omk_cbor_val *root = omk_cbor_root(&doc);
    if (root == NULL) {
        return 0;
    }
    for (int64_t key = -4; key <= 12; key++) {
        const omk_cbor_val *v = omk_cbor_map_get_int(&doc, root, key);
        if (v != NULL && v->type == OMK_CBOR_ARRAY) {
            for (size_t i = 0; i < v->count && i < 8; i++) {
                (void)omk_cbor_array_get(&doc, v, i);
            }
        }
    }
    (void)omk_cbor_map_get_text(&doc, root, "id", 2);
    (void)omk_cbor_map_get_text(&doc, root, "hmac-secret-mc", 14);

    /* Re-encode the root head and every scalar to exercise the encoder. */
    uint8_t out[256];
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, out, sizeof out);
    omk_cbor_put_uint(&e, (uint64_t)size);
    omk_cbor_put_bytes(&e, data, size > 64 ? 64 : size);
    omk_cbor_put_nint(&e, -1);
    omk_cbor_put_bool(&e, true);
    omk_cbor_put_text(&e, "x", 1);
    return 0;
}
