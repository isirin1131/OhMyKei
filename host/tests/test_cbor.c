/* CBOR decoder/encoder tests. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fido/omk_cbor.h"

static int g_failures;

static void check(bool cond, const char *what) {
    if (!cond) {
        printf("FAIL: %s\n", what);
        g_failures++;
    }
}

static bool decode_hex(omk_cbor_doc *doc, const char *hex) {
    static uint8_t buf[256];
    size_t n = 0;
    for (size_t i = 0; hex[i] != '\0';) {
        unsigned v = 0;
        int used = 0;
        if (sscanf(hex + i, "%2x%n", &v, &used) == 1) {
            buf[n++] = (uint8_t)v;
            i += (size_t)used;
        } else {
            i++;
        }
    }
    omk_cbor_decode(doc, buf, n);
    return omk_cbor_root(doc) != NULL;
}

static void test_request_map(void) {
    /* {1: "example.com", 2: h'0102', 3: {"up": true, "rk": false},
        4: [1, 2, 3], 5: -7, 6: 4294967296} */
    static const char *hex =
        "a6"
        "01 6b 6578616d706c652e636f6d"
        "02 42 0102"
        "03 a2 62 7570 f5 62 726b f4"
        "04 83 01 02 03"
        "05 26"
        "06 1b 0000000100000000";
    omk_cbor_doc doc;
    check(decode_hex(&doc, hex), "decode request map");
    const omk_cbor_val *root = omk_cbor_root(&doc);
    check(root != NULL && root->type == OMK_CBOR_MAP, "root is map");
    check(root != NULL && root->count == 12, "map has 6 pairs");

    const omk_cbor_val *v = omk_cbor_map_get_int(&doc, root, 1);
    check(v != NULL && v->type == OMK_CBOR_TEXT && v->len == 11 &&
              memcmp(v->data, "example.com", 11) == 0,
          "key 1 text");
    v = omk_cbor_map_get_int(&doc, root, 2);
    check(v != NULL && v->type == OMK_CBOR_BYTES && v->len == 2 &&
              v->data[0] == 1 && v->data[1] == 2,
          "key 2 bytes");
    v = omk_cbor_map_get_int(&doc, root, 3);
    check(v != NULL && v->type == OMK_CBOR_MAP, "key 3 map");
    if (v != NULL) {
        const omk_cbor_val *up = omk_cbor_map_get_text(&doc, v, "up", 2);
        const omk_cbor_val *rk = omk_cbor_map_get_text(&doc, v, "rk", 2);
        check(up != NULL && up->type == OMK_CBOR_BOOL && up->boolean,
              "up true");
        check(rk != NULL && rk->type == OMK_CBOR_BOOL && !rk->boolean,
              "rk false");
    }
    v = omk_cbor_map_get_int(&doc, root, 4);
    check(v != NULL && v->type == OMK_CBOR_ARRAY && v->count == 3, "key 4 arr");
    if (v != NULL) {
        const omk_cbor_val *e = omk_cbor_array_get(&doc, v, 2);
        check(e != NULL && e->type == OMK_CBOR_UINT && e->num == 3, "arr[2]");
    }
    v = omk_cbor_map_get_int(&doc, root, 5);
    check(v != NULL && v->type == OMK_CBOR_NINT && v->num == -7, "key 5 -7");
    v = omk_cbor_map_get_int(&doc, root, 6);
    check(v != NULL && v->type == OMK_CBOR_UINT && v->num == 4294967296LL,
          "key 6 2^32");
    check(omk_cbor_map_get_int(&doc, root, 99) == NULL, "missing key");
}

static void test_rejects(void) {
    omk_cbor_doc doc;
    /* duplicate integer keys: {1:1, 1:2} */
    check(!decode_hex(&doc, "a2 01 01 01 02"), "reject duplicate keys");
    /* duplicate text keys: {"up":1,"up":2} */
    check(!decode_hex(&doc, "a2 62 7570 01 62 7570 02"),
          "reject duplicate text keys");
    /* non-minimal uint 23: 0x18 0x17 */
    check(!decode_hex(&doc, "1817"), "reject non-minimal uint");
    /* non-minimal text length: 0x78 0x01 'a' */
    check(!decode_hex(&doc, "78 01 61"), "reject non-minimal text length");
    /* indefinite array */
    check(!decode_hex(&doc, "9f 01 ff"), "reject indefinite array");
    /* trailing byte */
    check(!decode_hex(&doc, "01 01"), "reject trailing bytes");
    /* truncated payload */
    check(!decode_hex(&doc, "43 0102"), "reject truncated bytes");
    /* map key that is not a scalar */
    check(!decode_hex(&doc, "a1 80 01"), "reject container key");
    /* undefined / floats */
    check(!decode_hex(&doc, "f7"), "reject undefined");
    check(!decode_hex(&doc, "fa 3f800000"), "reject float32");
    /* too deep (10 nested arrays) */
    check(!decode_hex(&doc,
                      "81 81 81 81 81 81 81 81 81 81 01"),
          "reject too deep");
}

static void test_map_keys(void) {
    omk_cbor_doc doc;
    /* Same-looking scalar values of different CBOR types are distinct keys;
     * null is accepted as an unknown key, but must still be unique. */
    check(decode_hex(&doc, "a8 00 00 20 00 40 00 60 00 f4 00 f5 00 f6 00 01 00"),
          "accept distinct scalar key types");
    static const char *duplicates[] = {
        "a2 20 00 20 01",       /* negative integer */
        "a2 41 61 00 41 61 01", /* byte string */
        "a2 40 00 40 01",       /* empty byte string */
        "a2 60 00 60 01",       /* empty text string */
        "a2 f4 00 f4 01",       /* false */
        "a2 f5 00 f5 01",       /* true */
        "a2 01 82 a1 02 03 80 01 00", /* duplicate after nested value */
    };
    for (size_t i = 0; i < sizeof duplicates / sizeof duplicates[0]; i++) {
        check(!decode_hex(&doc, duplicates[i]), "reject duplicate scalar key");
    }
    check(!decode_hex(&doc, "a2 f6 00 f6 01"), "reject duplicate null keys");
    check(decode_hex(&doc, "a3 01 a1 02 03 02 82 a1 01 04 80 03 a0"),
          "nested map keys have independent scope");
    const omk_cbor_val *last = omk_cbor_map_get_int(&doc, omk_cbor_root(&doc), 3);
    check(last != NULL && last->type == OMK_CBOR_MAP && last->count == 0,
          "lookup skips nested values");
    check(!decode_hex(&doc, "a2 01 00 02"), "reject missing final map value");
    check(!decode_hex(&doc, "a1 a0 00"), "reject map as key");

    uint8_t buf[1024];
    const size_t max_pairs = (OMK_CBOR_MAX_NODES - 1) / 2;
    for (unsigned variant = 0; variant < 3; variant++) {
        const size_t pairs = max_pairs + (variant == 2 ? 1 : 0);
        omk_cbor_enc e;
        omk_cbor_enc_init(&e, buf, sizeof buf);
        omk_cbor_put_map(&e, pairs);
        for (size_t i = 0; i < pairs; i++) {
            const bool duplicate = variant == 1 && i == pairs - 1;
            omk_cbor_put_uint(&e, duplicate ? pairs : pairs - i);
            omk_cbor_put_array(&e, 0);
        }
        check(!e.overflow, "encode map at node limit");
        const bool ok = omk_cbor_decode(&doc, buf, e.len);
        check(ok == (variant == 0),
              "accept full map; reject final duplicate and excess nodes");
        if (variant == 0) {
            last = omk_cbor_map_get_int(&doc, omk_cbor_root(&doc), 1);
            check(last != NULL && last->type == OMK_CBOR_ARRAY && last->count == 0,
                  "lookup last key in full reverse-order map");
        }
    }
}

static void test_api_contract(void) {
    static const uint8_t valid[] = {0x01};
    static const uint8_t trailing[] = {0x01, 0x00};
    static const uint8_t invalid[] = {0x18, 0x17}; /* non-minimal uint */
    omk_cbor_doc doc;
    size_t used = 99;

    memset(&doc, 0xA5, sizeof doc);
    check(omk_cbor_decode_prefix(&doc, trailing, sizeof trailing, &used),
          "prefix API accepts a valid root with trailing bytes");
    check(!doc.bad && doc.has_root && used == 1 &&
              omk_cbor_root(&doc) != NULL,
          "prefix API success state");

    check(omk_cbor_decode(&doc, valid, sizeof valid),
          "decode API accepts a complete item");
    check(!doc.bad && doc.has_root && omk_cbor_root(&doc) != NULL,
          "decode API success state");
    check(!omk_cbor_decode(&doc, trailing, sizeof trailing),
          "decode API rejects trailing bytes");
    check(doc.bad && !doc.has_root && omk_cbor_root(&doc) == NULL,
          "decode API trailing-byte failure state");

    memset(&doc, 0xA5, sizeof doc);
    used = 99;
    check(!omk_cbor_decode_prefix(&doc, invalid, sizeof invalid, &used),
          "prefix API rejects malformed input");
    check(doc.bad && !doc.has_root && used == 0 &&
              omk_cbor_root(&doc) == NULL,
          "prefix API malformed-input failure state");
}

static void test_encode(void) {
    uint8_t buf[64];
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, buf, sizeof buf);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_text(&e, "ok", 2);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_nint(&e, -7);
    check(!e.overflow, "encode no overflow");
    static const uint8_t want[] = {0xA2, 0x01, 0x62, 'o', 'k', 0x02, 0x26};
    check(e.len == sizeof want && memcmp(buf, want, sizeof want) == 0,
          "canonical encode");

    /* round-trip uint boundaries */
    static const uint64_t values[] = {0,   23,       24,        255,
                                     256, 65535,    65536,     4294967295u,
                                     4294967296ull};
    for (size_t i = 0; i < sizeof values / sizeof values[0]; i++) {
        omk_cbor_enc_init(&e, buf, sizeof buf);
        omk_cbor_put_uint(&e, values[i]);
        omk_cbor_doc doc;
        omk_cbor_decode(&doc, buf, e.len);
        const omk_cbor_val *v = omk_cbor_root(&doc);
        check(v != NULL && v->type == OMK_CBOR_UINT && v->num == (int64_t)values[i],
              "uint round-trip");
    }

    /* overflow is sticky and leaves a short buffer */
    omk_cbor_enc_init(&e, buf, 2);
    omk_cbor_put_text(&e, "hello", 5);
    check(e.overflow && e.len <= 2, "encoder overflow flag");

    static const uint8_t raw[] = {0xA1, 0x01, 0x02};
    omk_cbor_enc_init(&e, buf, sizeof raw);
    omk_cbor_put_raw(&e, raw, sizeof raw);
    check(!e.overflow && e.len == sizeof raw &&
              memcmp(buf, raw, sizeof raw) == 0,
          "raw CBOR encode");
    omk_cbor_enc_init(&e, buf, 2);
    omk_cbor_put_raw(&e, raw, sizeof raw);
    check(e.overflow && e.len == 0, "raw CBOR overflow writes no partial value");
}

static void test_encode_payload_capacity(void) {
    static const char payload[] = "abcdefghijklmnopqrstuvwx";
    const size_t payload_len = sizeof payload - 1;
    const size_t encoded_len = 2 + payload_len;
    uint8_t buf[32];
    for (unsigned text = 0; text < 2; text++) {
        for (size_t cap = 0; cap <= encoded_len; cap++) {
            memset(buf, 0xA5, sizeof buf);
            omk_cbor_enc e;
            omk_cbor_enc_init(&e, buf, cap);
            if (text) {
                omk_cbor_put_text(&e, payload, payload_len);
            } else {
                omk_cbor_put_bytes(&e, payload, payload_len);
            }
            check(e.len <= cap && e.overflow == (cap < encoded_len),
                  "payload encoding respects capacity and reports overflow");
            for (size_t i = cap; i < sizeof buf; i++) {
                check(buf[i] == 0xA5, "payload encoding preserves canary");
            }
            if (!e.overflow) {
                check(e.len == encoded_len && buf[0] == (text ? 0x78 : 0x58) &&
                          buf[1] == payload_len &&
                          memcmp(buf + 2, payload, payload_len) == 0,
                      "exact-fit payload encoding matches wire format");
            }
        }
    }
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, buf, 2);
    omk_cbor_put_bytes(&e, NULL, 0);
    omk_cbor_put_text(&e, NULL, 0);
    check(!e.overflow && e.len == 2 && buf[0] == 0x40 && buf[1] == 0x60,
          "empty payloads need only their headers");
}

int main(void) {
    test_request_map();
    test_rejects();
    test_map_keys();
    test_api_contract();
    test_encode();
    test_encode_payload_capacity();
    if (g_failures != 0) {
        printf("%d cbor test(s) failed\n", g_failures);
        return 1;
    }
    printf("cbor: all tests passed\n");
    return 0;
}
