#include "fido/omk_cbor.h"

#include <string.h>

#define CBOR_CHILD_NONE 0xFFFFu

static bool cbor_read_head(const uint8_t *buf, size_t len, size_t *pos,
                           uint8_t *major, uint64_t *arg) {
    if (*pos >= len) {
        return false;
    }
    const uint8_t ib = buf[(*pos)++];
    *major = (uint8_t)(ib >> 5);
    const uint8_t ai = (uint8_t)(ib & 0x1Fu);
    uint64_t val = 0;

    if (ai < 24) {
        val = ai;
    } else if (ai == 24) {
        if (*pos + 1 > len) {
            return false;
        }
        val = buf[(*pos)++];
        if (val < 24) {
            return false; /* non-minimal encoding */
        }
    } else if (ai == 25) {
        if (*pos + 2 > len) {
            return false;
        }
        val = ((uint64_t)buf[*pos] << 8) | buf[*pos + 1];
        *pos += 2;
        if (val <= 0xFFu) {
            return false;
        }
    } else if (ai == 26) {
        if (*pos + 4 > len) {
            return false;
        }
        val = ((uint64_t)buf[*pos] << 24) | ((uint64_t)buf[*pos + 1] << 16) |
              ((uint64_t)buf[*pos + 2] << 8) | buf[*pos + 3];
        *pos += 4;
        if (val <= 0xFFFFu) {
            return false;
        }
    } else if (ai == 27) {
        if (*pos + 8 > len) {
            return false;
        }
        for (int i = 0; i < 8; i++) {
            val = (val << 8) | buf[*pos + i];
        }
        *pos += 8;
        if (val <= 0xFFFFFFFFu) {
            return false;
        }
    } else {
        /* 28..30 reserved, 31 indefinite length: not allowed. */
        return false;
    }
    *arg = val;
    return true;
}

static bool cbor_key_equal(const omk_cbor_val *a, const omk_cbor_val *b) {
    if (a->type != b->type) {
        return false;
    }
    switch (a->type) {
    case OMK_CBOR_UINT:
    case OMK_CBOR_NINT:
        return a->num == b->num;
    case OMK_CBOR_BYTES:
    case OMK_CBOR_TEXT:
        return a->len == b->len && memcmp(a->data, b->data, a->len) == 0;
    case OMK_CBOR_BOOL:
        return a->boolean == b->boolean;
    default:
        return false;
    }
}

static bool cbor_key_is_scalar(const omk_cbor_val *v) {
    return v->type != OMK_CBOR_ARRAY && v->type != OMK_CBOR_MAP;
}

/* Returns the key node index of pair `pair`, or CBOR_CHILD_NONE. */
static uint16_t cbor_map_pair_key(const omk_cbor_doc *doc,
                                  const omk_cbor_val *map, uint64_t pair) {
    uint16_t k = map->first_child;
    for (uint64_t i = 0; i < pair; i++) {
        if (k == CBOR_CHILD_NONE) {
            return CBOR_CHILD_NONE;
        }
        const uint16_t v = doc->vals[k].next;
        if (v == CBOR_CHILD_NONE) {
            return CBOR_CHILD_NONE;
        }
        k = doc->vals[v].next;
    }
    return k;
}

static bool cbor_parse_item(omk_cbor_doc *doc, size_t *pos, unsigned depth) {
    if (depth > OMK_CBOR_MAX_DEPTH || doc->used >= OMK_CBOR_MAX_NODES) {
        return false;
    }

    const size_t start = *pos;
    uint8_t major = 0;
    uint64_t arg = 0;
    if (!cbor_read_head(doc->buf, doc->buf_len, pos, &major, &arg)) {
        return false;
    }

    const uint16_t idx = (uint16_t)doc->used++;
    omk_cbor_val *v = &doc->vals[idx];
    memset(v, 0, sizeof(*v));
    v->next = CBOR_CHILD_NONE;
    v->raw_off = (uint32_t)start;

    switch (major) {
    case 0:
    case 1:
        if (arg > (uint64_t)INT64_MAX) {
            return false;
        }
        v->type = (major == 0) ? OMK_CBOR_UINT : OMK_CBOR_NINT;
        v->num = (major == 0) ? (int64_t)arg : -1 - (int64_t)arg;
        v->raw_len = (uint32_t)(*pos - start);
        return true;

    case 2:
    case 3:
        if (arg > doc->buf_len - *pos) {
            return false;
        }
        v->type = (major == 2) ? OMK_CBOR_BYTES : OMK_CBOR_TEXT;
        v->data = doc->buf + *pos;
        v->len = (size_t)arg;
        *pos += (size_t)arg;
        v->raw_len = (uint32_t)(*pos - start);
        return true;

    case 4:
    case 5: {
        const bool is_map = (major == 5);
        const uint64_t items = is_map ? arg * 2u : arg;
        if (is_map && arg != 0 && items / 2u != arg) {
            return false;
        }
        if (items > (uint64_t)(OMK_CBOR_MAX_NODES - doc->used)) {
            return false;
        }
        v->type = is_map ? OMK_CBOR_MAP : OMK_CBOR_ARRAY;
        v->count = (uint16_t)items;

        uint16_t first = CBOR_CHILD_NONE;
        uint16_t prev = CBOR_CHILD_NONE;
        for (uint64_t i = 0; i < items; i++) {
            const uint16_t child = (uint16_t)doc->used;
            if (!cbor_parse_item(doc, pos, depth + 1)) {
                return false;
            }
            if (prev == CBOR_CHILD_NONE) {
                first = child;
            } else {
                doc->vals[prev].next = child;
            }
            prev = child;
        }
        v = &doc->vals[idx];
        v->first_child = first;
        v->raw_len = (uint32_t)(*pos - start);

        if (is_map) {
            for (uint64_t i = 0; i < arg; i++) {
                const uint16_t k = cbor_map_pair_key(doc, v, i);
                if (k == CBOR_CHILD_NONE || !cbor_key_is_scalar(&doc->vals[k])) {
                    return false;
                }
                for (uint64_t j = i + 1; j < arg; j++) {
                    const uint16_t k2 = cbor_map_pair_key(doc, v, j);
                    if (k2 == CBOR_CHILD_NONE) {
                        return false;
                    }
                    if (cbor_key_equal(&doc->vals[k], &doc->vals[k2])) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    case 7:
        if (arg == 20 || arg == 21) {
            v->type = OMK_CBOR_BOOL;
            v->boolean = (arg == 21);
            v->raw_len = (uint32_t)(*pos - start);
            return true;
        }
        if (arg == 22) {
            v->type = OMK_CBOR_NULL;
            v->raw_len = (uint32_t)(*pos - start);
            return true;
        }
        return false;

    default:
        /* Major 6 (tags) is not used by CTAP2. */
        return false;
    }
}

bool omk_cbor_decode_prefix(omk_cbor_doc *doc, const uint8_t *buf, size_t len,
                            size_t *used) {
    memset(doc, 0, sizeof(*doc));
    doc->buf = buf;
    doc->buf_len = len;
    size_t pos = 0;
    if (!cbor_parse_item(doc, &pos, 0)) {
        doc->bad = true;
        doc->has_root = false;
        if (used != NULL) {
            *used = 0;
        }
        return false;
    }
    doc->has_root = true;
    if (used != NULL) {
        *used = pos;
    }
    return true;
}

bool omk_cbor_decode(omk_cbor_doc *doc, const uint8_t *buf, size_t len) {
    size_t used = 0;
    if (!omk_cbor_decode_prefix(doc, buf, len, &used)) {
        return false;
    }
    if (used != len) {
        doc->bad = true;
        doc->has_root = false;
        return false;
    }
    return true;
}

const omk_cbor_val *omk_cbor_root(const omk_cbor_doc *doc) {
    if (!doc->has_root || doc->bad || doc->used == 0) {
        return NULL;
    }
    return &doc->vals[0];
}

const omk_cbor_val *omk_cbor_map_get_int(const omk_cbor_doc *doc,
                                         const omk_cbor_val *map, int64_t key) {
    if (map == NULL || map->type != OMK_CBOR_MAP) {
        return NULL;
    }
    uint16_t k = map->first_child;
    for (uint16_t i = 0; i < map->count && k != CBOR_CHILD_NONE; i += 2) {
        const omk_cbor_val *kv = &doc->vals[k];
        if ((kv->type == OMK_CBOR_UINT || kv->type == OMK_CBOR_NINT) &&
            kv->num == key) {
            const uint16_t vi = kv->next;
            return (vi == CBOR_CHILD_NONE) ? NULL : &doc->vals[vi];
        }
        const uint16_t vi = kv->next;
        if (vi == CBOR_CHILD_NONE) {
            return NULL;
        }
        k = doc->vals[vi].next;
    }
    return NULL;
}

const omk_cbor_val *omk_cbor_map_get_text(const omk_cbor_doc *doc,
                                          const omk_cbor_val *map,
                                          const char *key, size_t key_len) {
    if (map == NULL || map->type != OMK_CBOR_MAP) {
        return NULL;
    }
    uint16_t k = map->first_child;
    for (uint16_t i = 0; i < map->count && k != CBOR_CHILD_NONE; i += 2) {
        const omk_cbor_val *kv = &doc->vals[k];
        if (kv->type == OMK_CBOR_TEXT && kv->len == key_len &&
            memcmp(kv->data, key, key_len) == 0) {
            const uint16_t vi = kv->next;
            return (vi == CBOR_CHILD_NONE) ? NULL : &doc->vals[vi];
        }
        const uint16_t vi = kv->next;
        if (vi == CBOR_CHILD_NONE) {
            return NULL;
        }
        k = doc->vals[vi].next;
    }
    return NULL;
}

const omk_cbor_val *omk_cbor_array_get(const omk_cbor_doc *doc,
                                       const omk_cbor_val *arr, size_t idx) {
    if (arr == NULL || arr->type != OMK_CBOR_ARRAY || idx >= arr->count) {
        return NULL;
    }
    uint16_t n = arr->first_child;
    for (size_t i = 0; i < idx && n != CBOR_CHILD_NONE; i++) {
        n = doc->vals[n].next;
    }
    return (n == CBOR_CHILD_NONE) ? NULL : &doc->vals[n];
}

/* ---------------------------------------------------------------------- */
/* Encoder                                                                 */
/* ---------------------------------------------------------------------- */

void omk_cbor_enc_init(omk_cbor_enc *e, uint8_t *buf, size_t cap) {
    e->buf = buf;
    e->cap = cap;
    e->len = 0;
    e->overflow = false;
}

static void cbor_put_byte(omk_cbor_enc *e, uint8_t b) {
    if (e->len >= e->cap) {
        e->overflow = true;
        return;
    }
    e->buf[e->len++] = b;
}

static void cbor_put_head(omk_cbor_enc *e, uint8_t major, uint64_t arg) {
    const uint8_t m = (uint8_t)(major << 5);
    if (arg < 24) {
        cbor_put_byte(e, (uint8_t)(m | arg));
    } else if (arg <= 0xFFu) {
        cbor_put_byte(e, (uint8_t)(m | 24));
        cbor_put_byte(e, (uint8_t)arg);
    } else if (arg <= 0xFFFFu) {
        cbor_put_byte(e, (uint8_t)(m | 25));
        cbor_put_byte(e, (uint8_t)(arg >> 8));
        cbor_put_byte(e, (uint8_t)arg);
    } else if (arg <= 0xFFFFFFFFu) {
        cbor_put_byte(e, (uint8_t)(m | 26));
        for (int i = 3; i >= 0; i--) {
            cbor_put_byte(e, (uint8_t)(arg >> (8 * i)));
        }
    } else {
        cbor_put_byte(e, (uint8_t)(m | 27));
        for (int i = 7; i >= 0; i--) {
            cbor_put_byte(e, (uint8_t)(arg >> (8 * i)));
        }
    }
}

void omk_cbor_put_uint(omk_cbor_enc *e, uint64_t v) {
    cbor_put_head(e, 0, v);
}

void omk_cbor_put_nint(omk_cbor_enc *e, int64_t v) {
    if (v >= 0) {
        e->overflow = true;
        return;
    }
    cbor_put_head(e, 1, (uint64_t)(-1 - v));
}

void omk_cbor_put_bytes(omk_cbor_enc *e, const void *data, size_t len) {
    cbor_put_head(e, 2, len);
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < len; i++) {
        cbor_put_byte(e, p[i]);
    }
}

void omk_cbor_put_text(omk_cbor_enc *e, const char *s, size_t len) {
    cbor_put_head(e, 3, len);
    for (size_t i = 0; i < len; i++) {
        cbor_put_byte(e, (uint8_t)s[i]);
    }
}

void omk_cbor_put_bool(omk_cbor_enc *e, bool b) {
    cbor_put_byte(e, b ? 0xF5 : 0xF4);
}

void omk_cbor_put_array(omk_cbor_enc *e, size_t count) {
    cbor_put_head(e, 4, count);
}

void omk_cbor_put_map(omk_cbor_enc *e, size_t pairs) {
    cbor_put_head(e, 5, pairs);
}

void omk_cbor_put_raw(omk_cbor_enc *e, const void *data, size_t len) {
    if (len > e->cap - e->len) {
        e->overflow = true;
        return;
    }
    if (len != 0) {
        memcpy(e->buf + e->len, data, len);
        e->len += len;
    }
}
