/* End-to-end CTAP core tests through the real CBOR/CTAPHID/store stack. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto/omk_crypto.h"
#include "fido/omk_cbor.h"
#include "fido/omk_ctap.h"
#include "fido/omk_ctap_internal.h"

static int g_failures;
static void check(bool cond, const char *what) {
    if (!cond) {
        printf("FAIL: %s\n", what);
        g_failures++;
    }
}

static uint8_t g_flash[OMK_FLASH_REGION_SIZE];

typedef struct {
    uint64_t now;
    uint32_t rng;
    bool auto_up;
    bool fail_write;
    bool fail_erase;
    bool fail_random;
    bool cancel_long_op;
    long random_fail_at; /* 1-based random call to fail, 0 = disabled */
    long random_calls;
    /* Fail the first read after the next successful write: this targets the
     * read-back verification that makes an append-only meta write durable. */
    bool fail_readback;
    bool readback_armed;
    /* -1: writes always succeed; 0: fail the next write; N: allow N writes. */
    int write_fail_after;
    uint8_t packets[256][64];
    size_t packet_count;
} env_t;

static uint64_t env_now(void *ctx) { return ((env_t *)ctx)->now; }

static bool env_random(void *ctx, void *out, size_t len) {
    env_t *e = (env_t *)ctx;
    uint8_t *p = (uint8_t *)out;
    const bool fail = e->fail_random || (e->random_fail_at > 0 &&
                                         ++e->random_calls == e->random_fail_at);
    const size_t fill = fail ? (len + 1u) / 2u : len;
    for (size_t i = 0; i < fill; i++) {
        e->rng ^= e->rng << 13;
        e->rng ^= e->rng >> 17;
        e->rng ^= e->rng << 5;
        p[i] = (uint8_t)(e->rng >> 24);
    }
    if (fail) {
        return false; /* partial output must be discarded by the caller */
    }
    return true;
}

static int env_read(void *ctx, uint32_t off, void *dst, size_t len) {
    env_t *e = (env_t *)ctx;
    if (e->readback_armed) {
        e->readback_armed = false;
        return -1;
    }
    if (off < OMK_FLASH_REGION_OFF ||
        off + len > OMK_FLASH_REGION_OFF + OMK_FLASH_REGION_SIZE) {
        return -1;
    }
    memcpy(dst, g_flash + (off - OMK_FLASH_REGION_OFF), len);
    return 0;
}

static int env_write(void *ctx, uint32_t off, const void *src, size_t len) {
    env_t *e = (env_t *)ctx;
    if (e->fail_write) {
        return -1;
    }
    if (e->write_fail_after >= 0) {
        if (e->write_fail_after == 0) {
            return -1;
        }
        e->write_fail_after--;
    }
    if (off < OMK_FLASH_REGION_OFF ||
        off + len > OMK_FLASH_REGION_OFF + OMK_FLASH_REGION_SIZE) {
        return -1;
    }
    memcpy(g_flash + (off - OMK_FLASH_REGION_OFF), src, len);
    if (e->fail_readback) {
        e->readback_armed = true;
    }
    return 0;
}

static int env_erase(void *ctx, uint32_t off) {
    env_t *e = (env_t *)ctx;
    if (e->fail_erase) {
        return -1;
    }
    if (off < OMK_FLASH_REGION_OFF ||
        off + OMK_FLASH_SECTOR_SIZE >
            OMK_FLASH_REGION_OFF + OMK_FLASH_REGION_SIZE) {
        return -1;
    }
    memset(g_flash + (off - OMK_FLASH_REGION_OFF), 0xFF,
           OMK_FLASH_SECTOR_SIZE);
    return 0;
}

static bool env_up(void *ctx) {
    env_t *e = (env_t *)ctx;
    if (!e->auto_up) {
        return false;
    }
    const uint64_t phase = (e->now / 10) % 30;
    return phase >= 5 && phase < 9;
}

static void env_led(void *ctx, bool on) {
    (void)ctx;
    (void)on;
}

static bool env_send(void *ctx, const uint8_t packet[64]) {
    env_t *e = (env_t *)ctx;
    if (e->packet_count < 256) {
        memcpy(e->packets[e->packet_count++], packet, 64);
        return true;
    }
    return false;
}

static void env_delay(void *ctx, uint32_t ms) {
    ((env_t *)ctx)->now += ms;
}

static bool env_long_op_poll(void *ctx) {
    return !((env_t *)ctx)->cancel_long_op;
}

typedef struct {
    env_t env;
    omk_port port;
    omk_ctaphid hid;
    omk_ctap ct;
} fixture;

static void fixture_init(fixture *f) {
    memset(f, 0, sizeof(*f));
    memset(g_flash, 0xFF, sizeof g_flash);
    f->env.rng = 0xC0FFEEu;
    f->env.now = 1000;
    f->env.auto_up = true;
    f->env.write_fail_after = -1;
    f->env.fail_random = false;
    f->env.random_fail_at = 0;
    f->env.random_calls = 0;
    f->port.ctx = &f->env;
    f->port.now_ms = env_now;
    f->port.random_bytes = env_random;
    f->port.flash_read = env_read;
    f->port.flash_write = env_write;
    f->port.flash_erase = env_erase;
    f->port.up_pressed = env_up;
    f->port.led = env_led;
    f->port.hid_send = env_send;
    f->port.hid_pump = NULL;
    f->port.delay_ms = env_delay;
    f->port.long_op_poll = env_long_op_poll;
    omk_ctaphid_init(&f->hid, &f->port, NULL, NULL);
    check(omk_ctap_init(&f->ct, &f->port, &f->hid) == 0, "ctap init");
}

/* Assemble the last CTAPHID_CBOR message from captured packets. */
static bool last_cbor(const env_t *e, uint8_t *out, size_t cap, size_t *len) {
    bool found = false;
    size_t expected = 0;
    size_t got = 0;
    for (size_t i = 0; i < e->packet_count; i++) {
        const uint8_t *p = e->packets[i];
        const uint8_t b = p[4];
        if ((b & 0x80u) != 0) {
            if (b == OMK_CTAPHID_CMD_CBOR) {
                expected = (size_t)((p[5] << 8) | p[6]);
                got = expected < 57 ? expected : 57;
                if (got > cap) {
                    return false;
                }
                memcpy(out, p + 7, got);
                found = true;
            } else {
                found = false;
            }
        } else if (found && got < expected) {
            size_t chunk = expected - got;
            if (chunk > 59) {
                chunk = 59;
            }
            if (got + chunk > cap) {
                return false;
            }
            memcpy(out + got, p + 5, chunk);
            got += chunk;
        }
    }
    if (found && got == expected) {
        *len = got;
        return true;
    }
    return false;
}

/* Send a command and capture the raw CTAPHID_CBOR payload, which is
 * CTAP status byte || optional CBOR response parameters. */
static bool send_cmd_raw(fixture *f, uint8_t cmd, const uint8_t *body,
                         size_t body_len, uint8_t *resp, size_t cap,
                         size_t *resp_len) {
    uint8_t msg[OMK_CTAP_MAX_MSG];
    if (body_len + 1 > sizeof msg) {
        return false;
    }
    msg[0] = cmd;
    if (body_len != 0) {
        memcpy(msg + 1, body, body_len);
    }
    f->env.packet_count = 0;
    omk_ctap_handle(&f->ct, 0x11223344, msg, body_len + 1);
    size_t len = 0;
    if (!last_cbor(&f->env, resp, cap, &len)) {
        return false;
    }
    *resp_len = len;
    return true;
}

/* Strict CTAP framing helper: the response must start with a status byte.
 * Errors are status-only; success is 0x00 followed by an optional CBOR body,
 * which is stripped into resp.  Returns the CTAP status, or 0xFF when no
 * well-formed response arrived (a response without a status byte fails). */
static uint8_t send_cmd(fixture *f, uint8_t cmd, const uint8_t *body,
                        size_t body_len, uint8_t *resp, size_t cap,
                        size_t *resp_len) {
    *resp_len = 0;
    uint8_t full[OMK_CTAP_MAX_MSG];
    size_t full_len = 0;
    if (!send_cmd_raw(f, cmd, body, body_len, full, sizeof full, &full_len)) {
        return 0xFF;
    }
    if (full_len < 1) {
        return 0xFF;
    }
    const uint8_t status = full[0];
    if (status != 0) {
        if (full_len != 1) {
            return 0xFF; /* malformed: an error must carry no CBOR body */
        }
        return status;
    }
    const size_t body_out = full_len - 1;
    if (body_out > cap) {
        return 0xFF;
    }
    memmove(resp, full + 1, body_out);
    *resp_len = body_out;
    return 0;
}

static size_t build_mc_ex(uint8_t *out, size_t cap, const uint8_t cdh[32],
                          const char *rp, const uint8_t *uid, size_t uid_len,
                          bool rk, bool eddsa, bool hmac_secret,
                          uint8_t cred_protect) {
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, out, cap);
    omk_cbor_put_map(&e, 5u + ((hmac_secret || cred_protect != 0) ? 1u : 0u));
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_bytes(&e, cdh, 32);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_text(&e, rp, strlen(rp));
    omk_cbor_put_text(&e, "name", 4);
    omk_cbor_put_text(&e, rp, strlen(rp));
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_bytes(&e, uid, uid_len);
    omk_cbor_put_text(&e, "displayName", 11);
    omk_cbor_put_text(&e, "User", 4);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_array(&e, 1);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_text(&e, "alg", 3);
    omk_cbor_put_nint(&e, eddsa ? -8 : -7);
    omk_cbor_put_text(&e, "type", 4);
    omk_cbor_put_text(&e, "public-key", 10);
    if (hmac_secret || cred_protect != 0) {
        omk_cbor_put_uint(&e, 6);
        omk_cbor_put_map(&e, (hmac_secret ? 1u : 0u) +
                                 (cred_protect != 0 ? 1u : 0u));
        if (hmac_secret) {
            omk_cbor_put_text(&e, "hmac-secret", 11);
            omk_cbor_put_bool(&e, true);
        }
        if (cred_protect != 0) {
            omk_cbor_put_text(&e, "credProtect", 11);
            omk_cbor_put_uint(&e, cred_protect);
        }
    }
    omk_cbor_put_uint(&e, 7);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "rk", 2);
    omk_cbor_put_bool(&e, rk);
    return e.overflow ? 0 : e.len;
}

static size_t build_mc(uint8_t *out, size_t cap, const uint8_t cdh[32],
                       const char *rp, const uint8_t *uid, size_t uid_len,
                       bool rk, bool eddsa, bool hmac_secret) {
    return build_mc_ex(out, cap, cdh, rp, uid, uid_len, rk, eddsa, hmac_secret,
                       0);
}

typedef struct {
    uint8_t cred_id[OMK_CRED_ID_MAX];
    size_t cred_id_len;
    uint8_t pub[65];
    size_t pub_len;
    uint8_t auth_data[512];
    size_t auth_len;
    bool has_extensions;
    bool cred_protect_echo;
    uint32_t cred_protect;
    size_t ext_offset;
    size_t ext_len;
} mc_result;

static bool parse_mc(const uint8_t *resp, size_t len, mc_result *out) {
    memset(out, 0, sizeof *out);
    if (len == 0) {
        return false;
    }
    omk_cbor_doc doc;
    omk_cbor_decode(&doc, resp, len);
    const omk_cbor_val *root = omk_cbor_root(&doc);
    if (root == NULL || root->type != OMK_CBOR_MAP) {
        return false;
    }
    const omk_cbor_val *ad = omk_cbor_map_get_int(&doc, root, 2);
    if (ad == NULL || ad->type != OMK_CBOR_BYTES || ad->len < 55 ||
        ad->len > sizeof out->auth_data) {
        return false;
    }
    memcpy(out->auth_data, ad->data, ad->len);
    out->auth_len = ad->len;
    size_t o = 37 + 16;
    const size_t id_len = ((size_t)ad->data[o] << 8) | ad->data[o + 1];
    o += 2;
    if (o + id_len > ad->len || id_len > OMK_CRED_ID_MAX) {
        return false;
    }
    memcpy(out->cred_id, ad->data + o, id_len);
    out->cred_id_len = id_len;
    o += id_len;
    omk_cbor_doc keydoc;
    size_t key_used = 0;
    omk_cbor_decode_prefix(&keydoc, ad->data + o, ad->len - o, &key_used);
    const omk_cbor_val *key = omk_cbor_root(&keydoc);
    if (key == NULL || key->type != OMK_CBOR_MAP) {
        return false;
    }
    const omk_cbor_val *x = omk_cbor_map_get_int(&keydoc, key, -2);
    const omk_cbor_val *y = omk_cbor_map_get_int(&keydoc, key, -3);
    if (x != NULL && y != NULL) {
        out->pub[0] = 0x04;
        memcpy(out->pub + 1, x->data, 32);
        memcpy(out->pub + 33, y->data, 32);
        out->pub_len = 65;
    } else {
        const omk_cbor_val *ed = omk_cbor_map_get_int(&keydoc, key, -2);
        if (ed == NULL || ed->type != OMK_CBOR_BYTES || ed->len != 32) {
            return false;
        }
        memcpy(out->pub, ed->data, 32);
        out->pub_len = 32;
    }
    o += key_used;
    if (o < ad->len) {
        out->ext_offset = o;
        out->ext_len = ad->len - o;
        omk_cbor_doc extdoc;
        omk_cbor_decode(&extdoc, ad->data + o, ad->len - o);
        const omk_cbor_val *ext = omk_cbor_root(&extdoc);
        if (ext == NULL || ext->type != OMK_CBOR_MAP) {
            return false;
        }
        out->has_extensions = true;
        const omk_cbor_val *cp =
            omk_cbor_map_get_text(&extdoc, ext, "credProtect", 11);
        if (cp != NULL) {
            if (!omk_ctap_val_uint(cp, &out->cred_protect)) {
                return false;
            }
            out->cred_protect_echo = true;
        }
    }
    return true;
}

static void test_getinfo(fixture *f) {
    uint8_t resp[512];
    size_t len = 0;
    uint8_t status = send_cmd(f, 0x04, NULL, 0, resp, sizeof resp, &len);
    check(status == 0, "getInfo status");
    omk_cbor_doc doc;
    omk_cbor_decode(&doc, resp, len);
    const omk_cbor_val *root = omk_cbor_root(&doc);
    check(root != NULL && root->type == OMK_CBOR_MAP, "getInfo map");
    const omk_cbor_val *versions = omk_cbor_map_get_int(&doc, root, 1);
    check(versions != NULL && versions->type == OMK_CBOR_ARRAY &&
              versions->count == 3,
          "getInfo versions");
    const omk_cbor_val *ext = omk_cbor_map_get_int(&doc, root, 2);
    check(ext != NULL && ext->type == OMK_CBOR_ARRAY && ext->count == 3,
          "getInfo extensions");
    const omk_cbor_val *opts = omk_cbor_map_get_int(&doc, root, 4);
    check(opts != NULL, "getInfo options");
    if (opts != NULL) {
        const omk_cbor_val *rk = omk_cbor_map_get_text(&doc, opts, "rk", 2);
        const omk_cbor_val *cm =
            omk_cbor_map_get_text(&doc, opts, "credMgmt", 8);
        check(rk != NULL && rk->boolean, "getInfo rk");
        check(cm != NULL && cm->boolean, "getInfo credMgmt");
    }
    const omk_cbor_val *aaguid = omk_cbor_map_get_int(&doc, root, 3);
    check(aaguid != NULL && aaguid->type == OMK_CBOR_BYTES && aaguid->len == 16,
          "getInfo aaguid");
    const omk_cbor_val *algos = omk_cbor_map_get_int(&doc, root, 10);
    check(algos != NULL && algos->count == 2, "getInfo algorithms");
}

static void test_response_framing(fixture *f) {
    uint8_t resp[OMK_CTAP_MAX_MSG];
    size_t len = 0;

    /* getInfo must be status byte 0x00 followed by the CBOR map 0xAC... */
    check(send_cmd_raw(f, 0x04, NULL, 0, resp, sizeof resp, &len),
          "raw getInfo response");
    check(len >= 2, "raw getInfo has status byte and body");
    check(resp[0] == OMK_CTAP2_OK, "raw getInfo first byte is 0x00");
    check(resp[1] == 0xAC, "raw getInfo body begins with CBOR map");

    /* Selection has no response parameters: exactly one 0x00 byte. */
    len = 0;
    check(send_cmd_raw(f, 0x0B, NULL, 0, resp, sizeof resp, &len),
          "raw Selection response");
    check(len == 1, "status-only success length is 1");
    check(resp[0] == OMK_CTAP2_OK, "status-only success is single 0x00");

    /* An error response is status-only too. */
    static const uint8_t empty_map[] = {0xA0};
    len = 0;
    check(send_cmd_raw(f, 0x40, empty_map, sizeof empty_map, resp, sizeof resp,
                       &len),
          "raw unsupported command response");
    check(len == 1 && resp[0] == OMK_CTAP1_ERR_INVALID_COMMAND,
          "error response is a single status byte");
}

static void check_attestation_format_order(fixture *f, const char *first,
                                           const char *second,
                                           const char *expected) {
    uint8_t cdh[32];
    memset(cdh, 0x42, sizeof cdh);
    uint8_t uid[4] = {1, 2, 3, 4};
    uint8_t body[512];
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 5);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_bytes(&e, cdh, sizeof cdh);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_text(&e, "formats.test", 12);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_bytes(&e, uid, sizeof uid);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_array(&e, 1);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_text(&e, "alg", 3);
    omk_cbor_put_nint(&e, -7);
    omk_cbor_put_text(&e, "type", 4);
    omk_cbor_put_text(&e, "public-key", 10);
    omk_cbor_put_uint(&e, 0x0B);
    omk_cbor_put_array(&e, second != NULL ? 2 : 1);
    omk_cbor_put_text(&e, first, strlen(first));
    if (second != NULL) {
        omk_cbor_put_text(&e, second, strlen(second));
    }
    check(!e.overflow, "attestation format request encoding");

    uint8_t resp[1024];
    size_t len = 0;
    const uint8_t status =
        send_cmd(f, 0x01, body, e.len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_OK, "attestation format request status");
    omk_cbor_doc doc;
    omk_cbor_decode(&doc, resp, len);
    const omk_cbor_val *root = omk_cbor_root(&doc);
    const omk_cbor_val *fmt = omk_cbor_map_get_int(&doc, root, 1);
    check(fmt != NULL && fmt->type == OMK_CBOR_TEXT &&
              fmt->len == strlen(expected) &&
              memcmp(fmt->data, expected, fmt->len) == 0,
          "attestation format honours client preference order");
}

static void test_attestation_format_order(fixture *f) {
    check_attestation_format_order(f, "none", "packed", "none");
    check_attestation_format_order(f, "packed", "none", "packed");
    check_attestation_format_order(f, "none", NULL, "none");
}

/* Parse the wire format independently of the firmware's DER encoder. */
static bool decode_es256_signature(const omk_cbor_val *sig, uint8_t raw[64]) {
    if (sig == NULL || sig->type != OMK_CBOR_BYTES || sig->len < 8 ||
        sig->len > 72 || sig->data[0] != 0x30 ||
        sig->data[1] != sig->len - 2) {
        return false;
    }
    memset(raw, 0, 64);
    size_t pos = 2;
    for (size_t i = 0; i < 2; i++) {
        if (pos + 2 > sig->len || sig->data[pos++] != 0x02) {
            return false;
        }
        size_t n = sig->data[pos++];
        if (n == 0 || n > 33 || n > sig->len - pos ||
            (sig->data[pos] & 0x80u) != 0) {
            return false;
        }
        if (sig->data[pos] == 0 && n > 1) {
            if ((sig->data[pos + 1] & 0x80u) == 0) {
                return false; /* redundant leading zero */
            }
            pos++;
            n--;
        }
        if (n > 32) {
            return false;
        }
        memcpy(raw + i * 32 + 32 - n, sig->data + pos, n);
        pos += n;
    }
    return pos == sig->len;
}

static void put_test_descriptor(omk_cbor_enc *e, const uint8_t *id,
                                 size_t len) {
    omk_cbor_put_map(e, 2);
    omk_cbor_put_text(e, "id", 2);
    omk_cbor_put_bytes(e, id, len);
    omk_cbor_put_text(e, "type", 4);
    omk_cbor_put_text(e, "public-key", 10);
}

static const omk_cbor_val *cm_response_id(const omk_cbor_doc *doc,
                                         const omk_cbor_val *root) {
    const omk_cbor_val *descriptor = omk_cbor_map_get_int(doc, root, 7);
    const omk_cbor_val *type =
        omk_cbor_map_get_text(doc, descriptor, "type", 4);
    const omk_cbor_val *id = omk_cbor_map_get_text(doc, descriptor, "id", 2);
    check(descriptor != NULL && descriptor->type == OMK_CBOR_MAP &&
              type != NULL && type->type == OMK_CBOR_TEXT && type->len == 10 &&
              memcmp(type->data, "public-key", 10) == 0 && id != NULL &&
              id->type == OMK_CBOR_BYTES,
          "CM response contains a public-key credential descriptor");
    return id;
}

static void test_makecredential_assertion(fixture *f) {
    uint8_t cdh[32];
    memset(cdh, 0x42, sizeof cdh);
    uint8_t uid[16];
    memset(uid, 0x11, sizeof uid);
    uint8_t body[512];
    const size_t body_len =
        build_mc(body, sizeof body, cdh, "example.com", uid, sizeof uid, false,
                 false, false);
    uint8_t resp[1024];
    size_t len = 0;
    uint8_t status =
        send_cmd(f, 0x01, body, body_len, resp, sizeof resp, &len);
    check(status == 0, "makeCredential status");
    mc_result mc;
    check(parse_mc(resp, len, &mc), "makeCredential parse");

    /* Verify the RP ID hash and UP|AT flags. */
    uint8_t rp_hash[32];
    omk_sha256("example.com", 11, rp_hash);
    check(memcmp(mc.auth_data, rp_hash, 32) == 0, "mc rpIdHash");
    check((mc.auth_data[32] & 0x41) == 0x41, "mc UP|AT flags");
    check(memcmp(mc.auth_data + 37, f->ct.store.aaguid, 16) == 0, "mc aaguid");

    /* Verify the self-attestation signature. */
    omk_cbor_doc doc;
    omk_cbor_decode(&doc, resp, len);
    const omk_cbor_val *root = omk_cbor_root(&doc);
    const omk_cbor_val *fmt = omk_cbor_map_get_int(&doc, root, 1);
    const omk_cbor_val *att = omk_cbor_map_get_int(&doc, root, 3);
    check(fmt != NULL && fmt->type == OMK_CBOR_TEXT && fmt->len == 6 &&
              memcmp(fmt->data, "packed", 6) == 0,
          "mc packed fmt");
    const omk_cbor_val *sig =
        att != NULL ? omk_cbor_map_get_text(&doc, att, "sig", 3) : NULL;
    uint8_t raw_sig[64];
    const bool att_der = decode_es256_signature(sig, raw_sig);
    check(att_der, "mc attestation signature is canonical DER");
    if (att_der) {
        uint8_t input[768];
        memcpy(input, mc.auth_data, mc.auth_len);
        memcpy(input + mc.auth_len, cdh, 32);
        uint8_t hash[32];
        omk_sha256(input, mc.auth_len + 32, hash);
        check(omk_p256_ecdsa_verify(mc.pub, hash, raw_sig),
              "mc attestation verifies");
    }

    /* GetAssertion by credential ID. */
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 3);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_text(&e, "example.com", 11);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_bytes(&e, cdh, 32);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_array(&e, 1);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_text(&e, "type", 4);
    omk_cbor_put_text(&e, "public-key", 10);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_bytes(&e, mc.cred_id, mc.cred_id_len);
    memset(resp, 0, sizeof resp);
    status = send_cmd(f, 0x02, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "getAssertion status");
    omk_cbor_doc gdoc;
    omk_cbor_decode(&gdoc, resp, len);
    const omk_cbor_val *groot = omk_cbor_root(&gdoc);
    const omk_cbor_val *ad = omk_cbor_map_get_int(&gdoc, groot, 2);
    const omk_cbor_val *gsig = omk_cbor_map_get_int(&gdoc, groot, 3);
    check(ad != NULL && ad->type == OMK_CBOR_BYTES && ad->len == 37,
          "assertion authData length");
    const bool ga_der = decode_es256_signature(gsig, raw_sig);
    check(ga_der, "assertion signature is canonical DER");
    if (ad != NULL && ga_der) {
        uint8_t input[128];
        memcpy(input, ad->data, ad->len);
        memcpy(input + ad->len, cdh, 32);
        uint8_t hash[32];
        omk_sha256(input, ad->len + 32, hash);
        check(omk_p256_ecdsa_verify(mc.pub, hash, raw_sig),
              "assertion verifies");
        check((ad->data[32] & 0x01) != 0, "assertion UP flag");
    }
}

static void test_assertion_key_validation(void) {
    fixture f;
    fixture_init(&f);
    static const char rp[] = "scalar.test";
    uint8_t rp_hash[32], cdh[32] = {0};
    omk_sha256(rp, sizeof rp - 1, rp_hash);
    /* Public P-256 order, used only to exercise scalar boundaries. */
    static const uint8_t order[32] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    };
    for (unsigned i = 0; i < 7; i++) {
        uint8_t seed[32] = {0};
        uint8_t alg = OMK_ALG_ES256;
        if (i == 1 || i == 4) {
            memcpy(seed, order, sizeof seed);
            if (i == 4) {
                seed[31]--; /* n - 1 */
            }
        } else if (i == 2) {
            memset(seed, 0xff, sizeof seed);
        } else if (i == 3) {
            seed[31] = 1;
        } else if (i == 5) {
            alg = OMK_ALG_EDDSA; /* every 32-byte Ed25519 seed is valid */
        } else if (i == 6) {
            alg = 0xff;
        }
        const bool valid = i >= 3 && i <= 5;
        uint8_t id[OMK_CRED_ID_MAX];
        const size_t id_len = omk_store_seal_credential(
            &f.ct.store, rp_hash, seed, alg, 1, false, id);
        check(id_len != 0, "scalar: seal boundary credential");
        uint8_t body[256], resp[512];
        omk_cbor_enc e;
        omk_cbor_enc_init(&e, body, sizeof body);
        omk_cbor_put_map(&e, 3);
        omk_cbor_put_uint(&e, 1);
        omk_cbor_put_text(&e, rp, sizeof rp - 1);
        omk_cbor_put_uint(&e, 2);
        omk_cbor_put_bytes(&e, cdh, sizeof cdh);
        omk_cbor_put_uint(&e, 3);
        omk_cbor_put_array(&e, 1);
        put_test_descriptor(&e, id, id_len);
        check(!e.overflow, "scalar: request fits");
        const uint32_t before = f.ct.store.counter;
        size_t len = 0;
        const uint8_t status =
            send_cmd(&f, 0x02, body, e.len, resp, sizeof resp, &len);
        check(status == (valid ? OMK_CTAP2_OK
                               : OMK_CTAP2_ERR_INVALID_CREDENTIAL),
              "scalar: assertion accepts only valid algorithm/key pairs");
        if (!valid) {
            check(f.ct.store.counter == before && len == 0,
                  "scalar: rejected credential consumes no counter or body");
        }
    }
}

static void test_resident(fixture *f) {
    uint8_t cdh[32];
    memset(cdh, 0x24, sizeof cdh);
    uint8_t uid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t body[512];
    size_t len = 0;
    uint8_t resp[1024];

    for (int i = 0; i < 2; i++) {
        const size_t body_len = build_mc(body, sizeof body, cdh, "passkey.test",
                                         uid, sizeof uid, true, false, false);
        uint8_t status =
            send_cmd(f, 0x01, body, body_len, resp, sizeof resp, &len);
        check(status == 0, "rk makeCredential status");
    }
    check(f->ct.store.cred_count == 1, "rk overwrite same user keeps one");

    /* Discoverable assertion: user fields present. */
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_text(&e, "passkey.test", 12);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_bytes(&e, cdh, 32);
    uint8_t status = send_cmd(f, 0x02, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "discoverable assertion status");
    omk_cbor_doc doc;
    omk_cbor_decode(&doc, resp, len);
    const omk_cbor_val *root = omk_cbor_root(&doc);
    const omk_cbor_val *user = omk_cbor_map_get_int(&doc, root, 4);
    check(user != NULL && user->type == OMK_CBOR_MAP, "assertion user present");
    if (user != NULL) {
        const omk_cbor_val *id = omk_cbor_map_get_text(&doc, user, "id", 2);
        check(id != NULL && id->len == sizeof uid &&
                  memcmp(id->data, uid, sizeof uid) == 0,
              "assertion user id");
    }
}

static void test_hmac_secret(fixture *f) {
    uint8_t cdh[32];
    memset(cdh, 0x77, sizeof cdh);
    uint8_t uid[4] = {9, 9, 9, 9};
    uint8_t body[1024];
    size_t len = 0;
    uint8_t resp[1024];
    const size_t body_len = build_mc(body, sizeof body, cdh, "hmac.test", uid,
                                     sizeof uid, false, false, true);
    uint8_t status = send_cmd(f, 0x01, body, body_len, resp, sizeof resp, &len);
    check(status == 0, "hmac makeCredential status");
    mc_result mc;
    check(parse_mc(resp, len, &mc), "hmac mc parse");

    omk_p256_keypair plat;
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        seed[i] = (uint8_t)(i + 1);
    }
    check(omk_p256_keypair_from_scalar(seed, &plat), "platform key");
    uint8_t shared[32];
    check(omk_p256_ecdh(plat.d, f->ct.pin.key_pub, shared), "ecdh");
    uint8_t aes_key[32], hmac_key[32], iv[16] = {0};
    omk_sha256(shared, 32, aes_key);
    memcpy(hmac_key, aes_key, 32);
    uint8_t salt[32];
    memset(salt, 0x5A, sizeof salt);
    uint8_t salt_enc[32], salt_auth[32];
    omk_aes256_cbc_encrypt(aes_key, iv, salt, 32, salt_enc);
    omk_hmac_sha256(hmac_key, 32, salt_enc, 32, salt_auth);

    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 4);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_text(&e, "hmac.test", 9);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_bytes(&e, cdh, 32);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_array(&e, 1);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_text(&e, "type", 4);
    omk_cbor_put_text(&e, "public-key", 10);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_bytes(&e, mc.cred_id, mc.cred_id_len);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "hmac-secret", 11);
    omk_cbor_put_map(&e, 3);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_map(&e, 5);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_nint(&e, -25);
    omk_cbor_put_nint(&e, -1);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_nint(&e, -2);
    omk_cbor_put_bytes(&e, plat.pub + 1, 32);
    omk_cbor_put_nint(&e, -3);
    omk_cbor_put_bytes(&e, plat.pub + 33, 32);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_bytes(&e, salt_enc, sizeof salt_enc);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_bytes(&e, salt_auth, 16);

    /* hmac-secret protocol-2 output encryption uses a fresh random IV.  A
     * failed RNG must not consume the signature counter or leave extension
     * key material in the live GA state.  Build a protocol-2 request (the
     * main body above deliberately exercises the zero-IV protocol 1). */
    uint8_t hkdf_salt[32] = {0};
    uint8_t aes2[32], hmac2[32];
    omk_hkdf_sha256(hkdf_salt, sizeof hkdf_salt, shared, 32,
                    (const uint8_t *)"CTAP2 AES key", 13, aes2, 32);
    omk_hkdf_sha256(hkdf_salt, sizeof hkdf_salt, shared, 32,
                    (const uint8_t *)"CTAP2 HMAC key", 14, hmac2, 32);
    uint8_t iv2[16];
    for (size_t i = 0; i < sizeof iv2; i++) {
        iv2[i] = (uint8_t)(0x90 + i);
    }
    uint8_t salt_enc2[48];
    uint8_t salt_auth2[32];
    memcpy(salt_enc2, iv2, sizeof iv2);
    omk_aes256_cbc_encrypt(aes2, iv2, salt, 32, salt_enc2 + 16);
    omk_hmac_sha256(hmac2, 32, salt_enc2, sizeof salt_enc2, salt_auth2);

    uint8_t body2[1024];
    omk_cbor_enc e2;
    omk_cbor_enc_init(&e2, body2, sizeof body2);
    omk_cbor_put_map(&e2, 4);
    omk_cbor_put_uint(&e2, 1);
    omk_cbor_put_text(&e2, "hmac.test", 9);
    omk_cbor_put_uint(&e2, 2);
    omk_cbor_put_bytes(&e2, cdh, 32);
    omk_cbor_put_uint(&e2, 3);
    omk_cbor_put_array(&e2, 1);
    omk_cbor_put_map(&e2, 2);
    omk_cbor_put_text(&e2, "type", 4);
    omk_cbor_put_text(&e2, "public-key", 10);
    omk_cbor_put_text(&e2, "id", 2);
    omk_cbor_put_bytes(&e2, mc.cred_id, mc.cred_id_len);
    omk_cbor_put_uint(&e2, 4);
    omk_cbor_put_map(&e2, 1);
    omk_cbor_put_text(&e2, "hmac-secret", 11);
    omk_cbor_put_map(&e2, 4);
    omk_cbor_put_uint(&e2, 1);
    omk_cbor_put_map(&e2, 5);
    omk_cbor_put_uint(&e2, 1);
    omk_cbor_put_uint(&e2, 2);
    omk_cbor_put_uint(&e2, 3);
    omk_cbor_put_nint(&e2, -25);
    omk_cbor_put_nint(&e2, -1);
    omk_cbor_put_uint(&e2, 1);
    omk_cbor_put_nint(&e2, -2);
    omk_cbor_put_bytes(&e2, plat.pub + 1, 32);
    omk_cbor_put_nint(&e2, -3);
    omk_cbor_put_bytes(&e2, plat.pub + 33, 32);
    omk_cbor_put_uint(&e2, 2);
    omk_cbor_put_bytes(&e2, salt_enc2, sizeof salt_enc2);
    omk_cbor_put_uint(&e2, 3);
    omk_cbor_put_bytes(&e2, salt_auth2, sizeof salt_auth2);
    omk_cbor_put_uint(&e2, 4);
    omk_cbor_put_uint(&e2, 2);

    const uint32_t counter_before = f->ct.store.counter;
    f->env.random_calls = 0;
    f->env.random_fail_at = 1;
    status = send_cmd(f, 0x02, body2, e2.len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_OTHER,
          "hmac-secret IV RNG failure returns OTHER");
    check(f->ct.store.counter == counter_before,
          "hmac-secret IV failure consumes no counter");
    check(!f->ct.ga.hmac_secret && !f->ct.ga.valid,
          "hmac-secret IV failure clears extension state");
    f->env.random_fail_at = 0;
    status = send_cmd(f, 0x02, body2, e2.len, resp, sizeof resp, &len);
    check(status == 0, "hmac-secret protocol-2 assertion succeeds after recovery");

    status = send_cmd(f, 0x02, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "hmac assertion status");
    omk_cbor_doc doc;
    omk_cbor_decode(&doc, resp, len);
    const omk_cbor_val *root = omk_cbor_root(&doc);
    const omk_cbor_val *ad = omk_cbor_map_get_int(&doc, root, 2);
    check(ad != NULL && ad->type == OMK_CBOR_BYTES, "hmac authData");
    if (ad == NULL) {
        return;
    }
    check((ad->data[32] & 0x80) != 0, "hmac ED flag");
    omk_cbor_doc extdoc;
    omk_cbor_decode(&extdoc, ad->data + 37, ad->len - 37);
    const omk_cbor_val *extmap = omk_cbor_root(&extdoc);
    const omk_cbor_val *hs =
        extmap != NULL ? omk_cbor_map_get_text(&extdoc, extmap, "hmac-secret",
                                               11)
                       : NULL;
    check(hs != NULL && hs->type == OMK_CBOR_BYTES && hs->len == 32,
          "hmac output present");
    if (hs == NULL) {
        return;
    }
    uint8_t out[32];
    omk_aes256_cbc_decrypt(aes_key, iv, hs->data, 32, out);

    uint8_t rp_hash[32], cred_seed[32];
    omk_sha256("hmac.test", 9, rp_hash);
    uint8_t alg = 0, cp = 0;
    bool resident = false;
    check(omk_store_open_credential(&f->ct.store, rp_hash, mc.cred_id,
                                    mc.cred_id_len, cred_seed, &alg, &cp,
                                    &resident),
          "open hmac credential");
    uint8_t expect[32];
    size_t expect_len = 0;
    check(omk_ctap_hmac_secret_output(cred_seed, false, salt, 32,
                                      expect, &expect_len),
          "expected hmac");
    check(memcmp(out, expect, 32) == 0, "hmac output matches");
}

static void test_pin(fixture *f);
static void test_eddsa(fixture *f);
static void test_persistence(fixture *f);
static void test_pin_protocol1(fixture *f);
static void test_pin_oversize(fixture *f);
static void test_hmac_oversize(fixture *f);
static void test_key_agreement_invalid_point(fixture *f);
static void test_getassertion_pin_upfalse(fixture *f);
static void test_pin_lockout(fixture *f);
static void test_pin_retry_exhaustion(fixture *f);
static void test_pin_last_retry_success(fixture *f);
static void test_pin_flash_failure(fixture *f);
static void test_pin_fault_reset_recovery(fixture *f);
static void test_key_agreement_cose(fixture *f);
static void test_puat_failure_statuses(fixture *f);
static void test_puat_sliding_expiry(fixture *f);
static void test_pin_utf8(fixture *f);
static void test_cm_rp_bound_enumeration(fixture *f);
static void test_getassertion_no_credentials(fixture *f);
static void test_hmac_mc_dependency(fixture *f);
static void test_exclude_timeout(fixture *f);
static void test_update_user_immutable(fixture *f);
static void test_pubkey_params(fixture *f);
static void test_gna_timer(fixture *f);
static void test_cm_zero_length_auth(fixture *f);
static void test_missing_pin_protocol(fixture *f);
static void test_cred_protect_echo(fixture *f);
static void test_cm_enumeration_after_delete(fixture *f);
static void test_cm_rp_enumeration_after_delete(fixture *f);
static void test_init_rng_failure(void);
static void test_makecredential_rng_failure(void);
static void test_pin_token_rng_failure(void);
static void test_reset_invalidates_state(void);
static void test_reset_long_op_cancel(void);

int main(void) {
    fixture f;
    fixture_init(&f);
    test_response_framing(&f);
    test_getinfo(&f);
    test_makecredential_assertion(&f);
    test_attestation_format_order(&f);
    test_resident(&f);
    test_hmac_secret(&f);
    test_eddsa(&f);
    test_pin(&f);
    test_pin_protocol1(&f);
    test_persistence(&f);
    test_pin_oversize(&f);
    test_hmac_oversize(&f);
    test_key_agreement_invalid_point(&f);
    test_getassertion_pin_upfalse(&f);
    test_pin_lockout(&f);
    test_pin_retry_exhaustion(&f);
    test_pin_last_retry_success(&f);
    test_pin_flash_failure(&f);
    test_pin_fault_reset_recovery(&f);
    test_key_agreement_cose(&f);
    test_puat_failure_statuses(&f);
    test_puat_sliding_expiry(&f);
    test_pin_utf8(&f);
    test_cm_rp_bound_enumeration(&f);
    test_getassertion_no_credentials(&f);
    test_hmac_mc_dependency(&f);
    test_exclude_timeout(&f);
    test_update_user_immutable(&f);
    test_pubkey_params(&f);
    test_gna_timer(&f);
    test_cm_zero_length_auth(&f);
    test_missing_pin_protocol(&f);
    test_cred_protect_echo(&f);
    test_cm_enumeration_after_delete(&f);
    test_cm_rp_enumeration_after_delete(&f);
    test_init_rng_failure();
    test_makecredential_rng_failure();
    test_pin_token_rng_failure();
    test_reset_long_op_cancel();
    test_reset_invalidates_state();
    test_assertion_key_validation();
    if (g_failures != 0) {
        printf("%d ctap test(s) failed\n", g_failures);
        return 1;
    }
    printf("ctap: all tests passed\n");
    return 0;
}

static void test_persistence(fixture *f) {
    uint8_t master[32], aaguid[16];
    memcpy(master, f->ct.store.master, 32);
    memcpy(aaguid, f->ct.store.aaguid, 16);
    const bool pin_set = f->ct.store.pin_set;
    const uint8_t pin_retries = f->ct.store.pin_retries;
    const uint8_t cred_count = f->ct.store.cred_count;
    const uint32_t before = omk_store_next_counter(&f->ct.store);

    omk_store reloaded;
    check(omk_store_init(&reloaded, &f->port) == 0, "store reload");
    check(memcmp(reloaded.master, master, 32) == 0, "master persists");
    check(memcmp(reloaded.aaguid, aaguid, 16) == 0, "aaguid persists");
    check(reloaded.pin_set == pin_set, "pin_set persists");
    check(reloaded.pin_retries == pin_retries, "pin retries persist");
    check(reloaded.cred_count == cred_count, "resident credentials persist");

    bool found = reloaded.cred_count > 0;
    if (found) {
        check(memcmp(reloaded.creds[0].id, f->ct.store.creds[0].id,
                     reloaded.creds[0].id_len) == 0,
              "credential id survives reload");
        check(reloaded.creds[0].id_len == f->ct.store.creds[0].id_len,
              "credential length survives reload");
    }
    check(found, "credentials survive reload");

    const uint32_t after = omk_store_next_counter(&reloaded);
    check(after > before, "counter does not regress across reload");
}

/* ---------------------------------------------------------------------- */
/* ClientPIN and CredentialManagement                                      */
/* ---------------------------------------------------------------------- */

typedef struct {
    omk_p256_keypair plat;
    uint8_t aes[32];
    uint8_t hmac[32];
} pin_client;

static size_t cose_put(omk_cbor_enc *e, const uint8_t pub[65]) {
    uint8_t cose[128];
    const size_t n = omk_ctap_build_cose_key(cose, sizeof cose, OMK_ALG_ES256,
                                             pub);
    for (size_t i = 0; i < n; i++) {
        e->buf[e->len++] = cose[i];
    }
    return n;
}

static void pin_client_init(fixture *f, pin_client *pc, uint32_t protocol,
                            const uint8_t auth_pub[65]) {
    (void)f;
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        seed[i] = (uint8_t)(0x40 + i);
    }
    check(omk_p256_keypair_from_scalar(seed, &pc->plat), "platform keypair");
    uint8_t shared[32];
    check(omk_p256_ecdh(pc->plat.d, auth_pub, shared), "pin ecdh");
    if (protocol == 1) {
        omk_sha256(shared, 32, pc->aes);
        memcpy(pc->hmac, pc->aes, 32);
    } else {
        uint8_t salt[32] = {0};
        omk_hkdf_sha256(salt, 32, shared, 32, (const uint8_t *)"CTAP2 AES key",
                        13, pc->aes, 32);
        omk_hkdf_sha256(salt, 32, shared, 32, (const uint8_t *)"CTAP2 HMAC key",
                        14, pc->hmac, 32);
    }
}

static void pin_encrypt_c(const pin_client *pc, uint32_t protocol,
                          const uint8_t *in, size_t len, uint8_t *out,
                          size_t *out_len) {
    if (protocol == 1) {
        uint8_t iv[16] = {0};
        omk_aes256_cbc_encrypt(pc->aes, iv, in, len, out);
        *out_len = len;
    } else {
        uint8_t iv[16];
        for (int i = 0; i < 16; i++) {
            iv[i] = (uint8_t)(0x80 + i);
        }
        memcpy(out, iv, 16);
        omk_aes256_cbc_encrypt(pc->aes, iv, in, len, out + 16);
        *out_len = len + 16;
    }
}

static void pin_decrypt_c(const pin_client *pc, uint32_t protocol,
                          const uint8_t *in, size_t len, uint8_t *out,
                          size_t *out_len) {
    if (protocol == 1) {
        uint8_t iv[16] = {0};
        omk_aes256_cbc_decrypt(pc->aes, iv, in, len, out);
        *out_len = len;
    } else {
        omk_aes256_cbc_decrypt(pc->aes, in, in + 16, len - 16, out);
        *out_len = len - 16;
    }
}

static void pin_auth_c(const pin_client *pc, uint32_t protocol,
                       const uint8_t *msg, size_t len, uint8_t *out,
                       size_t *out_len) {
    uint8_t mac[32];
    omk_hmac_sha256(pc->hmac, 32, msg, len, mac);
    const size_t n = protocol == 1 ? 16 : 32;
    memcpy(out, mac, n);
    *out_len = n;
}

static bool extract_cose_pub(const omk_cbor_doc *doc, const omk_cbor_val *cose,
                             uint8_t pub[65]) {
    if (cose == NULL || cose->type != OMK_CBOR_MAP) {
        return false;
    }
    const omk_cbor_val *x = omk_cbor_map_get_int(doc, cose, -2);
    const omk_cbor_val *y = omk_cbor_map_get_int(doc, cose, -3);
    if (x == NULL || y == NULL || x->len != 32 || y->len != 32) {
        return false;
    }
    pub[0] = 0x04;
    memcpy(pub + 1, x->data, 32);
    memcpy(pub + 33, y->data, 32);
    return true;
}

static uint32_t get_retries(fixture *f) {
    uint8_t body[64], resp[128];
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 1);
    size_t len = 0;
    uint8_t status = send_cmd(f, 0x06, body, e.len, resp, sizeof resp, &len);
    if (status != 0) {
        return 0;
    }
    omk_cbor_doc doc;
    omk_cbor_decode(&doc, resp, len);
    const omk_cbor_val *root = omk_cbor_root(&doc);
    const omk_cbor_val *r = omk_cbor_map_get_int(&doc, root, 3);
    return r != NULL ? (uint32_t)r->num : 0;
}

static size_t build_mc_pin(uint8_t *out, size_t cap, const uint8_t cdh[32],
                           const char *rp, const uint8_t *uid, size_t uid_len,
                           const uint8_t *puat, size_t puat_len,
                           uint32_t protocol) {
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, out, cap);
    omk_cbor_put_map(&e, 7);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_bytes(&e, cdh, 32);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_text(&e, rp, strlen(rp));
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_bytes(&e, uid, uid_len);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_array(&e, 1);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_text(&e, "alg", 3);
    omk_cbor_put_nint(&e, -7);
    omk_cbor_put_text(&e, "type", 4);
    omk_cbor_put_text(&e, "public-key", 10);
    omk_cbor_put_uint(&e, 7);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "rk", 2);
    omk_cbor_put_bool(&e, true);
    omk_cbor_put_uint(&e, 8);
    omk_cbor_put_bytes(&e, puat, puat_len);
    omk_cbor_put_uint(&e, 9);
    omk_cbor_put_uint(&e, protocol);
    return e.overflow ? 0 : e.len;
}

static void test_eddsa(fixture *f) {
    uint8_t cdh[32];
    memset(cdh, 0x31, sizeof cdh);
    uint8_t uid[3] = {7, 7, 7};
    uint8_t body[512], resp[1024];
    size_t len = 0;
    const size_t body_len =
        build_mc(body, sizeof body, cdh, "ed.test", uid, sizeof uid, false,
                 true, false);
    uint8_t status = send_cmd(f, 0x01, body, body_len, resp, sizeof resp, &len);
    check(status == 0, "eddsa makeCredential status");
    mc_result mc;
    check(parse_mc(resp, len, &mc), "eddsa mc parse");
    check(mc.pub_len == 32, "eddsa public key length");

    omk_cbor_doc doc;
    omk_cbor_decode(&doc, resp, len);
    const omk_cbor_val *root = omk_cbor_root(&doc);
    const omk_cbor_val *att = omk_cbor_map_get_int(&doc, root, 3);
    const omk_cbor_val *sig =
        att != NULL ? omk_cbor_map_get_text(&doc, att, "sig", 3) : NULL;
    check(sig != NULL && sig->len == 64, "eddsa attestation sig");
    if (sig != NULL) {
        uint8_t input[768];
        memcpy(input, mc.auth_data, mc.auth_len);
        memcpy(input + mc.auth_len, cdh, 32);
        check(omk_ed25519_verify(mc.pub, input, mc.auth_len + 32, sig->data),
              "eddsa attestation verifies");
    }

    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 3);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_text(&e, "ed.test", 7);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_bytes(&e, cdh, 32);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_array(&e, 1);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_text(&e, "type", 4);
    omk_cbor_put_text(&e, "public-key", 10);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_bytes(&e, mc.cred_id, mc.cred_id_len);
    status = send_cmd(f, 0x02, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "eddsa assertion status");
    omk_cbor_doc gdoc;
    omk_cbor_decode(&gdoc, resp, len);
    const omk_cbor_val *groot = omk_cbor_root(&gdoc);
    const omk_cbor_val *ad = omk_cbor_map_get_int(&gdoc, groot, 2);
    const omk_cbor_val *gsig = omk_cbor_map_get_int(&gdoc, groot, 3);
    if (ad != NULL && gsig != NULL) {
        uint8_t input[128];
        memcpy(input, ad->data, ad->len);
        memcpy(input + ad->len, cdh, 32);
        check(omk_ed25519_verify(mc.pub, input, ad->len + 32, gsig->data),
              "eddsa assertion verifies");
    }
}

static void test_pin(fixture *f) {
    pin_client pc;
    uint8_t body[1024], resp[1024];
    size_t len = 0;

    /* getKeyAgreement (protocol 2). */
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 2);
    uint8_t status = send_cmd(f, 0x06, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "getKeyAgreement status");
    omk_cbor_doc doc;
    omk_cbor_decode(&doc, resp, len);
    const omk_cbor_val *root = omk_cbor_root(&doc);
    const omk_cbor_val *cose = omk_cbor_map_get_int(&doc, root, 1);
    uint8_t auth_pub[65];
    check(extract_cose_pub(&doc, cose, auth_pub), "key agreement cose");
    check(memcmp(auth_pub, f->ct.pin.key_pub, 65) == 0,
          "key agreement matches");
    pin_client_init(f, &pc, 2, auth_pub);

    /* setPIN("1234"). */
    uint8_t pinpad[64] = {0};
    memcpy(pinpad, "1234", 4);
    uint8_t new_pin_enc[96];
    size_t new_pin_enc_len = 0;
    pin_encrypt_c(&pc, 2, pinpad, sizeof pinpad, new_pin_enc,
                  &new_pin_enc_len);
    uint8_t auth[32];
    size_t auth_len = 0;
    pin_auth_c(&pc, 2, new_pin_enc, new_pin_enc_len, auth, &auth_len);
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 5);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_uint(&e, 3);
    cose_put(&e, pc.plat.pub);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, auth, auth_len);
    omk_cbor_put_uint(&e, 5);
    omk_cbor_put_bytes(&e, new_pin_enc, new_pin_enc_len);
    status = send_cmd(f, 0x06, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "setPIN status");
    check(len == 0, "setPIN status-only success has no CBOR body");
    check(f->ct.store.pin_set, "PIN is set");

    /* getPinToken with the correct PIN. */
    uint8_t pin_hash_full[32], pin_hash[16];
    omk_sha256("1234", 4, pin_hash_full);
    memcpy(pin_hash, pin_hash_full, 16);
    uint8_t pin_hash_enc[48];
    size_t pin_hash_enc_len = 0;
    pin_encrypt_c(&pc, 2, pin_hash, 16, pin_hash_enc, &pin_hash_enc_len);
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 4);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 5);
    omk_cbor_put_uint(&e, 3);
    cose_put(&e, pc.plat.pub);
    omk_cbor_put_uint(&e, 6);
    omk_cbor_put_bytes(&e, pin_hash_enc, pin_hash_enc_len);
    status = send_cmd(f, 0x06, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "getPinToken status");
    omk_cbor_decode(&doc, resp, len);
    root = omk_cbor_root(&doc);
    const omk_cbor_val *tok_enc = omk_cbor_map_get_int(&doc, root, 2);
    uint8_t token[32];
    size_t token_len = 0;
    check(tok_enc != NULL && tok_enc->type == OMK_CBOR_BYTES,
          "pin token present");
    pin_decrypt_c(&pc, 2, tok_enc->data, tok_enc->len, token, &token_len);
    check(token_len == 32, "pin token length");

    /* MakeCredential with rk + PUAT. */
    uint8_t cdh[32];
    memset(cdh, 0x66, sizeof cdh);
    uint8_t puat[32];
    size_t puat_len = 0;
    pin_auth_c(&pc, 2, cdh, 32, puat, &puat_len);
    /* pin_auth_c uses the key agreement HMAC key, not the token: redo with
     * the token itself (PUAT = HMAC(token, clientDataHash)). */
    omk_hmac_sha256(token, 32, cdh, 32, puat);
    uint8_t uid[8] = {1, 1, 1, 1, 2, 2, 2, 2};
    const size_t mc_len = build_mc_pin(body, sizeof body, cdh, "pin.test", uid,
                                       sizeof uid, puat, 32, 2);
    status = send_cmd(f, 0x01, body, mc_len, resp, sizeof resp, &len);
    check(status == 0, "PIN makeCredential status");
    mc_result mc;
    check(parse_mc(resp, len, &mc), "PIN makeCredential parse");
    uint8_t pin_rp_hash[32];
    omk_sha256("pin.test", 8, pin_rp_hash);
    bool pin_cred_found = false;
    for (uint8_t i = 0; i < f->ct.store.cred_count; i++) {
        if (memcmp(f->ct.store.creds[i].rp_id_hash, pin_rp_hash, 32) == 0) {
            pin_cred_found = true;
        }
    }
    check(pin_cred_found, "PIN rk stored");

    /* Wrong PIN decrements the retry counter. */
    memset(pin_hash, 0x00, sizeof pin_hash);
    pin_encrypt_c(&pc, 2, pin_hash, 16, pin_hash_enc, &pin_hash_enc_len);
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 4);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 5);
    omk_cbor_put_uint(&e, 3);
    cose_put(&e, pc.plat.pub);
    omk_cbor_put_uint(&e, 6);
    omk_cbor_put_bytes(&e, pin_hash_enc, pin_hash_enc_len);
    status = send_cmd(f, 0x06, body, e.len, resp, sizeof resp, &len);
    check(status == 0x31, "wrong PIN returns PIN_INVALID");
    check(get_retries(f) == 7, "retries decremented");
    /* A failed comparison rotates the key agreement, so redo ECDH before the
     * next PIN command. */
    pin_client_init(f, &pc, 2, f->ct.pin.key_pub);

    /* Obtain a cm token. */
    omk_sha256("1234", 4, pin_hash_full);
    memcpy(pin_hash, pin_hash_full, 16);
    pin_encrypt_c(&pc, 2, pin_hash, 16, pin_hash_enc, &pin_hash_enc_len);
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 5);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 9);
    omk_cbor_put_uint(&e, 3);
    cose_put(&e, pc.plat.pub);
    omk_cbor_put_uint(&e, 6);
    omk_cbor_put_bytes(&e, pin_hash_enc, pin_hash_enc_len);
    omk_cbor_put_uint(&e, 9);
    omk_cbor_put_uint(&e, OMK_PERM_CM);
    status = send_cmd(f, 0x06, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "cm token status");
    omk_cbor_decode(&doc, resp, len);
    root = omk_cbor_root(&doc);
    tok_enc = omk_cbor_map_get_int(&doc, root, 2);
    uint8_t cm_token[32];
    size_t cm_token_len = 0;
    pin_decrypt_c(&pc, 2, tok_enc->data, tok_enc->len, cm_token,
                  &cm_token_len);
    check(cm_token_len == 32, "cm token length");

    /* getCredsMetadata: auth over the subcommand byte. */
    uint8_t auth_in[256];
    uint8_t cm_auth[32];
    size_t cm_auth_len = 0;
    auth_in[0] = 0x01;
    pin_auth_c(&pc, 2, auth_in, 1, cm_auth, &cm_auth_len);
    omk_hmac_sha256(cm_token, 32, auth_in, 1, cm_auth);
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 3);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, cm_auth, 32);
    status = send_cmd(f, 0x0A, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "creds metadata status");
    omk_cbor_decode(&doc, resp, len);
    root = omk_cbor_root(&doc);
    const omk_cbor_val *cnt = omk_cbor_map_get_int(&doc, root, 1);
    check(cnt != NULL && cnt->num >= 1, "creds metadata count");

    /* Enumerate RPs. */
    auth_in[0] = 0x02;
    omk_hmac_sha256(cm_token, 32, auth_in, 1, cm_auth);
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 3);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, cm_auth, 32);
    status = send_cmd(f, 0x0A, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "enumerateRPsBegin status");
    omk_cbor_doc rpdoc;
    omk_cbor_decode(&rpdoc, resp, len);
    const omk_cbor_val *rproot = omk_cbor_root(&rpdoc);
    const omk_cbor_val *rp_hash =
        omk_cbor_map_get_int(&rpdoc, rproot, 4);
    check(rp_hash != NULL && rp_hash->type == OMK_CBOR_BYTES &&
              rp_hash->len == 32,
          "enumerateRPsBegin hash");

    /* Enumerate credentials for that RP. */
    uint8_t params[64];
    omk_cbor_enc pe;
    omk_cbor_enc_init(&pe, params, sizeof params);
    omk_cbor_put_map(&pe, 1);
    omk_cbor_put_uint(&pe, 1);
    omk_cbor_put_bytes(&pe, pin_rp_hash, 32);
    auth_in[0] = 0x04;
    memcpy(auth_in + 1, params, pe.len);
    omk_hmac_sha256(cm_token, 32, auth_in, 1 + pe.len, cm_auth);
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 4);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_uint(&e, 2);
    for (size_t i = 0; i < pe.len; i++) {
        e.buf[e.len++] = params[i];
    }
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, cm_auth, 32);
    status = send_cmd(f, 0x0A, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "enumerateCredentialsBegin status");
    omk_cbor_doc cdoc;
    omk_cbor_decode(&cdoc, resp, len);
    const omk_cbor_val *croot = omk_cbor_root(&cdoc);
    const omk_cbor_val *enumerated_id =
        cm_response_id(&cdoc, croot);
    check(enumerated_id != NULL && enumerated_id->type == OMK_CBOR_BYTES,
          "enumerated credential id");

    if (enumerated_id == NULL) {
        return;
    }

    /* Delete it. */
    uint8_t dparams[128];
    omk_cbor_enc de;
    omk_cbor_enc_init(&de, dparams, sizeof dparams);
    omk_cbor_put_map(&de, 1);
    omk_cbor_put_uint(&de, 2);
    put_test_descriptor(&de, enumerated_id->data, enumerated_id->len);
    auth_in[0] = 0x06;
    memcpy(auth_in + 1, dparams, de.len);
    omk_hmac_sha256(cm_token, 32, auth_in, 1 + de.len, cm_auth);
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 4);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 6);
    omk_cbor_put_uint(&e, 2);
    for (size_t i = 0; i < de.len; i++) {
        e.buf[e.len++] = dparams[i];
    }
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, cm_auth, 32);
    status = send_cmd(f, 0x0A, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "deleteCredential status");
    check(len == 0, "deleteCredential status-only success has no CBOR body");
    bool still_there = false;
    for (uint8_t i = 0; i < f->ct.store.cred_count; i++) {
        if (memcmp(f->ct.store.creds[i].rp_id_hash, pin_rp_hash, 32) == 0) {
            still_there = true;
        }
    }
    check(!still_there, "credential deleted");
}
static void test_pin_protocol1(fixture *f) {
    fixture_init(f); /* fresh flash, protocol 1 end-to-end */
    pin_client pc;
    pin_client_init(f, &pc, 1, f->ct.pin.key_pub);

    uint8_t body[1024], resp[1024];
    size_t len = 0;
    uint8_t pinpad[64] = {0};
    memcpy(pinpad, "1234", 4);
    uint8_t enc[96];
    size_t enc_len = 0;
    pin_encrypt_c(&pc, 1, pinpad, 64, enc, &enc_len);
    uint8_t auth[32];
    size_t auth_len = 0;
    pin_auth_c(&pc, 1, enc, enc_len, auth, &auth_len);
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 5);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_uint(&e, 3);
    cose_put(&e, pc.plat.pub);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, auth, auth_len);
    omk_cbor_put_uint(&e, 5);
    omk_cbor_put_bytes(&e, enc, enc_len);
    uint8_t status = send_cmd(f, 0x06, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "pin1 setPIN status");

    uint8_t hash_full[32], hash[16];
    omk_sha256("1234", 4, hash_full);
    memcpy(hash, hash_full, 16);
    pin_encrypt_c(&pc, 1, hash, 16, enc, &enc_len);
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 4);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 5);
    omk_cbor_put_uint(&e, 3);
    cose_put(&e, pc.plat.pub);
    omk_cbor_put_uint(&e, 6);
    omk_cbor_put_bytes(&e, enc, enc_len);
    status = send_cmd(f, 0x06, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "pin1 getPinToken status");
    omk_cbor_doc doc;
    omk_cbor_decode(&doc, resp, len);
    const omk_cbor_val *root = omk_cbor_root(&doc);
    const omk_cbor_val *tok = omk_cbor_map_get_int(&doc, root, 2);
    uint8_t token[32];
    size_t token_len = 0;
    if (tok != NULL) {
        pin_decrypt_c(&pc, 1, tok->data, tok->len, token, &token_len);
    }
    check(token_len == 32, "pin1 token length");

    uint8_t cdh[32];
    memset(cdh, 0x12, sizeof cdh);
    uint8_t puat_full[32], puat[16];
    omk_hmac_sha256(token, 32, cdh, 32, puat_full);
    memcpy(puat, puat_full, 16);
    uint8_t uid[4] = {3, 3, 3, 3};
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 7);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_bytes(&e, cdh, 32);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_text(&e, "pin1.test", 9);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_bytes(&e, uid, sizeof uid);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_array(&e, 1);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_text(&e, "alg", 3);
    omk_cbor_put_nint(&e, -7);
    omk_cbor_put_text(&e, "type", 4);
    omk_cbor_put_text(&e, "public-key", 10);
    omk_cbor_put_uint(&e, 7);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "rk", 2);
    omk_cbor_put_bool(&e, true);
    omk_cbor_put_uint(&e, 8);
    omk_cbor_put_bytes(&e, puat, 16);
    omk_cbor_put_uint(&e, 9);
    omk_cbor_put_uint(&e, 1);
    status = send_cmd(f, 0x01, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "pin1 makeCredential status");
    check(f->ct.store.cred_count == 1, "pin1 rk stored");
}

/* ---------------------------------------------------------------------- */
/* Oversized PIN/UV ciphertext regression tests                            */
/* ---------------------------------------------------------------------- */

static uint8_t clientpin_set(fixture *f, const pin_client *pc,
                             uint32_t protocol, const uint8_t *plain,
                             size_t plain_len) {
    uint8_t enc[256], auth[32], body[512], resp[256];
    size_t enc_len = 0, auth_len = 0, resp_len = 0;
    pin_encrypt_c(pc, protocol, plain, plain_len, enc, &enc_len);
    pin_auth_c(pc, protocol, enc, enc_len, auth, &auth_len);
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 5);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, protocol);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 0x03);
    omk_cbor_put_uint(&e, 3);
    cose_put(&e, pc->plat.pub);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, auth, auth_len);
    omk_cbor_put_uint(&e, 5);
    omk_cbor_put_bytes(&e, enc, enc_len);
    if (e.overflow) {
        return 0xFF;
    }
    const uint8_t status =
        send_cmd(f, 0x06, body, e.len, resp, sizeof resp, &resp_len);
    if (status == 0 && resp_len != 0) {
        return 0xFE; /* setPIN success must be status-only */
    }
    return status;
}

static uint8_t clientpin_change(fixture *f, const pin_client *pc,
                                uint32_t protocol, const uint8_t *current,
                                size_t current_len, const uint8_t *newpin,
                                size_t new_len) {
    uint8_t cur_enc[256], new_enc[256], auth_input[512], auth[32];
    uint8_t body[768], resp[256];
    size_t cur_enc_len = 0, new_enc_len = 0, auth_len = 0, resp_len = 0;
    pin_encrypt_c(pc, protocol, current, current_len, cur_enc, &cur_enc_len);
    pin_encrypt_c(pc, protocol, newpin, new_len, new_enc, &new_enc_len);
    if (new_enc_len + cur_enc_len > sizeof auth_input) {
        return 0xFF;
    }
    memcpy(auth_input, new_enc, new_enc_len);
    memcpy(auth_input + new_enc_len, cur_enc, cur_enc_len);
    pin_auth_c(pc, protocol, auth_input, new_enc_len + cur_enc_len, auth,
               &auth_len);
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 6);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, protocol);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 0x04);
    omk_cbor_put_uint(&e, 3);
    cose_put(&e, pc->plat.pub);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, auth, auth_len);
    omk_cbor_put_uint(&e, 5);
    omk_cbor_put_bytes(&e, new_enc, new_enc_len);
    omk_cbor_put_uint(&e, 6);
    omk_cbor_put_bytes(&e, cur_enc, cur_enc_len);
    if (e.overflow) {
        return 0xFF;
    }
    const uint8_t status =
        send_cmd(f, 0x06, body, e.len, resp, sizeof resp, &resp_len);
    if (status == 0 && resp_len != 0) {
        return 0xFE; /* changePIN success must be status-only */
    }
    return status;
}

static uint8_t clientpin_get(fixture *f, const pin_client *pc,
                             uint32_t protocol, uint32_t subcommand,
                             const uint8_t *plain, size_t plain_len,
                             uint32_t permissions) {
    uint8_t enc[256], body[512], resp[256];
    size_t enc_len = 0, resp_len = 0;
    pin_encrypt_c(pc, protocol, plain, plain_len, enc, &enc_len);
    const bool with_perms = subcommand == 0x09;
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, with_perms ? 5 : 4);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, protocol);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, subcommand);
    omk_cbor_put_uint(&e, 3);
    cose_put(&e, pc->plat.pub);
    omk_cbor_put_uint(&e, 6);
    omk_cbor_put_bytes(&e, enc, enc_len);
    if (with_perms) {
        omk_cbor_put_uint(&e, 9);
        omk_cbor_put_uint(&e, permissions);
    }
    if (e.overflow) {
        return 0xFF;
    }
    return send_cmd(f, 0x06, body, e.len, resp, sizeof resp, &resp_len);
}

static size_t build_hmac_mc_cp(uint8_t *out, size_t cap, const uint8_t cdh[32],
                               const char *rp, const uint8_t *uid, size_t uid_len,
                               const uint8_t auth_pub[65], uint32_t protocol,
                               const uint8_t *salt_enc, size_t salt_enc_len,
                               const uint8_t *salt_auth, size_t salt_auth_len,
                               uint8_t cred_protect) {
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, out, cap);
    omk_cbor_put_map(&e, 5);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_bytes(&e, cdh, 32);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_text(&e, rp, strlen(rp));
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_bytes(&e, uid, uid_len);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_array(&e, 1);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_text(&e, "alg", 3);
    omk_cbor_put_nint(&e, -7);
    omk_cbor_put_text(&e, "type", 4);
    omk_cbor_put_text(&e, "public-key", 10);
    omk_cbor_put_uint(&e, 6);
    omk_cbor_put_map(&e, cred_protect != 0 ? 3 : 2);
    if (cred_protect != 0) {
        omk_cbor_put_text(&e, "credProtect", 11);
        omk_cbor_put_uint(&e, cred_protect);
    }
    omk_cbor_put_text(&e, "hmac-secret", 11);
    omk_cbor_put_bool(&e, true);
    omk_cbor_put_text(&e, "hmac-secret-mc", 14);
    omk_cbor_put_map(&e, 4);
    omk_cbor_put_uint(&e, 1);
    cose_put(&e, auth_pub);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_bytes(&e, salt_enc, salt_enc_len);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_bytes(&e, salt_auth, salt_auth_len);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_uint(&e, protocol);
    return e.overflow ? 0 : e.len;
}

static size_t build_hmac_mc(uint8_t *out, size_t cap, const uint8_t cdh[32],
                            const char *rp, const uint8_t *uid, size_t uid_len,
                            const uint8_t auth_pub[65], uint32_t protocol,
                            const uint8_t *salt_enc, size_t salt_enc_len,
                            const uint8_t *salt_auth, size_t salt_auth_len) {
    return build_hmac_mc_cp(out, cap, cdh, rp, uid, uid_len, auth_pub, protocol,
                            salt_enc, salt_enc_len, salt_auth, salt_auth_len, 0);
}

static size_t build_hmac_ga(uint8_t *out, size_t cap, const char *rp,
                            const uint8_t cdh[32], const uint8_t auth_pub[65],
                            uint32_t protocol, const uint8_t *salt_enc,
                            size_t salt_enc_len, const uint8_t *salt_auth,
                            size_t salt_auth_len) {
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, out, cap);
    omk_cbor_put_map(&e, 3);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_text(&e, rp, strlen(rp));
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_bytes(&e, cdh, 32);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "hmac-secret", 11);
    omk_cbor_put_map(&e, 4);
    omk_cbor_put_uint(&e, 1);
    cose_put(&e, auth_pub);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_bytes(&e, salt_enc, salt_enc_len);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_bytes(&e, salt_auth, salt_auth_len);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_uint(&e, protocol);
    return e.overflow ? 0 : e.len;
}

static void test_key_agreement_invalid_point(fixture *f) {
    for (uint32_t protocol = 1; protocol <= 2; protocol++) {
        fixture_init(f);
        pin_client pc;
        pin_client_init(f, &pc, protocol, f->ct.pin.key_pub);
        uint8_t valid_pub[65];
        memcpy(valid_pub, pc.plat.pub, sizeof valid_pub);
        /* Correct COSE shape, but (0, 0) is not on P-256. */
        memset(pc.plat.pub + 1, 0, 64);

        uint8_t pinpad[64] = {0};
        memcpy(pinpad, "1234", 4);
        const uint8_t retries = f->ct.store.pin_retries;
        check(clientpin_set(f, &pc, protocol, pinpad, sizeof pinpad) ==
                  OMK_CTAP1_ERR_INVALID_PARAMETER,
              "invalid point: setPIN rejects off-curve peer");
        check(!f->ct.store.pin_set && f->ct.store.pin_retries == retries,
              "invalid point: PIN state unchanged");

        uint8_t cdh[32] = {0};
        uint8_t uid[4] = {1, 2, 3, 4};
        uint8_t salt[32] = {0};
        uint8_t salt_enc[64], salt_auth[32], body[1024], resp[1024];
        size_t enc_len = 0, auth_len = 0, resp_len = 0;
        pin_encrypt_c(&pc, protocol, salt, sizeof salt, salt_enc, &enc_len);
        pin_auth_c(&pc, protocol, salt_enc, enc_len, salt_auth, &auth_len);
        const uint32_t counter = f->ct.store.counter;
        size_t body_len = build_hmac_mc(
            body, sizeof body, cdh, "invalid-point.test", uid, sizeof uid,
            pc.plat.pub, protocol, salt_enc, enc_len, salt_auth, auth_len);
        check(body_len != 0, "invalid point: MC request built");
        check(send_cmd(f, 0x01, body, body_len, resp, sizeof resp,
                       &resp_len) == OMK_CTAP1_ERR_INVALID_PARAMETER,
              "invalid point: hmac-secret-mc rejects off-curve peer");
        check(f->ct.store.counter == counter,
              "invalid point: MC does not consume counter");

        body_len = build_hmac_ga(
            body, sizeof body, "invalid-point.test", cdh, pc.plat.pub,
            protocol, salt_enc, enc_len, salt_auth, auth_len);
        check(body_len != 0, "invalid point: GA request built");
        check(send_cmd(f, 0x02, body, body_len, resp, sizeof resp,
                       &resp_len) == OMK_CTAP1_ERR_INVALID_PARAMETER,
              "invalid point: hmac-secret rejects off-curve peer");

        memcpy(pc.plat.pub, valid_pub, sizeof valid_pub);
        body_len = build_hmac_mc(
            body, sizeof body, cdh, "invalid-point.test", uid, sizeof uid,
            pc.plat.pub, protocol, salt_enc, enc_len, salt_auth, auth_len);
        check(body_len != 0, "valid point: MC request built");
        check(send_cmd(f, 0x01, body, body_len, resp, sizeof resp,
                       &resp_len) == OMK_CTAP2_OK,
              "valid point: hmac-secret-mc recovers after rejection");
        check(clientpin_set(f, &pc, protocol, pinpad, sizeof pinpad) ==
                  OMK_CTAP2_OK,
              "valid point: setPIN recovers after rejection");
    }
}

static void test_pin_oversize(fixture *f) {
    fixture_init(f);
    pin_client pc1, pc2;
    pin_client_init(f, &pc1, 1, f->ct.pin.key_pub);
    pin_client_init(f, &pc2, 2, f->ct.pin.key_pub);

    uint8_t pinpad[64] = {0};
    memcpy(pinpad, "1234", 4);
    uint8_t big[128];
    memset(big, 0x41, sizeof big);

    /* CTAP 2.3 6.5.5.5: paddedNewPin must be exactly 64 bytes. A 64-byte
     * unpadded PIN violates policy; larger plaintexts have invalid shape.
     * Cover each block boundary deterministically: the official F-2 test
     * randomizes this length but expects PIN_POLICY_VIOLATION for all. */
    for (size_t n = 64; n <= sizeof big; n += 16) {
        const uint8_t expected = n == 64 ? OMK_CTAP2_ERR_PIN_POLICY_VIOLATION
                                        : OMK_CTAP1_ERR_INVALID_PARAMETER;
        check(clientpin_set(f, &pc1, 1, big, n) == expected,
              "oversize setPIN p1 distinguishes policy from shape");
        check(clientpin_set(f, &pc2, 2, big, n) == expected,
              "oversize setPIN p2 distinguishes policy from shape");
    }
    check(!f->ct.store.pin_set, "oversize setPIN does not set PIN");
    check(clientpin_set(f, &pc2, 2, pinpad, 64) == 0, "valid setPIN p2");

    uint8_t full[32], current[16];
    omk_sha256("1234", 4, full);
    memcpy(current, full, 16);
    uint8_t newpad[64] = {0};
    memcpy(newpad, "5678", 4);
    uint8_t huge[112];
    memset(huge, 0x52, sizeof huge);

    /* changePIN current pinHash is exactly 16 bytes.  The MAC covers the
     * concatenated ciphertext before its shape is rejected. */
    check(clientpin_change(f, &pc1, 1, big, 48, newpad, 64) ==
              OMK_CTAP1_ERR_INVALID_PARAMETER,
          "oversize changePIN current p1 rejected");
    check(clientpin_change(f, &pc2, 2, big, 48, big, 48) ==
              OMK_CTAP1_ERR_INVALID_PARAMETER,
          "oversize changePIN current p2 rejected");
    check(clientpin_change(f, &pc1, 1, current, 16, big, 80) ==
              OMK_CTAP1_ERR_INVALID_PARAMETER,
          "oversize changePIN new p1 rejected");
    check(clientpin_change(f, &pc2, 2, current, 16, big, 80) ==
              OMK_CTAP1_ERR_INVALID_PARAMETER,
          "oversize changePIN new p2 rejected");
    /* newPinEnc > 128 bytes combined with pinHashEnc exceeds the old scratch
     * buffer; the MAC must still be verified and the shape rejected as 0x02. */
    check(clientpin_change(f, &pc2, 2, current, 16, huge, sizeof huge) ==
              OMK_CTAP1_ERR_INVALID_PARAMETER,
          "oversize changePIN new beyond scratch p2 rejected");
    check(clientpin_change(f, &pc2, 2, current, 16, newpad, 64) == 0,
          "valid changePIN p2");

    /* getPinToken/getTokenPermissions pinHash is exactly 16 bytes. */
    check(clientpin_get(f, &pc1, 1, 0x05, big, 48, 0) ==
              OMK_CTAP1_ERR_INVALID_PARAMETER,
          "oversize getPinToken p1 rejected");
    check(clientpin_get(f, &pc2, 2, 0x05, big, 48, 0) ==
              OMK_CTAP1_ERR_INVALID_PARAMETER,
          "oversize getPinToken p2 rejected");
    check(clientpin_get(f, &pc1, 1, 0x09, big, 48, OMK_PERM_CM) ==
              OMK_CTAP1_ERR_INVALID_PARAMETER,
          "oversize getTokenPermissions p1 rejected");
    check(clientpin_get(f, &pc2, 2, 0x09, big, 48, OMK_PERM_CM) ==
              OMK_CTAP1_ERR_INVALID_PARAMETER,
          "oversize getTokenPermissions p2 rejected");
}

static void test_hmac_oversize(fixture *f) {
    fixture_init(f);
    pin_client pc1, pc2;
    pin_client_init(f, &pc1, 1, f->ct.pin.key_pub);
    pin_client_init(f, &pc2, 2, f->ct.pin.key_pub);

    uint8_t cdh[32];
    memset(cdh, 0x5C, sizeof cdh);
    uint8_t uid[8] = {5, 5, 5, 5, 6, 6, 6, 6};
    uint8_t plain[96];
    memset(plain, 0x6D, sizeof plain);
    uint8_t salt_enc[128], salt_auth[32], body[1024], resp[1024];
    size_t enc_len = 0, auth_len = 0, resp_len = 0, body_len = 0;
    uint8_t status = 0;

    /* MakeCredential hmac-secret-mc with a valid saltAuth but an oversized
     * saltEnc.  The plaintext is 80 bytes instead of 32 or 64. */
    pin_encrypt_c(&pc1, 1, plain, 80, salt_enc, &enc_len);
    pin_auth_c(&pc1, 1, salt_enc, enc_len, salt_auth, &auth_len);
    body_len = build_hmac_mc(body, sizeof body, cdh, "hmac-over.test", uid,
                             sizeof uid, pc1.plat.pub, 1, salt_enc,
                             enc_len, salt_auth, auth_len);
    check(body_len != 0, "oversize hmac MC p1 build");
    status = send_cmd(f, 0x01, body, body_len, resp, sizeof resp, &resp_len);
    check(status == OMK_CTAP1_ERR_INVALID_PARAMETER,
          "oversize hmac MC p1 rejected");

    pin_encrypt_c(&pc2, 2, plain, 80, salt_enc, &enc_len);
    pin_auth_c(&pc2, 2, salt_enc, enc_len, salt_auth, &auth_len);
    body_len = build_hmac_mc(body, sizeof body, cdh, "hmac-over.test", uid,
                             sizeof uid, pc2.plat.pub, 2, salt_enc,
                             enc_len, salt_auth, auth_len);
    check(body_len != 0, "oversize hmac MC p2 build");
    status = send_cmd(f, 0x01, body, body_len, resp, sizeof resp, &resp_len);
    check(status == OMK_CTAP1_ERR_INVALID_PARAMETER,
          "oversize hmac MC p2 rejected");

    /* GetAssertion hmac-secret with the same oversized saltEnc. */
    pin_encrypt_c(&pc1, 1, plain, 80, salt_enc, &enc_len);
    pin_auth_c(&pc1, 1, salt_enc, enc_len, salt_auth, &auth_len);
    body_len = build_hmac_ga(body, sizeof body, "hmac-over.test", cdh,
                             pc1.plat.pub, 1, salt_enc, enc_len, salt_auth,
                             auth_len);
    check(body_len != 0, "oversize hmac GA p1 build");
    status = send_cmd(f, 0x02, body, body_len, resp, sizeof resp, &resp_len);
    check(status == OMK_CTAP1_ERR_INVALID_PARAMETER,
          "oversize hmac GA p1 rejected");

    pin_encrypt_c(&pc2, 2, plain, 80, salt_enc, &enc_len);
    pin_auth_c(&pc2, 2, salt_enc, enc_len, salt_auth, &auth_len);
    body_len = build_hmac_ga(body, sizeof body, "hmac-over.test", cdh,
                             pc2.plat.pub, 2, salt_enc, enc_len, salt_auth,
                             auth_len);
    check(body_len != 0, "oversize hmac GA p2 build");
    status = send_cmd(f, 0x02, body, body_len, resp, sizeof resp, &resp_len);
    check(status == OMK_CTAP1_ERR_INVALID_PARAMETER,
          "oversize hmac GA p2 rejected");

    /* A legal protocol-2 32-byte salt still reaches the success path. */
    memset(plain, 0x2A, 32);
    pin_encrypt_c(&pc2, 2, plain, 32, salt_enc, &enc_len);
    pin_auth_c(&pc2, 2, salt_enc, enc_len, salt_auth, &auth_len);
    body_len = build_hmac_mc(body, sizeof body, cdh, "hmac-over.test", uid,
                             sizeof uid, pc2.plat.pub, 2, salt_enc, enc_len,
                             salt_auth, auth_len);
    check(body_len != 0, "valid hmac MC p2 build");
    status = send_cmd(f, 0x01, body, body_len, resp, sizeof resp, &resp_len);
    check(status == 0, "valid hmac MC p2 accepted");
}


/* ---------------------------------------------------------------------- */
/* PIN / GetAssertion regression tests                                     */
/* ---------------------------------------------------------------------- */

/* Authenticate with a PIN through the real ClientPIN getPinToken path. */
static uint8_t pin_get_token(fixture *f, pin_client *pc, uint32_t protocol,
                             const char *pin, size_t *resp_len) {
    uint8_t full[32], hash[16], enc[64];
    size_t enc_len = 0;
    omk_sha256(pin, strlen(pin), full);
    memcpy(hash, full, 16);
    pin_encrypt_c(pc, protocol, hash, 16, enc, &enc_len);

    uint8_t body[512], resp[256];
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 4);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, protocol);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 0x05);
    omk_cbor_put_uint(&e, 3);
    cose_put(&e, pc->plat.pub);
    omk_cbor_put_uint(&e, 6);
    omk_cbor_put_bytes(&e, enc, enc_len);
    size_t len = 0;
    uint8_t status = 0xFF;
    if (!e.overflow) {
        status = send_cmd(f, 0x06, body, e.len, resp, sizeof resp, &len);
    }
    if (resp_len != NULL) {
        *resp_len = status == 0 ? len : 0;
    }
    return status;
}

/* Simulate a power cycle: reload the store and regenerate the PIN key
 * agreement, then redo the client-side ECDH. */
static void pin_reboot(fixture *f, pin_client *pc, uint32_t protocol) {
    check(omk_ctap_init(&f->ct, &f->port, &f->hid) == 0, "PIN reboot init");
    pin_client_init(f, pc, protocol, f->ct.pin.key_pub);
}

static void pin_set_1234(fixture *f, pin_client *pc, uint32_t protocol) {
    uint8_t pinpad[64] = {0};
    memcpy(pinpad, "1234", 4);
    pin_client_init(f, pc, protocol, f->ct.pin.key_pub);
    check(clientpin_set(f, pc, protocol, pinpad, sizeof pinpad) == 0,
          "PIN test setPIN");
}

static void test_getassertion_pin_upfalse(fixture *f) {
    fixture_init(f);

    /* Create a resident credential before a PIN exists. */
    uint8_t cdh[32];
    memset(cdh, 0x5A, sizeof cdh);
    uint8_t uid[8] = {4, 4, 4, 4, 5, 5, 5, 5};
    uint8_t body[512], resp[1024];
    size_t len = 0;
    const size_t mc_len = build_mc(body, sizeof body, cdh, "upfalse.test", uid,
                                   sizeof uid, true, false, false);
    check(send_cmd(f, 0x01, body, mc_len, resp, sizeof resp, &len) == 0,
          "upfalse rk makeCredential");
    mc_result mc;
    check(parse_mc(resp, len, &mc), "upfalse rk parse");
    check(f->ct.store.cred_count == 1, "upfalse resident credential stored");

    /* Now protect the authenticator with a PIN. */
    pin_client pc;
    pin_set_1234(f, &pc, 2);
    check(f->ct.store.pin_set, "upfalse PIN is set");

    /* credProtect=1 remains discoverable without UV after a PIN is set. */
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 3);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_text(&e, "upfalse.test", 12);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_bytes(&e, cdh, 32);
    omk_cbor_put_uint(&e, 5);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "up", 2);
    omk_cbor_put_bool(&e, false);
    len = 1;
    const uint64_t before = f->env.now;
    check(send_cmd(f, 0x02, body, e.len, resp, sizeof resp, &len) == 0,
          "credProtect=1 discovery does not require PIN");
    check(f->env.now == before, "up:false discovery does not wait for presence");
    omk_cbor_doc discovery;
    check(omk_cbor_decode(&discovery, resp, len),
          "unverified discovery response parses");
    const omk_cbor_val *ad = omk_cbor_map_get_int(
        &discovery, omk_cbor_root(&discovery), 2);
    check(ad != NULL && ad->type == OMK_CBOR_BYTES && ad->len >= 37 &&
              (ad->data[32] & 0x05u) == 0,
          "unverified discovery has neither UP nor UV flags");

    /* allowList remains a legal no-PIN path. */
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 3);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_text(&e, "upfalse.test", 12);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_bytes(&e, cdh, 32);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_array(&e, 1);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_text(&e, "type", 4);
    omk_cbor_put_text(&e, "public-key", 10);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_bytes(&e, mc.cred_id, mc.cred_id_len);
    len = 0;
    check(send_cmd(f, 0x02, body, e.len, resp, sizeof resp, &len) == 0,
          "allowList assertion still succeeds");
    omk_cbor_doc doc;
    omk_cbor_decode(&doc, resp, len);
    const omk_cbor_val *root = omk_cbor_root(&doc);
    check(root != NULL && omk_cbor_map_get_int(&doc, root, 3) != NULL,
          "allowList assertion carries a signature");
}

static void test_pin_lockout(fixture *f) {
    fixture_init(f);
    pin_client pc;
    pin_set_1234(f, &pc, 2);

    uint8_t pub_before[65];
    memcpy(pub_before, f->ct.pin.key_pub, 65);
    check(pin_get_token(f, &pc, 2, "0000", NULL) ==
              OMK_CTAP2_ERR_PIN_INVALID,
          "first wrong PIN is PIN_INVALID");
    check(f->ct.store.pin_retries == 7, "first wrong PIN consumes one retry");
    check(memcmp(pub_before, f->ct.pin.key_pub, 65) != 0,
          "wrong PIN regenerates key agreement");

    pin_client_init(f, &pc, 2, f->ct.pin.key_pub);
    check(pin_get_token(f, &pc, 2, "0000", NULL) ==
              OMK_CTAP2_ERR_PIN_INVALID,
          "second wrong PIN is PIN_INVALID");
    check(f->ct.store.pin_retries == 6, "second wrong PIN consumes one retry");

    pin_client_init(f, &pc, 2, f->ct.pin.key_pub);
    check(pin_get_token(f, &pc, 2, "0000", NULL) ==
              OMK_CTAP2_ERR_PIN_AUTH_BLOCKED,
          "third consecutive wrong PIN is PIN_AUTH_BLOCKED");
    check(f->ct.store.pin_retries == 5, "blocked attempt consumes no retry");

    /* The correct PIN does not bypass the per-boot consecutive lock. */
    pin_client_init(f, &pc, 2, f->ct.pin.key_pub);
    check(pin_get_token(f, &pc, 2, "1234", NULL) ==
              OMK_CTAP2_ERR_PIN_AUTH_BLOCKED,
          "correct PIN is refused while consecutively locked");
    check(f->ct.store.pin_retries == 5, "locked correct PIN consumes no retry");

    /* Reboot clears the RAM-only consecutive counter. */
    pin_reboot(f, &pc, 2);
    check(pin_get_token(f, &pc, 2, "1234", NULL) == 0,
          "correct PIN succeeds after reboot");
    check(f->ct.store.pin_retries == 8, "correct PIN restores 8 retries");
    check(f->ct.consecutive_pin_failures == 0,
          "correct PIN clears consecutive failures");
}

static void test_pin_retry_exhaustion(fixture *f) {
    fixture_init(f);
    pin_client pc;
    pin_set_1234(f, &pc, 2);

    static const uint8_t expect_retries[8] = {7, 6, 5, 4, 3, 2, 1, 0};
    for (int i = 0; i < 8; i++) {
        /* Three consecutive failures lock this boot; reboot to continue. */
        if (i % 3 == 0) {
            pin_reboot(f, &pc, 2);
        }
        uint8_t expected;
        if (i == 7) {
            expected = OMK_CTAP2_ERR_PIN_BLOCKED;
        } else if (i % 3 == 2) {
            expected = OMK_CTAP2_ERR_PIN_AUTH_BLOCKED;
        } else {
            expected = OMK_CTAP2_ERR_PIN_INVALID;
        }
        const uint8_t status = pin_get_token(f, &pc, 2, "0000", NULL);
        check(status == expected, "retry exhaustion status code");
        check(f->ct.store.pin_retries == expect_retries[i],
              "retry exhaustion persistent counter");
        if (i != 7) {
            pin_client_init(f, &pc, 2, f->ct.pin.key_pub);
        }
    }

    /* Persistent retries are 0: current and later attempts are PIN_BLOCKED. */
    pin_client_init(f, &pc, 2, f->ct.pin.key_pub);
    check(pin_get_token(f, &pc, 2, "1234", NULL) ==
              OMK_CTAP2_ERR_PIN_BLOCKED,
          "correct PIN after exhaustion is PIN_BLOCKED");
    check(f->ct.store.pin_retries == 0, "blocked authenticator stays at zero");
}

static void test_pin_last_retry_success(fixture *f) {
    fixture_init(f);
    pin_client pc;
    pin_set_1234(f, &pc, 2);

    /* Consume seven of the eight persistent retries. */
    for (int i = 0; i < 7; i++) {
        if (i % 3 == 0) {
            pin_reboot(f, &pc, 2);
        }
        const uint8_t status = pin_get_token(f, &pc, 2, "0000", NULL);
        const uint8_t expected =
            (i % 3 == 2) ? OMK_CTAP2_ERR_PIN_AUTH_BLOCKED
                         : OMK_CTAP2_ERR_PIN_INVALID;
        check(status == expected, "last-retry setup status");
        if (i != 6) {
            pin_client_init(f, &pc, 2, f->ct.pin.key_pub);
        }
    }
    check(f->ct.store.pin_retries == 1, "one retry left");

    /* The correct PIN must succeed on the last available retry. */
    pin_client_init(f, &pc, 2, f->ct.pin.key_pub);
    check(pin_get_token(f, &pc, 2, "1234", NULL) == 0,
          "correct PIN succeeds on the last retry");
    check(f->ct.store.pin_retries == 8, "success restores all retries");
    check(f->ct.consecutive_pin_failures == 0,
          "success clears consecutive failures");
}

static void test_pin_flash_failure(fixture *f) {
    pin_client pc;
    size_t len = 0;
    uint8_t status = 0;

    /* A failed write while reserving a retry must not compare the PIN.  On
     * the append-only meta log no erase is needed for an ordinary attempt,
     * so the injected write failure hits the decrement+candidate record
     * itself. */
    fixture_init(f);
    pin_set_1234(f, &pc, 2);
    f->env.fail_write = true;
    len = 1;
    status = pin_get_token(f, &pc, 2, "0000", &len);
    check(status == OMK_CTAP2_ERR_OTHER,
          "write failure is an explicit error, not PIN_INVALID");
    check(len == 0, "write failure issues no token");
    check(f->ct.store.pin_retries == 8,
          "failed retry write leaves the counter unchanged");
    check(f->ct.pin_store_fault, "write failure fails closed");
    f->env.fail_write = false;
    check(pin_get_token(f, &pc, 2, "1234", NULL) == OMK_CTAP2_ERR_OTHER,
          "write failure stays fail-closed within this boot");
    check(pin_get_token(f, &pc, 2, "0000", NULL) == OMK_CTAP2_ERR_OTHER,
          "wrong PIN never falls through to PIN_INVALID after flash failure");

    /* A failed read-back of the append-only record genuinely fails the
     * attempt: the write was not acknowledged, RAM keeps the old counter and
     * the authenticator fails closed.  The record is still on flash and the
     * next boot resolves the candidate (wrong) while keeping the decrement. */
    fixture_init(f);
    pin_set_1234(f, &pc, 2);
    f->env.fail_readback = true;
    len = 1;
    status = pin_get_token(f, &pc, 2, "0000", &len);
    check(status == OMK_CTAP2_ERR_OTHER,
          "read-back failure is an explicit error, not PIN_INVALID");
    check(len == 0, "read-back failure issues no token");
    check(f->ct.store.pin_retries == 8,
          "unacknowledged retry save is rolled back in RAM");
    check(f->ct.pin_store_fault, "read-back failure fails closed");
    f->env.fail_readback = false;
    check(pin_get_token(f, &pc, 2, "1234", NULL) == OMK_CTAP2_ERR_OTHER,
          "read-back failure stays fail-closed within this boot");
    check(pin_get_token(f, &pc, 2, "0000", NULL) == OMK_CTAP2_ERR_OTHER,
          "wrong PIN never falls through to PIN_INVALID after read-back fault");
    pin_reboot(f, &pc, 2);
    check(f->ct.store.pin_retries == 7,
          "read-back-failed attempt is durable across reboot");
    check(pin_get_token(f, &pc, 2, "1234", NULL) == 0,
          "authenticator recovers after the fault latch clears on reboot");
    check(f->ct.store.pin_retries == 8, "recovered success restores retries");

    /* The restore-to-8 write after a correct PIN can fail too.  Allow the
     * retry decrement write, then fail the success write. */
    fixture_init(f);
    pin_set_1234(f, &pc, 2);
    f->env.write_fail_after = 1;
    len = 1;
    status = pin_get_token(f, &pc, 2, "1234", &len);
    check(status == OMK_CTAP2_ERR_OTHER,
          "failed retry restore is propagated");
    check(len == 0, "failed retry restore issues no token");
    check(f->ct.store.pin_retries == 7,
          "failed retry restore rolls RAM back to the persisted value");
    check(f->ct.pin_store_fault, "failed retry restore fails closed");
    f->env.write_fail_after = -1;
    check(pin_get_token(f, &pc, 2, "1234", NULL) == OMK_CTAP2_ERR_OTHER,
          "restore failure stays fail-closed within this boot");

    /* The reject write after a wrong comparison must persist before the
     * response.  Fail only the reject record: the decrement is already
     * durable, the response is an explicit error and no token is issued. */
    fixture_init(f);
    pin_set_1234(f, &pc, 2);
    f->env.write_fail_after = 1;
    len = 1;
    status = pin_get_token(f, &pc, 2, "0000", &len);
    check(status == OMK_CTAP2_ERR_OTHER,
          "failed reject persistence is an explicit error");
    check(status != OMK_CTAP2_ERR_PIN_INVALID,
          "failed reject persistence is not reported as PIN_INVALID");
    check(len == 0, "failed reject persistence issues no token");
    check(f->ct.store.pin_retries == 7,
          "failed reject persistence keeps the durable decrement");
    check(f->ct.pin_store_fault, "failed reject persistence fails closed");
    f->env.write_fail_after = -1;
    check(pin_get_token(f, &pc, 2, "1234", NULL) == OMK_CTAP2_ERR_OTHER,
          "reject failure stays fail-closed within this boot");
}


/* A successful authenticatorReset rebuilds the store and must therefore
 * release the per-boot pin_store_fault latch; a failed Reset must not. */
static void test_pin_fault_reset_recovery(fixture *f) {
    pin_client pc;
    uint8_t resp[64];
    size_t resp_len = 0;

    fixture_init(f);
    pin_set_1234(f, &pc, 2);

    /* Latch the fault with a real getPinToken whose retry-counter write
     * fails. */
    f->env.fail_write = true;
    check(pin_get_token(f, &pc, 2, "1234", NULL) == OMK_CTAP2_ERR_OTHER,
          "reset-recovery: fault injection fails closed");
    check(f->ct.pin_store_fault,
          "reset-recovery: fault injection latches pin_store_fault");

    /* Keep the flash fault injected so Reset itself fails: the latch must
     * survive that failure. */
    resp_len = 1;
    check(send_cmd(f, 0x07, NULL, 0, resp, sizeof resp, &resp_len) ==
              OMK_CTAP2_ERR_OTHER,
          "reset-recovery: Reset fails while flash writes fail");
    check(f->ct.pin_store_fault,
          "reset-recovery: failed Reset keeps pin_store_fault latched");

    /* Undo the injection and Reset through the real command dispatcher. */
    f->env.fail_write = false;
    resp_len = 1;
    check(send_cmd(f, 0x07, NULL, 0, resp, sizeof resp, &resp_len) == 0,
          "reset-recovery: authenticatorReset succeeds");
    check(resp_len == 0, "reset-recovery: Reset success is status-only");
    check(!f->ct.pin_store_fault,
          "reset-recovery: successful Reset clears pin_store_fault");
    check(!f->ct.store.pin_set, "reset-recovery: Reset clears the PIN");

    /* A fresh setPIN followed by getPinToken must work again. */
    pin_set_1234(f, &pc, 2);
    resp_len = 1;
    check(pin_get_token(f, &pc, 2, "1234", &resp_len) == 0,
          "reset-recovery: getPinToken recovers after Reset");
    check(resp_len != 0,
          "reset-recovery: recovered getPinToken returns a token");
}

/* ---------------------------------------------------------------------- */
/* CTAP 2.3 default-profile regressions                                    */
/* ---------------------------------------------------------------------- */

/* Obtain a token through getPinToken (0x05) or
 * getPinUvAuthTokenUsingPinWithPermissions (0x09), optionally with the
 * permissions/rpId parameters, and decrypt it on success. */
static uint8_t pin_token_cmd(fixture *f, const pin_client *pc,
                             uint32_t protocol, const char *pin,
                             uint32_t subcommand, bool with_permissions,
                             uint32_t permissions, const char *rp,
                             uint8_t token[32]) {
    uint8_t full[32], hash[16], enc[64], body[512], resp[512];
    size_t enc_len = 0;
    omk_sha256(pin, strlen(pin), full);
    memcpy(hash, full, 16);
    pin_encrypt_c(pc, protocol, hash, sizeof hash, enc, &enc_len);

    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 4 + (with_permissions ? 1u : 0u) +
                             (rp != NULL ? 1u : 0u));
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, protocol);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, subcommand);
    omk_cbor_put_uint(&e, 3);
    cose_put(&e, pc->plat.pub);
    omk_cbor_put_uint(&e, 6);
    omk_cbor_put_bytes(&e, enc, enc_len);
    if (with_permissions) {
        omk_cbor_put_uint(&e, 9);
        omk_cbor_put_uint(&e, permissions);
    }
    if (rp != NULL) {
        omk_cbor_put_uint(&e, 10);
        omk_cbor_put_text(&e, rp, strlen(rp));
    }
    if (e.overflow) {
        return 0xFF;
    }

    size_t len = 0;
    const uint8_t status =
        send_cmd(f, 0x06, body, e.len, resp, sizeof resp, &len);
    if (status != 0 || token == NULL) {
        return status;
    }
    omk_cbor_doc doc;
    omk_cbor_decode(&doc, resp, len);
    const omk_cbor_val *root = omk_cbor_root(&doc);
    const omk_cbor_val *tok = omk_cbor_map_get_int(&doc, root, 2);
    if (tok == NULL || tok->type != OMK_CBOR_BYTES) {
        return 0xFE;
    }
    size_t token_len = 0;
    pin_decrypt_c(pc, protocol, tok->data, tok->len, token, &token_len);
    return token_len == 32 ? 0 : 0xFE;
}

static uint8_t authorize_test_token(fixture *f, const uint8_t token[32],
                                    const uint8_t cdh[32],
                                    const uint8_t rp_hash[32]) {
    uint8_t auth[32];
    omk_hmac_sha256(token, 32, cdh, 32, auth);
    omk_cbor_val param;
    memset(&param, 0, sizeof param);
    param.type = OMK_CBOR_BYTES;
    param.data = auth;
    param.len = sizeof auth;
    return omk_ctap_authorize_raw(&f->ct, &param, 2, cdh, 32, OMK_PERM_MC,
                                  rp_hash, NULL);
}

static void test_puat_sliding_expiry(fixture *f) {
    static const char rp[] = "puat-idle.test";
    fixture_init(f);
    pin_client pc;
    pin_set_1234(f, &pc, 2);
    uint8_t rp_hash[32];
    omk_sha256(rp, sizeof rp - 1, rp_hash);
    uint8_t cdh[32];
    memset(cdh, 0x64, sizeof cdh);
    uint8_t token[32];

    /* The first use switches expiry from created_ms to used_ms. */
    check(pin_token_cmd(f, &pc, 2, "1234", 0x09, true, OMK_PERM_MC, rp,
                        token) == 0,
          "puat-idle: initial token issued");
    check(authorize_test_token(f, token, cdh, rp_hash) == OMK_CTAP2_OK,
          "puat-idle: first use succeeds");
    check(f->ct.pin.used_once && f->ct.pin.used_ms == f->env.now,
          "puat-idle: first use records activity");
    f->env.now = f->ct.pin.used_ms + OMK_CTAP_PUAT_INITIAL_MS + 1;
    check(authorize_test_token(f, token, cdh, rp_hash) ==
              OMK_CTAP2_ERR_PIN_AUTH_INVALID,
          "puat-idle: authenticating check rejects idle token");
    check(!f->ct.pin.token_valid, "puat-idle: failed use invalidates token");

    /* Another use inside the window refreshes the idle deadline. */
    check(pin_token_cmd(f, &pc, 2, "1234", 0x09, true, OMK_PERM_MC, rp,
                        token) == 0,
          "puat-idle: refresh token issued");
    check(authorize_test_token(f, token, cdh, rp_hash) == OMK_CTAP2_OK,
          "puat-idle: refresh token first use");
    f->env.now = f->ct.pin.used_ms + OMK_CTAP_PUAT_INITIAL_MS;
    check(authorize_test_token(f, token, cdh, rp_hash) == OMK_CTAP2_OK,
          "puat-idle: use at idle boundary succeeds");
    check(f->ct.pin.used_ms == f->env.now,
          "puat-idle: second use refreshes activity timestamp");
    f->env.now = f->ct.pin.used_ms + OMK_CTAP_PUAT_INITIAL_MS + 1;
    check(authorize_test_token(f, token, cdh, rp_hash) ==
              OMK_CTAP2_ERR_PIN_AUTH_INVALID,
          "puat-idle: refreshed window expires on use");

    /* Keep using the token every 30 seconds: activity must not extend the
     * absolute ten-minute lifetime. At the exact boundary authorization still
     * succeeds; one millisecond later only the total timer can reject it. */
    check(pin_token_cmd(f, &pc, 2, "1234", 0x09, true, OMK_PERM_MC, rp,
                        token) == 0,
          "puat-total: token issued");
    const uint64_t created = f->ct.pin.created_ms;
    check(authorize_test_token(f, token, cdh, rp_hash) == OMK_CTAP2_OK,
          "puat-total: initial use");
    for (unsigned i = 1; i <= 20; i++) {
        f->env.now = created + (uint64_t)i * OMK_CTAP_PUAT_INITIAL_MS;
        check(authorize_test_token(f, token, cdh, rp_hash) == OMK_CTAP2_OK,
              "puat-total: periodic use remains valid through total boundary");
    }
    check(f->ct.pin.used_ms == created + OMK_CTAP_PUAT_TOTAL_MS,
          "puat-total: last use refreshed idle window at total boundary");
    f->env.now = created + OMK_CTAP_PUAT_TOTAL_MS + 1;
    check(authorize_test_token(f, token, cdh, rp_hash) ==
              OMK_CTAP2_ERR_PIN_AUTH_INVALID,
          "puat-total: use enforces unrefreshed total limit");
}

static uint8_t cm_enum_begin(fixture *f, const uint8_t token[32],
                             const uint8_t rp_hash[32], uint8_t *resp,
                             size_t resp_cap, size_t *resp_len) {
    uint8_t params[64], auth_input[96], auth[32], body[256];
    omk_cbor_enc pe;
    omk_cbor_enc_init(&pe, params, sizeof params);
    omk_cbor_put_map(&pe, 1);
    omk_cbor_put_uint(&pe, 1);
    omk_cbor_put_bytes(&pe, rp_hash, 32);
    if (pe.overflow) {
        return 0xFF;
    }
    auth_input[0] = 0x04;
    memcpy(auth_input + 1, params, pe.len);
    omk_hmac_sha256(token, 32, auth_input, 1 + pe.len, auth);

    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 4);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 0x04);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_raw(&e, params, pe.len);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, auth, sizeof auth);
    if (e.overflow) {
        return 0xFF;
    }
    return send_cmd(f, 0x0A, body, e.len, resp, resp_cap, resp_len);
}

static void test_cm_rp_bound_enumeration(fixture *f) {
    static const char rp[] = "cm-bound-a.test";
    fixture_init(f);
    uint8_t cdh[32];
    memset(cdh, 0x65, sizeof cdh);
    const uint8_t uid[4] = {6, 5, 6, 5};
    uint8_t body[512], resp[512];
    const size_t mc_len = build_mc(body, sizeof body, cdh, rp, uid, sizeof uid,
                                   true, false, false);
    size_t resp_len = 0;
    check(send_cmd(f, 0x01, body, mc_len, resp, sizeof resp, &resp_len) == 0,
          "cm-bound: resident credential created");

    pin_client pc;
    pin_set_1234(f, &pc, 2);
    uint8_t token[32];
    check(pin_token_cmd(f, &pc, 2, "1234", 0x09, true, OMK_PERM_CM, rp,
                        token) == 0,
          "cm-bound: CM-only RP-bound token issued");
    check(f->ct.pin.rp_bound && f->ct.pin.permissions == OMK_PERM_CM,
          "cm-bound: test token has exactly CM permission and RP binding");
    uint8_t rp_hash[32], wrong_rp_hash[32];
    omk_sha256(rp, sizeof rp - 1, rp_hash);
    omk_sha256("cm-bound-b.test", 15, wrong_rp_hash);

    check(cm_enum_begin(f, token, wrong_rp_hash, resp, sizeof resp,
                        &resp_len) == OMK_CTAP2_ERR_PIN_AUTH_INVALID,
          "cm-bound: wrong RP is rejected");
    check(cm_enum_begin(f, token, rp_hash, resp, sizeof resp, &resp_len) ==
              OMK_CTAP2_OK,
          "cm-bound: matching RP enumerates successfully");
    omk_cbor_doc doc;
    memset(&doc, 0, sizeof doc);
    check(omk_cbor_decode(&doc, resp, resp_len) && !doc.bad,
          "cm-bound: enumeration response is valid CBOR");
    const omk_cbor_val *root = omk_cbor_root(&doc);
    const omk_cbor_val *got_id = cm_response_id(&doc, root);
    check(got_id != NULL && got_id->type == OMK_CBOR_BYTES &&
              f->ct.store.cred_count == 1 &&
              got_id->len == f->ct.store.creds[0].id_len &&
              memcmp(got_id->data, f->ct.store.creds[0].id, got_id->len) == 0,
          "cm-bound: response returns the authorized RP credential");
}

static void test_pin_utf8(fixture *f) {
    fixture_init(f);
    pin_client pc;
    pin_client_init(f, &pc, 2, f->ct.pin.key_pub);

    uint8_t malformed_pad[64] = {0};
    memcpy(malformed_pad, "1234", 4);
    malformed_pad[5] = 0xA5;
    check(clientpin_set(f, &pc, 2, malformed_pad, sizeof malformed_pad) ==
              OMK_CTAP1_ERR_INVALID_PARAMETER,
          "padding: setPIN rejects non-zero bytes after the first zero");
    check(!f->ct.store.pin_set,
          "padding: rejected setPIN does not persist a PIN");

    static const struct {
        uint8_t bytes[8];
        size_t len;
    } invalid[] = {
        {{'a', 'b', 'c', 0x80}, 4},                    /* stray continuation */
        {{'a', 'b', 'c', 0xE2, 0x28, 0xA1}, 6},       /* bad continuation */
        {{'a', 'b', 'c', 0xF0, 0x9F, 0x92}, 6},       /* truncated */
        {{'a', 'b', 'c', 0xC0, 0xAF}, 5},             /* overlong 2-byte */
        {{'a', 'b', 'c', 0xE0, 0x80, 0xAF}, 6},       /* overlong 3-byte */
        {{'a', 'b', 'c', 0xF0, 0x80, 0x80, 0xAF}, 7}, /* overlong 4-byte */
        {{'a', 'b', 'c', 0xED, 0xA0, 0x80}, 6},       /* surrogate */
        {{'a', 'b', 'c', 0xF4, 0x90, 0x80, 0x80}, 7}, /* > U+10FFFF */
        {{'a', 'b', 'c', 0xF5, 0x80, 0x80, 0x80}, 7}, /* invalid lead */
    };
    for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; i++) {
        uint8_t pinpad[64] = {0};
        memcpy(pinpad, invalid[i].bytes, invalid[i].len);
        check(clientpin_set(f, &pc, 2, pinpad, sizeof pinpad) ==
                  OMK_CTAP2_ERR_PIN_POLICY_VIOLATION,
              "utf8: setPIN rejects malformed sequence");
        check(!f->ct.store.pin_set,
              "utf8: malformed setPIN does not persist a PIN");
    }

    /* Three valid code points are still too few even though they occupy 12
     * bytes. */
    uint8_t pinpad[64] = {0};
    static const uint8_t three_codepoints[12] = {
        0xF0, 0x9F, 0x98, 0x80, 0xF0, 0x9F,
        0x98, 0x80, 0xF0, 0x9F, 0x98, 0x80,
    };
    memcpy(pinpad, three_codepoints, sizeof three_codepoints);
    check(clientpin_set(f, &pc, 2, pinpad, sizeof pinpad) ==
              OMK_CTAP2_ERR_PIN_POLICY_VIOLATION,
          "utf8: setPIN enforces four code points rather than four bytes");

    /* Four code points covering 2/3/4-byte forms, including U+10FFFF. */
    static const uint8_t initial_pin[] = {
        0xC2, 0xA2,             /* U+00A2 */
        0xE2, 0x82, 0xAC,       /* U+20AC */
        0xF4, 0x8F, 0xBF, 0xBF, /* U+10FFFF */
        'a',
    };
    memset(pinpad, 0, sizeof pinpad);
    memcpy(pinpad, initial_pin, sizeof initial_pin);
    check(clientpin_set(f, &pc, 2, pinpad, sizeof pinpad) == OMK_CTAP2_OK,
          "utf8: setPIN accepts four valid multibyte code points");

    uint8_t current_full[32], current[16];
    omk_sha256(initial_pin, sizeof initial_pin, current_full);
    memcpy(current, current_full, sizeof current);
    static const uint8_t invalid_new_four[] = {'a', 0xED, 0xA0, 0x80};
    static const uint8_t invalid_new_longer[] = {'a', 'b', 'c',
                                                 0xED, 0xA0, 0x80};
    uint8_t newpad[64] = {0};
    memcpy(newpad, invalid_new_four, sizeof invalid_new_four);
    check(clientpin_change(f, &pc, 2, current, sizeof current, newpad,
                           sizeof newpad) == OMK_CTAP2_ERR_PIN_POLICY_VIOLATION,
          "utf8: changePIN rejects malformed four-byte PIN");
    memset(newpad, 0, sizeof newpad);
    memcpy(newpad, invalid_new_longer, sizeof invalid_new_longer);
    check(clientpin_change(f, &pc, 2, current, sizeof current, newpad,
                           sizeof newpad) == OMK_CTAP2_ERR_PIN_POLICY_VIOLATION,
          "utf8: changePIN rejects malformed non-four-byte PIN");

    /* Exactly 63 bytes: 21 copies of U+20AC.  Success with the old PIN also
     * proves the rejected change did not replace it. */
    uint8_t longest[63];
    for (size_t i = 0; i < 21; i++) {
        longest[i * 3] = 0xE2;
        longest[i * 3 + 1] = 0x82;
        longest[i * 3 + 2] = 0xAC;
    }
    memset(newpad, 0, sizeof newpad);
    memcpy(newpad, longest, sizeof longest);
    check(clientpin_change(f, &pc, 2, current, sizeof current, newpad,
                           sizeof newpad) == OMK_CTAP2_OK,
          "utf8: changePIN accepts valid 63-byte multibyte PIN");

    omk_sha256(longest, sizeof longest, current_full);
    memcpy(current, current_full, 16);
    memset(newpad, 0, sizeof newpad);
    memcpy(newpad, "5678", 4);
    newpad[5] = 0xA5;
    check(clientpin_change(f, &pc, 2, current, sizeof current, newpad,
                           sizeof newpad) == OMK_CTAP1_ERR_INVALID_PARAMETER,
          "padding: changePIN rejects non-zero bytes after the first zero");
    memset(newpad, 0, sizeof newpad);
    memcpy(newpad, "5678", 4);
    check(clientpin_change(f, &pc, 2, current, sizeof current, newpad,
                           sizeof newpad) == OMK_CTAP2_OK,
          "padding: rejected changePIN leaves the previous PIN usable");
}

static size_t build_ga_pin(uint8_t *out, size_t cap, const char *rp,
                           const uint8_t cdh[32], const uint8_t *puat,
                           size_t puat_len, uint32_t protocol) {
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, out, cap);
    omk_cbor_put_map(&e, 4);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_text(&e, rp, strlen(rp));
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_bytes(&e, cdh, 32);
    omk_cbor_put_uint(&e, 6);
    omk_cbor_put_bytes(&e, puat, puat_len);
    omk_cbor_put_uint(&e, 7);
    omk_cbor_put_uint(&e, protocol);
    return e.overflow ? 0 : e.len;
}

static size_t build_mc_params(uint8_t *out, size_t cap, const uint8_t cdh[32],
                              const char *rp, const uint8_t *uid, size_t uid_len,
                              const uint8_t *params, size_t params_len) {
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, out, cap);
    omk_cbor_put_map(&e, 4);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_bytes(&e, cdh, 32);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_text(&e, rp, strlen(rp));
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_bytes(&e, uid, uid_len);
    omk_cbor_put_uint(&e, 4);
    for (size_t i = 0; i < params_len; i++) {
        e.buf[e.len++] = params[i];
        if (e.len >= e.cap) {
            e.overflow = true;
            break;
        }
    }
    return e.overflow ? 0 : e.len;
}

static size_t build_mc_exclude(uint8_t *out, size_t cap, const uint8_t cdh[32],
                               const char *rp, const uint8_t *uid,
                               size_t uid_len, const uint8_t *exclude_id,
                               size_t exclude_len) {
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, out, cap);
    omk_cbor_put_map(&e, 5);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_bytes(&e, cdh, 32);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_text(&e, rp, strlen(rp));
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_bytes(&e, uid, uid_len);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_array(&e, 1);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_text(&e, "alg", 3);
    omk_cbor_put_nint(&e, -7);
    omk_cbor_put_text(&e, "type", 4);
    omk_cbor_put_text(&e, "public-key", 10);
    omk_cbor_put_uint(&e, 5);
    omk_cbor_put_array(&e, 1);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_text(&e, "type", 4);
    omk_cbor_put_text(&e, "public-key", 10);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_bytes(&e, exclude_id, exclude_len);
    return e.overflow ? 0 : e.len;
}

static size_t build_mc_hmac_mc_only(uint8_t *out, size_t cap,
                                    const uint8_t cdh[32], const char *rp,
                                    const uint8_t *uid, size_t uid_len,
                                    bool include_hmac_bool, bool hmac_bool) {
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, out, cap);
    omk_cbor_put_map(&e, 5);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_bytes(&e, cdh, 32);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_text(&e, rp, strlen(rp));
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_bytes(&e, uid, uid_len);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_array(&e, 1);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_text(&e, "alg", 3);
    omk_cbor_put_nint(&e, -7);
    omk_cbor_put_text(&e, "type", 4);
    omk_cbor_put_text(&e, "public-key", 10);
    omk_cbor_put_uint(&e, 6);
    omk_cbor_put_map(&e, include_hmac_bool ? 2 : 1);
    if (include_hmac_bool) {
        omk_cbor_put_text(&e, "hmac-secret", 11);
        omk_cbor_put_bool(&e, hmac_bool);
    }
    omk_cbor_put_text(&e, "hmac-secret-mc", 14);
    omk_cbor_put_map(&e, 0);
    return e.overflow ? 0 : e.len;
}

static bool cose_alg(const omk_cbor_doc *doc, const omk_cbor_val *cose,
                     int64_t *out) {
    if (cose == NULL || cose->type != OMK_CBOR_MAP) {
        return false;
    }
    const omk_cbor_val *alg = omk_cbor_map_get_int(doc, cose, 3);
    if (alg == NULL ||
        (alg->type != OMK_CBOR_NINT && alg->type != OMK_CBOR_UINT)) {
        return false;
    }
    *out = alg->num;
    return true;
}

static void test_key_agreement_cose(fixture *f) {
    fixture_init(f);
    uint8_t body[128], resp[512];
    size_t len = 0;
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 2);
    uint8_t status = send_cmd(f, 0x06, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "ka cose: getKeyAgreement status");
    omk_cbor_doc doc;
    omk_cbor_decode(&doc, resp, len);
    const omk_cbor_val *root = omk_cbor_root(&doc);
    const omk_cbor_val *cose = omk_cbor_map_get_int(&doc, root, 1);
    int64_t alg = 0;
    check(cose_alg(&doc, cose, &alg), "ka cose: alg present");
    check(alg == -25, "ka cose: key agreement alg is -25");
    const omk_cbor_val *kty = omk_cbor_map_get_int(&doc, cose, 1);
    const omk_cbor_val *crv = omk_cbor_map_get_int(&doc, cose, -1);
    check(kty != NULL && kty->type == OMK_CBOR_UINT && kty->num == 2,
          "ka cose: kty EC2");
    check(crv != NULL && crv->type == OMK_CBOR_UINT && crv->num == 1,
          "ka cose: crv P-256");

    /* Credential public keys keep the signature algorithm identifiers. */
    uint8_t cdh[32];
    memset(cdh, 0x3C, sizeof cdh);
    uint8_t uid[4] = {1, 2, 3, 4};
    for (int eddsa = 0; eddsa < 2; eddsa++) {
        const size_t mc_len =
            build_mc(body, sizeof body, cdh, "cose.test", uid, sizeof uid,
                     false, eddsa != 0, false);
        status = send_cmd(f, 0x01, body, mc_len, resp, sizeof resp, &len);
        check(status == 0, "ka cose: credential makeCredential status");
        mc_result mc;
        check(parse_mc(resp, len, &mc), "ka cose: credential parse");
        const size_t off = 37 + 16 + 2 + mc.cred_id_len;
        omk_cbor_doc keydoc;
        size_t used = 0;
        omk_cbor_decode_prefix(&keydoc, mc.auth_data + off,
                               mc.auth_len - off, &used);
        int64_t key_alg = 0;
        check(cose_alg(&keydoc, omk_cbor_root(&keydoc), &key_alg),
              "ka cose: credential COSE alg present");
        check(key_alg == (eddsa != 0 ? -8 : -7),
              "ka cose: credential COSE alg is -7/-8");
    }
}

static void test_puat_failure_statuses(fixture *f) {
    pin_client pc;
    uint8_t body[1024], resp[1024];
    size_t len = 0;
    uint8_t cdh[32];
    memset(cdh, 0x71, sizeof cdh);
    uint8_t uid[4] = {7, 1, 7, 1};
    omk_cbor_enc e;

    fixture_init(f);

    /* A credential that belongs to a different RP, created before the PIN. */
    size_t mc_len = build_mc(body, sizeof body, cdh, "rp-b.test", uid,
                             sizeof uid, true, false, false);
    uint8_t status = send_cmd(f, 0x01, body, mc_len, resp, sizeof resp, &len);
    check(status == 0, "puat: baseline credential status");
    mc_result mc_b;
    check(parse_mc(resp, len, &mc_b), "puat: baseline credential parse");
    check(f->ct.store.cred_count == 1, "puat: baseline credential stored");

    pin_set_1234(f, &pc, 2);

    /* Invalid permissions are rejected at issuance only. */
    check(pin_token_cmd(f, &pc, 2, "1234", 0x09, true, 0, NULL, NULL) ==
              OMK_CTAP1_ERR_INVALID_PARAMETER,
          "puat: zero permissions is INVALID_PARAMETER");
    check(pin_token_cmd(f, &pc, 2, "1234", 0x09, true, OMK_PERM_BE, NULL,
                        NULL) == OMK_CTAP2_ERR_UNAUTHORIZED_PERMISSION,
          "puat: unsupported permission is UNAUTHORIZED_PERMISSION");

    /* getPinToken must not accept the newer parameters. */
    check(pin_token_cmd(f, &pc, 2, "1234", 0x05, true, OMK_PERM_CM, NULL,
                        NULL) == OMK_CTAP1_ERR_INVALID_PARAMETER,
          "puat: legacy getPinToken rejects permissions");
    check(pin_token_cmd(f, &pc, 2, "1234", 0x05, false, 0, "rp-a.test",
                        NULL) == OMK_CTAP1_ERR_INVALID_PARAMETER,
          "puat: legacy getPinToken rejects rpId");
    uint8_t legacy_tok[32];
    check(pin_token_cmd(f, &pc, 2, "1234", 0x05, false, 0, NULL,
                        legacy_tok) == 0,
          "puat: legacy getPinToken still works without extras");

    /* A token limited to credMgmt cannot authorize MakeCredential. */
    uint8_t cm_tok[32];
    check(pin_token_cmd(f, &pc, 2, "1234", 0x09, true, OMK_PERM_CM, NULL,
                        cm_tok) == 0,
          "puat: credMgmt token issued");
    uint8_t mc_cdh[32];
    memset(mc_cdh, 0x72, sizeof mc_cdh);
    uint8_t puat[32];
    omk_hmac_sha256(cm_tok, 32, mc_cdh, 32, puat);
    mc_len = build_mc_pin(body, sizeof body, mc_cdh, "rp-a.test", uid,
                          sizeof uid, puat, sizeof puat, 2);
    status = send_cmd(f, 0x01, body, mc_len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_PIN_AUTH_INVALID,
          "puat: missing mc permission is PIN_AUTH_INVALID");
    check(f->ct.store.cred_count == 1,
          "puat: permission failure creates no credential");

    /* RP-bound token presented for another RP fails the same way. */
    uint8_t rp_tok[32];
    check(pin_token_cmd(f, &pc, 2, "1234", 0x09, true,
                        OMK_PERM_MC | OMK_PERM_GA, "rp-a.test",
                        rp_tok) == 0,
          "puat: RP-bound token issued");
    omk_hmac_sha256(rp_tok, 32, mc_cdh, 32, puat);
    mc_len = build_mc_pin(body, sizeof body, mc_cdh, "rp-b.test", uid,
                          sizeof uid, puat, sizeof puat, 2);
    status = send_cmd(f, 0x01, body, mc_len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_PIN_AUTH_INVALID,
          "puat: MC RP mismatch is PIN_AUTH_INVALID");
    len = 0;
    const size_t ga_len = build_ga_pin(body, sizeof body, "rp-b.test", mc_cdh,
                                       puat, sizeof puat, 2);
    status = send_cmd(f, 0x02, body, ga_len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_PIN_AUTH_INVALID,
          "puat: GA RP mismatch is PIN_AUTH_INVALID");

    /* The same RP-bound token is also enforced by CredentialManagement. */
    uint8_t params[128];
    omk_cbor_enc pe;
    omk_cbor_enc_init(&pe, params, sizeof params);
    omk_cbor_put_map(&pe, 1);
    omk_cbor_put_uint(&pe, 2);
    put_test_descriptor(&pe, mc_b.cred_id, mc_b.cred_id_len);
    uint8_t cm_input[160];
    cm_input[0] = 0x06;
    memcpy(cm_input + 1, params, pe.len);
    omk_hmac_sha256(rp_tok, 32, cm_input, 1 + pe.len, puat);
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 4);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 6);
    omk_cbor_put_uint(&e, 2);
    for (size_t i = 0; i < pe.len; i++) {
        e.buf[e.len++] = params[i];
    }
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, puat, sizeof puat);
    len = 0;
    status = send_cmd(f, 0x0A, body, e.len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_PIN_AUTH_INVALID,
          "puat: CM RP mismatch is PIN_AUTH_INVALID");
    check(omk_store_find_id(&f->ct.store, mc_b.cred_id, mc_b.cred_id_len) !=
              NULL,
          "puat: CM RP mismatch deletes nothing");

    /* Token expiry is reported as PIN_AUTH_INVALID, not PIN_TOKEN_EXPIRED. */
    uint8_t exp_tok[32];
    check(pin_token_cmd(f, &pc, 2, "1234", 0x09, true,
                        OMK_PERM_MC | OMK_PERM_GA, "rp-a.test",
                        exp_tok) == 0,
          "puat: expiry token issued");
    f->env.now += OMK_CTAP_PUAT_INITIAL_MS + 1;
    omk_hmac_sha256(exp_tok, 32, mc_cdh, 32, puat);
    mc_len = build_mc_pin(body, sizeof body, mc_cdh, "rp-a.test", uid,
                          sizeof uid, puat, sizeof puat, 2);
    status = send_cmd(f, 0x01, body, mc_len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_PIN_AUTH_INVALID,
          "puat: expired token is PIN_AUTH_INVALID");
    check(!f->ct.pin.token_valid, "puat: expired token is invalidated");
}

static void test_getassertion_no_credentials(fixture *f) {
    fixture_init(f);
    uint8_t cdh[32], body[1024], resp[1024];
    memset(cdh, 0x3D, sizeof cdh);
    uint8_t uid[4] = {8, 8, 8, 8};
    size_t len = 0;
    const size_t mc_len = build_mc(body, sizeof body, cdh, "only.test", uid,
                                   sizeof uid, true, false, false);
    uint8_t status = send_cmd(f, 0x01, body, mc_len, resp, sizeof resp, &len);
    check(status == 0, "nocr: baseline credential");
    mc_result mc;
    check(parse_mc(resp, len, &mc), "nocr: baseline credential parse");

    omk_cbor_enc e;
    f->env.auto_up = false;

    /* No discoverable credential for this RP: no UP wait. */
    uint64_t before = f->env.now;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_text(&e, "other.test", 10);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_bytes(&e, cdh, 32);
    len = 0;
    status = send_cmd(f, 0x02, body, e.len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_NO_CREDENTIALS,
          "nocr: no resident credentials is NO_CREDENTIALS");
    check(f->env.now == before, "nocr: no resident credentials does not wait");
    check(len == 0, "nocr: no credentials emits no assertion");

    /* An unmatched allowList is also immediate. */
    uint8_t fake_id[32];
    memset(fake_id, 0xAB, sizeof fake_id);
    before = f->env.now;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 3);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_text(&e, "only.test", 9);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_bytes(&e, cdh, 32);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_array(&e, 1);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_text(&e, "type", 4);
    omk_cbor_put_text(&e, "public-key", 10);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_bytes(&e, fake_id, sizeof fake_id);
    len = 0;
    status = send_cmd(f, 0x02, body, e.len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_NO_CREDENTIALS,
          "nocr: unmatched allowList is NO_CREDENTIALS");
    check(f->env.now == before, "nocr: unmatched allowList does not wait");

    /* A PUAT that reaches an empty allowList is not cleared by consume-up. */
    pin_client pc;
    pin_set_1234(f, &pc, 2);
    uint8_t tok[32];
    check(pin_token_cmd(f, &pc, 2, "1234", 0x09, true, OMK_PERM_GA,
                        "only.test", tok) == 0,
          "nocr: GA token issued");
    uint8_t puat[32];
    omk_hmac_sha256(tok, 32, cdh, 32, puat);
    before = f->env.now;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 5);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_text(&e, "only.test", 9);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_bytes(&e, cdh, 32);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_array(&e, 1);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_text(&e, "type", 4);
    omk_cbor_put_text(&e, "public-key", 10);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_bytes(&e, fake_id, sizeof fake_id);
    omk_cbor_put_uint(&e, 6);
    omk_cbor_put_bytes(&e, puat, sizeof puat);
    omk_cbor_put_uint(&e, 7);
    omk_cbor_put_uint(&e, 2);
    len = 0;
    status = send_cmd(f, 0x02, body, e.len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_NO_CREDENTIALS,
          "nocr: PUAT request with no match is NO_CREDENTIALS");
    check(f->env.now == before, "nocr: PUAT request with no match does not wait");
    check(f->ct.pin.token_valid,
          "nocr: no-match request does not consume the PUAT permissions");
    check(!f->ct.pin.used_once,
          "nocr: no-match request does not start the PUAT 10-minute window");

    /* Because the token was not consumed, the initial 30 s window still
     * applies: a later request with the same token is PIN_AUTH_INVALID. */
    f->env.now += OMK_CTAP_PUAT_INITIAL_MS + 1;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 5);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_text(&e, "only.test", 9);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_bytes(&e, cdh, 32);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_array(&e, 1);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_text(&e, "type", 4);
    omk_cbor_put_text(&e, "public-key", 10);
    omk_cbor_put_text(&e, "id", 2);
    omk_cbor_put_bytes(&e, mc.cred_id, mc.cred_id_len);
    omk_cbor_put_uint(&e, 6);
    omk_cbor_put_bytes(&e, puat, sizeof puat);
    omk_cbor_put_uint(&e, 7);
    omk_cbor_put_uint(&e, 2);
    len = 0;
    status = send_cmd(f, 0x02, body, e.len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_PIN_AUTH_INVALID,
          "nocr: unconsumed token still expires after the initial window");
    check(!f->ct.pin.token_valid, "nocr: expired token is invalidated");
}

static void test_hmac_mc_dependency(fixture *f) {
    fixture_init(f);
    uint8_t cdh[32], body[1024], resp[512];
    memset(cdh, 0x4D, sizeof cdh);
    uint8_t uid[4] = {5, 5, 5, 5};
    f->env.auto_up = false;

    /* hmac-secret-mc without hmac-secret:true must fail before any UP wait
     * or credential creation. */
    uint64_t before = f->env.now;
    size_t body_len = build_mc_hmac_mc_only(body, sizeof body, cdh, "hmac-dep.test",
                                            uid, sizeof uid, false, false);
    size_t len = 0;
    uint8_t status = send_cmd(f, 0x01, body, body_len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_MISSING_PARAMETER,
          "hmac-mc: missing hmac-secret is MISSING_PARAMETER");
    check(f->env.now == before, "hmac-mc: dependency error does not wait for UP");
    check(f->ct.store.cred_count == 0,
          "hmac-mc: dependency error creates no credential");

    /* Explicit hmac-secret:false is treated the same as absence. */
    body_len = build_mc_hmac_mc_only(body, sizeof body, cdh, "hmac-dep.test",
                                     uid, sizeof uid, true, false);
    status = send_cmd(f, 0x01, body, body_len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_MISSING_PARAMETER,
          "hmac-mc: hmac-secret false is MISSING_PARAMETER");
    check(f->ct.store.cred_count == 0,
          "hmac-mc: false dependency creates no credential");
}

static void test_exclude_timeout(fixture *f) {
    fixture_init(f);
    uint8_t cdh[32], body[1024], resp[1024];
    memset(cdh, 0x6E, sizeof cdh);
    uint8_t uid[4] = {2, 4, 6, 8};
    size_t len = 0;
    size_t mc_len = build_mc(body, sizeof body, cdh, "excl.test", uid,
                             sizeof uid, true, false, false);
    uint8_t status = send_cmd(f, 0x01, body, mc_len, resp, sizeof resp, &len);
    check(status == 0, "excl: baseline credential");
    mc_result mc;
    check(parse_mc(resp, len, &mc), "excl: baseline parse");

    uint8_t other[4] = {9, 9, 9, 9};
    memset(cdh, 0x6F, sizeof cdh);
    mc_len = build_mc_exclude(body, sizeof body, cdh, "excl.test", other,
                              sizeof other, mc.cred_id, mc.cred_id_len);
    status = send_cmd(f, 0x01, body, mc_len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_CREDENTIAL_EXCLUDED,
          "excl: excludeList hit returns CREDENTIAL_EXCLUDED");
    check(f->ct.store.cred_count == 1, "excl: hit creates no duplicate");

    /* A missing touch must not turn the final exclusion decision into a
     * user-action timeout. */
    f->env.auto_up = false;
    uint64_t before = f->env.now;
    status = send_cmd(f, 0x01, body, mc_len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_CREDENTIAL_EXCLUDED,
          "excl: timeout still returns CREDENTIAL_EXCLUDED");
    check(f->env.now - before >= OMK_CTAP_UP_TIMEOUT_MS,
          "excl: exclusion still waits for the UP window");
    check(f->ct.store.cred_count == 1,
          "excl: timed-out hit creates no credential");
}

static void test_missing_pin_protocol(fixture *f) {
    fixture_init(f);
    uint8_t cdh[32] = {0};
    uint8_t uid[4] = {1, 2, 3, 4};
    uint8_t body[512], resp[512];
    size_t len = 0;

    size_t body_len = build_mc(body, sizeof body, cdh, "missing proto", uid,
                               sizeof uid, false, false, false);
    body[0]++; /* add key 8: pinUvAuthParam = empty bytes, without key 9 */
    body[body_len++] = 0x08;
    body[body_len++] = 0x40;
    uint8_t status = send_cmd(f, 0x01, body, body_len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_MISSING_PARAMETER,
          "MC pinUvAuthParam requires pinUvAuthProtocol");

    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 3);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_text(&e, "missing.proto", 13);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_bytes(&e, cdh, sizeof cdh);
    omk_cbor_put_uint(&e, 6);
    omk_cbor_put_bytes(&e, NULL, 0);
    status = send_cmd(f, 0x02, body, e.len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_MISSING_PARAMETER,
          "GA pinUvAuthParam requires pinUvAuthProtocol");

    pin_client pc;
    pin_set_1234(f, &pc, 2);
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, NULL, 0);
    status = send_cmd(f, 0x0A, body, e.len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_MISSING_PARAMETER,
          "CM pinUvAuthParam requires pinUvAuthProtocol");

    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, NULL, 0);
    status = send_cmd(f, 0x06, body, e.len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_MISSING_PARAMETER,
          "ClientPIN pinUvAuthParam requires pinUvAuthProtocol");
}

static void test_cred_protect_echo(fixture *f) {
    fixture_init(f);
    uint8_t cdh[32];
    memset(cdh, 0x6C, sizeof cdh);
    uint8_t uid[4] = {4, 3, 2, 1};
    uint8_t body[512], resp[1024];
    size_t len = 0;

    size_t body_len = build_mc_ex(body, sizeof body, cdh, "protect.test", uid,
                                  sizeof uid, false, false, true, 0);
    uint8_t status = send_cmd(f, 0x01, body, body_len, resp, sizeof resp, &len);
    check(status == 0, "credProtect: hmac-only MC succeeds");
    mc_result mc;
    check(parse_mc(resp, len, &mc), "credProtect: hmac-only response parses");
    check(mc.has_extensions && !mc.cred_protect_echo,
          "credProtect is not echoed when not requested");

    body_len = build_mc_ex(body, sizeof body, cdh, "protect.test", uid,
                           sizeof uid, false, false, false, 3);
    status = send_cmd(f, 0x01, body, body_len, resp, sizeof resp, &len);
    check(status == 0, "credProtect: requested MC succeeds");
    check(parse_mc(resp, len, &mc), "credProtect: requested response parses");
    check(mc.cred_protect_echo && mc.cred_protect == 3,
          "credProtect response echoes the requested value");
    uint8_t rp_hash[32], seed[32], alg = 0, cp = 0;
    bool resident = false;
    omk_sha256("protect.test", 12, rp_hash);
    check(omk_store_open_credential(&f->ct.store, rp_hash, mc.cred_id,
                                    mc.cred_id_len, seed, &alg, &cp,
                                    &resident) && cp == 3,
          "credProtect echo matches the sealed credential policy");
    omk_memzero(seed, sizeof seed);

    /* Regression test: when credProtect and hmac-secret are both present,
     * canonical CBOR ordering (length, bytes) requires "credProtect" (len 11, 'c')
     * to precede "hmac-secret" (len 11, 'h').  Directly verify the raw encoded
     * bytes of the extensions map rather than using omk_cbor_map_get_text(). */
    body_len = build_mc_ex(body, sizeof body, cdh, "protect.test", uid,
                           sizeof uid, false, false, true, 3);
    status = send_cmd(f, 0x01, body, body_len, resp, sizeof resp, &len);
    check(status == 0, "credProtect: credProtect + hmac-secret MC succeeds");
    check(parse_mc(resp, len, &mc), "credProtect: parse response with both extensions");
    check(mc.has_extensions && mc.cred_protect_echo && mc.cred_protect == 3,
          "credProtect: both extensions present in response");
    static const uint8_t expected_ext_order[] = {
        0xA2,
        0x6B, 'c', 'r', 'e', 'd', 'P', 'r', 'o', 't', 'e', 'c', 't', 0x03,
        0x6B, 'h', 'm', 'a', 'c', '-', 's', 'e', 'c', 'r', 'e', 't', 0xF5,
    };
    check(mc.ext_len == sizeof expected_ext_order,
          "credProtect: raw extension map length matches");
    check(memcmp(mc.auth_data + mc.ext_offset, expected_ext_order,
                 sizeof expected_ext_order) == 0,
          "credProtect: raw canonical CBOR key order: credProtect before hmac-secret");

    /* Regression test: when credProtect, hmac-secret, and hmac-secret-mc are
     * all present, canonical CBOR order requires:
     * "credProtect" (len 11, 'c') < "hmac-secret" (len 11, 'h') < "hmac-secret-mc" (len 14). */
    pin_client pc2;
    pin_client_init(f, &pc2, 2, f->ct.pin.key_pub);
    uint8_t plain[32];
    memset(plain, 0x33, sizeof plain);
    uint8_t salt_enc[128], salt_auth[32];
    size_t enc_len = 0, auth_len = 0;
    pin_encrypt_c(&pc2, 2, plain, sizeof plain, salt_enc, &enc_len);
    pin_auth_c(&pc2, 2, salt_enc, enc_len, salt_auth, &auth_len);
    body_len = build_hmac_mc_cp(body, sizeof body, cdh, "protect.test", uid,
                                sizeof uid, pc2.plat.pub, 2, salt_enc, enc_len,
                                salt_auth, auth_len, 3);
    check(body_len != 0, "build MC with 3 extensions");
    status = send_cmd(f, 0x01, body, body_len, resp, sizeof resp, &len);
    check(status == 0, "MC with 3 extensions succeeds");
    check(parse_mc(resp, len, &mc), "parse MC with 3 extensions");
    check(mc.has_extensions && mc.cred_protect_echo && mc.cred_protect == 3,
          "all extensions echoed");
    check(mc.ext_len >= 1 + 13 + 13 + 16, "ext_len covers 3 extension keys");
    check(mc.auth_data[mc.ext_offset] == 0xA3, "extension map has 3 pairs");
    static const uint8_t expected_prefix[] = {
        0xA3,
        0x6B, 'c', 'r', 'e', 'd', 'P', 'r', 'o', 't', 'e', 'c', 't', 0x03,
        0x6B, 'h', 'm', 'a', 'c', '-', 's', 'e', 'c', 'r', 'e', 't', 0xF5,
        0x6E, 'h', 'm', 'a', 'c', '-', 's', 'e', 'c', 'r', 'e', 't', '-', 'm', 'c',
    };
    check(memcmp(mc.auth_data + mc.ext_offset, expected_prefix,
                 sizeof expected_prefix) == 0,
          "raw canonical CBOR keys: credProtect < hmac-secret < hmac-secret-mc");
}

static void test_cm_enumeration_after_delete(fixture *f) {
    fixture_init(f);
    uint8_t cdh[32];
    memset(cdh, 0x6D, sizeof cdh);
    uint8_t body[1024], resp[1024];
    mc_result creds[3];
    size_t len = 0;

    for (uint8_t i = 0; i < 3; i++) {
        uint8_t uid[4] = {0xC0, i, 0, 0};
        const size_t n = build_mc(body, sizeof body, cdh, "enum-delete.test",
                                  uid, sizeof uid, true, false, false);
        const uint8_t rc = send_cmd(f, 0x01, body, n, resp, sizeof resp, &len);
        check(rc == 0 && parse_mc(resp, len, &creds[i]),
              "enum-delete: setup credential");
    }
    pin_client pc;
    pin_set_1234(f, &pc, 2);
    uint8_t token[32];
    check(pin_token_cmd(f, &pc, 2, "1234", 0x09, true, OMK_PERM_CM, NULL,
                        token) == 0,
          "enum-delete: CM token issued");

    uint8_t rp_hash[32];
    omk_sha256("enum-delete.test", 16, rp_hash);
    uint8_t params[256], auth_input[300], auth[32];
    omk_cbor_enc pe;
    omk_cbor_enc_init(&pe, params, sizeof params);
    omk_cbor_put_map(&pe, 1);
    omk_cbor_put_uint(&pe, 1);
    omk_cbor_put_bytes(&pe, rp_hash, sizeof rp_hash);
    auth_input[0] = 0x04;
    memcpy(auth_input + 1, params, pe.len);
    omk_hmac_sha256(token, sizeof token, auth_input, 1 + pe.len, auth);

    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 4);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_raw(&e, params, pe.len);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, auth, sizeof auth);
    uint8_t status = send_cmd(f, 0x0A, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "enum-delete: enumeration begins");

    omk_cbor_doc doc;
    omk_cbor_decode(&doc, resp, len);
    const omk_cbor_val *root = omk_cbor_root(&doc);
    const omk_cbor_val *id = cm_response_id(&doc, root);
    check(id != NULL && id->len == creds[2].cred_id_len &&
              memcmp(id->data, creds[2].cred_id, id->len) == 0,
          "enum-delete: newest credential returned first");
    const omk_cbor_val *total = omk_cbor_map_get_int(&doc, root, 9);
    check(total != NULL && total->type == OMK_CBOR_UINT && total->num == 3,
          "enum-delete: begin includes totalCredentials");
    const omk_cbor_val *pubkey = omk_cbor_map_get_int(&doc, root, 8);
    const omk_cbor_val *x = omk_cbor_map_get_int(&doc, pubkey, -2);
    const omk_cbor_val *y = omk_cbor_map_get_int(&doc, pubkey, -3);
    check(x != NULL && x->type == OMK_CBOR_BYTES && x->len == 32 &&
              y != NULL && y->type == OMK_CBOR_BYTES && y->len == 32 &&
              memcmp(x->data, creds[2].pub + 1, 32) == 0 &&
              memcmp(y->data, creds[2].pub + 33, 32) == 0,
          "enum-delete: begin includes the selected credential public key");

    /* Delete the middle (next-in-order) credential.  The old implementation
     * then reused its shifted array index and returned the newest one again. */
    omk_cbor_enc_init(&pe, params, sizeof params);
    omk_cbor_put_map(&pe, 1);
    omk_cbor_put_uint(&pe, 2);
    put_test_descriptor(&pe, creds[1].cred_id, creds[1].cred_id_len);
    auth_input[0] = 0x06;
    memcpy(auth_input + 1, params, pe.len);
    omk_hmac_sha256(token, sizeof token, auth_input, 1 + pe.len, auth);
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 4);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 6);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_raw(&e, params, pe.len);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, auth, sizeof auth);
    status = send_cmd(f, 0x0A, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "enum-delete: deletion succeeds during enumeration");

    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 5);
    status = send_cmd(f, 0x0A, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "enum-delete: continuation survives deletion");
    omk_cbor_decode(&doc, resp, len);
    root = omk_cbor_root(&doc);
    id = cm_response_id(&doc, root);
    check(id != NULL && id->len == creds[0].cred_id_len &&
              memcmp(id->data, creds[0].cred_id, id->len) == 0,
          "enum-delete: continuation skips deleted entry without duplicates");
    check(omk_cbor_map_get_int(&doc, root, 9) == NULL,
          "enum-delete: continuation omits totalCredentials");
    pubkey = omk_cbor_map_get_int(&doc, root, 8);
    x = omk_cbor_map_get_int(&doc, pubkey, -2);
    y = omk_cbor_map_get_int(&doc, pubkey, -3);
    check(x != NULL && x->type == OMK_CBOR_BYTES && x->len == 32 &&
              y != NULL && y->type == OMK_CBOR_BYTES && y->len == 32 &&
              memcmp(x->data, creds[0].pub + 1, 32) == 0 &&
              memcmp(y->data, creds[0].pub + 33, 32) == 0,
          "enum-delete: continuation includes its own credential public key");
}

static void test_cm_rp_enumeration_after_delete(fixture *f) {
    fixture_init(f);
    uint8_t cdh[32];
    memset(cdh, 0x7E, sizeof cdh);
    uint8_t body[1024], resp[1024];
    mc_result creds[3];
    size_t len = 0;

    const char *rps[3] = {"enum-rp-1.test", "enum-rp-2.test", "enum-rp-3.test"};
    for (uint8_t i = 0; i < 3; i++) {
        uint8_t uid[4] = {0xD0, i, 0, 0};
        const size_t n = build_mc(body, sizeof body, cdh, rps[i],
                                  uid, sizeof uid, true, false, false);
        const uint8_t rc = send_cmd(f, 0x01, body, n, resp, sizeof resp, &len);
        check(rc == 0 && parse_mc(resp, len, &creds[i]),
              "enum-rps-delete: setup resident credential");
    }

    pin_client pc;
    pin_set_1234(f, &pc, 2);
    uint8_t token[32];
    check(pin_token_cmd(f, &pc, 2, "1234", 0x09, true, OMK_PERM_CM, NULL,
                        token) == 0,
          "enum-rps-delete: CM token issued");

    /* enumerateRPsBegin (subcommand 0x02). */
    uint8_t auth_input[1] = {0x02};
    uint8_t auth[32];
    omk_hmac_sha256(token, sizeof token, auth_input, sizeof auth_input, auth);

    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 3);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, auth, sizeof auth);
    uint8_t status = send_cmd(f, 0x0A, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "enum-rps-delete: enumerateRPsBegin succeeds");

    uint8_t expected_hash1[32];
    omk_sha256(rps[0], strlen(rps[0]), expected_hash1);
    omk_cbor_doc doc;
    omk_cbor_decode(&doc, resp, len);
    const omk_cbor_val *root = omk_cbor_root(&doc);
    const omk_cbor_val *rp_hash_val = omk_cbor_map_get_int(&doc, root, 4);
    check(rp_hash_val != NULL && rp_hash_val->len == 32 &&
              memcmp(rp_hash_val->data, expected_hash1, 32) == 0,
          "enum-rps-delete: begin returns first RP");

    /* Delete all credentials of the next RP ("enum-rp-2.test"). */
    uint8_t params[256], del_auth_input[300], del_auth[32];
    omk_cbor_enc pe;
    omk_cbor_enc_init(&pe, params, sizeof params);
    omk_cbor_put_map(&pe, 1);
    omk_cbor_put_uint(&pe, 2);
    put_test_descriptor(&pe, creds[1].cred_id, creds[1].cred_id_len);
    del_auth_input[0] = 0x06;
    memcpy(del_auth_input + 1, params, pe.len);
    omk_hmac_sha256(token, sizeof token, del_auth_input, 1 + pe.len, del_auth);

    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 4);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 6);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_raw(&e, params, pe.len);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, del_auth, sizeof del_auth);
    status = send_cmd(f, 0x0A, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "enum-rps-delete: deleted next RP credential");

    /* enumerateRPsNext (subcommand 0x03). Must skip deleted RP and return surviving RP 3. */
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 3);
    status = send_cmd(f, 0x0A, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "enum-rps-delete: enumerateRPsNext succeeds after RP deleted");

    uint8_t expected_hash3[32];
    omk_sha256(rps[2], strlen(rps[2]), expected_hash3);
    omk_cbor_decode(&doc, resp, len);
    root = omk_cbor_root(&doc);
    rp_hash_val = omk_cbor_map_get_int(&doc, root, 4);
    check(rp_hash_val != NULL && rp_hash_val->len == 32 &&
              memcmp(rp_hash_val->data, expected_hash3, 32) == 0,
          "enum-rps-delete: next returns surviving third RP");

    /* Further enumerateRPsNext must return NOT_ALLOWED as enumeration is exhausted. */
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 1);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 3);
    status = send_cmd(f, 0x0A, body, e.len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_NOT_ALLOWED,
          "enum-rps-delete: exhausted enumeration returns NOT_ALLOWED");
}

static void test_update_user_immutable(fixture *f) {
    fixture_init(f);
    uint8_t cdh[32], body[1024], resp[1024];
    memset(cdh, 0x55, sizeof cdh);
    uint8_t uid[3] = {3, 1, 4};
    size_t len = 0;
    size_t mc_len = build_mc(body, sizeof body, cdh, "user.test", uid,
                             sizeof uid, true, false, false);
    uint8_t status = send_cmd(f, 0x01, body, mc_len, resp, sizeof resp, &len);
    check(status == 0, "user: resident credential");
    mc_result mc;
    check(parse_mc(resp, len, &mc), "user: resident parse");

    pin_client pc;
    pin_set_1234(f, &pc, 2);
    uint8_t tok[32];
    check(pin_token_cmd(f, &pc, 2, "1234", 0x09, true, OMK_PERM_CM, NULL,
                        tok) == 0,
          "user: CM token issued");

    uint8_t changed[3] = {9, 9, 9};
    uint8_t params[256];
    omk_cbor_enc pe;
    omk_cbor_enc_init(&pe, params, sizeof params);
    omk_cbor_put_map(&pe, 2);
    omk_cbor_put_uint(&pe, 2);
    put_test_descriptor(&pe, mc.cred_id, mc.cred_id_len);
    omk_cbor_put_uint(&pe, 3);
    omk_cbor_put_map(&pe, 2);
    omk_cbor_put_text(&pe, "id", 2);
    omk_cbor_put_bytes(&pe, changed, sizeof changed);
    omk_cbor_put_text(&pe, "name", 4);
    omk_cbor_put_text(&pe, "Renamed", 7);
    uint8_t auth_input[320], cm_auth[32];
    auth_input[0] = 0x07;
    memcpy(auth_input + 1, params, pe.len);
    omk_hmac_sha256(tok, 32, auth_input, 1 + pe.len, cm_auth);
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 4);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 7);
    omk_cbor_put_uint(&e, 2);
    for (size_t i = 0; i < pe.len; i++) {
        e.buf[e.len++] = params[i];
    }
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, cm_auth, sizeof cm_auth);
    len = 0;
    status = send_cmd(f, 0x0A, body, e.len, resp, sizeof resp, &len);
    check(status == OMK_CTAP1_ERR_INVALID_PARAMETER,
          "user: changing user.id is INVALID_PARAMETER");
    check(len == 0, "user: rejected update has no response body");
    const omk_credential *c =
        omk_store_find_id(&f->ct.store, mc.cred_id, mc.cred_id_len);
    check(c != NULL && c->user_id_len == sizeof changed &&
              memcmp(c->user_id, uid, sizeof uid) == 0,
          "user: rejected update leaves user.id unchanged");
    check(c != NULL && c->user_name_len == 0,
          "user: rejected update leaves the name unchanged");

    /* A same-ID update is still accepted and updates the profile fields. */
    pe.len = 0;
    omk_cbor_put_map(&pe, 2);
    omk_cbor_put_uint(&pe, 2);
    put_test_descriptor(&pe, mc.cred_id, mc.cred_id_len);
    omk_cbor_put_uint(&pe, 3);
    omk_cbor_put_map(&pe, 2);
    omk_cbor_put_text(&pe, "id", 2);
    omk_cbor_put_bytes(&pe, uid, sizeof uid);
    omk_cbor_put_text(&pe, "name", 4);
    omk_cbor_put_text(&pe, "Renamed", 7);
    auth_input[0] = 0x07;
    memcpy(auth_input + 1, params, pe.len);
    omk_hmac_sha256(tok, 32, auth_input, 1 + pe.len, cm_auth);
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 4);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 7);
    omk_cbor_put_uint(&e, 2);
    for (size_t i = 0; i < pe.len; i++) {
        e.buf[e.len++] = params[i];
    }
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, cm_auth, sizeof cm_auth);
    len = 0;
    status = send_cmd(f, 0x0A, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "user: same-id update succeeds");
    c = omk_store_find_id(&f->ct.store, mc.cred_id, mc.cred_id_len);
    check(c != NULL && c->user_name_len == 7 &&
              memcmp(c->user_name, "Renamed", 7) == 0,
          "user: same-id update changes the name");
    check(c != NULL && c->user_id_len == sizeof uid &&
              memcmp(c->user_id, uid, sizeof uid) == 0,
          "user: same-id update keeps user.id");
}

static void test_pubkey_params(fixture *f) {
    fixture_init(f);
    uint8_t cdh[32], params[256], body[1024], resp[512];
    memset(cdh, 0x66, sizeof cdh);
    uint8_t uid[3] = {6, 6, 6};
    size_t len = 0;

    /* Missing "type". */
    omk_cbor_enc pe;
    omk_cbor_enc_init(&pe, params, sizeof params);
    omk_cbor_put_array(&pe, 1);
    omk_cbor_put_map(&pe, 1);
    omk_cbor_put_text(&pe, "alg", 3);
    omk_cbor_put_nint(&pe, -7);
    size_t body_len =
        build_mc_params(body, sizeof body, cdh, "params.test", uid,
                        sizeof uid, params, pe.len);
    uint8_t status =
        send_cmd(f, 0x01, body, body_len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_MISSING_PARAMETER,
          "params: missing type is MISSING_PARAMETER");

    /* "type" with the wrong CBOR type. */
    pe.len = 0;
    omk_cbor_put_array(&pe, 1);
    omk_cbor_put_map(&pe, 2);
    omk_cbor_put_text(&pe, "type", 4);
    omk_cbor_put_uint(&pe, 5);
    omk_cbor_put_text(&pe, "alg", 3);
    omk_cbor_put_nint(&pe, -7);
    body_len = build_mc_params(body, sizeof body, cdh, "params.test", uid,
                               sizeof uid, params, pe.len);
    status = send_cmd(f, 0x01, body, body_len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
          "params: non-text type is CBOR_UNEXPECTED_TYPE");

    /* "alg" with the wrong CBOR type. */
    pe.len = 0;
    omk_cbor_put_array(&pe, 1);
    omk_cbor_put_map(&pe, 2);
    omk_cbor_put_text(&pe, "type", 4);
    omk_cbor_put_text(&pe, "public-key", 10);
    omk_cbor_put_text(&pe, "alg", 3);
    omk_cbor_put_text(&pe, "nope", 4);
    body_len = build_mc_params(body, sizeof body, cdh, "params.test", uid,
                               sizeof uid, params, pe.len);
    status = send_cmd(f, 0x01, body, body_len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
          "params: non-integer alg is CBOR_UNEXPECTED_TYPE");

    /* Missing "alg". */
    pe.len = 0;
    omk_cbor_put_array(&pe, 1);
    omk_cbor_put_map(&pe, 1);
    omk_cbor_put_text(&pe, "type", 4);
    omk_cbor_put_text(&pe, "public-key", 10);
    body_len = build_mc_params(body, sizeof body, cdh, "params.test", uid,
                               sizeof uid, params, pe.len);
    status = send_cmd(f, 0x01, body, body_len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_MISSING_PARAMETER,
          "params: missing alg is MISSING_PARAMETER");

    /* An unsupported text type may be skipped; a later entry can win. */
    pe.len = 0;
    omk_cbor_put_array(&pe, 2);
    omk_cbor_put_map(&pe, 2);
    omk_cbor_put_text(&pe, "type", 4);
    omk_cbor_put_text(&pe, "not-a-key", 9);
    omk_cbor_put_text(&pe, "alg", 3);
    omk_cbor_put_nint(&pe, -7);
    omk_cbor_put_map(&pe, 2);
    omk_cbor_put_text(&pe, "type", 4);
    omk_cbor_put_text(&pe, "public-key", 10);
    omk_cbor_put_text(&pe, "alg", 3);
    omk_cbor_put_nint(&pe, -7);
    body_len = build_mc_params(body, sizeof body, cdh, "params.test", uid,
                               sizeof uid, params, pe.len);
    status = send_cmd(f, 0x01, body, body_len, resp, sizeof resp, &len);
    check(status == 0, "params: unsupported text type is skipped");

    /* A supported type with an algorithm we do not implement. */
    static const uint8_t bad_params[] = {
        0x81,             /* array(1) */
        0xA2,             /* map(2) */
        0x64, 't', 'y', 'p', 'e', 0x6A, 'p', 'u', 'b', 'l', 'i', 'c', '-',
        'k', 'e', 'y',
        0x63, 'a', 'l', 'g', 0x28 /* -9 */
    };
    body_len = build_mc_params(body, sizeof body, cdh, "params.test", uid,
                               sizeof uid, bad_params, sizeof bad_params);
    status = send_cmd(f, 0x01, body, body_len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_UNSUPPORTED_ALGORITHM,
          "params: unsupported algorithm returns UNSUPPORTED_ALGORITHM");
}

static void test_gna_timer(fixture *f) {
    fixture_init(f);
    uint8_t cdh[32], body[1024], resp[1024];
    memset(cdh, 0x88, sizeof cdh);
    size_t len = 0;
    for (uint8_t i = 0; i < 3; i++) {
        uint8_t uid[2] = {i, (uint8_t)(0xA0 + i)};
        const size_t mc_len =
            build_mc(body, sizeof body, cdh, "gna.test", uid, sizeof uid, true,
                     false, false);
        const uint8_t status =
            send_cmd(f, 0x01, body, mc_len, resp, sizeof resp, &len);
        check(status == 0, "gna: resident credential created");
    }
    check(f->ct.store.cred_count == 3, "gna: three resident credentials");

    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_text(&e, "gna.test", 8);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_bytes(&e, cdh, 32);
    len = 0;
    uint8_t status = send_cmd(f, 0x02, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "gna: initial assertion");
    omk_cbor_doc doc;
    omk_cbor_decode(&doc, resp, len);
    const omk_cbor_val *root = omk_cbor_root(&doc);
    const omk_cbor_val *num = omk_cbor_map_get_int(&doc, root, 5);
    check(num != NULL && num->num == 3, "gna: numberOfCredentials is 3");

    f->env.now += OMK_CTAP_GA_STATE_MS - 10000;
    len = 0;
    status = send_cmd(f, 0x08, NULL, 0, resp, sizeof resp, &len);
    check(status == 0, "gna: first GetNextAssertion succeeds");

    /* The first GNA refreshed the 30 s window: this call is 40 s after the
     * original assertion but only 20 s after the refresh. */
    f->env.now += 20000;
    len = 0;
    status = send_cmd(f, 0x08, NULL, 0, resp, sizeof resp, &len);
    check(status == 0, "gna: GetNextAssertion refreshes the 30 s timer");
}

static void test_cm_zero_length_auth(fixture *f) {
    fixture_init(f);
    uint8_t body[128], resp[256];
    size_t len = 0;
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 3);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 3);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 4);
    omk_cbor_put_bytes(&e, NULL, 0);

    /* Without a PIN the discovery probe maps to PIN_NOT_SET. */
    uint8_t status = send_cmd(f, 0x0A, body, e.len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_PIN_NOT_SET,
          "cm probe: no PIN maps to PIN_NOT_SET");

    pin_client pc;
    pin_set_1234(f, &pc, 2);
    len = 0;
    status = send_cmd(f, 0x0A, body, e.len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_PIN_AUTH_INVALID,
          "cm probe: zero-length auth maps to PIN_AUTH_INVALID");
    check(status != OMK_CTAP_PIN_PROBE,
          "cm probe: internal probe code never escapes");
}

static bool all_zero_bytes(const void *p, size_t len) {
    const uint8_t *b = (const uint8_t *)p;
    for (size_t i = 0; i < len; i++) {
        if (b[i] != 0) {
            return false;
        }
    }
    return true;
}

static void test_init_rng_failure(void) {
    fixture f;
    fixture_init(&f);

    /* Format-time RNG failure is an init failure with no usable state. */
    memset(g_flash, 0xFF, sizeof g_flash);
    f.env.fail_random = true;
    check(omk_ctap_init(&f.ct, &f.port, &f.hid) == -1,
          "init fails when store RNG fails");

    /* PIN key-agreement generation is the second random draw on a fresh
     * store (master, keypair); the model AAGUID is constant. */
    memset(g_flash, 0xFF, sizeof g_flash);
    f.env.fail_random = false;
    f.env.random_fail_at = 2;
    f.env.random_calls = 0;
    check(omk_ctap_init(&f.ct, &f.port, &f.hid) == -1,
          "init fails when PIN keypair RNG fails");
    check(all_zero_bytes(f.ct.pin.key_priv, sizeof f.ct.pin.key_priv) &&
              all_zero_bytes(f.ct.pin.key_pub, sizeof f.ct.pin.key_pub),
          "failed init leaves no PIN keypair");

    memset(g_flash, 0xFF, sizeof g_flash);
    f.env.random_fail_at = 0;
    f.env.random_calls = 0;
    check(omk_ctap_init(&f.ct, &f.port, &f.hid) == 0,
          "init recovers after RNG failures");
}

static void test_makecredential_rng_failure(void) {
    fixture f;
    fixture_init(&f);
    uint8_t cdh[32];
    memset(cdh, 0x3C, sizeof cdh);
    uint8_t uid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t body[512];
    size_t body_len =
        build_mc(body, sizeof body, cdh, "rng.mc", uid, sizeof uid, true,
                 false, false);
    uint8_t resp[1024];
    size_t len = 0;
    const uint8_t count_before = f.ct.store.cred_count;
    const uint32_t counter_before = f.ct.store.counter;
    const uint32_t lease_before = f.ct.store.lease;
    const uint32_t next_before = f.ct.store.next_seq;

    f.env.random_calls = 0;
    f.env.random_fail_at = 1; /* credential key generation */
    uint8_t status = send_cmd(&f, 0x01, body, body_len, resp, sizeof resp,
                              &len);
    check(status == OMK_CTAP2_ERR_OTHER,
          "P-256 keygen RNG failure returns OTHER");
    check(f.ct.store.cred_count == count_before &&
              f.ct.store.counter == counter_before &&
              f.ct.store.lease == lease_before &&
              f.ct.store.next_seq == next_before,
          "failed keygen stores no credential and consumes no counter");

    f.env.random_calls = 0;
    f.env.random_fail_at = 2; /* credential-ID sealing IV */
    status = send_cmd(&f, 0x01, body, body_len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_OTHER,
          "seal IV RNG failure returns OTHER");
    check(f.ct.store.cred_count == count_before &&
              f.ct.store.counter == counter_before &&
              f.ct.store.lease == lease_before &&
              f.ct.store.next_seq == next_before,
          "failed sealing stores no credential and consumes no counter");

    /* Ed25519 credential key generation follows the same path. */
    body_len = build_mc(body, sizeof body, cdh, "rng.mc", uid, sizeof uid,
                        true, true, false);
    f.env.random_calls = 0;
    f.env.random_fail_at = 1;
    status = send_cmd(&f, 0x01, body, body_len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_OTHER,
          "Ed25519 keygen RNG failure returns OTHER");
    check(f.ct.store.cred_count == count_before &&
              f.ct.store.counter == counter_before &&
              f.ct.store.lease == lease_before &&
              f.ct.store.next_seq == next_before,
          "failed Ed25519 keygen stores no credential or counter");

    f.env.random_fail_at = 0;
    f.env.random_calls = 0;
    status = send_cmd(&f, 0x01, body, body_len, resp, sizeof resp, &len);
    check(status == 0, "MakeCredential succeeds after RNG recovery");
    check(f.ct.store.cred_count == count_before + 1,
          "recovered MakeCredential stores a credential");
}

static void test_pin_token_rng_failure(void) {
    fixture f;
    fixture_init(&f);
    uint8_t pin_full[32];
    uint8_t pin_hash[16];
    omk_sha256("1234", 4, pin_full);
    memcpy(pin_hash, pin_full, 16);
    check(omk_store_set_pin(&f.ct.store, pin_hash) == 0,
          "token RNG test sets PIN");

    /* getKeyAgreement (protocol 2). */
    uint8_t body[1024];
    uint8_t resp[1024];
    size_t len = 0;
    omk_cbor_enc e;
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 2);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 2);
    check(send_cmd(&f, 0x06, body, e.len, resp, sizeof resp, &len) == 0,
          "token RNG test getKeyAgreement");
    omk_cbor_doc doc;
    omk_cbor_decode(&doc, resp, len);
    const omk_cbor_val *root = omk_cbor_root(&doc);
    const omk_cbor_val *cose = omk_cbor_map_get_int(&doc, root, 1);
    uint8_t auth_pub[65];
    check(extract_cose_pub(&doc, cose, auth_pub),
          "token RNG test key agreement COSE");
    pin_client pc;
    pin_client_init(&f, &pc, 2, auth_pub);
    uint8_t hash_enc[64];
    size_t hash_enc_len = 0;
    pin_encrypt_c(&pc, 2, pin_hash, 16, hash_enc, &hash_enc_len);
    omk_cbor_enc_init(&e, body, sizeof body);
    omk_cbor_put_map(&e, 4);
    omk_cbor_put_uint(&e, 1);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 2);
    omk_cbor_put_uint(&e, 5);
    omk_cbor_put_uint(&e, 3);
    cose_put(&e, pc.plat.pub);
    omk_cbor_put_uint(&e, 6);
    omk_cbor_put_bytes(&e, hash_enc, hash_enc_len);

    f.env.random_calls = 0;
    f.env.random_fail_at = 1; /* token bytes */
    uint8_t status = send_cmd(&f, 0x06, body, e.len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_OTHER, "token RNG failure returns OTHER");
    check(!f.ct.pin.token_valid, "failed token generation leaves no token");

    f.env.random_calls = 0;
    f.env.random_fail_at = 2; /* token encryption IV */
    status = send_cmd(&f, 0x06, body, e.len, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_OTHER, "token IV RNG failure returns OTHER");
    check(!f.ct.pin.token_valid,
          "failed token encryption leaves no valid token");

    f.env.random_fail_at = 0;
    f.env.random_calls = 0;
    status = send_cmd(&f, 0x06, body, e.len, resp, sizeof resp, &len);
    check(status == 0, "token issuance succeeds after RNG recovery");
    check(f.ct.pin.token_valid, "recovered token issuance is valid");
}

static void test_reset_long_op_cancel(void) {
    fixture f;
    fixture_init(&f);
    uint8_t master[32];
    memcpy(master, f.ct.store.master, sizeof master);
    uint8_t resp[64];
    size_t len = 0;

    f.env.cancel_long_op = true;
    uint8_t status = send_cmd(&f, 0x07, NULL, 0, resp, sizeof resp, &len);
    check(status == OMK_CTAP2_ERR_KEEPALIVE_CANCEL,
          "Reset long operation maps cancellation to KEEPALIVE_CANCEL");
    check(memcmp(master, f.ct.store.master, sizeof master) == 0,
          "cancelled Reset preserves the old master secret");

    f.env.cancel_long_op = false;
    status = send_cmd(&f, 0x07, NULL, 0, resp, sizeof resp, &len);
    check(status == 0, "Reset succeeds when cooperative cancellation clears");
    check(memcmp(master, f.ct.store.master, sizeof master) != 0,
          "retried Reset installs a fresh master secret");
}

static void test_reset_invalidates_state(void) {
    fixture f;
    fixture_init(&f);

    /* Establish a fully live authorization/extension state directly. */
    f.ct.pin.token_valid = true;
    memset(f.ct.pin.token, 0x7A, sizeof f.ct.pin.token);
    f.ct.pin.permissions = OMK_PERM_MC | OMK_PERM_GA;
    memset(f.ct.pin.rp_hash, 0x11, sizeof f.ct.pin.rp_hash);
    f.ct.pin.rp_bound = true;
    f.ct.pin.user_verified = true;
    f.ct.pin.used_once = true;
    f.ct.pin.created_ms = f.ct.boot_ms;
    f.ct.pin.used_ms = f.ct.boot_ms;
    f.ct.pin.protocol = 2;
    memset(f.ct.pin.shared_aes, 0x22, sizeof f.ct.pin.shared_aes);
    memset(f.ct.pin.shared_hmac, 0x33, sizeof f.ct.pin.shared_hmac);

    f.ct.ga.valid = true;
    f.ct.ga.next = 1;
    f.ct.ga.count = 2;
    f.ct.ga.hmac_secret = true;
    f.ct.ga.hmac_salt_len = 32;
    memset(f.ct.ga.hmac_salt, 0x44, sizeof f.ct.ga.hmac_salt);
    memset(f.ct.ga.hmac_aes, 0x55, sizeof f.ct.ga.hmac_aes);
    memset(f.ct.ga.rp_hash, 0x77, sizeof f.ct.ga.rp_hash);

    f.ct.cm.valid = true;
    f.ct.cm.kind = 2;
    f.ct.cm.next = 1;
    f.ct.cm.count = 2;
    memset(f.ct.cm.rp_hash, 0x88, sizeof f.ct.cm.rp_hash);
    memset(f.ct.cm.rp_hashes, 0x99, sizeof f.ct.cm.rp_hashes);

    f.ct.pin_store_fault = true;
    f.ct.consecutive_pin_failures = 3;
    f.env.now = f.ct.boot_ms + 100;

    uint8_t resp[64];
    size_t len = 0;
    const uint8_t status = send_cmd(&f, 0x07, NULL, 0, resp, sizeof resp, &len);
    check(status == 0, "Reset succeeds");

    check(!f.ct.pin.token_valid &&
              all_zero_bytes(f.ct.pin.token, sizeof f.ct.pin.token) &&
              f.ct.pin.permissions == 0 && !f.ct.pin.rp_bound &&
              !f.ct.pin.user_verified && !f.ct.pin.used_once,
          "Reset clears PUAT bytes and flags");
    check(f.ct.pin.protocol == 0 &&
              all_zero_bytes(f.ct.pin.shared_aes,
                             sizeof f.ct.pin.shared_aes) &&
              all_zero_bytes(f.ct.pin.shared_hmac,
                             sizeof f.ct.pin.shared_hmac),
          "Reset clears PIN shared keys");
    check(!f.ct.ga.valid && !f.ct.ga.hmac_secret && f.ct.ga.count == 0 &&
              all_zero_bytes(f.ct.ga.hmac_salt,
                             sizeof f.ct.ga.hmac_salt) &&
              all_zero_bytes(f.ct.ga.hmac_aes, sizeof f.ct.ga.hmac_aes),
          "Reset clears GA continuation and extension keys");
    check(!f.ct.cm.valid && f.ct.cm.count == 0 &&
              all_zero_bytes(f.ct.cm.rp_hash, sizeof f.ct.cm.rp_hash),
          "Reset clears CredentialManagement enumeration state");
    check(!f.ct.pin_store_fault && f.ct.consecutive_pin_failures == 0,
          "successful Reset clears PIN fault state");

    /* The old token cannot authorize, and neither continuation can resume. */
    uint8_t old_token[32];
    memset(old_token, 0x7A, sizeof old_token);
    omk_cbor_val param;
    memset(&param, 0, sizeof param);
    param.type = OMK_CBOR_BYTES;
    param.data = old_token;
    param.len = sizeof old_token;
    uint8_t rp_hash[32];
    memset(rp_hash, 0x11, sizeof rp_hash);
    bool uv = false;
    const uint8_t auth_status = omk_ctap_authorize_raw(
        &f.ct, &param, 2, (const uint8_t *)"x", 1, OMK_PERM_GA, rp_hash, &uv);
    check(auth_status != OMK_CTAP2_OK, "pre-Reset PUAT cannot authorize");

    len = 0;
    check(send_cmd(&f, 0x08, NULL, 0, resp, sizeof resp, &len) ==
              OMK_CTAP2_ERR_NOT_ALLOWED,
          "pre-Reset GetNextAssertion continuation is gone");

    uint8_t cm_body[8];
    omk_cbor_enc ce;
    omk_cbor_enc_init(&ce, cm_body, sizeof cm_body);
    omk_cbor_put_map(&ce, 1);
    omk_cbor_put_uint(&ce, 1);
    omk_cbor_put_uint(&ce, 5);
    len = 0;
    check(send_cmd(&f, 0x0A, cm_body, ce.len, resp, sizeof resp, &len) ==
              OMK_CTAP2_ERR_NOT_ALLOWED,
          "pre-Reset CredentialManagement continuation is gone");
}

