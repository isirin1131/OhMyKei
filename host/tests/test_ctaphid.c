/* CTAPHID transport tests: framing, channels, keepalive, cancel, abort. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fido/omk_ctaphid.h"

static int g_failures;

static void check(bool cond, const char *what) {
    if (!cond) {
        printf("FAIL: %s\n", what);
        g_failures++;
    }
}

/* ---------------------------------------------------------------------- */
/* Fake port                                                               */
/* ---------------------------------------------------------------------- */

#define MAX_PACKETS 512

typedef struct {
    uint64_t now;
    uint32_t rng;
    uint8_t packets[MAX_PACKETS][64];
    size_t packet_count;
    /* Number of packets hid_send accepts before reporting backpressure. */
    size_t send_limit;
    unsigned led_calls;
    bool led_last;
    bool random_fail;
} fake_env;

typedef struct {
    uint32_t cid;
    uint8_t cmd;
    uint8_t data[OMK_CTAPHID_MAX_MESSAGE];
    size_t len;
    bool open;
} captured_msg;

typedef struct {
    captured_msg msgs[32];
    size_t count;
} captured;

static uint64_t fake_now(void *ctx) {
    return ((fake_env *)ctx)->now;
}

static bool fake_random(void *ctx, void *out, size_t len) {
    fake_env *e = (fake_env *)ctx;
    uint8_t *p = (uint8_t *)out;
    if (e->random_fail) {
        /* Partial fill: callers must discard every byte on false. */
        for (size_t i = 0; i < len / 2; i++) {
            e->rng ^= e->rng << 13;
            e->rng ^= e->rng >> 17;
            e->rng ^= e->rng << 5;
            p[i] = (uint8_t)(e->rng >> 24);
        }
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        e->rng ^= e->rng << 13;
        e->rng ^= e->rng >> 17;
        e->rng ^= e->rng << 5;
        p[i] = (uint8_t)(e->rng >> 24);
    }
    return true;
}

static bool fake_send(void *ctx, const uint8_t packet[64]) {
    fake_env *e = (fake_env *)ctx;
    if (e->packet_count >= e->send_limit ||
        e->packet_count >= MAX_PACKETS) {
        return false;
    }
    memcpy(e->packets[e->packet_count++], packet, 64);
    return true;
}

static void fake_led(void *ctx, bool on) {
    fake_env *e = (fake_env *)ctx;
    e->led_calls++;
    e->led_last = on;
}

static bool fake_up(void *ctx) {
    (void)ctx;
    return false;
}

static int fake_read(void *ctx, uint32_t off, void *dst, size_t len) {
    (void)ctx;
    (void)off;
    memset(dst, 0, len);
    return 0;
}

static int fake_write(void *ctx, uint32_t off, const void *src, size_t len) {
    (void)ctx;
    (void)off;
    (void)src;
    (void)len;
    return 0;
}

static int fake_erase(void *ctx, uint32_t off) {
    (void)ctx;
    (void)off;
    return 0;
}

static void fake_log(void *ctx, const char *msg) {
    (void)ctx;
    (void)msg;
}

/* ---------------------------------------------------------------------- */
/* Packet helpers                                                          */
/* ---------------------------------------------------------------------- */

static void build_frames(uint32_t cid, uint8_t cmd, const uint8_t *data,
                         size_t len, uint8_t out[][64], size_t *count) {
    size_t n = 0;
    memset(out[n], 0, 64);
    out[n][0] = (uint8_t)(cid >> 24);
    out[n][1] = (uint8_t)(cid >> 16);
    out[n][2] = (uint8_t)(cid >> 8);
    out[n][3] = (uint8_t)cid;
    out[n][4] = (uint8_t)(cmd | 0x80u);
    out[n][5] = (uint8_t)(len >> 8);
    out[n][6] = (uint8_t)len;
    size_t first = len < 57 ? len : 57;
    if (first != 0) {
        memcpy(out[n] + 7, data, first);
    }
    n++;
    size_t off = first;
    uint8_t seq = 0;
    while (off < len) {
        memset(out[n], 0, 64);
        out[n][0] = (uint8_t)(cid >> 24);
        out[n][1] = (uint8_t)(cid >> 16);
        out[n][2] = (uint8_t)(cid >> 8);
        out[n][3] = (uint8_t)cid;
        out[n][4] = seq++;
        size_t chunk = len - off;
        if (chunk > 59) {
            chunk = 59;
        }
        memcpy(out[n] + 5, data + off, chunk);
        off += chunk;
        n++;
    }
    *count = n;
}

static void capture_packets2(const fake_env *e, captured *cap) {
    memset(cap, 0, sizeof(*cap));
    captured_msg *cur = NULL;
    size_t expected = 0;
    for (size_t i = 0; i < e->packet_count; i++) {
        const uint8_t *p = e->packets[i];
        uint32_t cid = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                       ((uint32_t)p[2] << 8) | p[3];
        uint8_t b = p[4];
        if ((b & 0x80u) != 0) {
            if (cap->count >= 32) {
                break;
            }
            cur = &cap->msgs[cap->count++];
            cur->cid = cid;
            cur->cmd = b;
            expected = (size_t)((p[5] << 8) | p[6]);
            cur->len = expected < 57 ? expected : 57;
            memcpy(cur->data, p + 7, cur->len);
            cur->open = cur->len < expected;
        } else if (cur != NULL && cur->open) {
            size_t remaining = expected - cur->len;
            size_t chunk = remaining > 59 ? 59 : remaining;
            memcpy(cur->data + cur->len, p + 5, chunk);
            cur->len += chunk;
            if (cur->len >= expected) {
                cur->open = false;
            }
        }
    }
}

/* ---------------------------------------------------------------------- */
/* Dispatcher                                                              */
/* ---------------------------------------------------------------------- */

typedef struct {
    omk_ctaphid *hid;
    void (*during)(void *ctx);
    void *during_ctx;
    bool during_done;
    uint8_t last[OMK_CTAPHID_MAX_MESSAGE];
    size_t last_len;
    int calls;
    bool handle_cancel;
} dispatch_ctx;

static void dispatcher(void *ctx, uint32_t cid, const uint8_t *msg,
                       size_t len) {
    dispatch_ctx *d = (dispatch_ctx *)ctx;
    d->calls++;
    d->last_len = len;
    memcpy(d->last, msg, len);

    if (!d->during_done && d->during != NULL) {
        d->during_done = true;
        d->during(d->during_ctx);
    }
    if (d->handle_cancel && omk_ctaphid_cancel_pending(d->hid)) {
        const uint8_t status = 0x2D; /* CTAP2_ERR_KEEPALIVE_CANCEL */
        omk_ctaphid_send(d->hid, cid, &status, 1);
        return;
    }
    const uint8_t response[] = {0x00};
    omk_ctaphid_send(d->hid, cid, response, sizeof response);
}

typedef struct {
    fake_env env;
    omk_port port;
    omk_ctaphid hid;
    dispatch_ctx disp;
} fixture;

static void fixture_init(fixture *f) {
    memset(f, 0, sizeof(*f));
    f->env.now = 1000;
    f->env.rng = 0x12345678u;
    f->env.send_limit = (size_t)-1;
    f->port.ctx = &f->env;
    f->port.now_ms = fake_now;
    f->port.random_bytes = fake_random;
    f->port.flash_read = fake_read;
    f->port.flash_write = fake_write;
    f->port.flash_erase = fake_erase;
    f->port.up_pressed = fake_up;
    f->port.led = fake_led;
    f->port.hid_send = fake_send;
    f->port.hid_pump = NULL;
    f->port.log = fake_log;
    f->disp.hid = &f->hid;
    omk_ctaphid_init(&f->hid, &f->port, dispatcher, &f->disp);
}

static uint32_t do_init(fixture *f, const uint8_t nonce[8]) {
    uint8_t frames[4][64];
    size_t n = 0;
    build_frames(OMK_CTAPHID_BROADCAST_CID, 0x86, nonce, 8, frames, &n);
    for (size_t i = 0; i < n; i++) {
        omk_ctaphid_rx_packet(&f->hid, frames[i]);
    }
    captured cap;
    capture_packets2(&f->env, &cap);
    check(cap.count == 1, "INIT produces one response");
    if (cap.count != 1) {
        return 0;
    }
    check(cap.msgs[0].cid == OMK_CTAPHID_BROADCAST_CID,
          "INIT response CID is broadcast");
    check(cap.msgs[0].cmd == 0x86, "INIT response command");
    check(cap.msgs[0].len == 17, "INIT response length 17");
    check(memcmp(cap.msgs[0].data + 4, nonce, 8) == 0, "INIT nonce echo");
    check(cap.msgs[0].data[12] == 2, "CTAPHID version 2");
    check(cap.msgs[0].data[16] == 0x0D, "capabilities WINK|CBOR|NMSG");
    uint32_t new_cid = ((uint32_t)cap.msgs[0].data[0] << 24) |
                       ((uint32_t)cap.msgs[0].data[1] << 16) |
                       ((uint32_t)cap.msgs[0].data[2] << 8) | cap.msgs[0].data[3];
    check(new_cid != 0 && new_cid != OMK_CTAPHID_BROADCAST_CID, "new CID");
    f->env.packet_count = 0;
    return new_cid;
}

static void test_init(void) {
    fixture f;
    fixture_init(&f);
    static const uint8_t nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint32_t cid1 = do_init(&f, nonce);
    uint32_t cid2 = do_init(&f, nonce);
    uint32_t cid3 = do_init(&f, nonce);
    check(cid1 != 0 && cid2 != 0 && cid3 != 0, "three channels");
    check(cid1 != cid2 && cid2 != cid3 && cid1 != cid3,
          "broadcast INIT allocates unique channels");

    /* Re-INIT on an existing channel returns that channel again. */
    static const uint8_t nonce2[8] = {9, 9, 9, 9, 9, 9, 9, 9};
    uint8_t frames[4][64];
    size_t n = 0;
    build_frames(cid1, 0x86, nonce2, 8, frames, &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    captured cap;
    capture_packets2(&f.env, &cap);
    check(cap.count == 1, "sync INIT response");
    if (cap.count == 1) {
        uint32_t got = ((uint32_t)cap.msgs[0].data[0] << 24) |
                       ((uint32_t)cap.msgs[0].data[1] << 16) |
                       ((uint32_t)cap.msgs[0].data[2] << 8) |
                       cap.msgs[0].data[3];
        check(got == cid1, "sync INIT keeps CID");
    }
}

static void test_cid_rng_failure(void) {
    fixture f;
    fixture_init(&f);
    f.env.random_fail = true;

    static const uint8_t nonce[8] = {0x5A};
    uint8_t frames[4][64];
    size_t n = 0;
    build_frames(OMK_CTAPHID_BROADCAST_CID, 0x86, nonce, sizeof nonce,
                 frames, &n);
    f.env.packet_count = 0;
    omk_ctaphid_rx_packet(&f.hid, frames[0]);

    captured cap;
    capture_packets2(&f.env, &cap);
    check(cap.count == 1, "failed CID allocation sends one error");
    check(cap.count == 1 && cap.msgs[0].cmd == OMK_CTAPHID_CMD_ERROR &&
              cap.msgs[0].data[0] == OMK_CTAPHID_ERR_OTHER,
          "failed CID allocation reports ERR_OTHER");
    check(f.hid.channel_count == 0, "failed CID allocation adds no channel");

    /* Nothing was corrupted: a later INIT with a working RNG succeeds. */
    f.env.random_fail = false;
    f.env.packet_count = 0;
    const uint32_t cid = do_init(&f, nonce);
    check(cid != 0, "channel allocation recovers after RNG failure");
    check(f.hid.channel_count == 1, "recovered allocation adds one channel");
}

static void test_ping_sizes(void) {
    static const size_t sizes[] = {0, 1, 57, 58, 59, 60, 63, 64, 120, 1024};
    for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
        fixture f;
        fixture_init(&f);
        static const uint8_t nonce[8] = {0};
        uint32_t cid = do_init(&f, nonce);
        uint8_t payload[1024];
        for (size_t i = 0; i < sizes[s]; i++) {
            payload[i] = (uint8_t)(i * 3 + 1);
        }
        uint8_t frames[32][64];
        size_t n = 0;
        build_frames(cid, 0x81, payload, sizes[s], frames, &n);
        for (size_t i = 0; i < n; i++) {
            omk_ctaphid_rx_packet(&f.hid, frames[i]);
        }
        captured cap;
        capture_packets2(&f.env, &cap);
        check(cap.count == 1, "ping one response");
        if (cap.count == 1) {
            check(cap.msgs[0].cmd == 0x81, "ping command");
            check(cap.msgs[0].len == sizes[s], "ping length");
            if (memcmp(cap.msgs[0].data, payload, sizes[s]) != 0) {
                size_t bad = 0;
                while (bad < sizes[s] && cap.msgs[0].data[bad] == payload[bad]) {
                    bad++;
                }
                printf("ping echo mismatch size=%zu at %zu got=%02x want=%02x\n",
                       sizes[s], bad,
                       bad < cap.msgs[0].len ? cap.msgs[0].data[bad] : 0,
                       payload[bad]);
                g_failures++;
            }
        }
    }
}

static void test_cbor_dispatch(void) {
    fixture f;
    fixture_init(&f);
    static const uint8_t nonce[8] = {1};
    uint32_t cid = do_init(&f, nonce);
    static const uint8_t req[] = {0x04, 0xA0}; /* authenticatorGetInfo {} */
    uint8_t frames[2][64];
    size_t n = 0;
    build_frames(cid, 0x90, req, sizeof req, frames, &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    captured cap;
    capture_packets2(&f.env, &cap);
    check(f.disp.calls == 1, "cbor dispatched once");
    check(f.disp.last_len == sizeof req &&
              memcmp(f.disp.last, req, sizeof req) == 0,
          "cbor payload delivered");
    check(cap.count == 1 && cap.msgs[0].cmd == 0x90, "cbor response");
    check(cap.count == 1 && cap.msgs[0].data[0] == 0x00, "ok status");
}

typedef struct {
    fixture *f;
    uint32_t cid;
} during_ctx;

static void inject_cancel(void *ctx) {
    during_ctx *d = (during_ctx *)ctx;
    uint8_t frames[2][64];
    size_t n = 0;
    const uint8_t empty = 0;
    build_frames(d->cid, 0x91, &empty, 0, frames, &n);
    (void)n;
    omk_ctaphid_rx_packet(&d->f->hid, frames[0]);
    d->f->env.now += 10;
}

static void test_cancel(void) {
    fixture f;
    fixture_init(&f);
    static const uint8_t nonce[8] = {3};
    uint32_t cid = do_init(&f, nonce);
    during_ctx d = {&f, cid};
    f.disp.during = inject_cancel;
    f.disp.during_ctx = &d;
    f.disp.handle_cancel = true;

    static const uint8_t req[] = {0x01, 0xA0};
    uint8_t frames[2][64];
    size_t n = 0;
    build_frames(cid, 0x90, req, sizeof req, frames, &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    captured cap;
    capture_packets2(&f.env, &cap);
    check(cap.count == 1, "cancel response count");
    if (cap.count == 1) {
        check(cap.msgs[0].cmd == 0x90, "cancel response is CBOR");
        check(cap.msgs[0].len == 1 && cap.msgs[0].data[0] == 0x2D,
              "cancel returns KEEPALIVE_CANCEL");
    }

    /* A second CANCEL on an idle channel is silent. */
    f.env.packet_count = 0;
    build_frames(cid, 0x91, NULL, 0, frames, &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    check(f.env.packet_count == 0, "cancel when idle is silent");
}

static void inject_init_abort(void *ctx) {
    during_ctx *d = (during_ctx *)ctx;
    static const uint8_t nonce[8] = {7, 7, 7, 7, 7, 7, 7, 7};
    uint8_t frames[2][64];
    size_t n = 0;
    build_frames(d->cid, 0x86, nonce, 8, frames, &n);
    omk_ctaphid_rx_packet(&d->f->hid, frames[0]);
}

static void test_abort_with_init(void) {
    fixture f;
    fixture_init(&f);
    static const uint8_t nonce[8] = {4};
    uint32_t cid = do_init(&f, nonce);
    during_ctx d = {&f, cid};
    f.disp.during = inject_init_abort;
    f.disp.during_ctx = &d;

    static const uint8_t req[] = {0x02, 0xA0};
    uint8_t frames[2][64];
    size_t n = 0;
    build_frames(cid, 0x90, req, sizeof req, frames, &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    captured cap;
    capture_packets2(&f.env, &cap);
    check(cap.count == 1, "aborted command sends nothing");
    if (cap.count == 1) {
        check(cap.msgs[0].cmd == 0x86, "INIT response wins");
        check(cap.msgs[0].len == 17, "INIT abort response length");
    }
}

static void inject_other_cbor(void *ctx) {
    during_ctx *d = (during_ctx *)ctx;
    uint8_t frames[2][64];
    size_t n = 0;
    static const uint8_t req[] = {0x04, 0xA0};
    build_frames(d->cid, 0x90, req, sizeof req, frames, &n);
    omk_ctaphid_rx_packet(&d->f->hid, frames[0]);
    d->f->env.now += 5;
}

static void test_busy_other_channel(void) {
    fixture f;
    fixture_init(&f);
    static const uint8_t nonce[8] = {5};
    uint32_t cid1 = do_init(&f, nonce);
    uint32_t cid2 = do_init(&f, nonce);
    check(cid1 != cid2, "two channels for busy test");

    during_ctx d = {&f, cid2};
    f.disp.during = inject_other_cbor;
    f.disp.during_ctx = &d;

    uint8_t frames[2][64];
    size_t n = 0;
    static const uint8_t req[] = {0x01, 0xA0};
    build_frames(cid1, 0x90, req, sizeof req, frames, &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);

    captured cap;
    capture_packets2(&f.env, &cap);
    check(f.disp.calls == 1, "other-channel request not dispatched");
    bool saw_busy = false;
    bool saw_ok = false;
    for (size_t i = 0; i < cap.count; i++) {
        if (cap.msgs[i].cid == cid2 && cap.msgs[i].cmd == 0xBF &&
            cap.msgs[i].len == 1 && cap.msgs[i].data[0] == 0x06) {
            saw_busy = true;
        }
        if (cap.msgs[i].cid == cid1 && cap.msgs[i].cmd == 0x90) {
            saw_ok = true;
        }
    }
    check(saw_busy, "busy channel rejects other CID");
    check(saw_ok, "original command still completes");
}

static void test_stray_and_seq(void) {
    fixture f;
    fixture_init(&f);
    static const uint8_t nonce[8] = {6};
    uint32_t cid = do_init(&f, nonce);

    /* Stray continuation on an allocated channel: no response. */
    uint8_t pkt[64];
    memset(pkt, 0, sizeof pkt);
    pkt[0] = (uint8_t)(cid >> 24);
    pkt[1] = (uint8_t)(cid >> 16);
    pkt[2] = (uint8_t)(cid >> 8);
    pkt[3] = (uint8_t)cid;
    pkt[4] = 0;
    omk_ctaphid_rx_packet(&f.hid, pkt);
    check(f.env.packet_count == 0, "stray continuation ignored");

    /* Wrong sequence number after a valid first frame. */
    uint8_t payload[120];
    memset(payload, 0xAA, sizeof payload);
    uint8_t frames[4][64];
    size_t n = 0;
    build_frames(cid, 0x81, payload, sizeof payload, frames, &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    frames[1][4] = 5;
    omk_ctaphid_rx_packet(&f.hid, frames[1]);
    captured cap;
    capture_packets2(&f.env, &cap);
    check(cap.count == 1 && cap.msgs[0].cmd == 0xBF, "wrong seq error");
    if (cap.count == 1) {
        check(cap.msgs[0].len == 1 && cap.msgs[0].data[0] == 0x04,
              "wrong seq code");
    }
}

static void test_wink_and_msg(void) {
    fixture f;
    fixture_init(&f);
    static const uint8_t nonce[8] = {8};
    uint32_t cid = do_init(&f, nonce);

    uint8_t frames[2][64];
    size_t n = 0;
    build_frames(cid, 0x88, NULL, 0, frames, &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    captured cap;
    capture_packets2(&f.env, &cap);
    check(cap.count == 1 && cap.msgs[0].cmd == 0x88 && cap.msgs[0].len == 0,
          "wink empty response");

    f.env.packet_count = 0;
    build_frames(cid, 0x83, (const uint8_t *)"\x00", 1, frames, &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    capture_packets2(&f.env, &cap);
    check(cap.count == 1 && cap.msgs[0].cmd == 0xBF &&
              cap.msgs[0].data[0] == 0x01,
          "MSG rejected with INVALID_CMD");
}

/* A dispatcher "wait" that lasts well past the 500 ms reassembly timeout. */
static void wait_over_500ms(void *ctx) {
    during_ctx *d = (during_ctx *)ctx;
    fixture *f = d->f;
    check(!f->hid.rx_active, "reassembly ended before dispatch");
    check(omk_ctaphid_busy(&f->hid), "busy during dispatch");
    for (int i = 0; i < 70; i++) {
        f->env.now += 10;
        omk_ctaphid_poll(&f->hid);
    }
    check(omk_ctaphid_busy(&f->hid), "still busy after long wait");
}

static void test_multiframe_long_up_wait(void) {
    fixture f;
    fixture_init(&f);
    static const uint8_t nonce[8] = {0x31};
    uint32_t cid = do_init(&f, nonce);
    check(cid != 0, "long wait channel");

    during_ctx d = {&f, cid};
    f.disp.during = wait_over_500ms;
    f.disp.during_ctx = &d;

    uint8_t payload[120];
    for (size_t i = 0; i < sizeof payload; i++) {
        payload[i] = (uint8_t)(i + 1);
    }
    uint8_t frames[8][64];
    size_t n = 0;
    build_frames(cid, OMK_CTAPHID_CMD_CBOR, payload, sizeof payload, frames, &n);
    for (size_t i = 0; i < n; i++) {
        omk_ctaphid_rx_packet(&f.hid, frames[i]);
    }

    check(f.disp.calls == 1, "long wait dispatched once");
    captured cap;
    capture_packets2(&f.env, &cap);
    bool timeout = false;
    bool response = false;
    for (size_t i = 0; i < cap.count; i++) {
        if (cap.msgs[i].cmd == OMK_CTAPHID_CMD_ERROR && cap.msgs[i].len == 1 &&
            cap.msgs[i].data[0] == OMK_CTAPHID_ERR_MSG_TIMEOUT) {
            timeout = true;
        }
        if (cap.msgs[i].cid == cid && cap.msgs[i].cmd == OMK_CTAPHID_CMD_CBOR) {
            response = true;
        }
    }
    check(!timeout, "long UP wait does not produce ERR_MSG_TIMEOUT");
    check(response, "long UP wait still sends the response");
}

/* USB reset / deconfiguration arriving while the dispatcher waits for UP. */
static void usb_reset_during_wait(void *ctx) {
    during_ctx *d = (during_ctx *)ctx;
    fixture *f = d->f;

    check(omk_ctaphid_busy(&f->hid), "busy before USB reset");
    omk_ctaphid_reset(&f->hid);
    check(omk_ctaphid_busy(&f->hid), "USB reset does not clear busy");
    check(omk_ctaphid_aborted(&f->hid), "USB reset latches abort");
    check(!f->hid.rx_active, "USB reset clears reassembly");
    check(f->hid.channel_count == 0, "USB reset clears channels");
    check(!omk_ctaphid_send(&f->hid, d->cid, (const uint8_t[]){0}, 1),
          "response after USB reset is suppressed");
    check(!omk_ctaphid_send_error(&f->hid, d->cid,
                                  OMK_CTAPHID_ERR_INVALID_CHANNEL),
          "error after USB reset is suppressed");

    /* A broadcast INIT may still allocate during the aborting dispatch, but a
     * complete CBOR command must not recursively enter CTAP. */
    static const uint8_t nonce[8] = {0x41};
    const uint32_t fresh = do_init(f, nonce);
    check(fresh != 0 && fresh != d->cid, "fresh channel after USB reset");
    uint8_t frames[2][64];
    size_t n = 0;
    static const uint8_t req[] = {0x04, 0xA0};
    build_frames(fresh, OMK_CTAPHID_CMD_CBOR, req, sizeof req, frames, &n);
    omk_ctaphid_rx_packet(&f->hid, frames[0]);
    check(f->disp.calls == 1, "no recursive CTAP dispatch after USB reset");
}

static void test_usb_reset_during_wait(void) {
    fixture f;
    fixture_init(&f);
    static const uint8_t nonce[8] = {0x42};
    uint32_t cid = do_init(&f, nonce);
    check(cid != 0, "reset wait channel");

    during_ctx d = {&f, cid};
    f.disp.during = usb_reset_during_wait;
    f.disp.during_ctx = &d;

    static const uint8_t req[] = {0x01, 0xA0};
    uint8_t frames[2][64];
    size_t n = 0;
    build_frames(cid, OMK_CTAPHID_CMD_CBOR, req, sizeof req, frames, &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);

    check(f.disp.calls == 1, "USB reset wait dispatched once");
    check(f.env.packet_count == 0, "no stale-CID response after USB reset");
    check(!omk_ctaphid_busy(&f.hid), "dispatch epilogue clears busy");
    check(!omk_ctaphid_aborted(&f.hid), "dispatch epilogue clears abort");
    check(f.hid.channel_count == 1, "fresh channel survives epilogue");

    /* The transport still works on the freshly allocated channel. */
    const uint32_t fresh = f.hid.channels[0];
    f.env.packet_count = 0;
    const uint8_t ping = 0x5A;
    build_frames(fresh, OMK_CTAPHID_CMD_PING, &ping, 1, frames, &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    captured cap;
    capture_packets2(&f.env, &cap);
    check(cap.count == 1 && cap.msgs[0].cmd == OMK_CTAPHID_CMD_PING &&
              cap.msgs[0].len == 1 && cap.msgs[0].data[0] == ping,
          "transport recovers after USB reset");
}

static void test_idle_reassembly_timeout(void) {
    fixture f;
    fixture_init(&f);
    static const uint8_t nonce[8] = {0x51};
    uint32_t cid = do_init(&f, nonce);

    uint8_t payload[120];
    memset(payload, 0xA5, sizeof payload);
    uint8_t frames[4][64];
    size_t n = 0;
    build_frames(cid, OMK_CTAPHID_CMD_PING, payload, sizeof payload, frames,
                 &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    check(f.hid.rx_active, "reassembly active after first frame");

    f.env.now += 600;
    omk_ctaphid_tick(&f.hid);
    check(!f.hid.rx_active, "idle tick expires reassembly");
    captured cap;
    capture_packets2(&f.env, &cap);
    check(cap.count == 1 && cap.msgs[0].cmd == OMK_CTAPHID_CMD_ERROR &&
              cap.msgs[0].len == 1 &&
              cap.msgs[0].data[0] == OMK_CTAPHID_ERR_MSG_TIMEOUT,
          "idle tick sends ERR_MSG_TIMEOUT");

    /* The poll path must behave the same (used from the UP wait loop). */
    f.env.packet_count = 0;
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    f.env.now += 600;
    omk_ctaphid_poll(&f.hid);
    capture_packets2(&f.env, &cap);
    check(cap.count == 1 && cap.msgs[0].cmd == OMK_CTAPHID_CMD_ERROR &&
              cap.msgs[0].data[0] == OMK_CTAPHID_ERR_MSG_TIMEOUT,
          "poll expires idle reassembly");
}

static void test_two_cid_interleave(void) {
    fixture f;
    fixture_init(&f);
    static const uint8_t nonce[8] = {0x61};
    uint32_t cid_a = do_init(&f, nonce);
    uint32_t cid_b = do_init(&f, nonce);
    check(cid_a != 0 && cid_b != 0 && cid_a != cid_b,
          "two channels for interleave");

    uint8_t payload[120];
    for (size_t i = 0; i < sizeof payload; i++) {
        payload[i] = (uint8_t)(0x80 + i);
    }
    uint8_t frames[4][64];
    size_t n = 0;
    build_frames(cid_a, OMK_CTAPHID_CMD_PING, payload, sizeof payload, frames,
                 &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    check(f.hid.rx_active && f.hid.rx_cid == cid_a,
          "A reassembly active before B");

    f.env.packet_count = 0;
    const uint8_t b_payload = 0x11;
    uint8_t bframes[2][64];
    size_t bn = 0;
    build_frames(cid_b, OMK_CTAPHID_CMD_PING, &b_payload, 1, bframes, &bn);
    omk_ctaphid_rx_packet(&f.hid, bframes[0]);
    captured cap;
    capture_packets2(&f.env, &cap);
    check(cap.count == 1 && cap.msgs[0].cid == cid_b &&
              cap.msgs[0].cmd == OMK_CTAPHID_CMD_ERROR &&
              cap.msgs[0].data[0] == OMK_CTAPHID_ERR_CHANNEL_BUSY,
          "B initial frame gets CHANNEL_BUSY");
    check(f.hid.rx_active && f.hid.rx_cid == cid_a,
          "B does not destroy A reassembly");

    f.env.packet_count = 0;
    for (size_t i = 1; i < n; i++) {
        omk_ctaphid_rx_packet(&f.hid, frames[i]);
    }
    capture_packets2(&f.env, &cap);
    check(cap.count == 1 && cap.msgs[0].cid == cid_a &&
              cap.msgs[0].cmd == OMK_CTAPHID_CMD_PING &&
              cap.msgs[0].len == sizeof payload &&
              memcmp(cap.msgs[0].data, payload, sizeof payload) == 0,
          "A reassembly survives interleave and completes");
}

typedef struct {
    fixture *f;
    uint32_t busy_cid;
    uint32_t other_cid;
} wink_ctx;

static void inject_busy_wink(void *ctx) {
    wink_ctx *w = (wink_ctx *)ctx;
    uint8_t frames[2][64];
    size_t n = 0;
    build_frames(w->busy_cid, OMK_CTAPHID_CMD_WINK, NULL, 0, frames, &n);
    omk_ctaphid_rx_packet(&w->f->hid, frames[0]);
    build_frames(w->other_cid, OMK_CTAPHID_CMD_WINK, NULL, 0, frames, &n);
    omk_ctaphid_rx_packet(&w->f->hid, frames[0]);

    /* Re-INIT on another channel is a request on a busy transport too. */
    static const uint8_t nonce[8] = {0x73};
    build_frames(w->other_cid, OMK_CTAPHID_CMD_INIT, nonce, sizeof nonce,
                 frames, &n);
    omk_ctaphid_rx_packet(&w->f->hid, frames[0]);
    w->f->env.now += 5;
}

static void test_busy_wink(void) {
    fixture f;
    fixture_init(&f);
    static const uint8_t nonce[8] = {0x71};
    uint32_t cid1 = do_init(&f, nonce);
    uint32_t cid2 = do_init(&f, nonce);
    check(cid1 != 0 && cid2 != 0 && cid1 != cid2, "wink channels");

    wink_ctx w = {&f, cid1, cid2};
    f.disp.during = inject_busy_wink;
    f.disp.during_ctx = &w;

    static const uint8_t req[] = {0x01, 0xA0};
    uint8_t frames[2][64];
    size_t n = 0;
    build_frames(cid1, OMK_CTAPHID_CMD_CBOR, req, sizeof req, frames, &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);

    check(f.env.led_calls == 0, "WINK does not drive LED while busy");
    captured cap;
    capture_packets2(&f.env, &cap);
    unsigned busy = 0;
    unsigned wink = 0;
    unsigned init = 0;
    bool response = false;
    for (size_t i = 0; i < cap.count; i++) {
        if (cap.msgs[i].cmd == OMK_CTAPHID_CMD_WINK) {
            wink++;
        }
        if (cap.msgs[i].cmd == OMK_CTAPHID_CMD_INIT) {
            init++;
        }
        if (cap.msgs[i].cmd == OMK_CTAPHID_CMD_ERROR &&
            cap.msgs[i].len == 1 &&
            cap.msgs[i].data[0] == OMK_CTAPHID_ERR_CHANNEL_BUSY) {
            busy++;
        }
        if (cap.msgs[i].cid == cid1 &&
            cap.msgs[i].cmd == OMK_CTAPHID_CMD_CBOR) {
            response = true;
        }
    }
    check(busy == 3,
          "WINK/INIT on busy and other CID returns CHANNEL_BUSY");
    check(wink == 0, "no WINK response while busy");
    check(init == 0, "no re-INIT response for another channel while busy");
    check(response, "busy command still completes after WINK");
}

static void test_null_led_wink(void) {
    fixture f;
    fixture_init(&f);
    f.port.led = NULL;
    static const uint8_t nonce[8] = {0x72};
    uint32_t cid = do_init(&f, nonce);

    uint8_t frames[2][64];
    size_t n = 0;
    build_frames(cid, OMK_CTAPHID_CMD_WINK, NULL, 0, frames, &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    captured cap;
    capture_packets2(&f.env, &cap);
    check(cap.count == 1 && cap.msgs[0].cmd == OMK_CTAPHID_CMD_WINK &&
              cap.msgs[0].len == 0,
          "WINK works with NULL led");
    check(f.env.led_calls == 0, "NULL led is not called");
}

static void test_unknown_init(void) {
    fixture f;
    fixture_init(&f);
    const uint32_t foreign = 0x0BADF00Du;
    static const uint8_t nonce[8] = {0x81};

    uint8_t frames[2][64];
    size_t n = 0;
    build_frames(foreign, OMK_CTAPHID_CMD_INIT, nonce, sizeof nonce, frames,
                 &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    captured cap;
    capture_packets2(&f.env, &cap);
    check(cap.count == 1 && cap.msgs[0].cid == foreign &&
              cap.msgs[0].cmd == OMK_CTAPHID_CMD_ERROR &&
              cap.msgs[0].data[0] == OMK_CTAPHID_ERR_INVALID_CHANNEL,
          "unknown non-broadcast INIT returns INVALID_CHANNEL");
    check(f.hid.channel_count == 0, "unknown INIT does not allocate");

    f.env.packet_count = 0;
    const uint8_t ping = 0x22;
    build_frames(foreign, OMK_CTAPHID_CMD_PING, &ping, 1, frames, &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    capture_packets2(&f.env, &cap);
    check(cap.count == 1 && cap.msgs[0].cmd == OMK_CTAPHID_CMD_ERROR &&
              cap.msgs[0].data[0] == OMK_CTAPHID_ERR_INVALID_CHANNEL,
          "command on implicitly allocated CID is invalid");

    /* A malformed INIT on an unknown CID still reports the channel error. */
    f.env.packet_count = 0;
    memset(frames[0], 0, 64);
    frames[0][0] = (uint8_t)(foreign >> 24);
    frames[0][1] = (uint8_t)(foreign >> 16);
    frames[0][2] = (uint8_t)(foreign >> 8);
    frames[0][3] = (uint8_t)foreign;
    frames[0][4] = OMK_CTAPHID_CMD_INIT;
    frames[0][5] = 0;
    frames[0][6] = 4;
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    capture_packets2(&f.env, &cap);
    check(cap.count == 1 && cap.msgs[0].cmd == OMK_CTAPHID_CMD_ERROR &&
              cap.msgs[0].data[0] == OMK_CTAPHID_ERR_INVALID_CHANNEL,
          "unknown INIT checked before length");

    f.env.packet_count = 0;
    const uint32_t cid = do_init(&f, nonce);
    check(cid != 0 && cid != foreign, "broadcast INIT still allocates");
    check(f.hid.channel_count == 1, "broadcast INIT allocates one channel");
}

static void test_tx_failure_semantics(void) {
    fixture f;
    fixture_init(&f);
    static const uint8_t nonce[8] = {0x91};
    uint32_t cid = do_init(&f, nonce);

    /* A multi-frame reply stops at the first refused report instead of
     * pretending the truncated message was delivered. */
    uint8_t payload[120];
    memset(payload, 0x3C, sizeof payload);
    uint8_t frames[4][64];
    size_t n = 0;
    build_frames(cid, OMK_CTAPHID_CMD_PING, payload, sizeof payload, frames,
                 &n);
    f.env.packet_count = 0;
    f.env.send_limit = 1;
    for (size_t i = 0; i < n; i++) {
        omk_ctaphid_rx_packet(&f.hid, frames[i]);
    }
    check(f.env.packet_count == 1, "TX failure stops after refused packet");
    check(omk_ctaphid_tx_faulted(&f.hid), "TX failure is latched");
    captured cap;
    capture_packets2(&f.env, &cap);
    check(cap.count == 1 && cap.msgs[0].open,
          "truncated response is not completed");

    omk_ctaphid_reset(&f.hid);
    check(!omk_ctaphid_tx_faulted(&f.hid), "USB reset clears TX fault");

    /* Direct send reports the failure too. */
    f.env.packet_count = 0;
    f.env.send_limit = 0;
    const uint8_t status = 0;
    check(!omk_ctaphid_send(&f.hid, cid, &status, 1),
          "omk_ctaphid_send reports queue failure");
    check(f.env.packet_count == 0, "failed direct send queues nothing");
    check(omk_ctaphid_tx_faulted(&f.hid), "direct TX failure is latched");

    /* A command whose whole response cannot be queued leaves no success. */
    fixture g;
    fixture_init(&g);
    uint32_t gcid = do_init(&g, nonce);
    g.env.packet_count = 0;
    g.env.send_limit = 0;
    static const uint8_t req[] = {0x04, 0xA0};
    build_frames(gcid, OMK_CTAPHID_CMD_CBOR, req, sizeof req, frames, &n);
    omk_ctaphid_rx_packet(&g.hid, frames[0]);
    check(g.env.packet_count == 0, "failed command response sends nothing");
    check(omk_ctaphid_tx_faulted(&g.hid), "failed command response is latched");
    check(!omk_ctaphid_busy(&g.hid), "busy cleared after failed response");
}

static void alloc_channels(fixture *f, uint32_t *cids, size_t count) {
    static const uint8_t nonce[8] = {0xA0};
    for (size_t i = 0; i < count; i++) {
        f->env.now += 10;
        cids[i] = do_init(f, nonce);
        check(cids[i] != 0, "channel allocation");
    }
}

static bool has_cid(const uint32_t *cids, size_t count, uint32_t cid) {
    for (size_t i = 0; i < count; i++) {
        if (cids[i] == cid) {
            return true;
        }
    }
    return false;
}

static void test_channel_reclamation(void) {
    fixture f;
    fixture_init(&f);
    uint32_t cids[OMK_CTAPHID_MAX_CHANNELS];
    alloc_channels(&f, cids, OMK_CTAPHID_MAX_CHANNELS);
    check(f.hid.channel_count == OMK_CTAPHID_MAX_CHANNELS,
          "channel table filled");
    for (size_t i = 1; i < OMK_CTAPHID_MAX_CHANNELS; i++) {
        check(!has_cid(cids, i, cids[i]), "channel CIDs remain unique");
    }

    static const uint8_t nonce[8] = {0xA1};
    f.env.now += 10;
    const uint32_t cid17 = do_init(&f, nonce);
    check(cid17 != 0, "17th broadcast INIT reclaims an idle channel");
    check(cid17 != cids[0] && !has_cid(cids, OMK_CTAPHID_MAX_CHANNELS, cid17),
          "17th INIT has a fresh CID");
    check(f.hid.channel_count == OMK_CTAPHID_MAX_CHANNELS,
          "reclamation keeps the table bounded");

    /* The least recently used idle channel was reclaimed; recent channels
     * keep their visible CIDs. */
    uint8_t frames[2][64];
    size_t n = 0;
    const uint8_t ping = 0x33;
    f.env.packet_count = 0;
    build_frames(cids[0], OMK_CTAPHID_CMD_PING, &ping, 1, frames, &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    captured cap;
    capture_packets2(&f.env, &cap);
    check(cap.count == 1 && cap.msgs[0].cmd == OMK_CTAPHID_CMD_ERROR &&
              cap.msgs[0].data[0] == OMK_CTAPHID_ERR_INVALID_CHANNEL,
          "LRU idle CID was reclaimed");
    f.env.packet_count = 0;
    build_frames(cids[OMK_CTAPHID_MAX_CHANNELS - 1], OMK_CTAPHID_CMD_PING,
                 &ping, 1, frames, &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    capture_packets2(&f.env, &cap);
    check(cap.count == 1 && cap.msgs[0].cmd == OMK_CTAPHID_CMD_PING,
          "most recent CID is untouched");

    f.env.packet_count = 0;
    build_frames(cid17, OMK_CTAPHID_CMD_PING, &ping, 1, frames, &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    capture_packets2(&f.env, &cap);
    check(cap.count == 1 && cap.msgs[0].cid == cid17 &&
              cap.msgs[0].cmd == OMK_CTAPHID_CMD_PING,
          "reclaimed slot's new CID is usable");
}

static void test_reclamation_protects_reassembly(void) {
    fixture f;
    fixture_init(&f);
    uint32_t cids[OMK_CTAPHID_MAX_CHANNELS];
    alloc_channels(&f, cids, OMK_CTAPHID_MAX_CHANNELS);

    uint8_t payload[120];
    for (size_t i = 0; i < sizeof payload; i++) {
        payload[i] = (uint8_t)(i ^ 0x5A);
    }
    uint8_t ping_frames[4][64];
    size_t ping_n = 0;
    build_frames(cids[0], OMK_CTAPHID_CMD_PING, payload, sizeof payload,
                 ping_frames, &ping_n);
    omk_ctaphid_rx_packet(&f.hid, ping_frames[0]);
    check(f.hid.rx_active && f.hid.rx_cid == cids[0],
          "A reassembly active before reclamation");

    /* Touch every other channel so A becomes the LRU, but is protected. */
    static const uint8_t nonce[8] = {0xA2};
    uint8_t frames[2][64];
    size_t n = 0;
    for (size_t i = 1; i < OMK_CTAPHID_MAX_CHANNELS; i++) {
        f.env.now += 10;
        f.env.packet_count = 0;
        build_frames(cids[i], OMK_CTAPHID_CMD_INIT, nonce, sizeof nonce,
                     frames, &n);
        omk_ctaphid_rx_packet(&f.hid, frames[0]);
    }

    f.env.now += 10;
    f.env.packet_count = 0;
    const uint32_t cid17 = do_init(&f, nonce);
    check(cid17 != 0, "reclamation succeeds with A reassembling");
    check(f.hid.rx_active && f.hid.rx_cid == cids[0],
          "reclaiming INIT does not touch A reassembly");

    f.env.packet_count = 0;
    for (size_t i = 1; i < ping_n; i++) {
        omk_ctaphid_rx_packet(&f.hid, ping_frames[i]);
    }
    captured cap;
    capture_packets2(&f.env, &cap);
    check(cap.count == 1 && cap.msgs[0].cmd == OMK_CTAPHID_CMD_PING &&
              cap.msgs[0].len == sizeof payload,
          "A completes after reclamation");
    check(has_cid(f.hid.channels, f.hid.channel_count, cids[0]),
          "A channel survives reclamation");
}

typedef struct {
    fixture *f;
    uint32_t busy_cid;
} reclaim_busy_ctx;

static void reclaim_while_busy(void *ctx) {
    reclaim_busy_ctx *r = (reclaim_busy_ctx *)ctx;
    fixture *f = r->f;
    /* Force the busy channel to look like the LRU victim. */
    for (uint8_t i = 0; i < f->hid.channel_count; i++) {
        if (f->hid.channels[i] == r->busy_cid) {
            f->hid.channel_last_ms[i] = 0;
        }
    }
    static const uint8_t nonce[8] = {0xA3};
    uint8_t frames[2][64];
    size_t n = 0;
    build_frames(OMK_CTAPHID_BROADCAST_CID, OMK_CTAPHID_CMD_INIT, nonce,
                 sizeof nonce, frames, &n);
    omk_ctaphid_rx_packet(&f->hid, frames[0]);
}

static void test_reclamation_protects_busy(void) {
    fixture f;
    fixture_init(&f);
    uint32_t cids[OMK_CTAPHID_MAX_CHANNELS];
    alloc_channels(&f, cids, OMK_CTAPHID_MAX_CHANNELS);

    reclaim_busy_ctx r = {&f, cids[0]};
    f.disp.during = reclaim_while_busy;
    f.disp.during_ctx = &r;

    static const uint8_t req[] = {0x04, 0xA0};
    uint8_t frames[2][64];
    size_t n = 0;
    build_frames(cids[0], OMK_CTAPHID_CMD_CBOR, req, sizeof req, frames, &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    check(f.disp.calls == 1, "busy reclamation command completed");
    check(f.hid.channel_count == OMK_CTAPHID_MAX_CHANNELS,
          "busy reclamation keeps the table bounded");

    const uint8_t ping = 0x44;
    f.env.packet_count = 0;
    build_frames(cids[0], OMK_CTAPHID_CMD_PING, &ping, 1, frames, &n);
    omk_ctaphid_rx_packet(&f.hid, frames[0]);
    captured cap;
    capture_packets2(&f.env, &cap);
    check(cap.count == 1 && cap.msgs[0].cmd == OMK_CTAPHID_CMD_PING,
          "busy channel is not reclaimed");
}

int main(void) {
    test_init();
    test_cid_rng_failure();
    test_ping_sizes();
    test_cbor_dispatch();
    test_cancel();
    test_abort_with_init();
    test_busy_other_channel();
    test_stray_and_seq();
    test_wink_and_msg();
    test_multiframe_long_up_wait();
    test_usb_reset_during_wait();
    test_idle_reassembly_timeout();
    test_two_cid_interleave();
    test_busy_wink();
    test_null_led_wink();
    test_unknown_init();
    test_tx_failure_semantics();
    test_channel_reclamation();
    test_reclamation_protects_reassembly();
    test_reclamation_protects_busy();
    if (g_failures != 0) {
        printf("%d ctaphid test(s) failed\n", g_failures);
        return 1;
    }
    printf("ctaphid: all tests passed\n");
    return 0;
}
