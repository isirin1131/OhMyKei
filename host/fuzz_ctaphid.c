/* libFuzzer harness for CTAPHID packet reassembly and command handling.
 *
 * Every input starts from a completely fresh transport: channel table, RX
 * reassembly, TX queue and logical clock are reset, and the random source is
 * seeded only from this input.  Replaying one test case therefore reproduces
 * exactly the same channel allocation and timing, and inputs cannot saturate
 * the static channel table across fuzz iterations.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fido/omk_ctap.h"
#include "fido/omk_ctaphid.h"

#define TX_CAPTURE_PACKETS 128u

typedef struct {
    const uint8_t *data;
    size_t size;
    uint64_t rng;
    uint8_t response[OMK_CTAPHID_MAX_MESSAGE];
    size_t response_len;
    bool use_ctap;
} fuzz_state;

static fuzz_state g_state;
static omk_ctaphid g_hid;
static omk_ctap g_ctap;
static uint8_t g_flash[OMK_FLASH_REGION_SIZE];
static uint64_t g_now;
static uint8_t g_tx[TX_CAPTURE_PACKETS * OMK_CTAPHID_PACKET_SIZE];
static size_t g_tx_len;

static uint64_t splitmix64(uint64_t *state) {
    uint64_t z = (*state += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

static uint64_t input_seed(const uint8_t *data, size_t size) {
    uint64_t h = 0xCBF29CE484222325ull; /* FNV-1a basis */
    for (size_t i = 0; i < size; i++) {
        h ^= data[i];
        h *= 0x100000001B3ull;
    }
    return h != 0 ? h : 0x9E3779B97F4A7C15ull;
}

static uint64_t f_now(void *ctx) {
    (void)ctx;
    return g_now;
}

static bool f_random(void *ctx, void *out, size_t len) {
    fuzz_state *st = (fuzz_state *)ctx;
    uint8_t *p = (uint8_t *)out;
    for (size_t i = 0; i < len; i++) {
        p[i] = (uint8_t)(splitmix64(&st->rng) >> 24);
    }
    return true;
}

/* Keep the platform's bool-returning API: a failure means "the bounded TX
 * queue rejected this report", which must abort the response. */
static bool f_send(void *ctx, const uint8_t pkt[64]) {
    (void)ctx;
    if (g_tx_len + OMK_CTAPHID_PACKET_SIZE <= sizeof g_tx) {
        memcpy(g_tx + g_tx_len, pkt, OMK_CTAPHID_PACKET_SIZE);
        g_tx_len += OMK_CTAPHID_PACKET_SIZE;
        return true;
    }
    return false;
}

static bool f_up(void *ctx) {
    (void)ctx;
    const uint64_t phase = (g_now / 10u) % 30u;
    return phase >= 5u && phase < 9u;
}

static void f_led(void *ctx, bool on) {
    (void)ctx;
    (void)on;
}

static int f_read(void *ctx, uint32_t off, void *dst, size_t len) {
    (void)ctx;
    if (off < OMK_FLASH_REGION_OFF) {
        return -1;
    }
    const uint32_t rel = off - OMK_FLASH_REGION_OFF;
    if (rel > sizeof g_flash || len > sizeof g_flash - rel) {
        return -1;
    }
    memcpy(dst, g_flash + rel, len);
    return 0;
}

static int f_write(void *ctx, uint32_t off, const void *src, size_t len) {
    (void)ctx;
    if (off < OMK_FLASH_REGION_OFF) {
        return -1;
    }
    const uint32_t rel = off - OMK_FLASH_REGION_OFF;
    if (rel > sizeof g_flash || len > sizeof g_flash - rel) {
        return -1;
    }
    memcpy(g_flash + rel, src, len);
    return 0;
}

static int f_erase(void *ctx, uint32_t off) {
    (void)ctx;
    if (off < OMK_FLASH_REGION_OFF) {
        return -1;
    }
    const uint32_t rel = off - OMK_FLASH_REGION_OFF;
    if (rel > sizeof g_flash || OMK_FLASH_SECTOR_SIZE > sizeof g_flash - rel) {
        return -1;
    }
    memset(g_flash + rel, 0xFF, OMK_FLASH_SECTOR_SIZE);
    return 0;
}

static void f_delay(void *ctx, uint32_t ms) {
    (void)ctx;
    if (UINT64_MAX - g_now < ms) {
        g_now = UINT64_MAX;
    } else {
        g_now += ms;
    }
}

static void f_log(void *ctx, const char *msg) {
    (void)ctx;
    (void)msg;
}

static void handler(void *ctx, uint32_t cid, const uint8_t *msg, size_t len) {
    fuzz_state *st = (fuzz_state *)ctx;
    if (st->use_ctap) {
        omk_ctap_handle(&g_ctap, cid, msg, len);
    } else {
        (void)msg;
        (void)len;
        /* Exercise every TX chunking class: empty, single report, first+continuation
         * boundaries, and the maximum CTAPHID message length. */
        (void)omk_ctaphid_send(&g_hid, cid, st->response, st->response_len);
    }
}

static const omk_port g_port = {
    .ctx = &g_state,
    .now_ms = f_now,
    .random_bytes = f_random,
    .flash_read = f_read,
    .flash_write = f_write,
    .flash_erase = f_erase,
    .up_pressed = f_up,
    .led = f_led,
    .hid_send = f_send,
    .hid_pump = NULL,
    .delay_ms = f_delay,
    .log = f_log,
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const size_t response_lens[] = {0, 1, 57, 58, 200,
                                           OMK_CTAPHID_MAX_MESSAGE};

    /* Fresh state and logical time for every input. */
    g_now = 0;
    g_tx_len = 0;
    memset(g_flash, 0xFF, sizeof g_flash);
    memset(&g_ctap, 0, sizeof g_ctap);
    memset(&g_state, 0, sizeof g_state);
    g_state.data = data;
    g_state.size = size;
    g_state.rng = input_seed(data, size);

    const uint8_t selector = size != 0 ? data[size - 1] : 0;
    g_state.use_ctap = (selector & 0x80u) != 0;
    g_state.response_len =
        response_lens[(selector & 0x7Fu) %
                      (sizeof response_lens / sizeof response_lens[0])];
    for (size_t i = 0; i < g_state.response_len; i++) {
        g_state.response[i] = size != 0 ? data[i % size] : (uint8_t)i;
    }

    omk_ctaphid_init(&g_hid, &g_port, handler, &g_state);
    if (g_state.use_ctap &&
        omk_ctap_init(&g_ctap, &g_port, &g_hid) != 0) {
        fprintf(stderr, "omk_ctap_init failed during fuzz setup\n");
        abort();
    }

    static const uint8_t setup_init_pkt[OMK_CTAPHID_PACKET_SIZE] = {
        0xFF, 0xFF, 0xFF, 0xFF,
        OMK_CTAPHID_CMD_INIT,
        0x00, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    omk_ctaphid_rx_packet(&g_hid, setup_init_pkt);

    /* Feed every input byte: complete 64-byte reports keep identical coverage,
     * and a trailing partial report is zero-padded instead of being dropped. */
    for (size_t off = 0; off < size; off += OMK_CTAPHID_PACKET_SIZE) {
        uint8_t pkt[OMK_CTAPHID_PACKET_SIZE] = {0};
        size_t n = size - off;
        if (n > sizeof pkt) {
            n = sizeof pkt;
        }
        memcpy(pkt, data + off, n);
        if (n >= 4 && pkt[0] == 0x01 && pkt[1] == 0x02 && pkt[2] == 0x03 &&
            pkt[3] == 0x04) {
            pkt[0] = (uint8_t)(g_hid.channels[0] >> 24);
            pkt[1] = (uint8_t)(g_hid.channels[0] >> 16);
            pkt[2] = (uint8_t)(g_hid.channels[0] >> 8);
            pkt[3] = (uint8_t)g_hid.channels[0];
        }
        omk_ctaphid_rx_packet(&g_hid, pkt);
    }

    (void)omk_ctaphid_poll(&g_hid);
    /* Deterministically exercise the reassembly-timeout paths too. */
    g_now += 501;
    omk_ctaphid_tick(&g_hid);
    (void)omk_ctaphid_poll(&g_hid);
    return 0;
}

#ifdef OMK_FUZZ_CTAPHID_SELFTEST
/* Build-level replay regression: run several inputs interleaved, then replay
 * them in a different order.  A harness that leaks channel/time/RNG state from
 * one input into the next produces different captured packets here. */
#include <stdio.h>

static void run_case(const uint8_t *data, size_t size, uint8_t *out,
                     size_t *out_len) {
    (void)LLVMFuzzerTestOneInput(data, size);
    memcpy(out, g_tx, g_tx_len);
    *out_len = g_tx_len;
}

int main(void) {
    static const uint8_t init_pkt[OMK_CTAPHID_PACKET_SIZE] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x86, 0x00, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    static const uint8_t cbor_pkt[OMK_CTAPHID_PACKET_SIZE] = {
        0x01, 0x02, 0x03, 0x04, 0x90, 0x00, 0x01, 0xA1,
    };
    static const uint8_t ping_pkt[OMK_CTAPHID_PACKET_SIZE] = {
        0x01, 0x02, 0x03, 0x04, 0x81, 0x00, 0x04, 'a', 'b', 'c', 'd',
    };
    static const uint8_t partial_init[OMK_CTAPHID_PACKET_SIZE + 1] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x86, 0x00, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    static const uint8_t empty[1] = {0};

    static const struct {
        const uint8_t *data;
        size_t size;
    } cases[] = {
        {init_pkt, sizeof init_pkt},
        {cbor_pkt, sizeof cbor_pkt},
        {ping_pkt, sizeof ping_pkt},
        {partial_init, sizeof partial_init},
        {empty, 0},
    };
    enum { case_count = sizeof cases / sizeof cases[0] };

    static uint8_t snapshots[case_count][sizeof g_tx];
    static size_t snapshot_lens[case_count];

    for (size_t i = 0; i < case_count; i++) {
        run_case(cases[i].data, cases[i].size, snapshots[i],
                 &snapshot_lens[i]);
    }
    for (size_t i = case_count; i > 0; i--) {
        const size_t index = i - 1;
        uint8_t replay[sizeof g_tx];
        size_t replay_len = 0;
        run_case(cases[index].data, cases[index].size, replay, &replay_len);
        if (replay_len != snapshot_lens[index] ||
            memcmp(replay, snapshots[index], replay_len) != 0) {
            fprintf(stderr,
                    "fuzz_ctaphid replay mismatch for case %zu: "
                    "%zu vs %zu bytes\n",
                    index, replay_len, snapshot_lens[index]);
            return 1;
        }
    }
    return 0;
}
#endif
