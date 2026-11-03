#include "platform/platform.h"

#include <string.h>

#include "hardware/flash.h"
#include "hardware/regs/addressmap.h"
#include "hardware/sync.h"
#include "pico/flash.h"
#include "pico/rand.h"
#include "pico/status_led.h"
#include "pico/stdlib.h"
#include "platform/bootsel.h"
#include "tusb.h"

#define TX_QUEUE_PACKETS 96
#define RX_QUEUE_PACKETS 64

static const omk_port g_port;
static omk_ctaphid *g_hid;

static uint8_t g_txq[TX_QUEUE_PACKETS][64];
static volatile uint16_t g_tx_head;
static volatile uint16_t g_tx_tail;
static volatile uint32_t g_tx_dropped;

static uint8_t g_rxq[RX_QUEUE_PACKETS][64];
static volatile uint16_t g_rx_head;
static volatile uint16_t g_rx_tail;
static volatile uint32_t g_rx_dropped;

static uint64_t g_led_off_ms;
static bool g_led_on;

static uint64_t port_now(void *ctx) {
    (void)ctx;
    return time_us_64() / 1000u;
}

/* RELEASE BLOCKER: pico_rand exposes no entropy-health failure and its RP2350
 * raw TRNG path bypasses the hardware checks.  This adapter therefore cannot
 * satisfy omk_port's CSPRNG/failure contract; it always reports success.  Keep
 * the limitation explicit rather than inventing a health signal the SDK does
 * not provide. */
static bool port_random(void *ctx, void *out, size_t len) {
    (void)ctx;
    uint8_t *p = (uint8_t *)out;
    while (len >= 4) {
        const uint32_t v = get_rand_32();
        p[0] = (uint8_t)v;
        p[1] = (uint8_t)(v >> 8);
        p[2] = (uint8_t)(v >> 16);
        p[3] = (uint8_t)(v >> 24);
        p += 4;
        len -= 4;
    }
    if (len != 0) {
        const uint32_t v = get_rand_32();
        p[0] = (uint8_t)v;
        if (len > 1) {
            p[1] = (uint8_t)(v >> 8);
        }
        if (len > 2) {
            p[2] = (uint8_t)(v >> 16);
        }
    }
    return true;
}

static int port_flash_read(void *ctx, uint32_t off, void *dst, size_t len) {
    (void)ctx;
    if (off > PICO_FLASH_SIZE_BYTES ||
        len > PICO_FLASH_SIZE_BYTES - off) {
        return -1;
    }
    memcpy(dst, (const void *)(XIP_BASE + off), len);
    return 0;
}

typedef struct {
    uint32_t off;
    const uint8_t *src;
    size_t len;
} flash_program_op;

static void __no_inline_not_in_flash_func(flash_program_rom)(void *param) {
    const flash_program_op *op = (const flash_program_op *)param;
    flash_range_program(op->off, op->src, op->len);
}

typedef struct {
    uint32_t off;
    size_t len;
} flash_erase_op;

static void __no_inline_not_in_flash_func(flash_erase_rom)(void *param) {
    const flash_erase_op *op = (const flash_erase_op *)param;
    flash_range_erase(op->off, op->len);
}

static bool flash_region_contains(uint32_t off, size_t len) {
    if (off < OMK_FLASH_REGION_OFF ||
        off > OMK_FLASH_REGION_OFF + OMK_FLASH_REGION_SIZE) {
        return false;
    }
    const uint32_t rel = off - OMK_FLASH_REGION_OFF;
    return len <= OMK_FLASH_REGION_SIZE - rel;
}

static int port_flash_write(void *ctx, uint32_t off, const void *src,
                            size_t len) {
    (void)ctx;
    if ((off % FLASH_PAGE_SIZE) != 0 || (len % FLASH_PAGE_SIZE) != 0 ||
        !flash_region_contains(off, len)) {
        return -1;
    }
    flash_program_op op = {off, (const uint8_t *)src, len};
    return flash_safe_execute(flash_program_rom, &op, 1000) == PICO_OK ? 0
                                                                       : -1;
}

static int port_flash_erase(void *ctx, uint32_t off) {
    (void)ctx;
    if ((off % FLASH_SECTOR_SIZE) != 0 ||
        !flash_region_contains(off, FLASH_SECTOR_SIZE)) {
        return -1;
    }
    flash_erase_op op = {off, FLASH_SECTOR_SIZE};
    return flash_safe_execute(flash_erase_rom, &op, 1000) == PICO_OK ? 0 : -1;
}

static bool port_up(void *ctx) {
    (void)ctx;
    return omk_bootsel_pressed();
}

static void port_led(void *ctx, bool on) {
    (void)ctx;
    g_led_on = on;
    if (on) {
        g_led_off_ms = port_now(NULL) + 300u;
        colored_status_led_set_on_with_color(
            PICO_COLORED_STATUS_LED_COLOR_FROM_RGB(0, 48, 24));
    } else {
        colored_status_led_set_state(false);
    }
}

static bool tx_enqueue(const uint8_t packet[64]) {
    const uint16_t next = (uint16_t)((g_tx_head + 1u) % TX_QUEUE_PACKETS);
    if (next == g_tx_tail) {
        g_tx_dropped++;
        return false; /* bounded queue full: report, never block the core */
    }
    memcpy(g_txq[g_tx_head], packet, 64);
    g_tx_head = next;
    return true;
}

static void tx_drain(void) {
    while (g_tx_tail != g_tx_head && tud_hid_ready()) {
        if (!tud_hid_report(0, g_txq[g_tx_tail], 64)) {
            /* Do not consume the packet: the endpoint refused it. */
            break;
        }
        g_tx_tail = (uint16_t)((g_tx_tail + 1u) % TX_QUEUE_PACKETS);
    }
}

static void rx_drain(void) {
    while (g_rx_tail != g_rx_head) {
        uint8_t packet[64];
        memcpy(packet, g_rxq[g_rx_tail], 64);
        g_rx_tail = (uint16_t)((g_rx_tail + 1u) % RX_QUEUE_PACKETS);
        if (g_hid != NULL) {
            omk_ctaphid_rx_packet(g_hid, packet);
        }
    }
}

static bool port_hid_send(void *ctx, const uint8_t packet[64]) {
    (void)ctx;
    /* Make room before enqueueing, but never spin waiting for the host. */
    tx_drain();
    if (!tx_enqueue(packet)) {
        return false;
    }
    tx_drain();
    return true;
}

static void port_delay(void *ctx, uint32_t ms) {
    (void)ctx;
    sleep_ms(ms);
}

static void port_pump(void *ctx) {
    (void)ctx;
    tud_task();
    rx_drain();
    tx_drain();
}

static bool port_long_op_poll(void *ctx) {
    /* Called only between storage transactions, never from a Flash ROM
     * routine.  Polling accepts CANCEL/INIT and emits periodic KEEPALIVE while
     * the outer CTAPHID dispatch remains busy. */
    omk_ctaphid_poll(g_hid);
    (void)omk_ctaphid_send_keepalive(g_hid, OMK_KEEPALIVE_PROCESSING);
    (void)ctx;
    return !omk_ctaphid_aborted(g_hid) &&
           !omk_ctaphid_cancel_pending(g_hid);
}

void omk_platform_pump(void) {
    port_pump(NULL);
    if (g_led_on && port_now(NULL) >= g_led_off_ms) {
        g_led_on = false;
        colored_status_led_set_state(false);
    }
}

void omk_platform_usb_rx(const uint8_t packet[64]) {
    const uint16_t next = (uint16_t)((g_rx_head + 1u) % RX_QUEUE_PACKETS);
    if (next == g_rx_tail) {
        /* No room in the fixed queue.  Count it so the drop is not silent;
         * the resulting gap is serviced by the CTAPHID reassembly timeout. */
        g_rx_dropped++;
        return;
    }
    memcpy(g_rxq[g_rx_head], packet, 64);
    g_rx_head = next;
}

uint32_t omk_platform_usb_tx_dropped(void) {
    return g_tx_dropped;
}

uint32_t omk_platform_usb_rx_dropped(void) {
    return g_rx_dropped;
}

void omk_platform_usb_reset(void) {
    g_rx_head = 0;
    g_rx_tail = 0;
    g_tx_head = 0;
    g_tx_tail = 0;
    if (g_hid != NULL) {
        omk_ctaphid_reset(g_hid);
    }
}

int omk_platform_start(omk_ctaphid *hid, omk_ctap *ctap) {
    (void)ctap;
    status_led_init();
    g_hid = hid;
    return 0;
}

void omk_platform_usb_start(void) {
    tusb_init();
}

const omk_port *omk_platform_port(void) {
    return &g_port;
}

static const omk_port g_port = {
    .ctx = NULL,
    .now_ms = port_now,
    .random_bytes = port_random,
    .flash_read = port_flash_read,
    .flash_write = port_flash_write,
    .flash_erase = port_flash_erase,
    .up_pressed = port_up,
    .led = port_led,
    .hid_send = port_hid_send,
    .hid_pump = port_pump,
    .delay_ms = port_delay,
    .long_op_poll = port_long_op_poll,
    .log = NULL,
};
