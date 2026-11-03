/*
 * Platform port for the OhMyKei CTAP core.
 *
 * The core (CBOR, CTAPHID, CTAP, storage, crypto) is free of pico-sdk
 * dependencies.  Everything the core cannot do by itself lives here, so the
 * host test suite can provide an in-memory implementation.
 */
#ifndef OMK_PORT_H
#define OMK_PORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Location of the FIDO storage area inside flash. */
#define OMK_FLASH_SECTOR_SIZE 4096u
#define OMK_FLASH_REGION_OFF 0x00100000u
#define OMK_FLASH_REGION_SIZE 0x00100000u

typedef struct omk_port {
    void *ctx;

    /* Monotonic milliseconds since boot. */
    uint64_t (*now_ms)(void *ctx);

    /* Fill out with cryptographically secure random bytes.  Returns false
     * when the platform cannot produce them.  On false the buffer may hold
     * partial output and the caller must not use any of it. */
    bool (*random_bytes)(void *ctx, void *out, size_t len);

    /* Flash access, absolute byte offsets, 4 KiB sector granularity.
     * Return 0 on success. */
    int (*flash_read)(void *ctx, uint32_t off, void *dst, size_t len);
    int (*flash_write)(void *ctx, uint32_t off, const void *src, size_t len);
    int (*flash_erase)(void *ctx, uint32_t off);

    /* Non-blocking user presence input.  up_pressed() reports the current
     * state of the physical confirmation button. */
    bool (*up_pressed)(void *ctx);

    /* Blocking-ish LED helpers.  may be NULL. */
    void (*led)(void *ctx, bool on);

    /* Queue one 64-byte CTAPHID packet for transmission.  Must not block for
     * longer than a few milliseconds.  Returns false when the bounded queue
     * cannot accept the packet (or USB is not ready to take it); the CTAPHID
     * transport then aborts the response instead of pretending it was sent. */
    bool (*hid_send)(void *ctx, const uint8_t packet[64]);

    /* Drain the USB receive path and feed complete 64-byte packets back to
     * omk_ctaphid_rx_packet().  Called from the blocking UP wait loop so the
     * transport stays responsive while a command waits for a touch.  May be
     * NULL in tests that inject packets directly. */
    void (*hid_pump)(void *ctx);

    /* Optional cooperative delay used while waiting for user presence. */
    void (*delay_ms)(void *ctx, uint32_t ms);

    /* Service transport work between safe units of a long Flash operation.
     * Return false to request cancellation.  The store calls this only where
     * aborting still leaves the previous committed state recoverable; no Flash
     * write/erase is in flight during the callback.  May be NULL in tests. */
    bool (*long_op_poll)(void *ctx);

    /* Optional debug log, may be NULL. */
    void (*log)(void *ctx, const char *msg);
} omk_port;

#endif /* OMK_PORT_H */
