/*
 * CTAPHID transport (FIDO CTAPHID, 64-byte HID reports).
 *
 * The transport owns channel allocation, packet reassembly, keepalives and
 * cancellation.  It calls the CTAP dispatcher synchronously from
 * omk_ctaphid_rx_packet() once a complete message has been reassembled; while
 * the dispatcher waits for user presence it calls omk_ctaphid_poll() again
 * (via the core wait helper), which keeps USB and CTAPHID commands flowing.
 *
 * Reassembly state is ended before the dispatcher runs, so a long user
 * presence wait can never age the just-completed message into a timeout.
 */
#ifndef OMK_FIDO_CTAPHID_H
#define OMK_FIDO_CTAPHID_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "omk_port.h"

#define OMK_CTAPHID_PACKET_SIZE 64
#define OMK_CTAPHID_BROADCAST_CID 0xFFFFFFFFu
#define OMK_CTAPHID_MAX_CHANNELS 16
#define OMK_CTAPHID_MAX_MESSAGE 2048
#define OMK_CTAPHID_TX_TIMEOUT_MS 5000u

/* Command bytes (high bit set for the initial packet). */
#define OMK_CTAPHID_CMD_PING 0x81
#define OMK_CTAPHID_CMD_MSG 0x83
#define OMK_CTAPHID_CMD_LOCK 0x84
#define OMK_CTAPHID_CMD_INIT 0x86
#define OMK_CTAPHID_CMD_WINK 0x88
#define OMK_CTAPHID_CMD_CBOR 0x90
#define OMK_CTAPHID_CMD_CANCEL 0x91
#define OMK_CTAPHID_CMD_KEEPALIVE 0xBB
#define OMK_CTAPHID_CMD_ERROR 0xBF

/* CTAPHID error codes. */
#define OMK_CTAPHID_ERR_INVALID_CMD 0x01
#define OMK_CTAPHID_ERR_INVALID_PAR 0x02
#define OMK_CTAPHID_ERR_INVALID_LEN 0x03
#define OMK_CTAPHID_ERR_INVALID_SEQ 0x04
#define OMK_CTAPHID_ERR_MSG_TIMEOUT 0x05
#define OMK_CTAPHID_ERR_CHANNEL_BUSY 0x06
#define OMK_CTAPHID_ERR_LOCK_REQUIRED 0x0A
#define OMK_CTAPHID_ERR_INVALID_CHANNEL 0x0B
#define OMK_CTAPHID_ERR_OTHER 0x7F

/* Keepalive status byte. */
#define OMK_KEEPALIVE_PROCESSING 0x01
#define OMK_KEEPALIVE_UP_NEEDED 0x02

typedef void (*omk_ctaphid_handler)(void *ctx, uint32_t cid, const uint8_t *msg,
                                    size_t len);

typedef struct {
    const omk_port *port;
    omk_ctaphid_handler handler;
    void *handler_ctx;

    uint32_t channels[OMK_CTAPHID_MAX_CHANNELS];
    uint64_t channel_last_ms[OMK_CTAPHID_MAX_CHANNELS];
    uint8_t channel_count;

    /* Single reassembly / transaction buffer. */
    uint8_t rx[OMK_CTAPHID_MAX_MESSAGE];
    uint32_t rx_cid;
    uint8_t rx_cmd;
    size_t rx_len;
    size_t rx_expected;
    uint8_t rx_next_seq;
    uint64_t rx_last_ms;
    bool rx_active;

    uint32_t busy_cid;
    bool busy;
    /* True while the synchronous CTAP dispatcher owns the shared rx/response
     * buffers.  Used as a hard re-entrancy guard. */
    bool dispatching;
    bool cancel_pending;
    bool abort_pending;

    /* Latches a failed TX enqueue (queue full / USB not ready).  A response
     * that could not be fully queued is never reported as sent. */
    bool tx_fault;

    uint64_t last_keepalive_ms;
    bool keepalive_sent;

    uint16_t version_major;
    uint16_t version_minor;
    uint16_t version_build;
} omk_ctaphid;

void omk_ctaphid_init(omk_ctaphid *h, const omk_port *port,
                       omk_ctaphid_handler handler, void *handler_ctx);

/* Feed one 64-byte HID report.  Safe to call from the dispatcher itself (via
 * the port pump) while a command is waiting for user presence. */
void omk_ctaphid_rx_packet(omk_ctaphid *h, const uint8_t packet[64]);

/* Pump the port and expire stalled reassemblies. */
void omk_ctaphid_poll(omk_ctaphid *h);

/* Expire a stalled reassembly without pumping the port.  The normal idle main
 * loop calls this so timeouts are serviced outside the UP wait as well. */
void omk_ctaphid_tick(omk_ctaphid *h);

/* Drop all channels and pending transactions (USB bus reset).  When a
 * synchronous dispatch is in flight the channels/queues are cleared and an
 * abort is latched, but `busy` is deliberately retained until the dispatch
 * epilogue clears it. */
void omk_ctaphid_reset(omk_ctaphid *h);

/* Send a complete CTAPHID message on cid (chunked into 64-byte reports).
 * Returns false if the platform refused a report (bounded TX queue full) or
 * the transaction was aborted; a partially queued message is never reported
 * as sent.  Suppressed automatically after an aborting INIT. */
bool omk_ctaphid_send(omk_ctaphid *h, uint32_t cid, const void *data,
                      size_t len);
bool omk_ctaphid_send_error(omk_ctaphid *h, uint32_t cid, uint8_t code);
bool omk_ctaphid_send_keepalive(omk_ctaphid *h, uint8_t status);

bool omk_ctaphid_busy(const omk_ctaphid *h);
uint32_t omk_ctaphid_active_cid(const omk_ctaphid *h);
bool omk_ctaphid_cancel_pending(const omk_ctaphid *h);
bool omk_ctaphid_aborted(const omk_ctaphid *h);
bool omk_ctaphid_tx_faulted(const omk_ctaphid *h);

#endif /* OMK_FIDO_CTAPHID_H */
