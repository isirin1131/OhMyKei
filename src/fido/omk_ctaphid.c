#include "fido/omk_ctaphid.h"

#include <string.h>

#define CTAPHID_RX_TIMEOUT_MS 500u
#define CTAPHID_KEEPALIVE_INTERVAL_MS 100u

static uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static uint16_t rd_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void wr_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void wr_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static uint64_t now_ms(const omk_ctaphid *h) {
    return h->port->now_ms(h->port->ctx);
}

static bool tx_failed(omk_ctaphid *h, uint32_t cid) {
    h->tx_fault = true;
    /* Only a failure of the active transaction's own output aborts the
     * command.  A failed busy/error reply to another channel is reported via
     * tx_fault without killing the in-flight command. */
    if ((h->busy || h->dispatching) && cid == h->busy_cid) {
        h->abort_pending = true;
    }
    return false;
}

static bool send_packet(omk_ctaphid *h, uint32_t cid, uint8_t cmd,
                        const uint8_t *payload, size_t len, bool first,
                        uint16_t total_len) {
    uint8_t pkt[OMK_CTAPHID_PACKET_SIZE];
    memset(pkt, 0, sizeof pkt);
    wr_be32(pkt, cid);
    pkt[4] = cmd;
    if (first) {
        wr_be16(pkt + 5, total_len);
        if (len > 57) {
            len = 57;
        }
        if (len != 0) {
            memcpy(pkt + 7, payload, len);
        }
    } else {
        if (len > 59) {
            len = 59;
        }
        if (len != 0) {
            memcpy(pkt + 5, payload, len);
        }
    }
    if (h->port->hid_send == NULL ||
        !h->port->hid_send(h->port->ctx, pkt)) {
        return tx_failed(h, cid);
    }
    return true;
}

static bool send_message(omk_ctaphid *h, uint32_t cid, uint8_t cmd,
                         const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    if (len > OMK_CTAPHID_MAX_MESSAGE) {
        return omk_ctaphid_send_error(h, cid, OMK_CTAPHID_ERR_INVALID_LEN);
    }
    if (len <= 57) {
        return send_packet(h, cid, cmd, p, len, true, (uint16_t)len);
    }
    if (!send_packet(h, cid, cmd, p, 57, true, (uint16_t)len)) {
        return false;
    }
    p += 57;
    size_t remaining = len - 57;
    uint8_t seq = 0;
    while (remaining > 0) {
        size_t chunk = remaining > 59 ? 59 : remaining;
        if (!send_packet(h, cid, seq, p, chunk, false, 0)) {
            return false;
        }
        p += chunk;
        remaining -= chunk;
        seq++;
    }
    return true;
}

bool omk_ctaphid_send(omk_ctaphid *h, uint32_t cid, const void *data,
                      size_t len) {
    if (h->abort_pending) {
        return false;
    }
    return send_message(h, cid, OMK_CTAPHID_CMD_CBOR, data, len);
}

bool omk_ctaphid_send_error(omk_ctaphid *h, uint32_t cid, uint8_t code) {
    if (h->abort_pending) {
        return false;
    }
    return send_message(h, cid, OMK_CTAPHID_CMD_ERROR, &code, 1);
}

bool omk_ctaphid_send_keepalive(omk_ctaphid *h, uint8_t status) {
    if (!h->busy || h->abort_pending) {
        return false;
    }
    const uint64_t now = now_ms(h);
    if (h->keepalive_sent &&
        now - h->last_keepalive_ms < CTAPHID_KEEPALIVE_INTERVAL_MS) {
        return false;
    }
    h->last_keepalive_ms = now;
    h->keepalive_sent = true;
    return send_message(h, h->busy_cid, OMK_CTAPHID_CMD_KEEPALIVE, &status, 1);
}

bool omk_ctaphid_busy(const omk_ctaphid *h) {
    return h->busy;
}

uint32_t omk_ctaphid_active_cid(const omk_ctaphid *h) {
    return h->busy_cid;
}

bool omk_ctaphid_cancel_pending(const omk_ctaphid *h) {
    return h->cancel_pending;
}

bool omk_ctaphid_aborted(const omk_ctaphid *h) {
    return h->abort_pending;
}

bool omk_ctaphid_tx_faulted(const omk_ctaphid *h) {
    return h->tx_fault;
}

static bool channel_exists(const omk_ctaphid *h, uint32_t cid) {
    for (uint8_t i = 0; i < h->channel_count; i++) {
        if (h->channels[i] == cid) {
            return true;
        }
    }
    return false;
}

static void channel_touch(omk_ctaphid *h, uint32_t cid) {
    for (uint8_t i = 0; i < h->channel_count; i++) {
        if (h->channels[i] == cid) {
            h->channel_last_ms[i] = now_ms(h);
            return;
        }
    }
}

static bool channel_is_evictable(const omk_ctaphid *h, uint8_t idx) {
    const uint32_t cid = h->channels[idx];
    if (h->busy && cid == h->busy_cid) {
        return false;
    }
    if (h->rx_active && cid == h->rx_cid) {
        return false;
    }
    return true;
}

/* Add cid.  When the fixed 16-entry table is full, reclaim the least
 * recently used channel that is neither the busy transaction nor carrying an
 * active reassembly.  Existing live CIDs are never renumbered or modified. */
static bool channel_add(omk_ctaphid *h, uint32_t cid) {
    if (channel_exists(h, cid) || cid == 0 ||
        cid == OMK_CTAPHID_BROADCAST_CID) {
        return false;
    }
    const uint64_t now = now_ms(h);
    if (h->channel_count < OMK_CTAPHID_MAX_CHANNELS) {
        h->channels[h->channel_count] = cid;
        h->channel_last_ms[h->channel_count] = now;
        h->channel_count++;
        return true;
    }

    int victim = -1;
    for (uint8_t i = 0; i < h->channel_count; i++) {
        if (!channel_is_evictable(h, i)) {
            continue;
        }
        if (victim < 0 ||
            h->channel_last_ms[i] < h->channel_last_ms[victim]) {
            victim = (int)i;
        }
    }
    if (victim < 0) {
        return false;
    }
    h->channels[victim] = cid;
    h->channel_last_ms[victim] = now;
    return true;
}

/* Allocate a fresh channel id.  Returns 0 if the platform RNG could not
 * produce bytes or no free id/table slot is available.  A failed random fill
 * is never used: the candidate stays zero and no channel is added. */
static uint32_t channel_new(omk_ctaphid *h) {
    for (unsigned attempt = 0; attempt < 32; attempt++) {
        uint32_t cid = 0;
        if (!h->port->random_bytes(h->port->ctx, &cid, sizeof cid)) {
            return 0;
        }
        if (cid == 0 || cid == OMK_CTAPHID_BROADCAST_CID ||
            channel_exists(h, cid) ||
            (h->busy && cid == h->busy_cid)) {
            continue;
        }
        if (channel_add(h, cid)) {
            return cid;
        }
    }
    return 0;
}

static void reset_rx(omk_ctaphid *h) {
    h->rx_active = false;
    h->rx_len = 0;
    h->rx_expected = 0;
    h->rx_next_seq = 0;
}

static void handle_init(omk_ctaphid *h, uint32_t cid, uint16_t bcnt,
                        const uint8_t *payload) {
    /* Only the broadcast CID allocates a channel.  An unknown non-broadcast
     * CID is invalid; it must never create a channel implicitly. */
    if (cid != OMK_CTAPHID_BROADCAST_CID && !channel_exists(h, cid)) {
        (void)omk_ctaphid_send_error(h, cid, OMK_CTAPHID_ERR_INVALID_CHANNEL);
        return;
    }
    if (bcnt != 8) {
        (void)omk_ctaphid_send_error(h, cid, OMK_CTAPHID_ERR_INVALID_LEN);
        return;
    }

    if (cid != OMK_CTAPHID_BROADCAST_CID) {
        if (h->busy && cid != h->busy_cid) {
            /* Another channel's re-INIT cannot preempt the busy transaction;
             * only a broadcast INIT may allocate while busy. */
            (void)omk_ctaphid_send_error(h, cid,
                                         OMK_CTAPHID_ERR_CHANNEL_BUSY);
            return;
        }
        channel_touch(h, cid);
        if (h->busy && cid == h->busy_cid) {
            /* INIT on the busy channel aborts the in-flight transaction. */
            h->abort_pending = true;
        }
        if (h->rx_active && cid == h->rx_cid) {
            reset_rx(h);
        }
    }

    uint32_t new_cid = cid;
    if (cid == OMK_CTAPHID_BROADCAST_CID) {
        new_cid = channel_new(h);
        if (new_cid == 0) {
            /* RNG failure or an exhausted id/table is a local resource
             * failure, not a busy channel. */
            (void)omk_ctaphid_send_error(h, cid, OMK_CTAPHID_ERR_OTHER);
            return;
        }
    }

    uint8_t resp[17];
    memcpy(resp, payload, 8);
    wr_be32(resp + 8, new_cid);
    resp[12] = 2; /* CTAPHID protocol version */
    resp[13] = (uint8_t)h->version_major;
    resp[14] = (uint8_t)h->version_minor;
    resp[15] = (uint8_t)h->version_build;
    resp[16] = 0x0D; /* CAPABILITY_WINK | CBOR | NMSG */
    (void)send_message(h, cid, OMK_CTAPHID_CMD_INIT, resp, sizeof resp);
}

static void handle_cancel(omk_ctaphid *h, uint32_t cid) {
    if (channel_exists(h, cid)) {
        channel_touch(h, cid);
    }
    if (h->busy && cid == h->busy_cid) {
        h->cancel_pending = true;
    }
}

static void dispatch_cbor(omk_ctaphid *h) {
    if (h->dispatching) {
        /* The shared rx/response buffers are already owned by an outer
         * dispatch; never enter CTAP recursively. */
        h->tx_fault = true;
        return;
    }

    const uint32_t cid = h->rx_cid;
    const size_t len = h->rx_len;

    h->busy = true;
    h->busy_cid = cid;
    h->dispatching = true;
    h->cancel_pending = false;
    h->abort_pending = false;
    h->keepalive_sent = false;

    /* Reassembly is over before dispatch starts: a long UP wait must not age
     * the just-completed message into ERR_MSG_TIMEOUT.  The payload remains
     * valid in h->rx while the dispatcher runs. */
    reset_rx(h);

    if (h->handler != NULL) {
        h->handler(h->handler_ctx, cid, h->rx, len);
    }

    /* The epilogue owns clearing busy, including after a USB reset that
     * arrived while dispatch was in flight. */
    h->dispatching = false;
    h->busy = false;
    h->busy_cid = 0;
    h->cancel_pending = false;
    h->abort_pending = false;
    reset_rx(h);
}

static void handle_complete(omk_ctaphid *h) {
    switch (h->rx_cmd) {
    case OMK_CTAPHID_CMD_PING:
        (void)send_message(h, h->rx_cid, OMK_CTAPHID_CMD_PING, h->rx,
                           h->rx_len);
        reset_rx(h);
        break;
    case OMK_CTAPHID_CMD_CBOR:
        dispatch_cbor(h);
        break;
    case OMK_CTAPHID_CMD_MSG:
    case OMK_CTAPHID_CMD_LOCK:
    default:
        (void)omk_ctaphid_send_error(h, h->rx_cid, OMK_CTAPHID_ERR_INVALID_CMD);
        reset_rx(h);
        break;
    }
}

void omk_ctaphid_rx_packet(omk_ctaphid *h, const uint8_t packet[64]) {
    const uint32_t cid = rd_be32(packet);
    const uint8_t b = packet[4];
    const uint16_t bcnt = rd_be16(packet + 5);
    const uint8_t *payload = packet + 7;

    if ((b & 0x80u) != 0) {
        const uint8_t cmd = b;
        if (cmd == OMK_CTAPHID_CMD_INIT) {
            handle_init(h, cid, bcnt, payload);
            return;
        }
        if (cmd == OMK_CTAPHID_CMD_CANCEL) {
            handle_cancel(h, cid);
            return;
        }

        /* WINK participates in the same busy gate as every other command. */
        if (h->busy || h->dispatching) {
            (void)omk_ctaphid_send_error(h, cid,
                                         OMK_CTAPHID_ERR_CHANNEL_BUSY);
            return;
        }
        if (cid == OMK_CTAPHID_BROADCAST_CID || !channel_exists(h, cid)) {
            (void)omk_ctaphid_send_error(h, cid,
                                         OMK_CTAPHID_ERR_INVALID_CHANNEL);
            return;
        }
        channel_touch(h, cid);
        if (cmd == OMK_CTAPHID_CMD_WINK) {
            if (h->port->led != NULL) {
                h->port->led(h->port->ctx, true);
            }
            (void)send_message(h, cid, OMK_CTAPHID_CMD_WINK, NULL, 0);
            return;
        }
        if (bcnt > OMK_CTAPHID_MAX_MESSAGE) {
            (void)omk_ctaphid_send_error(h, cid,
                                         OMK_CTAPHID_ERR_INVALID_LEN);
            return;
        }
        if (h->rx_active && cid != h->rx_cid) {
            /* Another channel cannot displace A's in-progress reassembly. */
            (void)omk_ctaphid_send_error(h, cid,
                                         OMK_CTAPHID_ERR_CHANNEL_BUSY);
            return;
        }
        reset_rx(h);
        h->rx_cid = cid;
        h->rx_cmd = cmd;
        size_t n = bcnt < 57 ? bcnt : 57;
        if (n != 0) {
            memcpy(h->rx, payload, n);
        }
        h->rx_len = n;
        h->rx_expected = bcnt;
        h->rx_next_seq = 0;
        h->rx_last_ms = now_ms(h);
        if (n >= bcnt) {
            handle_complete(h);
        } else {
            h->rx_active = true;
        }
        return;
    }

    /* Continuation frame. */
    if (h->busy || h->dispatching || !h->rx_active || cid != h->rx_cid) {
        /* Stray continuation: silently discard (CTAPHID P-2). */
        return;
    }
    const uint8_t seq = b;
    if (seq != h->rx_next_seq) {
        (void)omk_ctaphid_send_error(h, cid, OMK_CTAPHID_ERR_INVALID_SEQ);
        reset_rx(h);
        return;
    }
    const size_t remaining = h->rx_expected - h->rx_len;
    const size_t chunk = remaining > 59 ? 59 : remaining;
    memcpy(h->rx + h->rx_len, packet + 5, chunk);
    h->rx_len += chunk;
    h->rx_next_seq++;
    h->rx_last_ms = now_ms(h);
    channel_touch(h, cid);
    if (h->rx_len >= h->rx_expected) {
        handle_complete(h);
    }
}

static void expire_reassembly(omk_ctaphid *h) {
    if (!h->rx_active || h->busy || h->dispatching) {
        return;
    }
    const uint64_t now = now_ms(h);
    if (now - h->rx_last_ms <= CTAPHID_RX_TIMEOUT_MS) {
        return;
    }
    const uint32_t cid = h->rx_cid;
    reset_rx(h);
    (void)omk_ctaphid_send_error(h, cid, OMK_CTAPHID_ERR_MSG_TIMEOUT);
}

void omk_ctaphid_poll(omk_ctaphid *h) {
    if (h->port->hid_pump != NULL) {
        h->port->hid_pump(h->port->ctx);
    }
    expire_reassembly(h);
}

void omk_ctaphid_tick(omk_ctaphid *h) {
    expire_reassembly(h);
}

void omk_ctaphid_reset(omk_ctaphid *h) {
    h->channel_count = 0;
    reset_rx(h);
    h->tx_fault = false;

    if (h->busy || h->dispatching) {
        /* A synchronous dispatch is using the shared rx/response buffers.
         * Clear transport state and latch an abort, but leave `busy` set so
         * no packet can re-enter CTAP; the dispatch epilogue clears it. */
        h->cancel_pending = false;
        h->abort_pending = true;
        return;
    }

    h->busy = false;
    h->busy_cid = 0;
    h->dispatching = false;
    h->cancel_pending = false;
    h->abort_pending = false;
    h->keepalive_sent = false;
}

void omk_ctaphid_init(omk_ctaphid *h, const omk_port *port,
                       omk_ctaphid_handler handler, void *handler_ctx) {
    memset(h, 0, sizeof(*h));
    h->port = port;
    h->handler = handler;
    h->handler_ctx = handler_ctx;
    h->version_major = 0;
    h->version_minor = 1;
    h->version_build = 0;
}
