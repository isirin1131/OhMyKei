#include "fido/omk_store.h"

#include <string.h>

#include "crypto/omk_crypto.h"

/* ---------------------------------------------------------------------- */
/* Layout and constants                                                    */
/* ---------------------------------------------------------------------- */

#define META_MAGIC 0x4F4D4B4Du /* "OMKM" */
#define META_VERSION 2u
#define META_KIND_SNAPSHOT 1u

#define REC_MAGIC 0x4F4D4B52u /* "OMKR" */
#define REC_VERSION 2u
#define REC_HDR_SIZE 32u
#define REC_SLOT_SIZE OMK_STORE_LOG_SLOT_SIZE
#define REC_MAX_PAYLOAD (REC_SLOT_SIZE - REC_HDR_SIZE)

#define REC_TYPE_CRED 1u
#define REC_TYPE_DELETE 2u
#define REC_TYPE_UPDATE 3u

#define META_RECORDS_PER_SECTOR \
    (OMK_FLASH_SECTOR_SIZE / OMK_STORE_META_RECORD_SIZE)
#define LOG_SLOTS_PER_SECTOR (OMK_FLASH_SECTOR_SIZE / REC_SLOT_SIZE)
#define LOG_SLOTS_PER_BANK (OMK_STORE_BANK_SIZE / REC_SLOT_SIZE)
#define COUNTER_LEASE_STEP 64u

/* CTAP AAGUID identifies the authenticator model, not an individual device or
 * a reset generation.  This UUIDv5 value is deterministically derived from
 * "OhMyKei RP2350-Zero-CM authenticator model v1" and must change only for a
 * genuinely different authenticator model. */
static const uint8_t model_aaguid[16] = {
    0x68u, 0xD8u, 0x40u, 0xC1u, 0xB0u, 0xAAu, 0x5Du, 0x75u,
    0xBBu, 0xBBu, 0xC4u, 0xF3u, 0xF6u, 0xC7u, 0x89u, 0xB3u,
};

#define ID_VERSION 1
#define ID_FLAG_RESIDENT 0x01
#define ID_LEN 68u
#define ID_MAC_LEN 16u

_Static_assert(OMK_FLASH_SECTOR_SIZE == 4096u, "sector size assumption");
_Static_assert(OMK_STORE_META_OFFSET + OMK_STORE_META_SECTORS *
                                              OMK_FLASH_SECTOR_SIZE ==
                   OMK_STORE_BANK_A_OFFSET,
               "meta/bank layout");
_Static_assert(OMK_STORE_BANK_A_OFFSET + OMK_STORE_BANK_SIZE ==
                   OMK_STORE_BANK_B_OFFSET,
               "bank A/B layout");
_Static_assert(OMK_STORE_BANK_B_OFFSET + OMK_STORE_BANK_SIZE ==
                   OMK_FLASH_REGION_SIZE,
               "bank B must end at the region end");
_Static_assert(LOG_SLOTS_PER_BANK >= OMK_MAX_CREDENTIALS,
               "each bank must hold every live credential");
_Static_assert(REC_MAX_PAYLOAD >=
                   1 + 1 + 1 + 1 + OMK_CRED_ID_MAX + 32 + 2 + OMK_RP_ID_MAX +
                       1 + OMK_USER_ID_MAX + 1 + OMK_USER_NAME_MAX + 1 +
                       OMK_USER_NAME_MAX,
               "credential payload must fit a log slot");

static uint32_t crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (unsigned b = 0; b < 8; b++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1u)));
        }
    }
    return ~crc;
}

static uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static uint64_t rd64(const uint8_t *p) {
    return ((uint64_t)rd32(p) << 32) | rd32(p + 4);
}

static void wr64(uint8_t *p, uint64_t v) {
    wr32(p, (uint32_t)(v >> 32));
    wr32(p + 4, (uint32_t)v);
}

static bool all_ff(const uint8_t *p, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (p[i] != 0xFFu) {
            return false;
        }
    }
    return true;
}

static int flash_read(const omk_store *s, uint32_t off, void *dst,
                      size_t len) {
    return s->port->flash_read(s->port->ctx, off, dst, len);
}

static int flash_write(const omk_store *s, uint32_t off, const void *src,
                       size_t len) {
    return s->port->flash_write(s->port->ctx, off, src, len);
}

static int flash_erase(const omk_store *s, uint32_t off) {
    return s->port->flash_erase(s->port->ctx, off);
}

static bool long_op_continue(const omk_store *s) {
    return s->port->long_op_poll == NULL ||
           s->port->long_op_poll(s->port->ctx);
}

/* Fill caller-owned output with platform randomness.  A false return means the
 * platform could not produce the bytes; the caller must discard any partial
 * output instead of deriving a secret from it. */
static bool store_random(const omk_store *s, void *out, size_t len) {
    return s->port->random_bytes(s->port->ctx, out, len);
}

/* 1 = erased, 0 = contains programming, -1 = read error. */
static int sector_is_erased(const omk_store *s, uint32_t off) {
    uint8_t buf[1024];
    for (uint32_t pos = 0; pos < OMK_FLASH_SECTOR_SIZE; pos += sizeof buf) {
        if (flash_read(s, off + pos, buf, sizeof buf) != 0) {
            return -1;
        }
        if (!all_ff(buf, sizeof buf)) {
            return 0;
        }
    }
    return 1;
}

static uint32_t meta_off(uint32_t sector, uint32_t slot) {
    return OMK_FLASH_REGION_OFF + OMK_STORE_META_OFFSET +
           sector * OMK_FLASH_SECTOR_SIZE +
           slot * OMK_STORE_META_RECORD_SIZE;
}

static uint32_t bank_off(uint8_t bank) {
    return OMK_FLASH_REGION_OFF +
           (bank == 0 ? OMK_STORE_BANK_A_OFFSET : OMK_STORE_BANK_B_OFFSET);
}

static uint32_t bank_end(uint8_t bank) {
    return bank_off(bank) + OMK_STORE_BANK_SIZE;
}

/* ---------------------------------------------------------------------- */
/* Meta log                                                                */
/* ---------------------------------------------------------------------- */

typedef struct {
    uint64_t seq;
    uint32_t reset_epoch;
    uint32_t log_epoch;
    uint8_t active_bank;
    bool pin_set;
    uint8_t pin_retries;
    bool attempt_valid;
    uint32_t pin_epoch;
    uint32_t lease;
    uint32_t next_seq;
    uint8_t master[32];
    uint8_t aaguid[16];
    uint8_t pin_hash[16];
    uint8_t attempt_candidate[16];
} meta_image;

/* Byte offsets inside a 256-byte meta record.  The CRC covers the first 120
 * bytes; bytes 120..255 are not part of the state. */
#define MO_MAGIC 0u
#define MO_VERSION 4u
#define MO_KIND 6u
#define MO_FLAGS 7u
#define MO_SEQ 8u
#define MO_RESET_EPOCH 16u
#define MO_LOG_EPOCH 20u
#define MO_ACTIVE_BANK 24u
#define MO_PIN_SET 25u
#define MO_PIN_RETRIES 26u
#define MO_ATTEMPT_VALID 27u
#define MO_PIN_EPOCH 28u
#define MO_LEASE 32u
#define MO_NEXT_SEQ 36u
#define MO_MASTER 40u
#define MO_AAGUID 72u
#define MO_PIN_HASH 88u
#define MO_ATTEMPT_CANDIDATE 104u
#define MO_CRC 120u
#define META_CRC_LEN 120u

static void meta_serialize(const meta_image *m,
                           uint8_t out[OMK_STORE_META_RECORD_SIZE]) {
    memset(out, 0xFF, OMK_STORE_META_RECORD_SIZE);
    wr32(out + MO_MAGIC, META_MAGIC);
    wr16(out + MO_VERSION, META_VERSION);
    out[MO_KIND] = META_KIND_SNAPSHOT;
    out[MO_FLAGS] = 0;
    wr64(out + MO_SEQ, m->seq);
    wr32(out + MO_RESET_EPOCH, m->reset_epoch);
    wr32(out + MO_LOG_EPOCH, m->log_epoch);
    out[MO_ACTIVE_BANK] = m->active_bank;
    out[MO_PIN_SET] = m->pin_set ? 1u : 0u;
    out[MO_PIN_RETRIES] = m->pin_retries;
    out[MO_ATTEMPT_VALID] = m->attempt_valid ? 1u : 0u;
    wr32(out + MO_PIN_EPOCH, m->pin_epoch);
    wr32(out + MO_LEASE, m->lease);
    wr32(out + MO_NEXT_SEQ, m->next_seq);
    memcpy(out + MO_MASTER, m->master, 32);
    memcpy(out + MO_AAGUID, m->aaguid, 16);
    memcpy(out + MO_PIN_HASH, m->pin_hash, 16);
    memcpy(out + MO_ATTEMPT_CANDIDATE, m->attempt_candidate, 16);
    wr32(out + MO_CRC, crc32(out, META_CRC_LEN));
}

/* Returns 1 for a valid snapshot, 0 for an erased/torn/foreign record and -1
 * for a CRC-valid record whose fields are impossible (a hard fault). */
static int meta_parse(const uint8_t in[OMK_STORE_META_RECORD_SIZE],
                      meta_image *m) {
    if (rd32(in + MO_MAGIC) != META_MAGIC ||
        rd16(in + MO_VERSION) != META_VERSION ||
        in[MO_KIND] != META_KIND_SNAPSHOT) {
        return 0;
    }
    if (rd32(in + MO_CRC) != crc32(in, META_CRC_LEN)) {
        return 0;
    }
    m->seq = rd64(in + MO_SEQ);
    m->reset_epoch = rd32(in + MO_RESET_EPOCH);
    m->log_epoch = rd32(in + MO_LOG_EPOCH);
    m->active_bank = in[MO_ACTIVE_BANK];
    m->pin_set = in[MO_PIN_SET] != 0;
    m->pin_retries = in[MO_PIN_RETRIES];
    m->attempt_valid = in[MO_ATTEMPT_VALID] != 0;
    m->pin_epoch = rd32(in + MO_PIN_EPOCH);
    m->lease = rd32(in + MO_LEASE);
    m->next_seq = rd32(in + MO_NEXT_SEQ);
    memcpy(m->master, in + MO_MASTER, 32);
    memcpy(m->aaguid, in + MO_AAGUID, 16);
    memcpy(m->pin_hash, in + MO_PIN_HASH, 16);
    memcpy(m->attempt_candidate, in + MO_ATTEMPT_CANDIDATE, 16);
    if (m->seq == 0 || m->active_bank > 1u || m->pin_retries > 8u ||
        in[MO_PIN_SET] > 1u || in[MO_ATTEMPT_VALID] > 1u ||
        m->pin_epoch == 0 || m->reset_epoch == 0 || m->log_epoch == 0) {
        return -1;
    }
    return 1;
}

static void meta_from_store(const omk_store *s, meta_image *m) {
    memset(m, 0, sizeof(*m));
    m->reset_epoch = s->reset_epoch;
    m->log_epoch = s->log_epoch;
    m->active_bank = s->active_bank;
    m->pin_set = s->pin_set;
    m->pin_retries = s->pin_retries;
    m->attempt_valid = s->attempt_valid;
    m->pin_epoch = s->pin_epoch;
    m->lease = s->lease;
    m->next_seq = s->next_seq;
    memcpy(m->master, s->master, 32);
    memcpy(m->aaguid, s->aaguid, 16);
    memcpy(m->pin_hash, s->pin_hash, 16);
    memcpy(m->attempt_candidate, s->attempt_candidate, 16);
}

static void meta_apply(omk_store *s, const meta_image *m) {
    s->reset_epoch = m->reset_epoch;
    s->log_epoch = m->log_epoch;
    s->active_bank = m->active_bank;
    s->pin_set = m->pin_set;
    s->pin_retries = m->pin_retries;
    s->attempt_valid = m->attempt_valid;
    s->pin_epoch = m->pin_epoch;
    s->lease = m->lease;
    s->next_seq = m->next_seq;
    memcpy(s->master, m->master, 32);
    /* Ignore per-device AAGUIDs written by older firmware.  The next meta
     * persist upgrades the stored copy; getInfo is model-correct immediately. */
    memcpy(s->aaguid, model_aaguid, sizeof model_aaguid);
    memcpy(s->pin_hash, m->pin_hash, 16);
    memcpy(s->attempt_candidate, m->attempt_candidate, 16);
}

/* Erase one 4 KiB meta sector and verify it reads back as erased. */
static int meta_sector_prepare(omk_store *s, uint32_t sector) {
    const uint32_t off = OMK_FLASH_REGION_OFF + OMK_STORE_META_OFFSET +
                         sector * OMK_FLASH_SECTOR_SIZE;
    if (flash_erase(s, off) != 0) {
        return -1;
    }
    return sector_is_erased(s, off) == 1 ? 0 : -1;
}

/* Advance only the append cursor after a target slot may have been dirtied.
 * The sequence number and mirrored state still come from the last verified
 * snapshot.  Keeping a separate authoritative sector prevents a full ring of
 * failed appends from erasing the only recoverable state. */
static void meta_skip_failed(omk_store *s, uint32_t sector, uint32_t slot) {
    if (s->meta_valid) {
        s->meta_sector = sector;
        s->meta_slot = (uint8_t)slot;
    }
}

/* Append one verified snapshot.  On failure the in-RAM mirrored state remains
 * unchanged.  However, if flash_write succeeded and a fault or cut occurred
 * during read-back verification, the record is already durable on Flash with a
 * valid CRC and higher sequence number, and will become authoritative on reboot.
 * A slot that may contain a partial program is skipped on the next same-boot
 * attempt, just as it is after the boot-time scan.  Every local copy of the state
 * (which carries the master key, PIN hash and persisted PIN candidate) is wiped
 * before returning. */
static int meta_persist(omk_store *s, const meta_image *in) {
    int rc = -1;
    uint8_t buf[OMK_STORE_META_RECORD_SIZE] = {0};
    uint8_t check[OMK_STORE_META_RECORD_SIZE] = {0};
    meta_image m;
    memset(&m, 0, sizeof m);

    uint32_t sector;
    uint32_t slot;
    if (s->meta_valid) {
        if (s->meta_slot + 1u < META_RECORDS_PER_SECTOR) {
            sector = s->meta_sector;
            slot = (uint32_t)s->meta_slot + 1u;
        } else {
            sector = (s->meta_sector + 1u) % OMK_STORE_META_SECTORS;
            slot = 0;
        }
    } else {
        sector = 0;
        slot = 0;
    }

    const uint32_t off = meta_off(sector, slot);
    if (slot == 0) {
        /* Never erase the sector containing the newest verified snapshot.
         * Normally the ring has a newer snapshot before it wraps; this guard
         * matters when same-boot retries have skipped damaged slots. */
        if (s->meta_valid && sector == s->meta_valid_sector) {
            goto done;
        }
        /* A sector switch reuses an older sector; erase it unless the whole
         * sector is already blank.  Checking the whole sector (not just the
         * first record) prevents later appends from programming over stale
         * bytes. */
        const int erased = sector_is_erased(s, meta_off(sector, 0));
        if (erased < 0) {
            goto done;
        }
        if (erased == 0 && meta_sector_prepare(s, sector) != 0) {
            /* A partial erase makes every slot in this sector unusable for
             * append.  Abandon it for this boot rather than hitting it again. */
            meta_skip_failed(s, sector, META_RECORDS_PER_SECTOR - 1u);
            goto done;
        }
    } else {
        if (flash_read(s, off, buf, sizeof buf) != 0) {
            goto done;
        }
        if (!all_ff(buf, sizeof buf)) {
            meta_skip_failed(s, sector, slot);
            goto done;
        }
    }

    m = *in;
    if (s->meta_valid) {
        if (s->meta_seq == UINT64_MAX) {
            goto done;
        }
        m.seq = s->meta_seq + 1u;
    } else {
        m.seq = 1;
    }
    meta_serialize(&m, buf);
    if (flash_write(s, off, buf, sizeof buf) != 0) {
        meta_skip_failed(s, sector, slot);
        goto done;
    }
    if (flash_read(s, off, check, sizeof check) != 0) {
        meta_skip_failed(s, sector, slot);
        goto done;
    }
    if (memcmp(buf, check, sizeof buf) != 0) {
        meta_skip_failed(s, sector, slot);
        goto done;
    }

    s->meta_valid = true;
    s->meta_seq = m.seq;
    s->meta_sector = sector;
    s->meta_slot = (uint8_t)slot;
    s->meta_valid_sector = sector;
    meta_apply(s, &m);
    rc = 0;

done:
    omk_memzero(&m, sizeof m);
    omk_memzero(buf, sizeof buf);
    omk_memzero(check, sizeof check);
    return rc;
}

/* Scan the whole meta log.  Any read error is a hard failure and the caller
 * must not write anything.  Return values:
 *
 *   1  a valid current-format snapshot was loaded.  Unrelated, unknown or
 *      torn non-blank records may follow it (or precede it); they are ignored
 *      once any valid snapshot exists.
 *   0  the entire meta region is erased (true first boot; safe to format)
 *   2  every non-blank record is a torn current-format record with no valid
 *      snapshot (recognized v2 recovery: safe to format with a newer epoch)
 *  -1  flash read error
 *  -2  CRC-valid current-format record with impossible fields
 *  -3  no valid current-format snapshot exists and at least one non-blank
 *      record is neither current-format nor a torn current-format record
 *      (legacy v1 or foreign/corrupt state).  The store fails closed without
 *      writing so old credentials are never factory-erased.
 *
 * The scan deliberately does not stop at an unknown record: a power cut that
 * programs only a prefix of a newly appended record (damaging magic, version,
 * kind or the CRC) must not hide a previous valid snapshot.  Only when no
 * valid snapshot exists does unknown non-blank data make the image fatal.
 */
static int meta_load(omk_store *s) {
    int rc = 0;
    meta_image best;
    meta_image m;
    bool have = false;
    bool any_nonblank = false;
    bool any_foreign = false;
    uint32_t best_sector = 0;
    uint8_t best_slot = 0;
    uint8_t last_nonblank[OMK_STORE_META_SECTORS];
    uint8_t buf[OMK_STORE_META_RECORD_SIZE];

    memset(&best, 0, sizeof best);
    memset(&m, 0, sizeof m);
    memset(buf, 0, sizeof buf);
    memset(last_nonblank, 0xFF, sizeof last_nonblank);

    for (uint32_t sector = 0; sector < OMK_STORE_META_SECTORS; sector++) {
        for (uint32_t slot = 0; slot < META_RECORDS_PER_SECTOR; slot++) {
            if (flash_read(s, meta_off(sector, slot), buf, sizeof buf) != 0) {
                rc = -1;
                goto done;
            }
            if (all_ff(buf, sizeof buf)) {
                continue;
            }
            any_nonblank = true;
            last_nonblank[sector] = (uint8_t)slot;
            /* A non-blank record in another format is legacy v1 or foreign
             * state.  It is never interpreted or formatted over, but the
             * decision is deferred until the whole region has been scanned: a
             * valid v2 snapshot elsewhere still lets the store recover. */
            if (rd32(buf + MO_MAGIC) != META_MAGIC ||
                rd16(buf + MO_VERSION) != META_VERSION ||
                buf[MO_KIND] != META_KIND_SNAPSHOT) {
                any_foreign = true;
                continue;
            }
            const int parsed = meta_parse(buf, &m);
            if (parsed < 0) {
                /* Impossible fields in a CRC-valid snapshot are always a hard
                 * fault, even if another snapshot is valid. */
                rc = -2;
                goto done;
            }
            if (parsed == 0) {
                /* Torn current-format record: retained for the recovery
                 * policy above, never treated as a valid snapshot. */
                continue;
            }
            if (!have || m.seq > best.seq) {
                best = m;
                best_sector = sector;
                best_slot = (uint8_t)slot;
                have = true;
            }
        }
    }

    if (!have) {
        if (any_foreign) {
            rc = -3;
        } else {
            rc = any_nonblank ? 2 : 0;
        }
        goto done;
    }

    meta_apply(s, &best);
    s->meta_valid = true;
    s->meta_seq = best.seq;
    s->meta_sector = best_sector;
    s->meta_valid_sector = best_sector;
    /* Skip every non-blank slot after the newest valid snapshot in its
     * sector, including unknown or torn records, so the next append never
     * tries to program a slot that already contains bits.  A full sector
     * moves to the next sector, which is erased first if it is not blank. */
    s->meta_slot = last_nonblank[best_sector] > best_slot
                       ? last_nonblank[best_sector]
                       : best_slot;
    rc = 1;

done:
    omk_memzero(buf, sizeof buf);
    omk_memzero(&m, sizeof m);
    omk_memzero(&best, sizeof best);
    return rc;
}

/* ---------------------------------------------------------------------- */
/* Record serialization helpers                                            */
/* ---------------------------------------------------------------------- */

typedef struct {
    uint8_t *p;
    const uint8_t *end;
    bool ok;
} writer;

static void w_u8(writer *w, uint8_t v) {
    if (w->p + 1 > w->end) {
        w->ok = false;
        return;
    }
    *w->p++ = v;
}

static void w_u16(writer *w, uint16_t v) {
    if (w->p + 2 > w->end) {
        w->ok = false;
        return;
    }
    wr16(w->p, v);
    w->p += 2;
}

static void w_data(writer *w, const void *data, size_t len) {
    if (len == 0) {
        return; /* avoids memcpy(dst, NULL, 0) for optional fields */
    }
    if (len > (size_t)(w->end - w->p)) {
        w->ok = false;
        return;
    }
    memcpy(w->p, data, len);
    w->p += len;
}

typedef struct {
    const uint8_t *p;
    const uint8_t *end;
    bool ok;
} reader;

static uint8_t r_u8(reader *r) {
    if (r->p + 1 > r->end) {
        r->ok = false;
        return 0;
    }
    return *r->p++;
}

static uint16_t r_u16(reader *r) {
    if (r->p + 2 > r->end) {
        r->ok = false;
        return 0;
    }
    const uint16_t v = rd16(r->p);
    r->p += 2;
    return v;
}

static bool r_data(reader *r, void *out, size_t len) {
    if (len > (size_t)(r->end - r->p)) {
        r->ok = false;
        return false;
    }
    memcpy(out, r->p, len);
    r->p += len;
    return true;
}

static size_t credential_serialize(const omk_credential *c, uint8_t *out,
                                   size_t cap) {
    writer w = {out, out + cap, true};
    w_u8(&w, c->alg);
    w_u8(&w, c->cred_protect);
    w_u8(&w, 0);
    w_u8(&w, c->id_len);
    w_data(&w, c->id, c->id_len);
    w_data(&w, c->rp_id_hash, 32);
    w_u16(&w, c->rp_id_len);
    w_data(&w, c->rp_id, c->rp_id_len);
    w_u8(&w, c->user_id_len);
    w_data(&w, c->user_id, c->user_id_len);
    w_u8(&w, c->user_name_len);
    w_data(&w, c->user_name, c->user_name_len);
    w_u8(&w, c->display_name_len);
    w_data(&w, c->display_name, c->display_name_len);
    return w.ok ? (size_t)(w.p - out) : 0;
}

static bool credential_parse(reader *r, omk_credential *c) {
    memset(c, 0, sizeof(*c));
    c->alg = r_u8(r);
    c->cred_protect = r_u8(r);
    (void)r_u8(r);
    c->id_len = r_u8(r);
    if (c->id_len == 0 || c->id_len > OMK_CRED_ID_MAX ||
        !r_data(r, c->id, c->id_len) ||
        !r_data(r, c->rp_id_hash, 32)) {
        return false;
    }
    c->rp_id_len = r_u16(r);
    if (c->rp_id_len > OMK_RP_ID_MAX || !r_data(r, c->rp_id, c->rp_id_len)) {
        return false;
    }
    c->user_id_len = r_u8(r);
    if (c->user_id_len > OMK_USER_ID_MAX ||
        !r_data(r, c->user_id, c->user_id_len)) {
        return false;
    }
    c->user_name_len = r_u8(r);
    if (c->user_name_len > OMK_USER_NAME_MAX ||
        !r_data(r, c->user_name, c->user_name_len)) {
        return false;
    }
    c->display_name_len = r_u8(r);
    if (c->display_name_len > OMK_USER_NAME_MAX ||
        !r_data(r, c->display_name, c->display_name_len)) {
        return false;
    }
    return r->ok && c->alg >= 1 && c->alg <= 2 && c->cred_protect <= 3;
}

static int credential_index_find(const omk_store *s, const uint8_t *id,
                                 size_t id_len) {
    for (uint8_t i = 0; i < s->cred_count; i++) {
        if (s->creds[i].id_len == id_len &&
            memcmp(s->creds[i].id, id, id_len) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/* Index that a new credential would overwrite: same credential ID or the
 * same rpId+user.id (WebAuthn overwrite semantics). */
static int credential_overwrite_index(const omk_store *s,
                                      const omk_credential *c) {
    const int id_idx = credential_index_find(s, c->id, c->id_len);
    if (id_idx >= 0) {
        return id_idx;
    }
    for (uint8_t i = 0; i < s->cred_count; i++) {
        if (s->creds[i].user_id_len == c->user_id_len &&
            s->creds[i].rp_id_len == c->rp_id_len &&
            memcmp(s->creds[i].rp_id_hash, c->rp_id_hash, 32) == 0 &&
            memcmp(s->creds[i].user_id, c->user_id, c->user_id_len) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static void credential_index_remove(omk_store *s, uint8_t idx) {
    if (idx >= s->cred_count) {
        return;
    }
    for (uint8_t i = idx; i + 1 < s->cred_count; i++) {
        s->creds[i] = s->creds[i + 1];
    }
    s->cred_count--;
    omk_memzero(&s->creds[s->cred_count], sizeof(s->creds[0]));
}

static void credential_index_put(omk_store *s, const omk_credential *c) {
    const int idx = credential_overwrite_index(s, c);
    if (idx >= 0) {
        s->creds[idx] = *c;
        return;
    }
    if (s->cred_count >= OMK_MAX_CREDENTIALS) {
        return;
    }
    s->creds[s->cred_count++] = *c;
}

/* ---------------------------------------------------------------------- */
/* Credential log                                                          */
/* ---------------------------------------------------------------------- */

#define RO_MAGIC 0u
#define RO_VERSION 4u
#define RO_TYPE 6u
#define RO_FLAGS 7u
#define RO_EPOCH 8u
#define RO_SEQ 12u
#define RO_PAYLOAD_LEN 16u
#define RO_CRC 20u

/* Program one record into an already-erased slot and verify it by read-back.
 * Sets *next_off only on success. */
static int log_write_slot(omk_store *s, uint32_t off, uint8_t type,
                          uint32_t epoch, uint32_t seq, const uint8_t *payload,
                          size_t payload_len, uint32_t *next_off) {
    if (payload_len > REC_MAX_PAYLOAD) {
        return -1;
    }
    uint8_t buf[REC_SLOT_SIZE];
    memset(buf, 0xFF, sizeof buf);
    wr32(buf + RO_MAGIC, REC_MAGIC);
    wr16(buf + RO_VERSION, REC_VERSION);
    buf[RO_TYPE] = type;
    buf[RO_FLAGS] = 0;
    wr32(buf + RO_EPOCH, epoch);
    wr32(buf + RO_SEQ, seq);
    wr16(buf + RO_PAYLOAD_LEN, (uint16_t)payload_len);
    wr16(buf + RO_PAYLOAD_LEN + 2, 0);
    memcpy(buf + REC_HDR_SIZE, payload, payload_len);
    wr32(buf + RO_CRC, 0);
    wr32(buf + RO_CRC, crc32(buf, REC_HDR_SIZE + payload_len));

    if (flash_write(s, off, buf, sizeof buf) != 0) {
        return -1;
    }
    uint8_t check[REC_SLOT_SIZE];
    if (flash_read(s, off, check, sizeof check) != 0) {
        return -1;
    }
    if (memcmp(buf, check, sizeof buf) != 0) {
        return -1;
    }
    *next_off = off + REC_SLOT_SIZE;
    return 0;
}

/* Validate a record in a slot.  Returns 1 if the slot holds a valid
 * current-epoch record, 0 for an erased/torn/foreign/invalid record and -1
 * for a flash read error. */
static int log_record_parse(omk_store *s, uint32_t off, uint8_t *type,
                            uint32_t *seq, uint8_t *payload,
                            size_t *payload_len, bool *erased) {
    uint8_t buf[REC_SLOT_SIZE];
    if (flash_read(s, off, buf, sizeof buf) != 0) {
        return -1;
    }
    if (erased != NULL) {
        *erased = all_ff(buf, sizeof buf);
    }
    if (all_ff(buf, sizeof buf)) {
        return 0;
    }
    if (rd32(buf + RO_MAGIC) != REC_MAGIC ||
        rd16(buf + RO_VERSION) != REC_VERSION) {
        return 0;
    }
    if (rd32(buf + RO_EPOCH) != s->log_epoch) {
        return 0;
    }
    const uint16_t len = rd16(buf + RO_PAYLOAD_LEN);
    if (len > REC_MAX_PAYLOAD) {
        return 0;
    }
    const uint32_t stored = rd32(buf + RO_CRC);
    wr32(buf + RO_CRC, 0);
    const bool ok = crc32(buf, REC_HDR_SIZE + len) == stored;
    wr32(buf + RO_CRC, stored);
    if (!ok) {
        return 0;
    }
    *type = buf[RO_TYPE];
    *seq = rd32(buf + RO_SEQ);
    if (*seq == 0) {
        return 0;
    }
    if (payload != NULL && len != 0) {
        memcpy(payload, buf + REC_HDR_SIZE, len);
    }
    *payload_len = len;
    return 1;
}

/* Ensure the slot at off is erased.  Only a slot at the start of a sector can
 * be reclaimed by erasing its sector; anything else would destroy earlier
 * records.  Return -2 for a non-blank interior slot so the caller can advance
 * past it on a same-boot retry; read/erase failures return -1. */
static int log_slot_prepare(omk_store *s, uint32_t off) {
    if ((off % OMK_FLASH_SECTOR_SIZE) == 0) {
        /* At a sector boundary we may reclaim the whole sector, but only if
         * it is actually stale: the append cursor is past every used slot, so
         * no live record can share this sector.  Check the whole sector, not
         * just the target slot, so a later append never programs over stale
         * bytes. */
        const int erased = sector_is_erased(s, off);
        if (erased < 0) {
            return -1;
        }
        if (erased == 0) {
            if (flash_erase(s, off) != 0) {
                return -1;
            }
            if (sector_is_erased(s, off) != 1) {
                return -1;
            }
        }
        return 0;
    }
    uint8_t buf[REC_SLOT_SIZE];
    if (flash_read(s, off, buf, sizeof buf) != 0) {
        return -1;
    }
    if (!all_ff(buf, sizeof buf)) {
        /* Programming over a non-erased slot would AND-corrupt it and could
         * destroy an earlier record; skip this damaged append position. */
        return -2;
    }
    return 0;
}

/* Copy every live credential into the inactive bank, verify the copy, then
 * commit the bank/epoch switch with one meta record.  The old bank is not
 * touched. */
static int log_compact(omk_store *s) {
    int rc = -1;
    uint8_t buf[1024] = {0};
    uint8_t order[OMK_MAX_CREDENTIALS] = {0};
    uint8_t payload[REC_MAX_PAYLOAD] = {0};
    meta_image m;
    memset(&m, 0, sizeof m);

    if (!s->ready || s->log_epoch == UINT32_MAX) {
        goto done;
    }
    const uint8_t target = (uint8_t)(1u - s->active_bank);
    const uint32_t off = bank_off(target);

    for (uint32_t pos = 0; pos < OMK_STORE_BANK_SIZE;
         pos += OMK_FLASH_SECTOR_SIZE) {
        if (flash_erase(s, off + pos) != 0) {
            goto done;
        }
        if (!long_op_continue(s)) {
            rc = OMK_STORE_ERR_CANCELLED;
            goto done;
        }
    }
    for (uint32_t pos = 0; pos < OMK_STORE_BANK_SIZE; pos += sizeof buf) {
        if (flash_read(s, off + pos, buf, sizeof buf) != 0) {
            goto done;
        }
        if (!all_ff(buf, sizeof buf)) {
            goto done;
        }
        if ((pos + sizeof buf) % OMK_FLASH_SECTOR_SIZE == 0 &&
            !long_op_continue(s)) {
            rc = OMK_STORE_ERR_CANCELLED;
            goto done;
        }
    }

    const uint8_t count = s->cred_count;
    for (uint8_t i = 0; i < count; i++) {
        order[i] = i;
    }
    for (uint8_t i = 1; i < count; i++) {
        const uint8_t v = order[i];
        int j = (int)i - 1;
        while (j >= 0 && s->creds[order[j]].seq > s->creds[v].seq) {
            order[j + 1] = order[j];
            j--;
        }
        order[j + 1] = v;
    }

    uint32_t write = off;
    const uint32_t new_epoch = s->log_epoch + 1u;
    for (uint8_t i = 0; i < count; i++) {
        const omk_credential *c = &s->creds[order[i]];
        const size_t len = credential_serialize(c, payload, sizeof payload);
        if (len == 0) {
            goto done;
        }
        uint32_t next = 0;
        if (log_write_slot(s, write, REC_TYPE_CRED, new_epoch, c->seq, payload,
                           len, &next) != 0) {
            goto done;
        }
        write = next;
        if (!long_op_continue(s)) {
            rc = OMK_STORE_ERR_CANCELLED;
            goto done;
        }
    }

    meta_from_store(s, &m);
    m.active_bank = target;
    m.log_epoch = new_epoch;
    if (meta_persist(s, &m) != 0) {
        goto done;
    }
    s->write_off = off + (uint32_t)count * REC_SLOT_SIZE;
    rc = 0;

done:
    /* In particular, m contains the master key and PIN hash.  Wipe every
     * temporary on both success and all failure exits. */
    omk_memzero(&m, sizeof m);
    omk_memzero(payload, sizeof payload);
    omk_memzero(order, sizeof order);
    omk_memzero(buf, sizeof buf);
    return rc;
}

/* Append a record to the active bank.  Compacts first if the bank is full.
 * RAM state is only changed by the caller after this returns success; on
 * failure RAM rolls back, but if the slot was fully programmed before a
 * read-back cut the record may already be durable on Flash upon reboot. */
static int log_append(omk_store *s, uint8_t type, uint32_t seq,
                      const uint8_t *payload, size_t payload_len) {
    if (!s->ready || payload_len > REC_MAX_PAYLOAD || seq == 0) {
        return -1;
    }
    if (s->write_off < bank_off(s->active_bank) ||
        s->write_off > bank_end(s->active_bank)) {
        return -1;
    }
    if (s->write_off + REC_SLOT_SIZE > bank_end(s->active_bank)) {
        const int compacted = log_compact(s);
        if (compacted != 0) {
            return compacted;
        }
    }
    if (s->write_off + REC_SLOT_SIZE > bank_end(s->active_bank)) {
        return -1;
    }
    const int prepared = log_slot_prepare(s, s->write_off);
    if (prepared != 0) {
        if (prepared == -2) {
            s->write_off += REC_SLOT_SIZE;
        }
        return -1;
    }
    uint32_t next = 0;
    if (log_write_slot(s, s->write_off, type, s->log_epoch, seq, payload,
                       payload_len, &next) != 0) {
        /* The failed program may have left a non-blank prefix.  Do not retry
         * the same slot until the boot-time scan has established a cursor. */
        s->write_off += REC_SLOT_SIZE;
        return -1;
    }
    s->write_off = next;
    return 0;
}

/* Rebuild the in-RAM credential index from the active bank.  Any read error
 * fails initialisation before a write.  Invalid/torn/foreign records are
 * skipped independently; the tail is never erased. */
static int log_load(omk_store *s) {
    const uint32_t base = bank_off(s->active_bank);
    uint32_t last_used = 0;
    bool any_used = false;
    uint32_t max_seq = 0;

    s->cred_count = 0;
    memset(s->creds, 0, sizeof(s->creds));

    for (uint32_t slot = 0; slot < LOG_SLOTS_PER_BANK; slot++) {
        const uint32_t off = base + slot * REC_SLOT_SIZE;
        uint8_t type = 0;
        uint32_t seq = 0;
        size_t payload_len = 0;
        uint8_t payload[REC_MAX_PAYLOAD];
        bool erased = false;
        const int parsed =
            log_record_parse(s, off, &type, &seq, payload, &payload_len,
                             &erased);
        if (parsed < 0) {
            return -1;
        }
        if (erased) {
            continue;
        }
        last_used = slot;
        any_used = true;
        if (parsed == 0) {
            continue;
        }

        reader r = {payload, payload + payload_len, true};
        if (type == REC_TYPE_CRED) {
            omk_credential c;
            if (credential_parse(&r, &c)) {
                c.seq = seq;
                credential_index_put(s, &c);
            }
        } else if (type == REC_TYPE_DELETE) {
            uint8_t id[OMK_CRED_ID_MAX];
            const uint8_t id_len = r_u8(&r);
            if (id_len != 0 && id_len <= OMK_CRED_ID_MAX &&
                r_data(&r, id, id_len)) {
                const int idx = credential_index_find(s, id, id_len);
                if (idx >= 0) {
                    credential_index_remove(s, (uint8_t)idx);
                }
            }
        } else if (type == REC_TYPE_UPDATE) {
            uint8_t id[OMK_CRED_ID_MAX];
            const uint8_t id_len = r_u8(&r);
            if (id_len != 0 && id_len <= OMK_CRED_ID_MAX &&
                r_data(&r, id, id_len)) {
                const int idx = credential_index_find(s, id, id_len);
                if (idx >= 0) {
                    uint8_t uid[OMK_USER_ID_MAX];
                    uint8_t name[OMK_USER_NAME_MAX];
                    uint8_t disp[OMK_USER_NAME_MAX];
                    /* Parse every field into temporaries before touching the
                     * live record so a malformed/torn update is skipped
                     * atomically. */
                    const uint8_t uid_len = r_u8(&r);
                    if (uid_len == 0 || uid_len > OMK_USER_ID_MAX ||
                        !r_data(&r, uid, uid_len)) {
                        continue;
                    }
                    const uint8_t name_len = r_u8(&r);
                    if (name_len > OMK_USER_NAME_MAX ||
                        !r_data(&r, name, name_len)) {
                        continue;
                    }
                    const uint8_t disp_len = r_u8(&r);
                    if (disp_len > OMK_USER_NAME_MAX ||
                        !r_data(&r, disp, disp_len)) {
                        continue;
                    }
                    omk_credential *c = &s->creds[idx];
                    c->user_id_len = uid_len;
                    memcpy(c->user_id, uid, uid_len);
                    c->user_name_len = name_len;
                    memcpy(c->user_name, name, name_len);
                    c->display_name_len = disp_len;
                    memcpy(c->display_name, disp, disp_len);
                }
            }
        }
        if (seq > max_seq) {
            max_seq = seq;
        }
    }

    if (any_used) {
        s->write_off = base + (last_used + 1u) * REC_SLOT_SIZE;
    } else {
        s->write_off = base;
    }
    if (max_seq == UINT32_MAX) {
        s->next_seq = UINT32_MAX; /* exhausted: no new sequence numbers */
    } else if (max_seq + 1u > s->next_seq) {
        s->next_seq = max_seq + 1u;
    }
    return 0;
}

/* Return the highest valid log epoch found in either bank.  Used only when
 * formatting so a new epoch is strictly newer than any surviving record. */
static int log_max_epoch(omk_store *s, uint32_t *max_epoch) {
    uint32_t best = 0;
    for (uint8_t bank = 0; bank < 2; bank++) {
        const uint32_t base = bank_off(bank);
        for (uint32_t slot = 0; slot < LOG_SLOTS_PER_BANK; slot++) {
            uint8_t buf[REC_SLOT_SIZE];
            const uint32_t off = base + slot * REC_SLOT_SIZE;
            if (flash_read(s, off, buf, sizeof buf) != 0) {
                return -1;
            }
            if (all_ff(buf, sizeof buf)) {
                continue;
            }
            if (rd32(buf + RO_MAGIC) != REC_MAGIC ||
                rd16(buf + RO_VERSION) != REC_VERSION) {
                continue;
            }
            const uint16_t len = rd16(buf + RO_PAYLOAD_LEN);
            if (len > REC_MAX_PAYLOAD) {
                continue;
            }
            const uint32_t stored = rd32(buf + RO_CRC);
            wr32(buf + RO_CRC, 0);
            const bool ok = crc32(buf, REC_HDR_SIZE + len) == stored;
            wr32(buf + RO_CRC, stored);
            if (!ok) {
                continue;
            }
            const uint32_t epoch = rd32(buf + RO_EPOCH);
            if (epoch > best) {
                best = epoch;
            }
        }
    }
    *max_epoch = best;
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Public API                                                              */
/* ---------------------------------------------------------------------- */

static int store_format(omk_store *s) {
    int rc = -1;
    uint8_t master[32] = {0};
    meta_image m;

    memset(&m, 0, sizeof m);

    /* Generate the new master secret before erasing anything: a failed RNG
     * must leave the flash untouched, and partially filled secrets are never
     * installed.  The model AAGUID is a constant, not random device state. */
    if (!store_random(s, master, sizeof master)) {
        goto done;
    }

    uint32_t max_epoch = 0;
    if (log_max_epoch(s, &max_epoch) != 0) {
        goto done;
    }
    if (max_epoch == UINT32_MAX) {
        goto done;
    }
    for (uint32_t sector = 0; sector < OMK_STORE_META_SECTORS; sector++) {
        if (meta_sector_prepare(s, sector) != 0) {
            goto done;
        }
    }

    s->meta_valid = false;
    s->meta_seq = 0;
    s->meta_sector = 0;
    s->meta_slot = 0;
    s->reset_epoch = max_epoch + 1u;
    s->log_epoch = max_epoch + 1u;
    s->active_bank = 0;
    s->pin_epoch = 1;
    s->lease = 0;
    s->counter = 0;
    s->next_seq = 1;
    s->pin_set = false;
    s->pin_retries = 8;
    s->attempt_valid = false;
    memset(s->pin_hash, 0, sizeof s->pin_hash);
    memset(s->attempt_candidate, 0, sizeof s->attempt_candidate);
    memset(s->creds, 0, sizeof s->creds);
    s->cred_count = 0;
    s->write_off = bank_off(0);
    memcpy(s->master, master, sizeof master);
    memcpy(s->aaguid, model_aaguid, sizeof model_aaguid);

    meta_from_store(s, &m);
    rc = meta_persist(s, &m);

done:
    omk_memzero(master, sizeof master);
    omk_memzero(&m, sizeof m);
    return rc;
}

/* Resolve a PIN attempt that was persisted before the comparison.  A matching
 * candidate is completed as a success (restores 8); a wrong candidate keeps
 * the persisted decrement.  The resolution is persisted best-effort: if the
 * write fails the device still boots with the safe RAM value and the marker
 * remains for the next boot. */
static void store_resolve_attempt(omk_store *s) {
    if (!s->attempt_valid) {
        return;
    }
    meta_image m;
    memset(&m, 0, sizeof m);
    meta_from_store(s, &m);
    m.attempt_valid = false;
    memset(m.attempt_candidate, 0, sizeof m.attempt_candidate);
    if (s->pin_set && s->pin_epoch != 0 &&
        s->attempt_valid) {
        if (omk_ct_equal(s->attempt_candidate, s->pin_hash, 16)) {
            m.pin_retries = 8;
            s->pin_retries = 8;
        }
    }
    if (meta_persist(s, &m) != 0) {
        /* Leave the marker in RAM so a later successful meta write carries
         * the resolution; the safe retry value above is already live. */
        s->attempt_valid = true;
    }
    omk_memzero(&m, sizeof m);
}

int omk_store_init(omk_store *s, const omk_port *port) {
    memset(s, 0, sizeof(*s));
    s->port = port;
    s->pin_retries = 8;
    s->next_seq = 1;

    const int loaded = meta_load(s);
    if (loaded < 0) {
        /* Read error, impossible current-format state, or recognized legacy/
         * foreign data.  Never write or erase in this path. */
        omk_memzero(s, sizeof *s);
        return -1;
    }
    if (loaded == 0 || loaded == 2) {
        if (store_format(s) != 0) {
            omk_memzero(s, sizeof *s);
            return -1;
        }
    } else {
        s->counter = s->lease;
        if (log_load(s) != 0) {
            omk_memzero(s, sizeof *s);
            return -1;
        }
        store_resolve_attempt(s);
    }
    s->ready = true;
    return 0;
}

int omk_store_reset(omk_store *s) {
    int rc = -1;
    uint8_t master[32] = {0};
    meta_image m;

    memset(&m, 0, sizeof m);

    if (!s->ready || s->reset_epoch == UINT32_MAX ||
        s->log_epoch == UINT32_MAX || s->pin_epoch == UINT32_MAX) {
        goto done;
    }

    /* A fresh master secret is generated before the inactive bank is touched,
     * so an RNG failure cannot leave a half-prepared reset behind.  Reset does
     * not change the model AAGUID. */
    if (!store_random(s, master, sizeof master)) {
        goto done;
    }

    const uint8_t target = (uint8_t)(1u - s->active_bank);
    const uint32_t off = bank_off(target);

    /* Phase 1: prepare a pristine inactive bank.  The active bank is never
     * touched, so a failure here leaves the old state fully intact. */
    for (uint32_t pos = 0; pos < OMK_STORE_BANK_SIZE;
         pos += OMK_FLASH_SECTOR_SIZE) {
        if (flash_erase(s, off + pos) != 0) {
            goto done;
        }
        if (!long_op_continue(s)) {
            rc = OMK_STORE_ERR_CANCELLED;
            goto done;
        }
    }
    uint8_t buf[1024];
    for (uint32_t pos = 0; pos < OMK_STORE_BANK_SIZE; pos += sizeof buf) {
        if (flash_read(s, off + pos, buf, sizeof buf) != 0) {
            omk_memzero(buf, sizeof buf);
            goto done;
        }
        if (!all_ff(buf, sizeof buf)) {
            omk_memzero(buf, sizeof buf);
            goto done;
        }
        if ((pos + sizeof buf) % OMK_FLASH_SECTOR_SIZE == 0 &&
            !long_op_continue(s)) {
            omk_memzero(buf, sizeof buf);
            rc = OMK_STORE_ERR_CANCELLED;
            goto done;
        }
    }
    omk_memzero(buf, sizeof buf);

    /* Phase 2: one verified meta record installs fresh keys, clears the PIN
     * and credentials, bumps both epochs and switches to the empty bank. */
    meta_from_store(s, &m);
    m.reset_epoch = s->reset_epoch + 1u;
    m.log_epoch = s->log_epoch + 1u;
    m.pin_epoch = s->pin_epoch + 1u;
    m.active_bank = target;
    m.pin_set = false;
    m.pin_retries = 8;
    m.attempt_valid = false;
    m.lease = 0;
    m.next_seq = 1;
    memset(m.pin_hash, 0, sizeof m.pin_hash);
    memset(m.attempt_candidate, 0, sizeof m.attempt_candidate);
    memcpy(m.master, master, sizeof master);
    memcpy(m.aaguid, model_aaguid, sizeof model_aaguid);
    if (meta_persist(s, &m) != 0) {
        goto done; /* old snapshot is still authoritative */
    }

    s->counter = 0;
    s->cred_count = 0;
    memset(s->creds, 0, sizeof s->creds);
    s->write_off = off;
    rc = 0;

done:
    omk_memzero(master, sizeof master);
    omk_memzero(&m, sizeof m);
    return rc;
}

uint32_t omk_store_next_counter(omk_store *s) {
    if (!s->ready || s->counter == UINT32_MAX) {
        return 0;
    }
    const uint32_t next = s->counter + 1u;
    if (next > s->lease) {
        if (s->lease == UINT32_MAX) {
            return 0;
        }
        uint32_t new_lease;
        if (next > UINT32_MAX - (COUNTER_LEASE_STEP - 1u)) {
            new_lease = UINT32_MAX;
        } else {
            new_lease = next + (COUNTER_LEASE_STEP - 1u);
        }
        meta_image m;
        memset(&m, 0, sizeof m);
        meta_from_store(s, &m);
        m.lease = new_lease;
        const int rc = meta_persist(s, &m);
        omk_memzero(&m, sizeof m);
        if (rc != 0) {
            return 0; /* RAM counter is unchanged */
        }
    }
    s->counter = next;
    return next;
}

int omk_store_pin_attempt(omk_store *s, const uint8_t candidate[16]) {
    if (!s->ready || !s->pin_set || s->pin_retries == 0) {
        return -1;
    }
    meta_image m;
    memset(&m, 0, sizeof m);
    meta_from_store(s, &m);
    m.pin_retries = (uint8_t)(s->pin_retries - 1u);
    m.attempt_valid = true;
    memcpy(m.attempt_candidate, candidate, 16);
    /* The verified meta record is the linearization point: the decrement and
     * the candidate are durable before the caller is allowed to compare. */
    const int rc = meta_persist(s, &m);
    omk_memzero(&m, sizeof m);
    return rc;
}

int omk_store_pin_success(omk_store *s) {
    if (!s->ready) {
        return -1;
    }
    if (s->pin_retries == 8 && !s->attempt_valid) {
        return 0;
    }
    meta_image m;
    memset(&m, 0, sizeof m);
    meta_from_store(s, &m);
    m.pin_retries = 8;
    m.attempt_valid = false;
    memset(m.attempt_candidate, 0, sizeof m.attempt_candidate);
    const int rc = meta_persist(s, &m);
    omk_memzero(&m, sizeof m);
    return rc;
}

int omk_store_pin_reject(omk_store *s) {
    if (!s->ready) {
        return -1;
    }
    meta_image m;
    memset(&m, 0, sizeof m);
    meta_from_store(s, &m);
    m.attempt_valid = false;
    memset(m.attempt_candidate, 0, sizeof m.attempt_candidate);
    /* Keep the decremented retry count. */
    const int rc = meta_persist(s, &m);
    omk_memzero(&m, sizeof m);
    return rc;
}

int omk_store_set_pin(omk_store *s, const uint8_t hash[16]) {
    if (!s->ready || s->pin_epoch == UINT32_MAX) {
        return -1;
    }
    meta_image m;
    memset(&m, 0, sizeof m);
    meta_from_store(s, &m);
    memcpy(m.pin_hash, hash, 16);
    m.pin_set = true;
    m.pin_retries = 8;
    m.pin_epoch = s->pin_epoch + 1u;
    m.attempt_valid = false;
    memset(m.attempt_candidate, 0, sizeof m.attempt_candidate);
    const int rc = meta_persist(s, &m);
    omk_memzero(&m, sizeof m);
    return rc;
}

int omk_store_put_credential(omk_store *s, const omk_credential *cred) {
    if (!s->ready || s->next_seq == UINT32_MAX || cred->id_len == 0 ||
        cred->id_len > OMK_CRED_ID_MAX ||
        cred->rp_id_len > OMK_RP_ID_MAX ||
        cred->user_id_len > OMK_USER_ID_MAX ||
        cred->user_name_len > OMK_USER_NAME_MAX ||
        cred->display_name_len > OMK_USER_NAME_MAX || cred->alg < 1 ||
        cred->alg > 2 || cred->cred_protect > 3) {
        return -1;
    }
    const int idx = credential_overwrite_index(s, cred);
    if (idx < 0 && s->cred_count >= OMK_MAX_CREDENTIALS) {
        return OMK_STORE_ERR_FULL;
    }
    omk_credential copy = *cred;
    copy.seq = s->next_seq;
    uint8_t payload[REC_MAX_PAYLOAD];
    const size_t len = credential_serialize(&copy, payload, sizeof payload);
    if (len == 0) {
        return -1;
    }
    const int appended = log_append(s, REC_TYPE_CRED, copy.seq, payload, len);
    if (appended != 0) {
        return appended;
    }
    credential_index_put(s, &copy);
    s->next_seq = copy.seq + 1u;
    return 0;
}

int omk_store_delete_credential(omk_store *s, const uint8_t *id,
                                size_t id_len) {
    if (!s->ready || s->next_seq == UINT32_MAX || id_len == 0 ||
        id_len > OMK_CRED_ID_MAX) {
        return -1;
    }
    const int idx = credential_index_find(s, id, id_len);
    if (idx < 0) {
        return -1;
    }
    uint8_t payload[1 + OMK_CRED_ID_MAX];
    payload[0] = (uint8_t)id_len;
    memcpy(payload + 1, id, id_len);
    const uint32_t seq = s->next_seq;
    const int appended = log_append(s, REC_TYPE_DELETE, seq, payload, 1 + id_len);
    if (appended != 0) {
        return appended;
    }
    credential_index_remove(s, (uint8_t)idx);
    s->next_seq = seq + 1u;
    return 0;
}

int omk_store_update_user(omk_store *s, const uint8_t *id, size_t id_len,
                          const uint8_t *user_id, size_t user_id_len,
                          const uint8_t *name, size_t name_len,
                          const uint8_t *display, size_t display_len) {
    if (!s->ready || s->next_seq == UINT32_MAX || id_len == 0 ||
        id_len > OMK_CRED_ID_MAX || user_id_len == 0 ||
        user_id_len > OMK_USER_ID_MAX || name_len > OMK_USER_NAME_MAX ||
        display_len > OMK_USER_NAME_MAX) {
        return -1;
    }
    const int idx = credential_index_find(s, id, id_len);
    if (idx < 0) {
        return -1;
    }
    uint8_t payload[1 + OMK_CRED_ID_MAX + 3 + 3 * OMK_USER_NAME_MAX];
    writer w = {payload, payload + sizeof payload, true};
    w_u8(&w, (uint8_t)id_len);
    w_data(&w, id, id_len);
    w_u8(&w, (uint8_t)user_id_len);
    w_data(&w, user_id, user_id_len);
    w_u8(&w, (uint8_t)name_len);
    w_data(&w, name, name_len);
    w_u8(&w, (uint8_t)display_len);
    w_data(&w, display, display_len);
    if (!w.ok) {
        return -1;
    }
    const uint32_t seq = s->next_seq;
    const int appended = log_append(s, REC_TYPE_UPDATE, seq, payload,
                                    (size_t)(w.p - payload));
    if (appended != 0) {
        return appended;
    }
    omk_credential *c = &s->creds[idx];
    c->user_id_len = (uint8_t)user_id_len;
    memcpy(c->user_id, user_id, user_id_len);
    c->user_name_len = (uint8_t)name_len;
    memcpy(c->user_name, name, name_len);
    c->display_name_len = (uint8_t)display_len;
    memcpy(c->display_name, display, display_len);
    s->next_seq = seq + 1u;
    return 0;
}

const omk_credential *omk_store_find_id(const omk_store *s, const uint8_t *id,
                                        size_t id_len) {
    const int idx = credential_index_find(s, id, id_len);
    return idx < 0 ? NULL : &s->creds[idx];
}

const omk_credential *omk_store_find_rp_user(const omk_store *s,
                                             const uint8_t rp_hash[32],
                                             const uint8_t *user_id,
                                             size_t user_id_len) {
    for (uint8_t i = 0; i < s->cred_count; i++) {
        if (s->creds[i].user_id_len == user_id_len &&
            memcmp(s->creds[i].rp_id_hash, rp_hash, 32) == 0 &&
            memcmp(s->creds[i].user_id, user_id, user_id_len) == 0) {
            return &s->creds[i];
        }
    }
    return NULL;
}

/* ---------------------------------------------------------------------- */
/* Credential ID sealing                                                   */
/* ---------------------------------------------------------------------- */

static void derive_keys(const omk_store *s, uint8_t enc[32], uint8_t mac[32]) {
    static const char enc_info[] = "OMK credid enc v1";
    static const char mac_info[] = "OMK credid mac v1";
    omk_hkdf_sha256(NULL, 0, s->master, 32, (const uint8_t *)enc_info,
                    sizeof enc_info - 1, enc, 32);
    omk_hkdf_sha256(NULL, 0, s->master, 32, (const uint8_t *)mac_info,
                    sizeof mac_info - 1, mac, 32);
}

size_t omk_store_seal_credential(const omk_store *s, const uint8_t rp_hash[32],
                                 const uint8_t seed[32], uint8_t alg,
                                 uint8_t cred_protect, bool resident,
                                 uint8_t out[OMK_CRED_ID_MAX]) {
    size_t rc = 0;
    uint8_t enc[32] = {0};
    uint8_t mac[32] = {0};
    uint8_t macbuf[32] = {0};
    uint8_t iv[16] = {0};
    uint8_t cipher[32] = {0};
    uint8_t id[ID_LEN] = {0};
    uint8_t opad[64] = {0};
    omk_sha256_ctx hm;
    memset(&hm, 0, sizeof hm);

    if (!s->ready) {
        goto done;
    }
    derive_keys(s, enc, mac);
    if (!store_random(s, iv, sizeof iv)) {
        goto done;
    }
    id[0] = ID_VERSION;
    id[1] = resident ? ID_FLAG_RESIDENT : 0;
    id[2] = alg;
    id[3] = cred_protect;
    memcpy(id + 4, iv, sizeof iv);
    omk_aes256_cbc_encrypt(enc, iv, seed, 32, cipher);
    memcpy(id + 20, cipher, 32);

    omk_hmac_sha256_init(&hm, opad, mac, 32);
    omk_hmac_sha256_update(&hm, id, 52);
    omk_hmac_sha256_update(&hm, rp_hash, 32);
    omk_hmac_sha256_final(&hm, opad, macbuf);
    memcpy(id + 52, macbuf, ID_MAC_LEN);
    memcpy(out, id, sizeof id);
    rc = ID_LEN;

done:
    omk_memzero(enc, sizeof enc);
    omk_memzero(mac, sizeof mac);
    omk_memzero(macbuf, sizeof macbuf);
    omk_memzero(iv, sizeof iv);
    omk_memzero(cipher, sizeof cipher);
    omk_memzero(id, sizeof id);
    omk_memzero(opad, sizeof opad);
    omk_memzero(&hm, sizeof hm);
    return rc;
}

bool omk_store_open_credential(const omk_store *s, const uint8_t rp_hash[32],
                               const uint8_t *id, size_t id_len, uint8_t seed[32],
                               uint8_t *alg, uint8_t *cred_protect,
                               bool *resident) {
    bool ok = false;
    uint8_t enc[32] = {0};
    uint8_t mac[32] = {0};
    uint8_t macbuf[32] = {0};
    uint8_t opad[64] = {0};
    omk_sha256_ctx hm;
    memset(&hm, 0, sizeof hm);

    if (id_len != ID_LEN || id[0] != ID_VERSION) {
        goto done;
    }
    derive_keys(s, enc, mac);
    omk_hmac_sha256_init(&hm, opad, mac, 32);
    omk_hmac_sha256_update(&hm, id, 52);
    omk_hmac_sha256_update(&hm, rp_hash, 32);
    omk_hmac_sha256_final(&hm, opad, macbuf);

    ok = omk_ct_equal(macbuf, id + 52, ID_MAC_LEN);
    if (ok) {
        omk_aes256_cbc_decrypt(enc, id + 4, id + 20, 32, seed);
        if (alg != NULL) {
            *alg = id[2];
        }
        if (cred_protect != NULL) {
            *cred_protect = id[3];
        }
        if (resident != NULL) {
            *resident = (id[1] & ID_FLAG_RESIDENT) != 0;
        }
    }

done:
    omk_memzero(enc, sizeof enc);
    omk_memzero(mac, sizeof mac);
    omk_memzero(macbuf, sizeof macbuf);
    omk_memzero(opad, sizeof opad);
    omk_memzero(&hm, sizeof hm);
    return ok;
}
