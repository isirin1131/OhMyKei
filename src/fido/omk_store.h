/*
 * Persistent authenticator state: master keys, PIN, signature counter and
 * resident (discoverable) credentials.
 *
 * Flash layout inside the reserved 1 MiB region (offsets relative to
 * OMK_FLASH_REGION_OFF, every sector is OMK_FLASH_SECTOR_SIZE = 4 KiB):
 *
 *   0x00000  meta log: 8 sectors, append-only 256-byte snapshot records
 *   0x08000  credential bank A: 124 sectors, 1 KiB append-only slots
 *   0x84000  credential bank B: 124 sectors, 1 KiB append-only slots
 *
 * The meta log is an append-only sequence of complete state snapshots.  Each
 * record carries a monotonically increasing 64-bit sequence number and a CRC.
 * Records are appended inside the current sector; when a sector is full the
 * next sector is erased and becomes current.  A torn meta write is detected by
 * CRC and the previous snapshot remains authoritative; however, if programming
 * completed before a read-back fault or cut, the new record may already carry
 * a valid CRC and become authoritative upon reboot.  A PIN
 * retry decrement is committed by one of these records *before* the supplied
 * PIN hash is compared with the stored one; the record also carries the
 * candidate hash and PIN epoch so a power cut between persistence and
 * comparison can be resolved on the next boot.
 *
 * Credentials live in one of two append-only log banks.  Records are tagged
 * with the current log epoch and are ignored when the epoch in the record
 * does not match the active meta snapshot.  When the active bank fills, the
 * inactive bank is erased, every live credential is copied into it, the copy
 * is read back and verified, and only then does a meta record atomically flip
 * the active bank and bump the log epoch.  The previous bank is left intact
 * and ignored until the next compaction, so a cut at any point leaves either
 * the old or the new bank authoritative.  Reset uses the same epoch trick: it
 * erases the inactive bank, installs fresh keys/PIN state and a new
 * reset/log epoch in one verified meta record.  Old records can therefore
 * never be resurrected by a failed erase or a power cut.
 *
 * Linearization and failure semantics: a state change is committed in RAM
 * only after its meta record (or, for credential changes, its log record) has
 * been programmed and read back byte-for-byte.  PIN retry decrement, PIN
 * success/reject, setPIN, counter lease extension, reset and the compaction
 * bank flip all commit to RAM at a verified meta record.  A credential
 * append/update/delete commits to RAM only after its verified log record.
 * On failure (e.g. flash write error, read-back verification mismatch, or
 * power cut), in-RAM state remains uncommitted (rolls back in RAM).
 * However, the Flash outcome is indeterminate: if flash programming completed
 * but read-back verification failed or was cut, the record may already be
 * durable on Flash with a valid CRC/sequence/epoch and will take effect on
 * the next boot.  Callers must not assume a failed call guarantees that the
 * change never took effect on Flash.
 *
 * There is no heap and no variable-length array in this implementation.
 */
#ifndef OMK_FIDO_STORE_H
#define OMK_FIDO_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "omk_port.h"

#define OMK_MAX_CREDENTIALS 64
#define OMK_CRED_ID_MAX 96
#define OMK_RP_ID_MAX 255
#define OMK_USER_ID_MAX 64
#define OMK_USER_NAME_MAX 64

/* Storage layout, relative to OMK_FLASH_REGION_OFF.  Exposed so the host
 * regression tests can inject per-offset flash faults without duplicating
 * the layout. */
#define OMK_STORE_META_OFFSET 0x00000u
#define OMK_STORE_META_SECTORS 8u
#define OMK_STORE_META_RECORD_SIZE 256u
#define OMK_STORE_BANK_A_OFFSET 0x08000u
#define OMK_STORE_BANK_B_OFFSET 0x84000u
#define OMK_STORE_BANK_SIZE 0x7C000u
#define OMK_STORE_LOG_SLOT_SIZE 1024u

/* Public storage error classes.  Other negative values denote invalid input,
 * missing records or persistence failures; only a genuinely new credential
 * at the live-credential limit returns OMK_STORE_ERR_FULL. */
#define OMK_STORE_ERR_FULL (-2)
#define OMK_STORE_ERR_CANCELLED (-3)

typedef struct {
    uint8_t id[OMK_CRED_ID_MAX];
    uint8_t id_len;
    uint8_t alg;          /* 1 = ES256, 2 = EdDSA */
    uint8_t cred_protect; /* 0..3 */
    uint32_t seq;         /* creation order, strictly increasing */
    uint8_t rp_id_hash[32];
    uint8_t rp_id[OMK_RP_ID_MAX];
    uint16_t rp_id_len;
    uint8_t user_id[OMK_USER_ID_MAX];
    uint8_t user_id_len;
    uint8_t user_name[OMK_USER_NAME_MAX];
    uint8_t user_name_len;
    uint8_t display_name[OMK_USER_NAME_MAX];
    uint8_t display_name_len;
} omk_credential;

typedef struct {
    const omk_port *port;
    bool ready;

    /* Meta log bookkeeping.  meta_seq is the sequence number of the newest
     * verified snapshot.  meta_sector/meta_slot form the append cursor and
     * may advance past a torn slot after a failed write; meta_valid_sector
     * still locates the authoritative snapshot so recovery never erases its
     * only surviving sector merely to skip a run of damaged append slots. */
    bool meta_valid;
    uint64_t meta_seq;
    uint32_t meta_sector;
    uint8_t meta_slot;
    uint32_t meta_valid_sector;

    /* Values mirrored from the newest meta snapshot. */
    uint32_t reset_epoch;
    uint32_t log_epoch;
    uint8_t active_bank; /* 0 = bank A, 1 = bank B */
    uint32_t pin_epoch;
    uint32_t lease;
    uint32_t counter;    /* RAM only; boot starts at lease */
    uint32_t next_seq;

    uint8_t master[32];
    uint8_t aaguid[16];
    uint8_t pin_hash[16];
    bool pin_set;
    uint8_t pin_retries;

    /* Unresolved PIN attempt persisted before the comparison. */
    bool attempt_valid;
    uint8_t attempt_candidate[16];

    /* Next append offset inside the active credential bank. */
    uint32_t write_off;

    omk_credential creds[OMK_MAX_CREDENTIALS];
    uint8_t cred_count;
} omk_store;

/* Load state, format the store on first use.  A flash read error or a
 * CRC-valid current-format record with impossible fields fails initialisation
 * before any write or erase is attempted.  When no valid current-format
 * snapshot exists, recognized legacy/foreign non-blank meta data also fails
 * initialisation before any write or erase, so old credentials are never
 * silently factory-formatted.  A genuinely erased meta region, or one
 * containing only torn current-format records, is formatted with a fresh
 * identity.  Otherwise the newest valid snapshot is recovered even when
 * unknown or torn non-blank records follow it.  Returns 0 on success. */
int omk_store_init(omk_store *store, const omk_port *port);

/* Wipe master key, PIN and all resident credentials, then reinitialise.
 * Fresh random identity bytes are obtained before the inactive bank is
 * touched; an RNG failure leaves the old state and flash intact.  The reset is
 * committed by one verified meta record carrying a fresh reset and log epoch,
 * so old records stay inert even if the old bank cannot be erased
 * immediately. */
int omk_store_reset(omk_store *store);

/* Signature counter: strictly increasing, never reused after power loss.
 * Returns 0 when no further value can be allocated (fail closed). */
uint32_t omk_store_next_counter(omk_store *store);

/* PIN state.  pin_attempt() persists the decremented retry count together
 * with the candidate hash *before* the caller compares it.  pin_success()
 * persists the restored count (8), pin_reject() persists the fact that the
 * candidate was wrong while keeping the decremented count.  All three return
 * non-zero on a flash failure; callers must fail closed and must not issue a
 * token until the persistence call succeeded. */
int omk_store_pin_attempt(omk_store *store, const uint8_t candidate[16]);
int omk_store_pin_success(omk_store *store);
int omk_store_pin_reject(omk_store *store);
int omk_store_set_pin(omk_store *store, const uint8_t hash[16]);

/* Resident credentials. */
int omk_store_put_credential(omk_store *store, const omk_credential *cred);
int omk_store_delete_credential(omk_store *store, const uint8_t *id,
                                size_t id_len);
int omk_store_update_user(omk_store *store, const uint8_t *id, size_t id_len,
                          const uint8_t *user_id, size_t user_id_len,
                          const uint8_t *name, size_t name_len,
                          const uint8_t *display, size_t display_len);
const omk_credential *omk_store_find_id(const omk_store *store,
                                        const uint8_t *id, size_t id_len);
const omk_credential *omk_store_find_rp_user(const omk_store *store,
                                             const uint8_t rp_hash[32],
                                             const uint8_t *user_id,
                                             size_t user_id_len);

/* Credential ID sealing: seed (private key material) is encrypted and bound
 * to the RP ID hash.  Returns 0 on a random-source failure without writing a
 * usable ID to out; the caller must not store a credential in that case. */
size_t omk_store_seal_credential(const omk_store *store,
                                 const uint8_t rp_hash[32],
                                 const uint8_t seed[32], uint8_t alg,
                                 uint8_t cred_protect, bool resident,
                                 uint8_t out[OMK_CRED_ID_MAX]);
bool omk_store_open_credential(const omk_store *store,
                               const uint8_t rp_hash[32], const uint8_t *id,
                               size_t id_len, uint8_t seed[32], uint8_t *alg,
                               uint8_t *cred_protect, bool *resident);

#endif /* OMK_FIDO_STORE_H */
