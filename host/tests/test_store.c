/*
 * Host regression tests for the persistent store.
 *
 * The flash model is deliberately NOR-faithful: programming can only clear
 * bits (AND), writes/erases are sector/page aligned, and a test can cut power
 * at any individual flash operation.  A cut programs only a prefix of the
 * in-flight write or erases only a prefix of the in-flight sector, then the
 * "device reboots" from the resulting bytes.  Per-offset read/write/erase
 * faults are supported as well.
 *
 * These tests do not model an attacker with BOOTSEL/picotool access to the
 * flash chip.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto/omk_crypto.h"
#include "fido/omk_store.h"

static int g_failures;

static void check(bool cond, const char *what) {
    if (!cond) {
        printf("FAIL: %s\n", what);
        g_failures++;
    }
}

/* ---------------------------------------------------------------------- */
/* NOR flash model                                                         */
/* ---------------------------------------------------------------------- */

typedef struct sim sim;
struct sim {
    uint8_t mem[OMK_FLASH_REGION_SIZE];
    uint64_t rng;

    long ops;      /* total read/write/erase operations seen */
    long cut_op;   /* 1-based operation index to cut at, 0 = disabled */
    bool dead;     /* power was cut (or the flash became unusable) */

    long fail_read_off;  /* -1 disabled, otherwise absolute byte offset */
    long fail_write_off;
    long fail_erase_off;
    long write_drop_off; /* silently skip programming this byte */
    bool fail_read_all;
    bool fail_write_all;
    bool fail_erase_all;
    bool fail_random;
    long random_fail_at;   /* 1-based random call to fail, 0 = disabled */
    long random_calls;
    long write_ok_budget; /* -1 unlimited, otherwise successful writes left */
    long operation_poll_calls;
    long operation_cancel_at; /* 1-based callback to reject, 0 = disabled */

    long reads;
    long writes;
    long erases;

    omk_port port;
};

static uint64_t sim_now(void *ctx) {
    (void)ctx;
    return 0;
}

static bool sim_random(void *ctx, void *out, size_t len) {
    sim *s = (sim *)ctx;
    uint8_t *p = (uint8_t *)out;
    s->random_calls++;
    const bool fail = s->fail_random ||
                      (s->random_fail_at > 0 &&
                       s->random_calls == s->random_fail_at);
    const size_t fill = fail ? len / 2u : len;
    for (size_t i = 0; i < fill; i++) {
        s->rng ^= s->rng << 13;
        s->rng ^= s->rng >> 7;
        s->rng ^= s->rng << 17;
        p[i] = (uint8_t)(s->rng >> 24);
    }
    if (fail) {
        return false; /* partial output must be discarded by the caller */
    }
    return true;
}

static bool sim_bounds(uint32_t off, size_t len) {
    return off >= OMK_FLASH_REGION_OFF &&
           (uint64_t)off + len <=
               (uint64_t)OMK_FLASH_REGION_OFF + OMK_FLASH_REGION_SIZE;
}

/* Returns true exactly once when this operation is the cut point. */
static bool sim_should_cut(sim *s) {
    if (s->dead) {
        return true;
    }
    s->ops++;
    if (s->cut_op > 0 && s->ops == s->cut_op) {
        s->dead = true;
        return true;
    }
    return false;
}

static bool sim_hit(uint32_t off, size_t len, long target) {
    return target >= 0 && (long)off <= target &&
           target < (long)off + (long)len;
}

static int sim_read(void *ctx, uint32_t off, void *dst, size_t len) {
    sim *s = (sim *)ctx;
    if (sim_should_cut(s)) {
        return -1;
    }
    if (!sim_bounds(off, len) || s->fail_read_all ||
        sim_hit(off, len, s->fail_read_off)) {
        return -1;
    }
    memcpy(dst, s->mem + (off - OMK_FLASH_REGION_OFF), len);
    s->reads++;
    return 0;
}

/* Vary the torn prefix (1/4, 1/2 or 3/4) so cuts are not all identical. */
static size_t sim_torn_prefix(size_t total, long op) {
    const size_t quarters = 1u + (size_t)(op % 3);
    size_t prefix = (total / 4u) * quarters;
    if (prefix >= total) {
        prefix = total - 1u;
    }
    return prefix;
}

static int sim_write(void *ctx, uint32_t off, const void *src, size_t len) {
    sim *s = (sim *)ctx;
    if (sim_should_cut(s)) {
        /* Torn program: only a prefix reaches the cell array, and NOR
         * programming can only clear bits. */
        if (sim_bounds(off, len)) {
            const size_t prefix = sim_torn_prefix(len, s->ops);
            uint8_t *const mem = s->mem + (off - OMK_FLASH_REGION_OFF);
            const uint8_t *const p = (const uint8_t *)src;
            for (size_t i = 0; i < prefix; i++) {
                mem[i] &= p[i];
            }
        }
        return -1;
    }
    if (!sim_bounds(off, len) || off % 256u != 0 || len % 256u != 0 ||
        s->fail_write_all ||
        (s->fail_write_off >= 0 && (long)off == s->fail_write_off)) {
        return -1;
    }
    if (s->write_ok_budget == 0) {
        return -1;
    }
    if (s->write_ok_budget > 0) {
        s->write_ok_budget--;
    }
    uint8_t *const mem = s->mem + (off - OMK_FLASH_REGION_OFF);
    const uint8_t *const p = (const uint8_t *)src;
    for (size_t i = 0; i < len; i++) {
        if ((long)(off + i) == s->write_drop_off) {
            continue; /* stuck bit: program reports success but did not stick */
        }
        mem[i] &= p[i];
    }
    s->writes++;
    return 0;
}

static int sim_erase(void *ctx, uint32_t off) {
    sim *s = (sim *)ctx;
    if (sim_should_cut(s)) {
        /* Torn erase: only part of the sector is returned to 0xFF. */
        if (sim_bounds(off, OMK_FLASH_SECTOR_SIZE)) {
            const size_t prefix =
                sim_torn_prefix(OMK_FLASH_SECTOR_SIZE, s->ops);
            memset(s->mem + (off - OMK_FLASH_REGION_OFF), 0xFF, prefix);
        }
        return -1;
    }
    if (!sim_bounds(off, OMK_FLASH_SECTOR_SIZE) ||
        off % OMK_FLASH_SECTOR_SIZE != 0 || s->fail_erase_all ||
        (s->fail_erase_off >= 0 && (long)off == s->fail_erase_off)) {
        return -1;
    }
    memset(s->mem + (off - OMK_FLASH_REGION_OFF), 0xFF,
           OMK_FLASH_SECTOR_SIZE);
    s->erases++;
    return 0;
}

static bool sim_up(void *ctx) {
    (void)ctx;
    return false;
}

static bool sim_long_op_poll(void *ctx) {
    sim *s = (sim *)ctx;
    s->operation_poll_calls++;
    return s->operation_cancel_at == 0 ||
           s->operation_poll_calls != s->operation_cancel_at;
}

static void sim_init(sim *s) {
    memset(s, 0, sizeof(*s));
    memset(s->mem, 0xFF, sizeof(s->mem));
    s->rng = 0x9E3779B97F4A7C15ull;
    s->cut_op = 0;
    s->fail_read_off = -1;
    s->fail_write_off = -1;
    s->fail_erase_off = -1;
    s->write_drop_off = -1;
    s->fail_random = false;
    s->random_fail_at = 0;
    s->random_calls = 0;
    s->write_ok_budget = -1;
    s->port.ctx = s;
    s->port.now_ms = sim_now;
    s->port.random_bytes = sim_random;
    s->port.flash_read = sim_read;
    s->port.flash_write = sim_write;
    s->port.flash_erase = sim_erase;
    s->port.up_pressed = sim_up;
    s->port.long_op_poll = sim_long_op_poll;
}

static void sim_copy(sim *dst, const sim *src, bool clear_faults) {
    *dst = *src;
    dst->port.ctx = dst;
    if (clear_faults) {
        dst->ops = 0;
        dst->cut_op = 0;
        dst->dead = false;
        dst->fail_read_off = -1;
        dst->fail_write_off = -1;
        dst->fail_erase_off = -1;
        dst->write_drop_off = -1;
        dst->fail_read_all = false;
        dst->fail_write_all = false;
        dst->fail_erase_all = false;
        dst->fail_random = false;
        dst->random_fail_at = 0;
        dst->random_calls = 0;
        dst->write_ok_budget = -1;
        dst->operation_poll_calls = 0;
        dst->operation_cancel_at = 0;
        dst->reads = 0;
        dst->writes = 0;
        dst->erases = 0;
    }
}

static void store_fresh(sim *s, omk_store *st) {
    sim_init(s);
    check(omk_store_init(st, &s->port) == 0, "fresh store init");
}

static void store_reboot(const sim *from, sim *rb, omk_store *st,
                         const char *what) {
    sim_copy(rb, from, true);
    check(omk_store_init(st, &rb->port) == 0, what);
}

/* ---------------------------------------------------------------------- */
/* Helpers                                                                 */
/* ---------------------------------------------------------------------- */

#define ABS_META(sector, slot)                                              \
    (OMK_FLASH_REGION_OFF + OMK_STORE_META_OFFSET +                         \
     (uint32_t)(sector) * OMK_FLASH_SECTOR_SIZE +                           \
     (uint32_t)(slot) * OMK_STORE_META_RECORD_SIZE)
#define ABS_BANK(bank)                                                      \
    (OMK_FLASH_REGION_OFF +                                                 \
     ((bank) == 0 ? OMK_STORE_BANK_A_OFFSET : OMK_STORE_BANK_B_OFFSET))
#define ABS_SLOT(bank, slot)                                                \
    (ABS_BANK(bank) + (uint32_t)(slot) * OMK_STORE_LOG_SLOT_SIZE)

static void make_cred(omk_credential *c, uint8_t id_tag, const char *rp,
                      const char *user, const char *name) {
    memset(c, 0, sizeof(*c));
    for (uint8_t i = 0; i < 32; i++) {
        c->id[i] = (uint8_t)(id_tag * 37u + i * 11u + 1u);
    }
    c->id_len = 32;
    c->alg = 1;
    c->cred_protect = 1;
    omk_sha256(rp, strlen(rp), c->rp_id_hash);
    c->rp_id_len = (uint16_t)strlen(rp);
    memcpy(c->rp_id, rp, c->rp_id_len);
    c->user_id_len = (uint8_t)strlen(user);
    memcpy(c->user_id, user, c->user_id_len);
    c->user_name_len = (uint8_t)strlen(name);
    memcpy(c->user_name, name, c->user_name_len);
    c->display_name_len = c->user_name_len;
    memcpy(c->display_name, name, c->display_name_len);
}

static bool store_has_id(const omk_store *st, const omk_credential *c) {
    return omk_store_find_id(st, c->id, c->id_len) != NULL;
}

static uint32_t cred_seq(const omk_store *st, const omk_credential *c) {
    const omk_credential *got = omk_store_find_id(st, c->id, c->id_len);
    return got != NULL ? got->seq : 0;
}

static void fill_hash(uint8_t out[16], uint8_t tag) {
    for (uint8_t i = 0; i < 16; i++) {
        out[i] = (uint8_t)(tag * 53u + i * 7u + 3u);
    }
}

static void corrupt_byte(sim *s, uint32_t off) {
    uint8_t *p = &s->mem[off - OMK_FLASH_REGION_OFF];
    if (*p != 0x00u) {
        *p = 0; /* clear every bit: guaranteed change */
    } else {
        /* Find another byte in the same 32-byte header and flip a bit. */
        for (uint32_t i = 1; i < 32; i++) {
            uint8_t *q = &s->mem[off - OMK_FLASH_REGION_OFF + i];
            if (*q != 0x00u) {
                *q &= 0xFEu;
                return;
            }
        }
    }
}

/* Leave a recognizable current-format meta record with a bad CRC.  Used to
 * force the store to erase an older sector without tripping the stricter
 * legacy/foreign-image rejection (a lone zero byte would now be rejected). */
static void write_torn_meta_v2(sim *s, uint32_t off) {
    uint8_t *p = &s->mem[off - OMK_FLASH_REGION_OFF];
    memset(p, 0xFF, OMK_STORE_META_RECORD_SIZE);
    p[0] = 0x4Fu; /* "OMKM" */
    p[1] = 0x4Du;
    p[2] = 0x4Bu;
    p[3] = 0x4Du;
    p[4] = 0x00u; /* version 2 */
    p[5] = 0x02u;
    p[6] = 0x01u; /* snapshot */
}

static void write_meta_prefix(sim *s, uint32_t off, uint32_t magic,
                               uint16_t version, uint8_t kind) {
    uint8_t *p = &s->mem[off - OMK_FLASH_REGION_OFF];
    memset(p, 0xFF, OMK_STORE_META_RECORD_SIZE);
    p[0] = (uint8_t)(magic >> 24);
    p[1] = (uint8_t)(magic >> 16);
    p[2] = (uint8_t)(magic >> 8);
    p[3] = (uint8_t)magic;
    p[4] = (uint8_t)(version >> 8);
    p[5] = (uint8_t)version;
    p[6] = kind;
}

/* Program only the first len bytes of a meta record; the rest stays erased,
 * exactly like a power cut that reaches only a short prefix of an append. */
static void inject_meta_bytes(sim *s, uint32_t off, const void *src,
                              size_t len) {
    uint8_t *p = &s->mem[off - OMK_FLASH_REGION_OFF];
    memset(p, 0xFF, OMK_STORE_META_RECORD_SIZE);
    memcpy(p, src, len);
}

/* Offset of the index-th append slot after the newest snapshot, wrapping
 * through the meta sectors like the store's append cursor. */
static uint32_t meta_append_off(const omk_store *st, uint32_t index) {
    const uint32_t per_sector =
        OMK_FLASH_SECTOR_SIZE / OMK_STORE_META_RECORD_SIZE;
    uint32_t sector = st->meta_sector;
    uint32_t slot = (uint32_t)st->meta_slot + 1u + index;
    while (slot >= per_sector) {
        slot -= per_sector;
        sector = (sector + 1u) % OMK_STORE_META_SECTORS;
    }
    return ABS_META(sector, slot);
}

/* Local copy of the record CRC32 so a test can build a CRC-valid record whose
 * fields are impossible (the store must still fail closed on it). */
static uint32_t test_crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (unsigned b = 0; b < 8; b++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1u)));
        }
    }
    return ~crc;
}

/* Write a copy of a valid snapshot with one byte damaged and the CRC repaired,
 * making it a CRC-valid but semantically impossible meta record. */
static void inject_impossible_meta(sim *s, uint32_t off,
                                   const uint8_t good[OMK_STORE_META_RECORD_SIZE],
                                   size_t field_off, uint8_t value) {
    uint8_t rec[OMK_STORE_META_RECORD_SIZE];
    memcpy(rec, good, sizeof rec);
    rec[field_off] = value;
    const uint32_t crc = test_crc32(rec, 120);
    rec[120] = (uint8_t)(crc >> 24);
    rec[121] = (uint8_t)(crc >> 16);
    rec[122] = (uint8_t)(crc >> 8);
    rec[123] = (uint8_t)crc;
    inject_meta_bytes(s, off, rec, sizeof rec);
}

/* ---------------------------------------------------------------------- */
/* PIN retry journal cuts                                                  */
/* ---------------------------------------------------------------------- */

typedef struct {
    sim *base;
    omk_store *base_store;
    uint8_t candidate[16];
    bool correct;
    uint8_t initial_retries;
    long attempt_end;
} pin_ctx;

static void pin_run(pin_ctx *c, sim *flash, omk_store *st, int *attempt_rc,
                    int *resolve_rc) {
    (void)flash;
    *attempt_rc = omk_store_pin_attempt(st, c->candidate);
    *resolve_rc = -1;
    if (*attempt_rc == 0) {
        *resolve_rc = c->correct ? omk_store_pin_success(st)
                                 : omk_store_pin_reject(st);
    }
}

static void pin_cut_loop(pin_ctx *c, const char *what) {
    /* Measure the operation range without a cut. */
    sim run;
    sim_copy(&run, c->base, true);
    omk_store rs = *c->base_store;
    rs.port = &run.port;
    int ar = 0;
    int rr = -1;
    c->attempt_end = 0;
    pin_run(c, &run, &rs, &ar, &rr);
    c->attempt_end = run.ops;
    if (ar == 0 && rr == 0) {
        check(rs.pin_retries == (c->correct ? 8 : c->initial_retries - 1),
              "uncut PIN operation persists the expected retry count");
        check(!rs.attempt_valid, "uncut PIN operation resolves the attempt");
    }
    const long total = run.ops;
    check(total > 0, "PIN operation performs flash work");

    for (long k = 1; k <= total; k++) {
        sim cs;
        sim_copy(&cs, c->base, true);
        omk_store st = *c->base_store;
        st.port = &cs.port;
        cs.cut_op = k;
        pin_run(c, &cs, &st, &ar, &rr);

        if (ar != 0) {
            check(st.pin_retries == c->initial_retries,
                  "failed PIN attempt leaves RAM retry count unchanged");
        }

        sim rb;
        omk_store rst;
        store_reboot(&cs, &rb, &rst, "PIN reboot init");
        const uint8_t got = rst.pin_retries;
        if (c->correct) {
            if (k > c->attempt_end) {
                check(got == 8, what);
            } else {
                check(got == c->initial_retries || got == 8, what);
            }
            check(got != 0, "unresolved correct attempt never bricks");
        } else {
            if (k > c->attempt_end) {
                check(got == c->initial_retries - 1, what);
            } else {
                check(got == c->initial_retries ||
                          got == c->initial_retries - 1,
                      what);
            }
            check(got <= c->initial_retries,
                  "committed wrong attempt never rolls back");
        }
        check(!rst.attempt_valid, "boot resolves the attempt marker");
        check(rst.pin_set, "PIN remains set across the cut");
    }
}

/* The helper above needs storage owned by the caller; keep the tests simple
 * by using file-scope stores. */
static sim g_base_sim;
static omk_store g_base_store;

static void pin_setup(int wrong_attempts, uint8_t correct[16],
                      uint8_t wrong[16]) {
    fill_hash(correct, 0x42);
    memcpy(wrong, correct, 16);
    wrong[0] ^= 0xFFu;
    store_fresh(&g_base_sim, &g_base_store);
    check(omk_store_set_pin(&g_base_store, correct) == 0, "set PIN");
    for (int i = 0; i < wrong_attempts; i++) {
        check(omk_store_pin_attempt(&g_base_store, wrong) == 0,
              "persist wrong attempt");
        check(omk_store_pin_reject(&g_base_store) == 0, "resolve wrong attempt");
    }
    check(g_base_store.pin_retries == 8 - wrong_attempts,
          "setup retry count");
}

static void run_pin_cuts(bool correct, int wrong_attempts, const char *label) {
    uint8_t good[16];
    uint8_t bad[16];
    pin_setup(wrong_attempts, good, bad);
    pin_ctx c;
    memset(&c, 0, sizeof c);
    c.base = &g_base_sim;
    c.base_store = &g_base_store;
    c.correct = correct;
    c.initial_retries = (uint8_t)(8 - wrong_attempts);
    memcpy(c.candidate, correct ? good : bad, 16);
    pin_cut_loop(&c, label);
}

static void test_pin_wrong_cuts(void) {
    run_pin_cuts(false, 0, "wrong PIN keeps the committed decrement");
    run_pin_cuts(false, 7, "wrong PIN on last retry stays blocked");
}

static void test_pin_correct_cuts(void) {
    run_pin_cuts(true, 0, "correct PIN restores retries after every cut");
    run_pin_cuts(true, 7, "correct PIN on last retry never bricks");
}

static void test_pin_boot_resolution_cuts(void) {
    for (int correct = 0; correct <= 1; correct++) {
        uint8_t good[16];
        uint8_t bad[16];
        fill_hash(good, 0x77);
        memcpy(bad, good, 16);
        bad[0] ^= 0xFFu;

        /* Produce a flash state with a persisted but unresolved attempt on the
         * last available retry. */
        sim base;
        omk_store base_store;
        store_fresh(&base, &base_store);
        check(omk_store_set_pin(&base_store, good) == 0, "boot-res set PIN");
        for (int i = 0; i < 7; i++) {
            check(omk_store_pin_attempt(&base_store, bad) == 0, "boot-res dec");
            check(omk_store_pin_reject(&base_store) == 0, "boot-res rej");
        }
        check(omk_store_pin_attempt(&base_store,
                                    correct != 0 ? good : bad) == 0,
              "persist unresolved attempt");
        check(base_store.pin_retries == 0,
              "unresolved last-retry attempt persists zero retries");

        /* Count boot-resolution operations (clean run). */
        sim run;
        omk_store rs;
        sim_copy(&run, &base, true);
        check(omk_store_init(&rs, &run.port) == 0, "resolution init");
        const long total = run.ops;
        check(total > 0, "boot resolution writes something");

        for (long k = 1; k <= total; k++) {
            sim cs;
            omk_store st;
            sim_copy(&cs, &base, true);
            cs.cut_op = k;
            (void)omk_store_init(&st, &cs.port);

            sim rb;
            omk_store rst;
            store_reboot(&cs, &rb, &rst, "resolution reboot");
            if (correct != 0) {
                check(rst.pin_retries == 8,
                      "resolution cut: correct attempt restores 8");
                check(rst.pin_retries != 0,
                      "resolution cut: last-retry correct never bricks");
            } else {
                check(rst.pin_retries == 0,
                      "resolution cut: wrong last-retry stays blocked");
            }
            check(!rst.attempt_valid, "resolution cut: marker cleared");

            /* The clean reboot persisted the resolution; a second reboot must
             * not resurrect the unresolved state. */
            sim rb2;
            omk_store rst2;
            store_reboot(&rb, &rb2, &rst2, "resolution second reboot");
            check(rst2.pin_retries == (correct != 0 ? 8 : 0),
                  "resolution survives a second reboot");
            check(!rst2.attempt_valid,
                  "resolution is not re-applied after a second reboot");
        }
    }
}

/* ---------------------------------------------------------------------- */
/* Reset cuts                                                              */
/* ---------------------------------------------------------------------- */

static void reset_setup(sim *s, omk_store *st, omk_credential *a,
                        omk_credential *b, uint8_t master[32],
                        uint8_t pin_hash[16]) {
    uint8_t pin[16];
    fill_hash(pin, 0x24);
    store_fresh(s, st);
    check(omk_store_set_pin(st, pin) == 0, "reset setup PIN");
    make_cred(a, 0xA1, "reset.example", "user-a", "Alice");
    make_cred(b, 0xB2, "reset.example", "user-b", "Bob");
    check(omk_store_put_credential(st, a) == 0, "reset setup cred A");
    check(omk_store_put_credential(st, b) == 0, "reset setup cred B");
    memcpy(master, st->master, 32);
    memcpy(pin_hash, st->pin_hash, 16);
}

static bool reset_old_state_ok(const omk_store *st, const uint8_t master[32],
                               const uint8_t pin_hash[16],
                               const omk_credential *a,
                               const omk_credential *b) {
    return memcmp(st->master, master, 32) == 0 && st->pin_set &&
           memcmp(st->pin_hash, pin_hash, 16) == 0 && st->cred_count == 2 &&
           store_has_id(st, a) && store_has_id(st, b);
}

static bool reset_new_state_ok(const omk_store *st, const uint8_t master[32],
                               const omk_credential *a,
                               const omk_credential *b) {
    return memcmp(st->master, master, 32) != 0 && !st->pin_set &&
           st->cred_count == 0 && !store_has_id(st, a) &&
           !store_has_id(st, b);
}

static void test_reset_cuts(void) {
    sim base;
    omk_store base_store;
    omk_credential a;
    omk_credential b;
    uint8_t master[32];
    uint8_t pin_hash[16];
    reset_setup(&base, &base_store, &a, &b, master, pin_hash);

    sim run;
    sim_copy(&run, &base, true);
    omk_store rs = base_store;
    rs.port = &run.port;
    check(omk_store_reset(&rs) == 0, "uncut reset");
    check(reset_new_state_ok(&rs, master, &a, &b), "uncut reset state");
    const long total = run.ops;
    check(total > 0, "reset performs flash work");

    for (long k = 1; k <= total; k++) {
        sim cs;
        omk_store st = base_store;
        sim_copy(&cs, &base, true);
        st.port = &cs.port;
        cs.cut_op = k;
        const int rc = omk_store_reset(&st);

        /* RAM must never be half-reset after a failed reset. */
        if (rc != 0) {
            check(reset_old_state_ok(&st, master, pin_hash, &a, &b),
                  "failed reset leaves RAM in the old state");
        }

        sim rb;
        omk_store rst;
        store_reboot(&cs, &rb, &rst, "reset reboot");
        const bool old_ok = reset_old_state_ok(&rst, master, pin_hash, &a, &b);
        const bool new_ok = reset_new_state_ok(&rst, master, &a, &b);
        check(old_ok || new_ok, "reset cut leaves old or new state, no hybrid");
        if (old_ok) {
            check(store_has_id(&rst, &a) && store_has_id(&rst, &b),
                  "old reset state keeps both credentials");
        }
        if (new_ok) {
            check(memcmp(rst.pin_hash, pin_hash, 16) != 0,
                  "new reset state has a fresh PIN hash");
            check(rst.reset_epoch > 0 && rst.log_epoch > 0,
                  "new reset state carries fresh epochs");
        }

        /* A second reboot must not resurrect the old epoch either. */
        sim rb2;
        omk_store rst2;
        store_reboot(&rb, &rb2, &rst2, "second reset reboot");
        if (new_ok) {
            check(reset_new_state_ok(&rst2, master, &a, &b),
                  "reset state is stable across reboot");
        }
    }
}

static void test_reset_failures(void) {
    omk_credential a;
    omk_credential b;
    uint8_t master[32];
    uint8_t pin_hash[16];

    /* Erase failure in the inactive bank: old state must survive. */
    sim base;
    omk_store st;
    reset_setup(&base, &st, &a, &b, master, pin_hash);

    sim canceled;
    sim_copy(&canceled, &base, true);
    omk_store cst = st;
    cst.port = &canceled.port;
    canceled.operation_cancel_at = 4;
    check(omk_store_reset(&cst) == OMK_STORE_ERR_CANCELLED,
          "reset reports cooperative cancellation");
    check(reset_old_state_ok(&cst, master, pin_hash, &a, &b),
          "reset cancellation preserves old RAM state");
    canceled.operation_cancel_at = 0;
    check(omk_store_reset(&cst) == 0,
          "reset same-boot retry succeeds after cancellation");
    check(reset_new_state_ok(&cst, master, &a, &b),
          "reset retry commits the complete new state");

    sim bad;
    sim_copy(&bad, &base, true);
    omk_store bst = st;
    bst.port = &bad.port;
    bad.fail_erase_off = (long)ABS_BANK(1);
    check(omk_store_reset(&bst) == -1, "reset reports erase failure");
    check(reset_old_state_ok(&bst, master, pin_hash, &a, &b),
          "reset erase failure leaves RAM old state");
    sim rb;
    omk_store rst;
    store_reboot(&bad, &rb, &rst, "reset erase failure reboot");
    check(reset_old_state_ok(&rst, master, pin_hash, &a, &b),
          "reset erase failure leaves flash old state");

    /* Write failure of the commit meta record. */
    sim_copy(&bad, &base, true);
    bst = st;
    bst.port = &bad.port;
    bad.fail_write_all = true;
    check(omk_store_reset(&bst) == -1, "reset reports meta write failure");
    check(reset_old_state_ok(&bst, master, pin_hash, &a, &b),
          "reset write failure leaves RAM old state");
    store_reboot(&bad, &rb, &rst, "reset write failure reboot");
    check(reset_old_state_ok(&rst, master, pin_hash, &a, &b),
          "reset write failure leaves flash old state");

    /* Read failure while verifying the freshly erased inactive bank. */
    sim_copy(&bad, &base, true);
    bst = st;
    bst.port = &bad.port;
    bad.fail_read_off = (long)ABS_BANK(1);
    check(omk_store_reset(&bst) == -1, "reset reports verify read failure");
    check(reset_old_state_ok(&bst, master, pin_hash, &a, &b),
          "reset read failure leaves RAM old state");
    store_reboot(&bad, &rb, &rst, "reset read failure reboot");
    check(reset_old_state_ok(&rst, master, pin_hash, &a, &b),
          "reset read failure leaves flash old state");
}

/* ---------------------------------------------------------------------- */
/* Credential append / delete / update cuts                                */
/* ---------------------------------------------------------------------- */

static void test_append_cuts(void) {
    sim base;
    omk_store base_store;
    store_fresh(&base, &base_store);
    omk_credential a;
    omk_credential b;
    omk_credential c;
    make_cred(&a, 0x11, "append.example", "user-a", "Alice");
    make_cred(&b, 0x22, "append.example", "user-b", "Bob");
    make_cred(&c, 0x33, "append.example", "user-c", "Carol");
    check(omk_store_put_credential(&base_store, &a) == 0, "append setup A");
    check(omk_store_put_credential(&base_store, &b) == 0, "append setup B");
    const uint32_t seq_a = cred_seq(&base_store, &a);
    const uint32_t seq_b = cred_seq(&base_store, &b);

    sim run;
    sim_copy(&run, &base, true);
    omk_store rs = base_store;
    rs.port = &run.port;
    check(omk_store_put_credential(&rs, &c) == 0, "uncut append C");
    check(store_has_id(&rs, &c), "uncut append appears");
    const long total = run.ops;

    for (long k = 1; k <= total; k++) {
        sim cs;
        omk_store st = base_store;
        sim_copy(&cs, &base, true);
        st.port = &cs.port;
        cs.cut_op = k;
        const int rc = omk_store_put_credential(&st, &c);
        if (rc != 0) {
            check(st.cred_count == 2 && !store_has_id(&st, &c),
                  "append failure rolls RAM back");
        }
        sim rb;
        omk_store rst;
        store_reboot(&cs, &rb, &rst, "append reboot");
        check(store_has_id(&rst, &a) && store_has_id(&rst, &b),
              "append cut keeps existing credentials");
        check(cred_seq(&rst, &a) == seq_a && cred_seq(&rst, &b) == seq_b,
              "append cut keeps credential ordering fields");
        /* C may be fully durable even if the read-back was cut; it must
         * never appear corrupt or duplicated. */
        if (store_has_id(&rst, &c)) {
            const omk_credential *got_c =
                omk_store_find_id(&rst, c.id, c.id_len);
            check(got_c != NULL && cred_seq(&rst, &c) != 0,
                  "durable appended C has a sequence");
            check(got_c != NULL && got_c->user_name_len == c.user_name_len &&
                      memcmp(got_c->user_name, c.user_name,
                             c.user_name_len) == 0,
                  "durable appended C has intact fields");
        }
        check(rst.cred_count == 2 || rst.cred_count == 3,
              "append cut leaves two or three credentials");
    }
}

static void test_delete_cuts(void) {
    sim base;
    omk_store base_store;
    store_fresh(&base, &base_store);
    omk_credential a;
    omk_credential b;
    omk_credential c;
    make_cred(&a, 0x41, "delete.example", "user-a", "Alice");
    make_cred(&b, 0x42, "delete.example", "user-b", "Bob");
    make_cred(&c, 0x43, "delete.example", "user-c", "Carol");
    check(omk_store_put_credential(&base_store, &a) == 0, "delete setup A");
    check(omk_store_put_credential(&base_store, &b) == 0, "delete setup B");
    check(omk_store_put_credential(&base_store, &c) == 0, "delete setup C");
    /* Acknowledged deletion before the snapshot: it must never resurrect. */
    check(omk_store_delete_credential(&base_store, a.id, a.id_len) == 0,
          "delete setup removes A");
    check(!store_has_id(&base_store, &a), "A gone before delete cuts");

    sim run;
    sim_copy(&run, &base, true);
    omk_store rs = base_store;
    rs.port = &run.port;
    check(omk_store_delete_credential(&rs, b.id, b.id_len) == 0,
          "uncut delete B");
    check(!store_has_id(&rs, &b), "uncut delete removes B");
    const long total = run.ops;

    for (long k = 1; k <= total; k++) {
        sim cs;
        omk_store st = base_store;
        sim_copy(&cs, &base, true);
        st.port = &cs.port;
        cs.cut_op = k;
        const int rc = omk_store_delete_credential(&st, b.id, b.id_len);
        if (rc != 0) {
            check(store_has_id(&st, &b),
                  "delete failure keeps the credential in RAM");
        }
        sim rb;
        omk_store rst;
        store_reboot(&cs, &rb, &rst, "delete reboot");
        check(!store_has_id(&rst, &a),
              "acknowledged deletion never resurrects");
        check(store_has_id(&rst, &c), "unrelated credential survives delete cut");
        /* B may still exist if the delete did not commit; that is not a
         * resurrection of an acknowledged deletion.  If it is present it must
         * still be the original record. */
        const omk_credential *got_b =
            omk_store_find_id(&rst, b.id, b.id_len);
        if (got_b != NULL) {
            check(got_b->id_len == b.id_len &&
                      memcmp(got_b->id, b.id, b.id_len) == 0 &&
                      got_b->user_name_len == b.user_name_len &&
                      memcmp(got_b->user_name, b.user_name,
                             b.user_name_len) == 0,
                  "uncommitted delete leaves the original record intact");
        }
    }
}

static void test_update_cuts(void) {
    sim base;
    omk_store base_store;
    store_fresh(&base, &base_store);
    omk_credential a;
    omk_credential b;
    make_cred(&a, 0x51, "update.example", "user-a", "Alice");
    make_cred(&b, 0x52, "update.example", "user-b", "Bob");
    check(omk_store_put_credential(&base_store, &a) == 0, "update setup A");
    check(omk_store_put_credential(&base_store, &b) == 0, "update setup B");
    const uint32_t seq_a = cred_seq(&base_store, &a);

    sim run;
    sim_copy(&run, &base, true);
    omk_store rs = base_store;
    rs.port = &run.port;
    check(omk_store_update_user(&rs, a.id, a.id_len, a.user_id, a.user_id_len,
                                (const uint8_t *)"Alicia", 6,
                                (const uint8_t *)"Alicia", 6) == 0,
          "uncut update A");
    const long total = run.ops;

    for (long k = 1; k <= total; k++) {
        sim cs;
        omk_store st = base_store;
        sim_copy(&cs, &base, true);
        st.port = &cs.port;
        cs.cut_op = k;
        const int rc = omk_store_update_user(
            &st, a.id, a.id_len, a.user_id, a.user_id_len,
            (const uint8_t *)"Alicia", 6, (const uint8_t *)"Alicia", 6);
        if (rc != 0) {
            const omk_credential *ram = omk_store_find_id(&st, a.id, a.id_len);
            check(ram != NULL && ram->user_name_len == 5 &&
                      memcmp(ram->user_name, "Alice", 5) == 0,
                  "update failure rolls RAM back");
        }
        sim rb;
        omk_store rst;
        store_reboot(&cs, &rb, &rst, "update reboot");
        const omk_credential *got = omk_store_find_id(&rst, a.id, a.id_len);
        check(got != NULL, "update cut keeps the credential");
        if (got != NULL) {
            const bool old_name = got->user_name_len == 5 &&
                                  memcmp(got->user_name, "Alice", 5) == 0;
            const bool new_name = got->user_name_len == 6 &&
                                  memcmp(got->user_name, "Alicia", 6) == 0;
            check(old_name || new_name,
                  "update cut leaves either old or new user name");
            check(got->seq == seq_a, "update never changes the creation seq");
        }
        check(store_has_id(&rst, &b), "update cut keeps other credentials");
    }
}

/* ---------------------------------------------------------------------- */
/* Torn records and error classification                                   */
/* ---------------------------------------------------------------------- */

static void test_torn_record_independent_scan(void) {
    sim s;
    omk_store st;
    store_fresh(&s, &st);
    omk_credential a;
    omk_credential b;
    omk_credential c;
    make_cred(&a, 0x61, "torn.example", "user-a", "Alice");
    make_cred(&b, 0x62, "torn.example", "user-b", "Bob");
    make_cred(&c, 0x63, "torn.example", "user-c", "Carol");
    check(omk_store_put_credential(&st, &a) == 0, "torn setup A");
    check(omk_store_put_credential(&st, &b) == 0, "torn setup B");

    /* B's slot is now non-blank but invalid: a torn record. */
    const uint32_t bad_off = ABS_SLOT(st.active_bank, 1);
    corrupt_byte(&s, bad_off);

    sim rb;
    omk_store rst;
    store_reboot(&s, &rb, &rst, "torn scan reboot");
    check(rb.erases == 0 && rb.writes == 0,
          "boot never erases or writes the log tail");
    check(store_has_id(&rst, &a), "torn record does not erase earlier record");
    check(!store_has_id(&rst, &b), "torn record is skipped");

    /* Append after the torn slot; boot must skip it but keep the older valid
     * record and the newer valid one. */
    check(omk_store_put_credential(&rst, &c) == 0, "append after torn record");
    sim rb2;
    omk_store rst2;
    store_reboot(&rb, &rb2, &rst2, "torn scan second reboot");
    check(store_has_id(&rst2, &a), "older valid record survives torn middle");
    check(store_has_id(&rst2, &c), "newer valid record survives torn middle");
    check(!store_has_id(&rst2, &b), "torn middle record never becomes live");

    /* Distinguish a read error from a bad CRC: the same slot read failure must
     * fail init before any write. */
    sim bad;
    sim_copy(&bad, &s, true);
    bad.fail_read_off = (long)bad_off;
    omk_store fail_store;
    check(omk_store_init(&fail_store, &bad.port) == -1,
          "read error fails init");
    check(bad.writes == 0 && bad.erases == 0,
          "read error fails init without writes");
}

static void test_read_error_offsets(void) {
    sim base;
    omk_store base_store;
    store_fresh(&base, &base_store);
    omk_credential a;
    make_cred(&a, 0x71, "read.example", "user-a", "Alice");
    check(omk_store_put_credential(&base_store, &a) == 0, "read setup A");

    const uint32_t offsets[] = {
        ABS_META(0, 0),
        ABS_META(0, 1),
        ABS_META(3, 9),
        ABS_SLOT(0, 0),
        ABS_SLOT(0, 1),
        ABS_SLOT(0, 100) + 512,
        ABS_SLOT(0, 495),
    };
    for (size_t i = 0; i < sizeof offsets / sizeof offsets[0]; i++) {
        sim cs;
        sim_copy(&cs, &base, true);
        cs.fail_read_off = (long)offsets[i];
        omk_store st;
        const int rc = omk_store_init(&st, &cs.port);
        check(rc == -1, "per-offset read error fails init");
        check(cs.writes == 0 && cs.erases == 0,
              "per-offset read error performs no write");
    }

    /* A blank device must also fail before formatting if reading the log
     * epoch scan fails. */
    sim blank;
    sim_init(&blank);
    blank.fail_read_off = (long)ABS_SLOT(0, 0);
    omk_store st;
    check(omk_store_init(&st, &blank.port) == -1,
          "format read error fails init");
    check(blank.writes == 0 && blank.erases == 0,
          "format read error performs no erase/write");
}

static void test_write_and_erase_failures(void) {
    sim base;
    omk_store base_store;
    store_fresh(&base, &base_store);
    omk_credential a;
    omk_credential c;
    make_cred(&a, 0x81, "fault.example", "user-a", "Alice");
    make_cred(&c, 0x82, "fault.example", "user-c", "Carol");
    check(omk_store_put_credential(&base_store, &a) == 0, "fault setup A");

    /* Per-offset write failure on the next log slot. */
    sim cs;
    sim_copy(&cs, &base, true);
    omk_store st = base_store;
    st.port = &cs.port;
    cs.fail_write_off = (long)st.write_off;
    check(omk_store_put_credential(&st, &c) == -1,
          "append reports write failure");
    check(st.cred_count == 1 && !store_has_id(&st, &c),
          "append write failure rolls RAM back");
    check(st.write_off == base_store.write_off + OMK_STORE_LOG_SLOT_SIZE,
          "append write failure advances past the suspect slot");
    sim rb;
    omk_store rst;
    store_reboot(&cs, &rb, &rst, "write failure reboot");
    check(store_has_id(&rst, &a) && !store_has_id(&rst, &c),
          "write failure leaves the previous log intact");
    cs.fail_write_off = -1;
    check(omk_store_put_credential(&st, &c) == 0,
          "append same-boot retry succeeds without reboot");
    check(st.cred_count == 2 && store_has_id(&st, &c) &&
              st.write_off == base_store.write_off + 2u * OMK_STORE_LOG_SLOT_SIZE,
          "same-boot retry commits at the next slot");
    sim retry_rb;
    omk_store retry_store;
    store_reboot(&cs, &retry_rb, &retry_store, "same-boot append retry reboot");
    check(store_has_id(&retry_store, &a) && store_has_id(&retry_store, &c),
          "same-boot append retry survives reboot");

    /* A write that reports success but does not program a byte must be caught
     * by read-back verification, and RAM must roll back. */
    sim_copy(&cs, &base, true);
    st = base_store;
    st.port = &cs.port;
    cs.write_drop_off = (long)st.write_off + 100;
    check(omk_store_put_credential(&st, &c) == -1,
          "append detects a non-verifying write");
    check(st.cred_count == 1 && !store_has_id(&st, &c) &&
              st.write_off == base_store.write_off + OMK_STORE_LOG_SLOT_SIZE,
          "non-verifying append rolls back and skips the dirty slot");
    store_reboot(&cs, &rb, &rst, "non-verifying write reboot");
    check(store_has_id(&rst, &a) && !store_has_id(&rst, &c),
          "non-verifying append never commits");
    cs.write_drop_off = -1;
    check(omk_store_put_credential(&st, &c) == 0,
          "dirty append slot does not block same-boot retry");
    check(store_has_id(&st, &c), "same-boot dirty-slot retry updates RAM");
    store_reboot(&cs, &retry_rb, &retry_store, "dirty-slot retry reboot");
    check(store_has_id(&retry_store, &a) && store_has_id(&retry_store, &c),
          "dirty-slot retry persists after the torn record");

    /* Meta write failure during setPIN. */
    sim_copy(&cs, &base, true);
    st = base_store;
    st.port = &cs.port;
    uint32_t next_meta;
    if (st.meta_slot + 1u <
        OMK_FLASH_SECTOR_SIZE / OMK_STORE_META_RECORD_SIZE) {
        next_meta = ABS_META(st.meta_sector, st.meta_slot + 1u);
    } else {
        next_meta = ABS_META((st.meta_sector + 1u) % OMK_STORE_META_SECTORS, 0);
    }
    const uint8_t new_pin[16] = {1, 2, 3, 4, 5, 6, 7, 8,
                                 9, 10, 11, 12, 13, 14, 15, 16};
    cs.fail_write_off = (long)next_meta;
    check(omk_store_set_pin(&st, new_pin) == -1, "setPIN reports write failure");
    check(!st.pin_set, "failed setPIN leaves RAM unchanged");
    store_reboot(&cs, &rb, &rst, "setPIN failure reboot");
    check(!rst.pin_set, "failed setPIN never commits");
    cs.fail_write_off = -1;
    check(omk_store_set_pin(&st, new_pin) == 0,
          "setPIN same-boot retry skips failed slot");
    check(st.pin_set && st.meta_seq == base_store.meta_seq + 1u,
          "same-boot meta retry commits one new sequence");
    store_reboot(&cs, &retry_rb, &retry_store, "same-boot meta retry reboot");
    check(retry_store.pin_set &&
              memcmp(retry_store.pin_hash, new_pin, sizeof new_pin) == 0,
          "same-boot meta retry survives reboot");

    /* A read-back mismatch leaves a genuinely dirty meta slot.  It must not
     * be programmed again by the immediate retry. */
    sim_copy(&cs, &base, true);
    st = base_store;
    st.port = &cs.port;
    cs.write_drop_off = (long)next_meta + 100;
    check(omk_store_set_pin(&st, new_pin) == -1,
          "setPIN detects non-verifying meta write");
    cs.write_drop_off = -1;
    check(omk_store_set_pin(&st, new_pin) == 0,
          "dirty meta slot does not block same-boot retry");
    store_reboot(&cs, &retry_rb, &retry_store, "dirty meta retry reboot");
    check(retry_store.pin_set &&
              memcmp(retry_store.pin_hash, new_pin, sizeof new_pin) == 0,
          "dirty meta retry persists after the torn record");

    /* Erase failure while preparing a new meta sector.  Fill the current
     * sector first, then inject an erase fault on the next sector. */
    sim_copy(&cs, &base, true);
    st = base_store;
    st.port = &cs.port;
    uint8_t rolling[16];
    fill_hash(rolling, 0x33);
    int guard = 0;
    while (st.meta_slot + 1u <
               OMK_FLASH_SECTOR_SIZE / OMK_STORE_META_RECORD_SIZE &&
           guard++ < 64) {
        rolling[0]++;
        check(omk_store_set_pin(&st, rolling) == 0, "fill meta sector");
    }
    check(st.meta_slot + 1u ==
              OMK_FLASH_SECTOR_SIZE / OMK_STORE_META_RECORD_SIZE,
          "meta sector is full before erase fault");
    const uint32_t next_sector =
        (st.meta_sector + 1u) % OMK_STORE_META_SECTORS;
    uint8_t expected_hash[16];
    memcpy(expected_hash, st.pin_hash, 16);
    /* Make the target sector non-blank so the store has to erase it before
     * the append; the injected erase failure must then be reported. */
    write_torn_meta_v2(&cs, ABS_META(next_sector, 0));
    cs.fail_erase_off = (long)ABS_META(next_sector, 0);
    rolling[0]++;
    check(omk_store_set_pin(&st, rolling) == -1,
          "setPIN reports meta sector erase failure");
    check(memcmp(st.pin_hash, expected_hash, 16) == 0,
          "meta erase failure leaves RAM PIN unchanged");
    store_reboot(&cs, &rb, &rst, "meta erase failure reboot");
    check(memcmp(rst.pin_hash, expected_hash, 16) == 0,
          "meta erase failure leaves the committed PIN unchanged");
}

/* ---------------------------------------------------------------------- */
/* Compaction cuts and reclaim                                             */
/* ---------------------------------------------------------------------- */

static void fill_bank_exactly(sim *s, omk_store *st, const omk_credential *a,
                              const omk_credential *b) {
    /* A occupies slot 0, B slot 1, delete(B) slot 2, then updates fill the
     * remaining slots up to the end of the 496-slot bank. */
    check(omk_store_put_credential(st, a) == 0, "fill A");
    check(omk_store_put_credential(st, b) == 0, "fill B");
    check(omk_store_delete_credential(st, b->id, b->id_len) == 0, "fill del B");
    uint8_t name[16];
    for (int i = 0; i < 493; i++) {
        const int n = snprintf((char *)name, sizeof name, "fill%d", i);
        check(omk_store_update_user(st, a->id, a->id_len, a->user_id,
                                    a->user_id_len, name, (size_t)n, name,
                                    (size_t)n) == 0,
              "fill update");
    }
    check(st->write_off == ABS_BANK(st->active_bank) + OMK_STORE_BANK_SIZE,
          "bank filled to the last slot");
    (void)s;
}

static void test_compaction_cuts(void) {
    sim base;
    omk_store base_store;
    store_fresh(&base, &base_store);
    omk_credential a;
    omk_credential b;
    make_cred(&a, 0x91, "compact.example", "user-a", "Alice");
    make_cred(&b, 0x92, "compact.example", "user-b", "Bob");
    fill_bank_exactly(&base, &base_store, &a, &b);
    const uint32_t seq_a = cred_seq(&base_store, &a);
    const uint32_t next_before = base_store.next_seq;

    /* One update must trigger compaction, copy the single live credential and
     * append the update to the new bank. */
    sim run;
    sim_copy(&run, &base, true);
    omk_store rs = base_store;
    rs.port = &run.port;
    check(omk_store_update_user(&rs, a.id, a.id_len, a.user_id, a.user_id_len,
                                (const uint8_t *)"final", 5,
                                (const uint8_t *)"final", 5) == 0,
          "uncut compacting update");
    check(rs.active_bank != base_store.active_bank,
          "compaction flips the active bank");
    const long total = run.ops;
    check(total > 100, "compaction performs a full bank reclaim");

    for (long k = 1; k <= total; k++) {
        sim cs;
        omk_store st = base_store;
        sim_copy(&cs, &base, true);
        st.port = &cs.port;
        cs.cut_op = k;
        (void)omk_store_update_user(
            &st, a.id, a.id_len, a.user_id, a.user_id_len,
            (const uint8_t *)"final", 5, (const uint8_t *)"final", 5);

        sim rb;
        omk_store rst;
        store_reboot(&cs, &rb, &rst, "compaction reboot");
        check(rst.cred_count == 1, "compaction never loses or duplicates live creds");
        const omk_credential *got = omk_store_find_id(&rst, a.id, a.id_len);
        check(got != NULL, "compaction cut keeps the live credential");
        check(!store_has_id(&rst, &b),
              "compaction never resurrects an acknowledged deletion");
        if (got != NULL) {
            const bool old_name = got->user_name_len == 7 &&
                                  memcmp(got->user_name, "fill492", 7) == 0;
            const bool new_name = got->user_name_len == 5 &&
                                  memcmp(got->user_name, "final", 5) == 0;
            check(old_name || new_name,
                  "compaction cut leaves old or new user name");
            check(got->seq == seq_a, "compaction preserves creation seq");
        }
        check(rst.next_seq >= next_before,
              "compaction keeps next_seq monotonic");
    }
}

static void test_compaction_failures(void) {
    sim base;
    omk_store base_store;
    store_fresh(&base, &base_store);
    omk_credential a;
    omk_credential b;
    make_cred(&a, 0xA1, "cfail.example", "user-a", "Alice");
    make_cred(&b, 0xA2, "cfail.example", "user-b", "Bob");
    fill_bank_exactly(&base, &base_store, &a, &b);

    /* Cooperative cancellation between inactive-bank erase units preserves
     * the active bank.  Clearing the request must allow a same-boot retry. */
    sim cs;
    sim_copy(&cs, &base, true);
    omk_store st = base_store;
    st.port = &cs.port;
    cs.operation_cancel_at = 3;
    check(omk_store_update_user(&st, a.id, a.id_len, a.user_id, a.user_id_len,
                                (const uint8_t *)"cancel", 6,
                                (const uint8_t *)"cancel", 6) ==
              OMK_STORE_ERR_CANCELLED,
          "compaction reports cooperative cancellation");
    check(st.active_bank == base_store.active_bank && st.cred_count == 1 &&
              store_has_id(&st, &a) && !store_has_id(&st, &b),
          "compaction cancellation preserves the active bank");
    const omk_credential *unchanged = omk_store_find_id(&st, a.id, a.id_len);
    check(unchanged != NULL && unchanged->user_name_len == 7 &&
              memcmp(unchanged->user_name, "fill492", 7) == 0,
          "compaction cancellation rolls RAM back");
    cs.operation_cancel_at = 0;
    check(omk_store_update_user(&st, a.id, a.id_len, a.user_id, a.user_id_len,
                                (const uint8_t *)"retry", 5,
                                (const uint8_t *)"retry", 5) == 0,
          "compaction same-boot retry succeeds after cancellation");

    /* Erase failure in the inactive bank: the append (and compaction) fails,
     * the old bank stays authoritative. */
    sim_copy(&cs, &base, true);
    st = base_store;
    st.port = &cs.port;
    cs.fail_erase_off = (long)ABS_BANK((uint8_t)(1u - st.active_bank));
    check(omk_store_update_user(&st, a.id, a.id_len, a.user_id, a.user_id_len,
                                (const uint8_t *)"final", 5,
                                (const uint8_t *)"final", 5) == -1,
          "compaction reports erase failure");
    sim rb;
    omk_store rst;
    store_reboot(&cs, &rb, &rst, "compact erase failure reboot");
    check(rst.cred_count == 1 && store_has_id(&rst, &a) && !store_has_id(&rst, &b),
          "compact erase failure preserves live state");

    /* Read failure while verifying the erased inactive bank. */
    sim_copy(&cs, &base, true);
    st = base_store;
    st.port = &cs.port;
    cs.fail_read_off = (long)ABS_BANK((uint8_t)(1u - st.active_bank));
    check(omk_store_update_user(&st, a.id, a.id_len, a.user_id, a.user_id_len,
                                (const uint8_t *)"final", 5,
                                (const uint8_t *)"final", 5) == -1,
          "compaction reports verify read failure");
    store_reboot(&cs, &rb, &rst, "compact read failure reboot");
    check(rst.cred_count == 1 && store_has_id(&rst, &a) && !store_has_id(&rst, &b),
          "compact read failure preserves live state");

    /* A copy that does not read back identically must abort before the meta
     * flip; the old bank remains authoritative. */
    sim_copy(&cs, &base, true);
    st = base_store;
    st.port = &cs.port;
    const uint8_t target_bank = (uint8_t)(1u - st.active_bank);
    cs.write_drop_off = (long)ABS_BANK(target_bank) + 100;
    check(omk_store_update_user(&st, a.id, a.id_len, a.user_id, a.user_id_len,
                                (const uint8_t *)"final", 5,
                                (const uint8_t *)"final", 5) == -1,
          "compaction rejects a non-verifying copy");
    store_reboot(&cs, &rb, &rst, "compact bad copy reboot");
    check(rst.cred_count == 1 && store_has_id(&rst, &a) && !store_has_id(&rst, &b),
          "compact bad copy preserves live state");

    /* Meta commit failure after the copy: the copy is ignored and the old
     * bank remains authoritative. */
    sim_copy(&cs, &base, true);
    st = base_store;
    st.port = &cs.port;
    cs.write_ok_budget = 1; /* one live credential copy, then fail meta */
    check(omk_store_update_user(&st, a.id, a.id_len, a.user_id, a.user_id_len,
                                (const uint8_t *)"final", 5,
                                (const uint8_t *)"final", 5) == -1,
          "compaction reports meta commit failure");
    store_reboot(&cs, &rb, &rst, "compact meta failure reboot");
    check(rst.cred_count == 1 && store_has_id(&rst, &a) && !store_has_id(&rst, &b),
          "compact meta failure preserves live state");
}

static void test_beyond_old_limit(void) {
    sim s;
    omk_store st;
    store_fresh(&s, &st);
    omk_credential a;
    omk_credential b;
    make_cred(&a, 0xB1, "long.example", "user-a", "Alice");
    make_cred(&b, 0xB2, "long.example", "user-b", "Bob");
    check(omk_store_put_credential(&st, &a) == 0, "long setup A");
    check(omk_store_put_credential(&st, &b) == 0, "long setup B");
    check(omk_store_delete_credential(&st, b.id, b.id_len) == 0, "long delete B");

    uint8_t name[16];
    for (int i = 0; i < 1200; i++) {
        const int n = snprintf((char *)name, sizeof name, "n%d", i);
        check(omk_store_update_user(&st, a.id, a.id_len, a.user_id,
                                    a.user_id_len, name, (size_t)n, name,
                                    (size_t)n) == 0,
              "update beyond old log limit");
    }
    check(st.cred_count == 1, "reclaim keeps exactly one live credential");
    const uint32_t seq_before = st.next_seq;
    check(seq_before > 1016, "sequence counter advanced past the old limit");

    sim rb;
    omk_store rst;
    store_reboot(&s, &rb, &rst, "long reboot");
    check(rst.cred_count == 1, "long test survives reboot");
    check(!store_has_id(&rst, &b), "long test keeps deletion tombstone");
    const omk_credential *got = omk_store_find_id(&rst, a.id, a.id_len);
    check(got != NULL && got->user_name_len == 5 &&
              memcmp(got->user_name, "n1199", 5) == 0,
          "long test keeps the newest update");

    /* A fresh append after many compactions must get a newer sequence. */
    omk_credential c;
    make_cred(&c, 0xB3, "long.example", "user-c", "Carol");
    check(omk_store_put_credential(&rst, &c) == 0, "long append after reclaim");
    check(cred_seq(&rst, &c) > seq_before - 1,
          "next_seq stays monotonic after reclaim");
}

/* ---------------------------------------------------------------------- */
/* Counter leases                                                          */
/* ---------------------------------------------------------------------- */

static void test_counter_lease_cuts(void) {
    sim base;
    omk_store base_store;
    store_fresh(&base, &base_store);
    uint32_t last = 0;
    for (uint32_t i = 0; i < 64; i++) {
        const uint32_t v = omk_store_next_counter(&base_store);
        check(v == i + 1, "initial counter lease values");
        last = v;
    }
    check(base_store.lease == 64, "initial lease persisted");
    check(base_store.counter == 64, "initial counter at lease");
    const uint32_t last_before = last;

    sim run;
    sim_copy(&run, &base, true);
    omk_store rs = base_store;
    rs.port = &run.port;
    const uint32_t next = omk_store_next_counter(&rs);
    check(next == 65, "uncut lease extension value");
    const long total = run.ops;
    check(total > 0, "lease extension writes flash");

    for (long k = 1; k <= total; k++) {
        sim cs;
        omk_store st = base_store;
        sim_copy(&cs, &base, true);
        st.port = &cs.port;
        cs.cut_op = k;
        const uint32_t v = omk_store_next_counter(&st);
        if (v != 0) {
            check(v > last_before, "counter never repeats after a cut");
        }
        sim rb;
        omk_store rst;
        store_reboot(&cs, &rb, &rst, "counter reboot");
        check(rst.counter >= last_before, "boot counter never regresses");
        const uint32_t after = omk_store_next_counter(&rst);
        check(after > last_before, "counter after reboot never repeats");
    }

    /* Failed lease write must roll the RAM counter back. */
    sim cs;
    sim_copy(&cs, &base, true);
    omk_store st = base_store;
    st.port = &cs.port;
    cs.write_ok_budget = 0;
    check(omk_store_next_counter(&st) == 0, "lease write failure returns 0");
    check(st.counter == 64, "lease write failure rolls RAM back");
    sim rb;
    omk_store rst;
    store_reboot(&cs, &rb, &rst, "lease failure reboot");
    check(rst.counter == 64, "lease failure leaves persisted counter");
    check(omk_store_next_counter(&rst) == 65, "no value was consumed by failure");
}

static void test_counter_overflow(void) {
    sim s;
    omk_store st;
    store_fresh(&s, &st);
    st.lease = UINT32_MAX - 1u;
    st.counter = UINT32_MAX - 1u;
    check(omk_store_next_counter(&st) == UINT32_MAX,
          "last representable counter is issued once");
    check(omk_store_next_counter(&st) == 0,
          "counter overflow fails closed instead of wrapping");

    sim rb;
    omk_store rst;
    store_reboot(&s, &rb, &rst, "counter overflow reboot");
    check(rst.counter == rst.lease, "boot resumes at the reserved lease");
    check(omk_store_next_counter(&rst) == 0,
          "persisted max lease never reissues a counter");

    /* A counter already at the maximum cannot be allocated. */
    rst.counter = UINT32_MAX;
    check(omk_store_next_counter(&rst) == 0,
          "exhausted counter fails closed");
}

/* ---------------------------------------------------------------------- */
/* Capacity and overwrite semantics                                        */
/* ---------------------------------------------------------------------- */

static void test_overwrite_at_capacity(void) {
    sim s;
    omk_store st;
    store_fresh(&s, &st);
    omk_credential first;
    for (int i = 0; i < OMK_MAX_CREDENTIALS; i++) {
        omk_credential c;
        char user[16];
        const int n = snprintf(user, sizeof user, "u%d", i);
        (void)n;
        make_cred(&c, (uint8_t)(0x10 + i), "full.example", user, "Name");
        if (i == 0) {
            first = c;
        }
        check(omk_store_put_credential(&st, &c) == 0, "fill 64 credentials");
    }
    check(st.cred_count == OMK_MAX_CREDENTIALS, "store is full");

    /* Same rpId+user.id overwrite is allowed even though the store is full. */
    omk_credential replacement;
    make_cred(&replacement, 0xF0, "full.example", "u0", "Replaced");
    check(omk_store_put_credential(&st, &replacement) == 0,
          "same rp+user overwrite succeeds at 64 credentials");
    check(st.cred_count == OMK_MAX_CREDENTIALS, "overwrite keeps the count");
    check(!store_has_id(&st, &first), "overwrite drops the old credential id");
    check(store_has_id(&st, &replacement), "overwrite installs the new id");

    /* Same credential ID overwrite also works at capacity. */
    omk_credential same_id;
    same_id = replacement;
    same_id.user_id_len = 3;
    memcpy(same_id.user_id, "u1x", 3);
    same_id.user_name_len = 3;
    memcpy(same_id.user_name, "New", 3);
    same_id.display_name_len = 3;
    memcpy(same_id.display_name, "New", 3);
    check(omk_store_put_credential(&st, &same_id) == 0,
          "same credential id overwrite succeeds at 64 credentials");
    check(st.cred_count == OMK_MAX_CREDENTIALS, "same-id overwrite keeps count");

    sim rb;
    omk_store rst;
    store_reboot(&s, &rb, &rst, "capacity reboot");
    check(rst.cred_count == OMK_MAX_CREDENTIALS, "capacity survives reboot");
    check(store_has_id(&rst, &replacement), "replacement survives reboot");
    check(!store_has_id(&rst, &first), "old id stays gone after reboot");

    /* A genuinely new credential is refused when full. */
    omk_credential extra;
    make_cred(&extra, 0xF7, "full.example", "u-new", "Extra");
    check(omk_store_put_credential(&rst, &extra) == OMK_STORE_ERR_FULL,
          "new credential refused at 64 with capacity error");
}

/* ---------------------------------------------------------------------- */
/* Legacy / foreign meta images                                            */
/* ---------------------------------------------------------------------- */

static void check_init_rejected_without_writes(sim *s, const char *what) {
    static uint8_t snapshot[OMK_FLASH_REGION_SIZE];
    memcpy(snapshot, s->mem, sizeof snapshot);
    const long writes = s->writes;
    const long erases = s->erases;
    omk_store st;
    check(omk_store_init(&st, &s->port) == -1, what);
    check(s->writes == writes && s->erases == erases,
          "rejected meta image causes no write or erase");
    check(memcmp(snapshot, s->mem, sizeof snapshot) == 0,
          "rejected meta image is left byte-identical");
}

static void test_legacy_meta_rejected(void) {
    /* Prior v1 image: same magic, version 1.  It must not be factory
     * formatted over; no credentials may be silently destroyed. */
    sim v1;
    sim_init(&v1);
    write_meta_prefix(&v1, ABS_META(0, 0), 0x4F4D4B4Du, 1, 1);
    check_init_rejected_without_writes(&v1, "v1 meta fails init");

    /* Other non-blank unrecognized images (unknown version/magic) fail closed
     * for the same reason. */
    sim v3;
    sim_init(&v3);
    write_meta_prefix(&v3, ABS_META(0, 0), 0x4F4D4B4Du, 3, 1);
    check_init_rejected_without_writes(&v3, "v3 meta fails init");

    sim foreign;
    sim_init(&foreign);
    write_meta_prefix(&foreign, ABS_META(0, 0), 0xDEADBEEFu, 2, 1);
    check_init_rejected_without_writes(&foreign, "foreign meta fails init");

    /* A partially programmed magic is indistinguishable from a foreign image
     * when there is no valid snapshot to recover. */
    sim short_magic;
    sim_init(&short_magic);
    write_meta_prefix(&short_magic, ABS_META(0, 0), 0x4F000000u, 2, 1);
    check_init_rejected_without_writes(&short_magic,
                                       "damaged-magic-only meta fails init");

    /* Unknown records do not become recoverable just because a torn v2 record
     * accompanies them: with no valid snapshot the image is still fatal. */
    sim mixed;
    sim_init(&mixed);
    write_meta_prefix(&mixed, ABS_META(0, 0), 0x4F4D4B4Du, 1, 1);
    write_torn_meta_v2(&mixed, ABS_META(0, 1));
    check_init_rejected_without_writes(&mixed, "mixed legacy/torn meta fails init");

    /* A truly erased store is still first-boot formatted. */
    sim blank;
    sim_init(&blank);
    omk_store st;
    check(omk_store_init(&st, &blank.port) == 0, "erased store formats");
    check(st.ready && blank.erases > 0, "first boot formats the meta log");

    /* A recognized torn current-format record with no valid snapshot is the
     * documented recovery case: it may be formatted with a newer epoch. */
    sim torn;
    sim_init(&torn);
    write_torn_meta_v2(&torn, ABS_META(0, 0));
    omk_store tst;
    check(omk_store_init(&tst, &torn.port) == 0,
          "torn v2 only is recoverable");
    check(tst.ready && tst.meta_valid, "torn v2 recovery installs a snapshot");
}

/* A power cut that programs only a few bytes of a newly appended meta record
 * must not hide the previous valid snapshot.  The whole meta region is
 * scanned, so short prefixes, damaged magic/version/kind and unrelated
 * non-blank records are skipped once a valid v2 snapshot exists. */
static void test_meta_unknown_records_recover(void) {
    /* Each sim owns a 1 MiB flash image; keep them off the stack so the test
     * is not sensitive to ASan's stack redzones. */
    static sim base;
    static sim cs;
    static sim rb;
    static sim rb2;
    static sim multi;
    static sim mrb;
    static sim mrb2;
    static sim impossible;
    static omk_store st;
    omk_store rst;
    omk_store rst2;
    omk_store mrst;
    omk_store mrst2;

    store_fresh(&base, &st);

    uint8_t pin[16];
    fill_hash(pin, 0x5A);
    check(omk_store_set_pin(&st, pin) == 0, "recovery base set PIN");
    omk_credential a;
    omk_credential b;
    omk_credential c;
    make_cred(&a, 0xA1, "recover.example", "user-a", "Alice");
    make_cred(&b, 0xA2, "recover.example", "user-b", "Bob");
    make_cred(&c, 0xA3, "recover.example", "user-c", "Carol");
    check(omk_store_put_credential(&st, &a) == 0, "recovery base cred A");
    check(omk_store_put_credential(&st, &b) == 0, "recovery base cred B");
    uint8_t wrong[16];
    memcpy(wrong, pin, 16);
    wrong[0] ^= 0xFFu;
    for (int i = 0; i < 2; i++) {
        check(omk_store_pin_attempt(&st, wrong) == 0,
              "recovery base attempt");
        check(omk_store_pin_reject(&st) == 0, "recovery base reject");
    }
    check(st.pin_retries == 6, "recovery base retry count");

    const uint32_t good_off = ABS_META(st.meta_sector, st.meta_slot);
    uint8_t good[OMK_STORE_META_RECORD_SIZE];
    memcpy(good, &base.mem[good_off - OMK_FLASH_REGION_OFF], sizeof good);

    static const char *const names[] = {
        "1-byte magic prefix",
        "1-byte zero",
        "torn v2 header prefix",
        "damaged magic",
        "unknown version",
        "unknown kind",
        "foreign magic",
        "unknown garbage",
        "zeroed record",
    };
    const int cases = (int)(sizeof names / sizeof names[0]);

    for (int pass = 0; pass < cases; pass++) {
        sim_copy(&cs, &base, true);
        uint8_t rec[OMK_STORE_META_RECORD_SIZE];
        size_t len = 0;
        memset(rec, 0xFF, sizeof rec);
        switch (pass) {
        case 0:
            rec[0] = 0x4Fu; /* first byte of a real append */
            len = 1;
            break;
        case 1:
            rec[0] = 0x00u; /* any single programmed bit pattern */
            len = 1;
            break;
        case 2:
            memcpy(rec, good, 9); /* v2 header + seq prefix, CRC still blank */
            len = 9;
            break;
        case 3:
            memcpy(rec, good, sizeof rec);
            rec[0] = 0x00u; /* damaged magic */
            len = sizeof rec;
            break;
        case 4:
            memcpy(rec, good, sizeof rec);
            rec[4] = 0x00u; /* version 3 */
            rec[5] = 0x03u;
            len = sizeof rec;
            break;
        case 5:
            memcpy(rec, good, sizeof rec);
            rec[6] = 0x02u; /* unknown kind */
            len = sizeof rec;
            break;
        case 6: {
            static const uint8_t foreign[7] = {0xDEu, 0xADu, 0xBEu,
                                               0xEFu, 0x00u, 0x02u,
                                               0x01u};
            memcpy(rec, foreign, sizeof foreign);
            len = sizeof foreign;
            break;
        }
        case 7:
            memset(rec, 0xAAu, 9);
            len = 9;
            break;
        default:
            memset(rec, 0x00u, sizeof rec);
            len = sizeof rec;
            break;
        }
        inject_meta_bytes(&cs, meta_append_off(&st, 0), rec, len);

        store_reboot(&cs, &rb, &rst, names[pass]);
        check(rb.writes == 0 && rb.erases == 0,
              "unknown record after valid snapshot needs no recovery write");
        check(memcmp(rst.master, st.master, 32) == 0,
              "master survives unknown record");
        check(memcmp(rst.aaguid, st.aaguid, 16) == 0,
              "AAGUID survives unknown record");
        check(memcmp(rst.pin_hash, st.pin_hash, 16) == 0 && rst.pin_set,
              "PIN hash survives unknown record");
        check(rst.pin_retries == st.pin_retries,
              "PIN retries survive unknown record");
        check(rst.meta_seq == st.meta_seq,
              "newest snapshot sequence is recovered");
        check(store_has_id(&rst, &a) && store_has_id(&rst, &b),
              "credentials survive unknown record");

        /* A meta append must skip the injected non-blank slot: extending the
         * counter lease calls meta_persist(), which refuses to program a slot
         * that already contains bits. */
        check(omk_store_next_counter(&rst) != 0,
              "meta append after unknown record succeeds");
        check(omk_store_put_credential(&rst, &c) == 0,
              "log append after unknown record succeeds");
        store_reboot(&rb, &rb2, &rst2, "append after unknown record reboot");
        check(store_has_id(&rst2, &a) && store_has_id(&rst2, &b),
              "prior credentials survive append after unknown record");
        check(store_has_id(&rst2, &c),
              "credential appended after unknown record survives");
        check(rst2.pin_set && rst2.pin_retries == st.pin_retries,
              "PIN state survives append after unknown record");
        check(rst2.lease > st.lease,
              "meta append committed past the unknown record");
    }

    /* Several different non-blank records after the snapshot are skipped
     * together, and the append cursor advances past all of them. */
    sim_copy(&multi, &base, true);
    uint8_t rec[OMK_STORE_META_RECORD_SIZE];
    memset(rec, 0xFF, sizeof rec);
    rec[0] = 0x4Fu;
    inject_meta_bytes(&multi, meta_append_off(&st, 0), rec, 1);
    inject_meta_bytes(&multi, meta_append_off(&st, 1), good, 9);
    memcpy(rec, good, sizeof rec);
    rec[0] = 0x00u;
    inject_meta_bytes(&multi, meta_append_off(&st, 2), rec, sizeof rec);

    store_reboot(&multi, &mrb, &mrst, "multiple unknown records reboot");
    check(mrb.writes == 0 && mrb.erases == 0,
          "multiple unknown records need no recovery write");
    check(store_has_id(&mrst, &a) && store_has_id(&mrst, &b),
          "credentials survive multiple unknown records");
    check(omk_store_next_counter(&mrst) != 0,
          "meta append after multiple unknown records succeeds");
    check(omk_store_put_credential(&mrst, &c) == 0,
          "log append after multiple unknown records succeeds");
    store_reboot(&mrb, &mrb2, &mrst2, "multiple unknown records second reboot");
    check(store_has_id(&mrst2, &a) && store_has_id(&mrst2, &b) &&
              store_has_id(&mrst2, &c),
          "append skips every injected non-blank slot");
    check(mrst2.lease > st.lease,
          "meta append advances past every injected non-blank slot");

    /* A CRC-valid record with impossible fields is still a hard fault even
     * when a valid snapshot exists.  It must not be skipped or written over. */
    sim_copy(&impossible, &base, true);
    inject_impossible_meta(&impossible, meta_append_off(&st, 0), good, 24, 2);
    check_init_rejected_without_writes(&impossible,
                                       "impossible CRC-valid meta fails init");
}

/* ---------------------------------------------------------------------- */
/* Random-source failures                                                  */
/* ---------------------------------------------------------------------- */

static void test_rng_failure_store(void) {
    sim s;
    omk_store st;
    store_fresh(&s, &st);
    uint8_t pin[16];
    fill_hash(pin, 0x55);
    check(omk_store_set_pin(&st, pin) == 0, "rng reset setup PIN");
    omk_credential a;
    make_cred(&a, 0xE1, "rng.example", "user-a", "Alice");
    check(omk_store_put_credential(&st, &a) == 0, "rng reset setup cred");
    uint8_t master[32];
    uint8_t pin_hash[16];
    memcpy(master, st.master, 32);
    memcpy(pin_hash, st.pin_hash, 16);
    const long writes = s.writes;
    const long erases = s.erases;

    /* Reset obtains its fresh identity before touching the inactive bank. */
    s.fail_random = true;
    check(omk_store_reset(&st) == -1, "reset reports RNG failure");
    check(memcmp(st.master, master, 32) == 0 && st.pin_set &&
              memcmp(st.pin_hash, pin_hash, 16) == 0 && st.cred_count == 1 &&
              store_has_id(&st, &a),
          "RNG-failed reset leaves live state intact");
    check(s.writes == writes && s.erases == erases,
          "RNG-failed reset performs no flash mutation");
    s.fail_random = false;

    /* Credential sealing never writes a usable ID on RNG failure. */
    uint8_t out[OMK_CRED_ID_MAX];
    memset(out, 0xAA, sizeof out);
    uint8_t seed[32];
    memset(seed, 0x33, sizeof seed);
    s.fail_random = true;
    check(omk_store_seal_credential(&st, a.rp_id_hash, seed, 1, 1, false,
                                    out) == 0,
          "seal reports RNG failure");
    bool untouched = true;
    for (size_t i = 0; i < sizeof out; i++) {
        if (out[i] != 0xAAu) {
            untouched = false;
        }
    }
    check(untouched, "failed seal leaves caller ID buffer untouched");
    s.fail_random = false;

    /* Fresh format with a failing RNG: init fails before any erase/write and
     * partial random output is discarded. */
    sim b;
    sim_init(&b);
    b.fail_random = true;
    omk_store bst;
    check(omk_store_init(&bst, &b.port) == -1, "format reports RNG failure");
    check(b.writes == 0 && b.erases == 0,
          "RNG-failed format performs no write or erase");

    /* AAGUID is model identity: formatting consumes no second RNG sample and
     * Reset preserves the exact same value while rotating the master key. */
    sim b2;
    sim_init(&b2);
    omk_store bst2;
    check(omk_store_init(&bst2, &b2.port) == 0, "fixed-AAGUID format succeeds");
    check(b2.random_calls == 1, "format draws only the master secret");
    check(memcmp(bst2.aaguid, st.aaguid, sizeof bst2.aaguid) == 0,
          "same model has the same AAGUID across devices");
    check(omk_store_reset(&bst2) == 0, "fixed-AAGUID reset succeeds");
    check(b2.random_calls == 2, "reset draws only a replacement master secret");
    check(memcmp(bst2.aaguid, st.aaguid, sizeof bst2.aaguid) == 0,
          "reset preserves model AAGUID");
}

/* ---------------------------------------------------------------------- */
/* Main                                                                    */
/* ---------------------------------------------------------------------- */

int main(void) {
    test_legacy_meta_rejected();
    test_meta_unknown_records_recover();
    test_rng_failure_store();
    test_pin_wrong_cuts();
    test_pin_correct_cuts();
    test_pin_boot_resolution_cuts();
    test_reset_cuts();
    test_reset_failures();
    test_append_cuts();
    test_delete_cuts();
    test_update_cuts();
    test_torn_record_independent_scan();
    test_read_error_offsets();
    test_write_and_erase_failures();
    test_compaction_cuts();
    test_compaction_failures();
    test_beyond_old_limit();
    test_counter_lease_cuts();
    test_counter_overflow();
    test_overwrite_at_capacity();

    if (g_failures != 0) {
        printf("store: %d test(s) failed\n", g_failures);
        return 1;
    }
    printf("store: all tests passed\n");
    return 0;
}
