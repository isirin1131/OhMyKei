/*
 * CTAP2 authenticator core.
 *
 * One omk_ctap instance owns the persistent store, the PIN/UV state machine
 * and the authenticator command dispatcher.  It is deliberately free of
 * pico-sdk dependencies; the firmware wires it to CTAPHID and the platform
 * port, host tests drive it through the same interface.
 */
#ifndef OMK_FIDO_CTAP_H
#define OMK_FIDO_CTAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fido/omk_ctaphid.h"
#include "fido/omk_store.h"
#include "omk_port.h"

#define OMK_CTAP_MAX_MSG 2048

/* Numeric firmware version reported in CTAP getInfo (key 14).  It can be set
 * from the build with -DOMK_FIRMWARE_VERSION=<uint32> (CMake option of the
 * same name); the default remains 1.  This value is metadata only and is not a
 * claim of FIDO certification or release conformance.  Both macros are
 * single-definition: -DOMK_FIRMWARE_VERSION never clashes with the default. */
#ifndef OMK_FIRMWARE_VERSION
#define OMK_FIRMWARE_VERSION 1
#endif
#ifndef OMK_CTAP_FIRMWARE_VERSION
#define OMK_CTAP_FIRMWARE_VERSION OMK_FIRMWARE_VERSION
#endif

#define OMK_CTAP_MIN_PIN_LENGTH 4
#define OMK_CTAP_MAX_PIN_RETRIES 8
#define OMK_CTAP_UP_TIMEOUT_MS 30000u
#define OMK_CTAP_GA_STATE_MS 30000u
#define OMK_CTAP_PUAT_INITIAL_MS 30000u
#define OMK_CTAP_PUAT_TOTAL_MS 600000u
#define OMK_CTAP_RESET_WINDOW_MS 10000u

/* CTAP2 status codes. */
#define OMK_CTAP2_OK 0x00
#define OMK_CTAP1_ERR_INVALID_COMMAND 0x01
#define OMK_CTAP1_ERR_INVALID_PARAMETER 0x02
#define OMK_CTAP1_ERR_INVALID_LENGTH 0x03
#define OMK_CTAP1_ERR_INVALID_SEQ 0x04
#define OMK_CTAP1_ERR_TIMEOUT 0x05
#define OMK_CTAP1_ERR_CHANNEL_BUSY 0x06
#define OMK_CTAP1_ERR_LOCK_REQUIRED 0x0A
#define OMK_CTAP1_ERR_INVALID_CHANNEL 0x0B
#define OMK_CTAP1_ERR_OTHER 0x7F
#define OMK_CTAP2_ERR_CBOR_UNEXPECTED_TYPE 0x11
#define OMK_CTAP2_ERR_INVALID_CBOR 0x12
#define OMK_CTAP2_ERR_MISSING_PARAMETER 0x14
#define OMK_CTAP2_ERR_LIMIT_EXCEEDED 0x15
#define OMK_CTAP2_ERR_UNSUPPORTED_EXTENSION 0x16
#define OMK_CTAP2_ERR_CREDENTIAL_EXCLUDED 0x19
#define OMK_CTAP2_ERR_PROCESSING 0x21
#define OMK_CTAP2_ERR_INVALID_CREDENTIAL 0x22
#define OMK_CTAP2_ERR_USER_ACTION_PENDING 0x23
#define OMK_CTAP2_ERR_OPERATION_PENDING 0x24
#define OMK_CTAP2_ERR_NO_OPERATIONS 0x25
#define OMK_CTAP2_ERR_UNSUPPORTED_ALGORITHM 0x26
#define OMK_CTAP2_ERR_OPERATION_DENIED 0x27
#define OMK_CTAP2_ERR_KEY_STORE_FULL 0x28
#define OMK_CTAP2_ERR_NOT_BUSY 0x29
#define OMK_CTAP2_ERR_NO_OPERATION_PENDING 0x2A
#define OMK_CTAP2_ERR_UNSUPPORTED_OPTION 0x2B
#define OMK_CTAP2_ERR_INVALID_OPTION 0x2C
#define OMK_CTAP2_ERR_KEEPALIVE_CANCEL 0x2D
#define OMK_CTAP2_ERR_NO_CREDENTIALS 0x2E
#define OMK_CTAP2_ERR_USER_ACTION_TIMEOUT 0x2F
#define OMK_CTAP2_ERR_NOT_ALLOWED 0x30
#define OMK_CTAP2_ERR_PIN_INVALID 0x31
#define OMK_CTAP2_ERR_PIN_BLOCKED 0x32
#define OMK_CTAP2_ERR_PIN_AUTH_INVALID 0x33
#define OMK_CTAP2_ERR_PIN_AUTH_BLOCKED 0x34
#define OMK_CTAP2_ERR_PIN_NOT_SET 0x35
#define OMK_CTAP2_ERR_PIN_REQUIRED 0x36
#define OMK_CTAP2_ERR_PIN_POLICY_VIOLATION 0x37
#define OMK_CTAP2_ERR_PIN_TOKEN_EXPIRED 0x38
#define OMK_CTAP2_ERR_REQUEST_TOO_LARGE 0x39
#define OMK_CTAP2_ERR_ACTION_TIMEOUT 0x3A
#define OMK_CTAP2_ERR_UP_REQUIRED 0x3B
#define OMK_CTAP2_ERR_UV_BLOCKED 0x3C
#define OMK_CTAP2_ERR_INTEGRITY_FAILURE 0x3D
#define OMK_CTAP2_ERR_INVALID_SUBCOMMAND 0x3E
#define OMK_CTAP2_ERR_UV_INVALID 0x3F
#define OMK_CTAP2_ERR_UNAUTHORIZED_PERMISSION 0x40
#define OMK_CTAP2_ERR_OTHER 0x7F

/* Permissions. */
#define OMK_PERM_MC 0x01
#define OMK_PERM_GA 0x02
#define OMK_PERM_CM 0x04
#define OMK_PERM_BE 0x08
#define OMK_PERM_LBW 0x10
#define OMK_PERM_ACFG 0x20
#define OMK_PERM_PCMR 0x40

#define OMK_ALG_ES256 1
#define OMK_ALG_EDDSA 2

typedef struct {
    bool valid;
    uint8_t key_priv[32];
    uint8_t key_pub[65];
    uint8_t token[32];
    bool token_valid;
    uint8_t permissions;
    uint8_t rp_hash[32];
    bool rp_bound;
    bool user_verified;
    uint64_t created_ms;
    uint64_t used_ms;
    bool used_once;
} omk_pin_state;

typedef struct {
    bool valid;
    uint64_t expires_ms;
    uint8_t client_data_hash[32];
    uint8_t rp_hash[32];
    bool up;
    bool uv;
    bool hmac_secret;
    uint8_t hmac_salt[64];
    size_t hmac_salt_len;
    uint8_t hmac_aes[32];
    uint8_t hmac_protocol;
    uint8_t indices[OMK_MAX_CREDENTIALS];
    uint8_t count;
    uint8_t next;
    uint8_t cred_protect_min;
    bool cred_protect_filter;
} omk_assertion_state;

typedef struct {
    bool valid;
    uint8_t kind; /* 1 = RP enumeration, 2 = credential enumeration */
    uint64_t expires_ms;
    uint8_t rp_hash[32];
    /* Stable creation sequences, not RAM array indices: delete compacts the
     * store array while an enumeration continuation may still be live. */
    uint32_t cred_seqs[OMK_MAX_CREDENTIALS];
    uint8_t rp_hashes[OMK_MAX_CREDENTIALS][32];
    uint8_t count;
    uint8_t next;
} omk_credmgmt_state;

typedef struct {
    const omk_port *port;
    omk_ctaphid *hid;
    omk_store store;
    omk_pin_state pin;
    uint8_t consecutive_pin_failures;
    /* Set when a PIN retry-counter write failed; PIN verification then fails
     * closed until the next boot. */
    bool pin_store_fault;
    uint64_t boot_ms;
    uint32_t uptime_ms;
    bool up_latched;

    omk_assertion_state ga;
    omk_credmgmt_state cm;

    uint8_t response[OMK_CTAP_MAX_MSG];
    size_t response_len;
} omk_ctap;

int omk_ctap_init(omk_ctap *ct, const omk_port *port, omk_ctaphid *hid);
void omk_ctap_handle(void *ctx, uint32_t cid, const uint8_t *msg, size_t len);

#endif /* OMK_FIDO_CTAP_H */
