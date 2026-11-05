# OhMyKei implementation notes

This document records the design that was actually built, complementing
[road.md](road.md) (scope) and [ROADMAP.md](ROADMAP.md) (order of work). It
also records the current verification surface and its limits; it is not a
security certification.

## Module map

| Area | Files |
|---|---|
| Platform abstraction | `src/omk_port.h` |
| Crypto | `src/crypto/{sha256,aes,p256,ed25519}.c`, `omk_crypto.h` |
| Strict CBOR | `src/fido/omk_cbor.{h,c}` |
| CTAPHID | `src/fido/omk_ctaphid.{h,c}` |
| Persistent state | `src/fido/omk_store.{h,c}` |
| CTAP dispatcher/getInfo/reset/selection | `src/fido/omk_ctap.{h,c}` |
| ClientPIN + PUAT | `src/fido/omk_ctap_pin.c` |
| Shared PIN/UV protocol cryptography | `src/fido/omk_pin_protocol.{h,c}` |
| MakeCredential/GetAssertion/extensions | `src/fido/omk_ctap_auth.c` |
| CredentialManagement | `src/fido/omk_ctap_mgmt.c` |
| Firmware USB/board glue | `src/platform/*`, `src/main.c` |
| Host tests / fuzzers / probes | `host/tests/*`, `host/fuzz_*.c`, `host/check_*.cmake` |
| Linker fragments and ELF layout check | `cmake/linker/*` |

The protocol core (`src/fido`, `src/crypto`, `src/omk_port.h`) has no
pico-sdk dependency. The host build compiles exactly the same sources.

## Build and verification checks

### Host tests

`OMK_HOST_BUILD=ON` (the `host` preset) builds the core and tests with the
host compiler. `OMK_SANITIZE=ON` is the default: AddressSanitizer plus
UndefinedBehaviorSanitizer with `-fno-sanitize-recover=all`, and CTest exports
`UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1` and
`ASAN_OPTIONS=detect_leaks=0:abort_on_error=1` so a stale build cannot pass by
recovering.

The current host configuration registers 12 CTest entries:

| Entry | Coverage |
|---|---|
| `test_build_smoke` | C17/host toolchain width sanity |
| `test_crypto` | SHA-256, HMAC-SHA-256, HKDF-SHA-256, AES-256 known-answer tests |
| `test_cbor` | strict decoder rejection cases and encoder output |
| `test_p256` | key derivation, ECDH, RFC 6979 ECDSA, failure/retry paths |
| `test_crypto_ed25519` | RFC 8032 vectors, signing, verification and negative cases |
| `test_ctaphid` | INIT/channel lifecycle, busy/cancel/abort, reassembly, USB reset, TX faults |
| `test_ctap` | end-to-end commands, independent ES256 DER parsing and verification, descriptor maps, `0x0B` format preference, scalar rejection before counter use, enumeration public keys/counts, PIN/extensions, Reset cancel and RNG failures |
| `test_store` | NOR model, per-operation power cuts and same-boot dirty-slot retry, PIN journal, compaction/cancel, legacy images, RNG failures |
| `test_fuzz_ctaphid_replay` | same inputs replayed in a different order produce identical output |
| `host.ubsan_nonrecoverable` | compiles and runs a deliberate signed-overflow probe; it must abort |
| `host.firmware_version_definition` | configured `OMK_FIRMWARE_VERSION` expands and is encoded for getInfo key 14 |
| `host.core_without_fuzzer_hooks` | every normal core archive member is free of SanitizerCoverage symbols |

With `OMK_SANITIZE=OFF` the UBSan probe is not registered, leaving 11 tests.
On 2026-11-04, the ASan + non-recoverable-UBSan host build passed all nine
executable tests after the CTAP/PIN cleanup, including off-curve key-agreement
requests for protocols 1 and 2. The three build probes passed earlier in the
protocol-fix pass, using isolated temporary copies with `REMOVE_RECURSE`
omitted; their compilation and checks were unchanged. They were not rerun for
this cleanup. The Release firmware also passed `layout-check` after the cleanup.
See [the audit record](audit-plan.md#55-2026-11-04-ctappin-过度防御清理)
for commands and scope. These results are not a proof of correctness or security.

### Virtual HID automation

Linux host builds also produce `omk_virtual` from `host/virtual/device.c`.
It links the same `omk_core`, creates a 64-byte FIDO UHID interface and exposes
it through the kernel's hidraw path. The platform uses monotonic time,
`getrandom`, and a file-backed NOR model (256-byte page multiples, 4 KiB erases,
1-to-0 programming only, synchronized writes). The HTTP supervisor restarts
the process to model power cycling while preserving the Flash file.

`python3 host/virtual/run.py test` uses a dedicated Colima container and runs
the nine executable host tests plus fourteen independent `python-fido2` HID tests.
After protocol deduplication on 2026-11-05, both passed in 14.45 and 26.192 seconds.
The new extension regression checks protocol 1/2 interoperability, one/two salts,
and matching hmac-secret-mc/GetAssertion outputs with independently verified signatures.
The core validates complete algorithm and credential lists before selecting an
algorithm or matching a credential; unknown types remain valid non-matches.
Unsupported enterprise attestation requests return `INVALID_PARAMETER`.
Selection preserves the transport cancellation status `KEEPALIVE_CANCEL`.
The HID regressions now cover malformed request entries before and after valid
entries, algorithm preference, unknown credential types, enterprise attestation
rejection, Selection cancellation, and credProtect 1/2/3 with a configured PIN.
GCC's UBSan also exposed zero-length copies from null optional profile fields
in `omk_store_update_user`; those copies now run only for nonempty fields.
The existing user-update regression covers the failure.

The local official v1.9.3.1 tool also ran under Linux Electron 41.7.0 with its
test sources unchanged: the selected Generic/GetInfo and PIN 1/2 key-agreement
smoke passed 5 tests, skipped 2 unsupported-feature cases, and failed none
(6.622 seconds). The test metadata now includes the independent empty-store
capacity expectation of 64. Official UP runs through its HTTP callback, with
the simulator's automatic touch disabled.

The first full CTAP 2.3 list completed with 183 passes, 118 skips and 25 failures
(734.027 seconds); four were metadata configuration errors now corrected.
The official entry now defaults to the full list, with smoke/group/title filters,
coverage checks, retry records and environment hashes. npm dependencies are locked.
The runner acceptance completed all 326 cases: 187 passes, 118 skips and 21
protocol-test failures. Core fixes on 2026-11-05 removed those 21 failures:
the focused run passed 76, skipped 12 and failed none, without retries;
the full run passed 208, skipped 118 and failed none in 582.138 seconds.
ClientPin2-Policy F-2 passed only after three retries: the official assertion
expects PIN_POLICY_VIOLATION even for padded plaintext longer than 64 bytes,
where CTAP 2.3 §6.5.5.5 requires INVALID_PARAMETER. The implementation follows
the specification, with deterministic tests for 64/80/96/112/128-byte inputs.
After protocol deduplication, the full run again completed 208/118/0 in 579.020
seconds with no changed case outcomes. The same PIN-policy case needed one retry;
report: `build/virtual-hid/official/session-nu4hfwxm/result.json`.
Seven runner checks and real skip/timeout/interruption paths also passed.
This does not emulate RP2350 instructions, TinyUSB, the hardware RNG or Flash
timing; the result is not hardware certification or a retry-free full pass.
Commands and current evidence: [automation.md](automation.md).

### Fuzz targets

`OMK_FUZZ=ON` adds two libFuzzer targets (`omk_fuzz_cbor` and
`omk_fuzz_ctaphid`), a short `fuzz.smoke` run, and `fuzz.core_has_sancov`.
It builds a separate instrumented copy of the core with
`-fsanitize=fuzzer-no-link,address,undefined`; the normal `omk_core` stays
clean. Configuration fails with an actionable message when the selected
compiler has no libFuzzer runtime; stock Apple clang needs an LLVM
compiler-rt/libFuzzer runtime. The CTAPHID replay regression is built and run
with the normal host suite, so it works without libFuzzer. The fuzz preset has
not been run in this checkout: the host checks described above, including the
replay regression, are the verification evidence. The command-layer harness now invokes the real
`omk_ctap_handle`, but that broadens fuzz coverage only once a libFuzzer run is
actually performed. CI installs the matching Ubuntu compiler-rt package; no CI
result is claimed here.

### Firmware/linker/layout

The firmware build requires arm-none-eabi-gcc (13.2 or newer; 14.2+ is the
tested toolchain), pico-sdk exactly 2.3.1 and picotool 2.3.x. It defines
`PICO_STACK_SIZE=0x8000` (32 KiB) and `PICO_USE_STACK_GUARDS=1`, so the SDK
loads `__StackBottom` into MSPLIM and a stack overflow faults instead of
walking into static data.

The vendored linker fragments place the main stack in regular SRAM (not the
4 KiB SCRATCH_Y region), set `__StackLimit` and `__HeapLimit` to the stack
bottom, and assert:

* the main stack is exactly 32 KiB and ends at the top of RAM;
* `__StackLimit` is the stack bottom, not the top of RAM;
* `__end__` stays below the heap/stack ceiling;
* the upper 1 MiB of flash is exactly the FIDO store and the firmware image
  ends at or below its base (`0x10100000` in XIP terms).

`cmake/linker/region_check.c.in` independently asserts the core's
`OMK_FLASH_REGION_OFF/SIZE` and 4 KiB sector constants against
`PICO_FLASH_SIZE_BYTES`. The `layout-check` target inspects the real ELF with
`nm` rather than trusting the linker assertions, checking `__StackTop`,
`__StackBottom`, `__StackLimit`, `__HeapLimit`, `__end__` and
`__flash_binary_end`. `size` reports the text/bss totals.

### Configurable firmware version

`OMK_FIRMWARE_VERSION` is a CMake cache string (default `1`). CMake rejects
non-decimal values, values with leading zeros, and values above 2^32-1, then
passes the value as a compile definition. `omk_ctap.h` provides a fallback
default and a single-definition alias (`OMK_CTAP_FIRMWARE_VERSION`) for
getInfo key 14. The host probe preprocesses `omk_ctap.c` to verify that key 14
actually encodes the configured value. The number is metadata only: it is not
a certification claim, not a release signature and not an anti-rollback
counter.

## CTAPHID and the UP wait loop

`omk_ctaphid_rx_packet()` accepts one 64-byte report, performs channel
bookkeeping and reassembly, and calls the CTAP dispatcher synchronously only
when a complete message arrives. Message size is bounded at 2048 bytes and the
channel table holds 16 CIDs.

Transport behavior that is covered by regressions:

* KEEPALIVE is emitted at most once per 100 ms, starting immediately while a
  command is busy.
* CANCEL on the active channel sets a flag; the wait loop returns
  `CTAP2_ERR_KEEPALIVE_CANCEL` and the dispatcher sends it as a CBOR response.
  CANCEL itself is never answered.
* INIT on the active/busy channel latches an abort and replies immediately;
  the in-flight command returns without sending its own response.
* Only a broadcast INIT allocates a channel. A non-broadcast INIT for an
  unknown CID is rejected with `ERR_INVALID_CHANNEL` and never creates a
  channel implicitly. A broadcast INIT may still allocate while another
  channel is busy; a re-INIT on a different busy channel gets
  `ERR_CHANNEL_BUSY`.
* Any other command while busy gets `CTAPHID_ERR_CHANNEL_BUSY`; WINK goes
  through the same gate and is no longer a way to bypass it.
* When the 16-entry channel table is full, the least-recently-used channel is
  reclaimed, but a busy transaction and a channel with an active reassembly
  are never evicted.
* Stray continuation packets are ignored; a wrong sequence number produces
  `ERR_INVALID_SEQ`; a stalled reassembly times out after 500 ms and produces
  `ERR_MSG_TIMEOUT`.
* Reassembly state is ended before the dispatcher runs, so a long UP wait
  cannot age the just-completed message into a timeout. The idle main loop
  calls `omk_ctaphid_tick()` so timeouts are also serviced outside the wait.
* A failed TX enqueue is latched as `tx_fault` and the active transaction is
  aborted; a partially queued response is never reported as sent. A failure
  while replying to another channel does not kill the in-flight command.
* A USB bus reset clears channels, reassembly and TX state. If a synchronous
  dispatch is in flight, it latches an abort but keeps `busy` set until the
  dispatch epilogue, preventing re-entry on the shared buffers.

While a command waits for a touch, `omk_ctap_wait_up()` calls
`omk_ctaphid_poll()`; the platform's `hid_pump` runs `tud_task()`, drains OUT
reports and transmits queued IN reports. The firmware uses bounded 96-packet
TX and 64-packet RX queues with drop counters rather than blocking the core.

## CBOR

The decoder rejects indefinite lengths, non-minimal integer/length encodings,
duplicate keys, tags, floats, and nesting deeper than 8. Map order is accepted
as received; unknown keys are skipped by command handlers. The encoder emits
minimal heads and definite lengths. `omk_cbor_decode_prefix()` is used for
structures embedded in binary blobs (COSE keys in `authData`).

A fixed arena of 384 nodes lives in static storage (not on the 32 KiB stack).

## Persistent storage

Reserved flash: 1 MiB at `0x00100000` (relative offsets below).

```text
0x00000  meta log: 8 sectors x 16 records x 256 bytes (append-only snapshots)
0x08000  credential bank A: 496 KiB, 124 x 4 KiB sectors, 496 x 1 KiB slots
0x84000  credential bank B: 496 KiB, 124 x 4 KiB sectors, 496 x 1 KiB slots
```

The two banks end exactly at the end of the reserved region. There is no heap
and no variable-length array in the store.

### Version 2 meta log

Each meta record is a complete 256-byte state snapshot with magic/version/kind,
a monotonically increasing 64-bit sequence number, and a CRC32 over the first
120 bytes. The snapshot carries:

* reset, log and PIN epochs;
* active bank and PIN state (set flag, retry count, candidate-attempt marker,
  PIN epoch);
* signature-counter lease and next credential sequence;
* master secret, AAGUID and truncated PIN hash;
* the pending PIN candidate hash, when an attempt is in flight.

Records are appended to the current sector. When the sector is full the next
sector is selected (wrapping through the eight sectors); a whole sector is
erased before reuse. A write is acknowledged only after a byte-for-byte read-back. A failed write
or read-back fault leaves mirrored RAM state uncommitted (rolled back in RAM).
A torn write is skipped by CRC at boot, leaving the previous snapshot
authoritative; however, if flash programming completed before a read-back fault
or power cut, the new record may already be durable on Flash with a valid CRC
and will become authoritative upon reboot. The append cursor advances past a
slot that may have been dirtied, so a same-boot retry does not program it again; a separate authoritative-sector guard prevents a
ring of failed appends from erasing the only recoverable snapshot. Local
copies of the record, including the master key and PIN material, are wiped
before return.

At boot the loader scans the whole meta log for a valid v2 snapshot with the
highest sequence number. If several snapshots are present, the newest complete
one wins. Non-blank records that are not valid v2 snapshots are skipped during
this scan; they are only treated as a fatal image when no valid snapshot
exists (see below).

### Boot policy and legacy images

The loader distinguishes these cases before any write or erase:

| Result | Meaning |
|---|---|
| valid v2 snapshot | load the newest one; unrelated unknown or torn non-blank records do not block recovery |
| entire meta region erased | true first boot; format with a fresh identity |
| only torn v2 records, no valid snapshot | recognized recovery case; format with a newer epoch |
| read error | fail init |
| CRC-valid v2 record with impossible fields | fail init |
| no valid v2 snapshot and any non-blank record is v1, unknown version or foreign magic | fail init |

A valid v2 snapshot takes precedence over non-blank records in any other class.
In particular, a power cut that programs only 1-9 bytes of a newly appended
record (damaging its magic, version, kind or CRC) leaves the previous snapshot
recoverable: the partial record is skipped and the append cursor is advanced
past the last non-blank slot, so the next record is never programmed over stale
bytes. Only when no valid snapshot exists do legacy/foreign records fail init.

On a failure the store is wiped from RAM and `omk_store_init()` returns -1;
`omk_ctap_init()` returns -1 and the firmware does not start USB. The rejected
flash bytes are left byte-identical, so a legacy store is not silently
factory-formatted. **No v1-to-v2 migration exists:** v1 deliberately fails
closed and needs an explicit recovery decision.

Formatting generates a fresh master secret before touching flash and installs
the fixed model AAGUID (`68d840c1-b0aa-5d75-bbbb-c4f3f6c789b3`). The AAGUID
is a UUIDv5 model identifier, not per-device random state; older per-device
values are ignored on load and replaced on the next meta persist. Formatting
scans both credential banks for the highest surviving log epoch, and starts
the new store at `max_epoch + 1` (or a fresh epoch on a blank device). It
then erases the eight meta sectors and appends the first snapshot. Credentials
in either bank are not imported; because the new epoch is newer than any
surviving record, they are not selected. A format therefore creates a new
identity rather than preserving old credentials.

A power cut during a meta-sector erase can leave a partial record whose header
no longer matches v2. When a valid v2 snapshot survives elsewhere in the log,
the loader recovers that snapshot and skips the partial slot, so this cut is
tolerated. If no valid snapshot remains at all, the partial image is rejected
without writing, so recovery still requires an explicit decision rather than a
silent format. This is one reason the fail-closed policy is not a guarantee
against all power-loss outcomes.

### Credential log and compaction

Credential records are 1 KiB slots: a 32-byte header (magic/version/type/
flags/epoch/sequence/payload length/CRC32) plus payload. Record types are
credential creation, deletion and user-info update. Every record is tagged
with the current `log_epoch`; the loader reads only the active bank and ignores
records whose epoch does not match. A torn or invalid record is skipped
independently, and the append cursor is placed after the last non-blank slot
so a later append never programs over stale bytes. A failed append also
advances the in-RAM cursor past the suspect slot, allowing the same boot to
retry without waiting for the boot-time scan.

The in-RAM index is rebuilt at boot. Overwriting a credential for the same
`rp.id` + `user.id` replaces its index entry; deletes and updates append new
records. The store holds at most 64 resident credentials
(`OMK_MAX_CREDENTIALS`); each bank has 496 slots, so a full set of live
credentials fits during compaction.

When the active bank runs out of slots, `log_compact()`:

1. erases the inactive bank and verifies every byte reads back as `0xFF`;
2. copies every live credential, ordered by creation sequence, into it using
   `log_epoch + 1`, verifying each write by read-back;
3. appends one verified meta snapshot that switches `active_bank` and commits
   the new `log_epoch`.

Only after step 3 is the new bank authoritative. The old bank is not erased
and remains readable, but its records carry the old epoch and are never
selected. A cut before the meta commit leaves the old bank authoritative; a cut
during the erase or copy leaves the target bank unrecognized or incomplete,
which is also inert because the epoch switch never happened. A later
compaction erases and replaces the old bank. The sensitive meta copy and other
compaction temporaries are wiped on every success and failure exit.

Between sector erases, sector verification units and credential copies,
`omk_port.long_op_poll()` services USB and emits processing KEEPALIVEs. A
CANCEL or abort stops before the meta commit and returns a distinct storage
cancellation status. This is cooperative, not pre-emptive: an individual Flash
ROM operation still runs to completion, and no physical timing guarantee is
claimed without hardware measurement.

### Reset and epochs

`authenticatorReset` is accepted only in the first 10 seconds after boot and
requires UP. The store reset:

* generates a fresh master secret before touching flash and keeps the fixed
  model AAGUID unchanged;
* erases the inactive bank and verifies it is blank, with the same cooperative
  KEEPALIVE/CANCEL boundaries as compaction;
* installs one verified meta record that bumps the reset, log and PIN epochs,
  clears PIN state and retries (back to 8), clears the pending candidate,
  resets the counter lease and sequence, and switches to the empty bank.

The previous bank is left physically in place. Old credential records are
inert because the active bank changed and their `log_epoch` no longer matches;
historical meta snapshots are superseded by the higher sequence number but are
not necessarily erased until their sector is reused. This is logical
invalidation, not a guarantee of secure physical erasure.

The separate epoch fields have distinct jobs. `log_epoch` is the tag compared
against credential records. `reset_epoch` and `pin_epoch` are monotonic
state-generation values that are persisted and validated (non-zero, no wrap);
the current credential path does not use them as a second record filter. Reset
bumps all three.

After a successful Reset the CTAP layer clears the whole live
authorization/extension state, not just `token_valid`: PUAT bytes and flags,
PIN shared AES/HMAC keys, GetAssertion continuation and hmac-secret salts/keys,
CredentialManagement cursors, the per-boot PIN fault latch, and the consecutive
PIN-failure count. A failed Reset leaves the old state and the fault latch
intact.

### Signature counter

The counter is leased from flash in 64-value steps. Boot starts the RAM counter
at the persisted lease. Each assertion or MakeCredential increments the RAM
value; when it crosses the lease, a new lease (`current + 63`, capped at
`UINT32_MAX`) is persisted *before* the value is used. A power cut can skip
values but the design avoids reusing one, because the lease extension is
durable before the value leaves the device. A failed lease write returns 0
without changing the RAM counter; an exhausted counter also returns 0, and the
CTAP paths map that to `CTAP2_ERR_OTHER`. MakeCredential requests the counter
only after all random operations (key generation, credential-ID sealing,
hmac-secret IV) have succeeded.

### Credential IDs

Non-resident credentials are self-contained, 68 bytes:

```text
[0]       version 0x01
[1]       flags (bit 0: resident)
[2]       algorithm (1 = ES256, 2 = EdDSA)
[3]       credProtect level
[4..19]   random CBC IV
[20..51]  AES-256-CBC(seed)      seed = 32-byte private key material
[52..67]  HMAC-SHA-256(...) truncated to 16 bytes
```

The MAC covers the first 52 bytes plus the RP ID hash, so an ID presented for
a different RP fails to authenticate. Resident credential IDs use the same
format but are additionally checked against the resident index, so deleting a
passkey invalidates its ID even though the ID is self-contained. If the
random IV cannot be produced, sealing returns 0 and leaves the caller's output
buffer untouched; MakeCredential then reports `CTAP2_ERR_OTHER` without storing
a credential or consuming the counter.

## Credential responses and implementation boundaries

ES256 signatures in packed self-attestation and assertions are ASN.1 DER
`Ecdsa-Sig-Value`; the crypto primitive still returns fixed-width `r || s`.
The CTAP adapter removes redundant leading zeros, adds a sign-protecting zero
when needed, and reserves 72 bytes. Ed25519 signatures remain 64 bytes.
MakeCredential reads `attestationFormatsPreference` from key `0x0B`, including
`["none"]`; key `0x0A` is not used as a format list.

CredentialManagement emits and accepts `PublicKeyCredentialDescriptor` maps
(`id` byte string and `type: "public-key"`). Delete/update authorization still
covers the original encoded `subCommandParams`, not a reconstructed map.

Assertions do not return a public key. Before consuming the signature counter,
they validate the algorithm and check an ES256 scalar is in `[1, n-1]` via
`omk_p256_scalar_valid`, without performing a public-key multiplication.
Ed25519 accepts any 32-byte seed. The signing primitive still checks its inputs
and propagates failure. This preserves rejection of invalid credentials while
removing the unused public-key computation.

Credential enumeration begin/next share `emit_cm_credential` for opening the
credential, deriving its required public key, encoding the response and wiping
scratch buffers. Only the first response includes `totalCredentials`. Cursor
selection, expiry and deletion handling remain in the callers. The command
entry point validates and authorizes the RP hash once, then passes the checked
hash to the begin helper.

Regression tests independently parse DER before cryptographic verification,
check descriptor maps, exercise scalar boundaries and unknown algorithms, and
compare enumeration public keys with the original registration public keys.

## PIN / UV

PIN/UV Auth protocols 1 and 2 are both implemented, in the advertised order
`[2, 1]`:

* protocol 1: `shared = SHA-256(ECDH_x)`, AES-256-CBC with zero IV,
  16-byte HMAC tags;
* protocol 2: HKDF-SHA-256 with `"CTAP2 HMAC key"` / `"CTAP2 AES key"`,
  random IV prepended to CBC ciphertext, 32-byte HMAC tags.

The stored PIN value is `LEFT(SHA-256(PIN), 16)`. PIN length is 4..63 bytes and
at least 4 UTF-8 codepoints. The PIN/UV key-agreement key is a separate
ECDH-ES+HKDF-256 COSE key (alg -25), not an ES256 credential key (-7).

A single 32-byte `pinUvAuthToken` carries a permission mask, optional RP ID
binding, a 30 s first-use/idle window and a 10 min absolute lifetime.
`getPinUvAuthTokenUsingPinWithPermissions` accepts only `mc`, `ga` and `cm`.
A successful UP consumes the token. The key-agreement key is rotated after a
failed PIN comparison so a platform that learned or tried to brute-force the
old shared secret cannot keep using it; if rotation cannot obtain randomness,
the derived shared secrets are cleared and the command fails closed.

Token validity is checked only on the authorization path; its tests exercise
that same path rather than maintaining a second validity-query implementation.
The unused `shared_ready` and `pin_initialized` flags have been removed;
initialization failure and Reset tests check actual key/state cleanup.

ClientPIN and extension parsers validate the COSE shape and coordinate lengths;
the ECDH primitive validates the curve point before scalar multiplication.
PIN decryption checks ciphertext shape and output capacity before writing,
and success guarantees the requested plaintext length. Callers do not repeat
that length check or receive a redundant output-length parameter.

### PIN candidate-attempt journal and boot resolution

The persistent retry counter is 8. A PIN attempt is committed in this order:

1. Reject early if the store is faulted, no PIN is set, retries are already 0,
   or three consecutive failures have occurred since boot
   (`PIN_AUTH_BLOCKED`).
2. Persist a meta record with `retries - 1`, `attempt_valid = true`, and the
   16-byte candidate hash. This record is the linearization point: the
   decrement is durable before the caller is allowed to compare.
3. Compare the candidate with the stored PIN hash.
4. On a match, persist `retries = 8` and clear the marker. On a mismatch,
   persist the cleared marker while keeping the decrement, rotate the
   key-agreement key, and report `PIN_BLOCKED` if this attempt exhausted the
   counter, `PIN_AUTH_BLOCKED` after three per-boot failures, otherwise
   `PIN_INVALID`.

If a step-2/4 write or read-back fails, the command returns
`CTAP2_ERR_OTHER`, no token is issued, and a per-boot `pin_store_fault` latch
makes later PIN verification fail closed until the next boot. A successful
Reset clears that latch; a failed Reset keeps it.

At boot, after loading the meta snapshot and credential index,
`store_resolve_attempt()` handles a persisted but unresolved attempt:

* a candidate equal to the stored PIN hash is completed as a success
  (retries restored to 8);
* a different candidate keeps the committed decrement;
* the marker is cleared.

The resolution write is best-effort. If it fails, the safe RAM retry value is
still live and the marker remains for the next boot or a later meta write.
This closes the window where a power cut after the decrement but before the
comparison could otherwise leave the result ambiguous.

### Host-simulation limits for the PIN journal

`test_store` models a 1 MiB NOR-like array: page writes are 256-byte aligned
and can only clear bits, erases are 4 KiB sector operations, and a cut at
operation *k* leaves a 1/4, 1/2 or 3/4 prefix programmed/erased before the
"device" reboots. The PIN tests cut at every observed read/write/erase
operation for wrong, correct and last-retry attempts, and check the state both
immediately after reboot and after a second reboot. These tests exercise the
persistence asymmetry: an unacknowledged write or read-back failure rolls back
RAM state, but cannot guarantee that the write had no effect on Flash; if
programming completed before the cut, reboot recovers the newer valid record
rather than rolling back Flash.

This is a deterministic software model, not a hardware power-cut test. It does
not model page-program timing, partial-page behavior beyond a prefix,
erase-suspend/brownout behavior, wear or bad blocks, cache/read-disturb
effects, USB power sequencing, or an attacker with BOOTSEL/picotool readout.
`test_ctap` uses a simpler byte-array flash model and command-level failure
injection; it does not cut every CTAP command at every flash operation. The
deterministic RNG in these tests fills part of the output and then reports
failure, which exercises the "discard partial secrets" contract, but it is not
a hardware TRNG model.

## Extensions

* `hmac-secret`: the per-credential secret is derived with HKDF-SHA-256 from
  the credential seed with a domain-separation string and a UV flag, so
  non-resident credentials work too. 32- and 64-byte salts are supported;
  protocol 1 and 2 key agreement and CBC operations share `omk_pin_protocol`
  with ClientPIN. The module takes explicit inputs and never accesses `omk_ctap`;
  each command retains its own state, error mapping and allowed plaintext sizes.
  The request HMAC key is local to parsing and cleared after MAC computation
  or agreement failure. Continuation state retains the salts and AES key needed
  for subsequent assertions. Decryption accepts only 32/64-byte plaintexts;
  request parsing relies on that result without repeating the length check.
* `hmac-secret-mc`: the same computation during MakeCredential, returned in
  `authData.extensions`; it requires the `hmac-secret` boolean in the request.
* `credProtect`: stored in the credential ID and resident record. Without UV,
  level 1 allows discovery, level 2 requires an explicit credential ID, and
  level 3 is not usable; excludeList ignores level 3 without UV. Setting a PIN
  does not change these policies. Unverified assertions omit user names.
  MakeCredential echoes the adopted value only when it was requested.

## RNG failure behavior

`omk_port.random_bytes` returns `bool`. On failure the output buffer may hold a
partially written prefix and **every caller must discard the whole buffer**
rather than derive a secret from it.

| Call site | Behavior on false |
|---|---|
| store format (master) | init fails before any write/erase |
| store reset (master) | reset fails; old state and flash remain intact |
| credential-ID sealing IV | no usable ID; MakeCredential returns `ERR_OTHER`, stores nothing, consumes no counter |
| P-256 key generation | `ERR_OTHER`; no credential stored and no counter consumed |
| Ed25519 seed generation | `ERR_OTHER`; no credential stored and no counter consumed |
| PIN key-agreement initialization | CTAP init fails; no partial key pair installed |
| PIN key-agreement rotation | old agreement key kept, shared secrets cleared, command returns `ERR_OTHER` |
| PIN token bytes | `ERR_OTHER`; any previous token was invalidated first and no new token is installed |
| PIN protocol-2 encryption IV | `ERR_OTHER`; no token response is emitted |
| hmac-secret encryption IV | `ERR_OTHER`; no extension output is emitted |
| CTAPHID CID allocation | `CTAPHID_ERR_OTHER`; no channel is added and no zero/partial CID is used |
| firmware port | currently always returns true (see below) |
| host test mocks | return false with a partial fill; tests assert the partial bytes are not used |
| fuzz harness | supplies deterministic bytes and always succeeds |

The RP2350 port currently uses `pico_rand`'s non-failing `get_rand_32()` API.
The SDK mixes fresh TRNG samples into a xoroshiro128** state, but its raw TRNG
sampling path bypasses the hardware health checks and exposes no entropy
failure to this adapter. Consequently the adapter always returns true and the
firmware does **not** currently satisfy the port's CSPRNG/failure-propagation
contract. The core and host mocks still exercise false returns correctly. A
release requires a reviewed hardware entropy source with bounded health
checks and real failure propagation; merely relabelling `pico_rand` as a
CSPRNG is not a fix.

## Security / release limitations (current)

The current phase is dev. OTP provisioning and boot/flash locking are outside
this phase; the physical-protection notes below describe the boundary for
future release work, not defects in the current protocol implementation.

* The firmware RNG cannot detect or propagate entropy-source failure, as
  detailed above. This remains a security-release blocker.
* The development USB identity is still Raspberry Pi VID `2E8A` with the
  officially unallocated PID `10A1`. Do not release with this identity; an
  allocated PID (or a different owned VID/PID) is a release decision, not a
  value the firmware should invent.
* No hardware FIDO Alliance conformance run. The CTAP 2.3 default-profile suite
  has not been executed against a physical device, so certification is not
  claimed.
* No physical power-cut, brownout or wear test. The host NOR model cuts at
  individual operations but cannot reproduce hardware timing and analog
  effects.
* No BOOTSEL/flash-rewrite anti-rollback, no OTP-backed key wrapping and no
  secure boot. The master secret and PIN hash are plaintext in external NOR
  flash and can be read back with picotool unless other hardware protection is
  present. The configurable firmware version is metadata, not rollback
  protection.
* Old credential-bank records are made epoch-inert and historical meta
  snapshots are superseded by newer records, but neither is necessarily
  securely erased. Flash may retain old master-key/PIN/credential material
  until sectors are reused, and reuse is not a verified sanitisation procedure.
* P-256 is not constant-time: the scalar loop is masked, but field/point
  helpers branch on carries, infinity and equality, and inversion chains are
  operand-dependent. AES uses table lookups. Ed25519's mask-based selects are
  a source-level property the compiler may turn into branches. None of these
  implementations is proven constant-time, and no timing/power-analysis
  guarantee is made.
* Secret buffers at the API boundary are wiped, but deeper field/point,
  SHA-512 and stack scratch is not individually wiped, and the compiler or
  calling convention may leave copies. Deeper scratch cleanup is not a formal
  guarantee.
* V1, unknown-version and foreign meta images fail closed with no write or
  erase **when no valid v2 snapshot is present**, and **no migration is
  implemented**. A legacy store needs an explicit recovery decision. When a
  valid v2 snapshot is present, unrelated unknown or torn non-blank records
  (such as a 1-9 byte torn prefix of an appended record) are skipped and the
  snapshot is recovered. A power cut during meta-sector erase that leaves no
  valid snapshot can leave an unrecognized partial image that fails init; this
  requires recovery.
* Second-batch features remain unimplemented and unadvertised:
  `authenticatorConfig`, `credBlob`, `largeBlobs`, `alwaysUv`,
  `minPinLength`/`setMinPINLength`, built-in UV/biometrics, U2F/CTAP1 and
  persistent PIN/UV auth tokens.
