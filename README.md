# OhMyKei

A programmer-oriented hardware passkey & security key firmware targeting the **Waveshare RP2350-Zero-CM** (RP2350A, 2MB NOR Flash, USB Type-C Male), written from scratch in C17 under the MIT license.

## Status

OhMyKei now contains a working CTAP 2.x protocol core: strict CBOR, CTAPHID
transport, P-256/Ed25519 crypto, flash-backed resident credentials, and the
`authenticatorGetInfo`, `MakeCredential`, `GetAssertion`, `GetNextAssertion`,
`ClientPIN` (protocols 1 and 2), `Reset`, `Selection` and
`CredentialManagement` commands. `hmac-secret`, `hmac-secret-mc` and
`credProtect` are implemented. The RP2350 firmware exposes a single
driverless USB HID (FIDO usage page) interface; the CDC debug interface has
been removed.

Implemented:

- CTAPHID: INIT/PING/CBOR/CANCEL/ERROR/KEEPALIVE/WINK, `NMSG` capability,
  non-blocking UP waits, cross-channel busy handling, and LRU channel
  reclamation that never evicts a busy channel or an active reassembly.
- Strict CTAP2 CBOR decoder/encoder (duplicate keys, indefinite lengths and
  non-minimal encodings rejected).
- ES256 (P-256, RFC 6979) and EdDSA (Ed25519) credentials, self-attestation
  (`packed`) and `none`. ES256 wire signatures use ASN.1 DER; Ed25519 stays
  64 bytes. MakeCredential reads `attestationFormatsPreference` at `0x0B`.
- Resident and non-resident credentials, RP/user overwrite semantics,
  lease-based signature counter, dual-bank credential log and compaction.
- Version 2 append-only meta log (8 sectors of 256-byte snapshots) plus two
  496 KiB credential-log banks (124 4-KiB sectors, 496 1-KiB slots each);
  compaction and Reset switch banks through one verified meta record carrying
  a new log epoch.
- PIN/UV Auth protocols 2 and 1, `getPinToken` compatibility, PUAT
  permissions and RP binding, persistent retry counter with a journaled PIN
  candidate resolved at boot.
- `hmac-secret` (32/64-byte salts, `age`/PRF use), `hmac-secret-mc`,
  `credProtect`, CredentialManagement enumeration/delete/update using
  `PublicKeyCredentialDescriptor` maps for credential identifiers.
- Host tests (12 registered CTest entries under ASan + non-recoverable UBSan)
  and libFuzzer harnesses for CBOR and CTAPHID.

Not implemented yet (kept out of `getInfo`): `authenticatorConfig`,
`credBlob`, `largeBlobs`, U2F/CTAP1, built-in UV/biometrics, `alwaysUv`, and
the second-batch `minPinLength` policy hooks.

> **Verification state (2026-11-04):** the host build with AddressSanitizer
> and non-recoverable UndefinedBehaviorSanitizer passed all nine executable
> tests after the CTAP/PIN cleanup. Three build probes passed earlier in the
> protocol-fix pass using isolated temporary copies with destructive cleanup
> omitted; they were not rerun for this cleanup. See [audit evidence](docs/audit-plan.md#55-2026-11-04-ctappin-过度防御清理).
> This result does **not** include a libFuzzer run. A Release
> firmware build passes the committed `layout-check` target (32 KiB stack and
> image placed below the upper 1 MiB store). The firmware has **not** been run against the FIDO
> Alliance conformance suite on physical hardware, and there has been **no
> physical power-cut test**. Treat this as a development build, not a
> certified authenticator.

The CTAP/PIN cleanup removes duplicate curve and post-decryption length
checks, unused state flags and the duplicate token-validity query. Extension
HMAC keys now remain local to request parsing and are cleared after use.

---

## Prerequisites

OhMyKei uses **CMake + Ninja** and the official Raspberry Pi **`pico-sdk` (2.3.1)** for RP2350 hardware drivers.

The RP2350-Zero-CM is the upstream Zero with 2 MB flash instead of 4 MB; the build uses the official `waveshare_rp2350_zero` board header and overrides only the flash region with `pico_override_flash_size()`.

Required tools on `PATH`:
- `cmake` (>= 3.25) and `ninja`
- `python3`
- `arm-none-eabi-gcc` (Arm GNU Toolchain 14.2+ with `newlib`)
- `picotool` (2.3.x)
- `clang` for host tests and fuzzing (libFuzzer requires LLVM's compiler-rt)

### Locating `pico-sdk`

The build searches for `pico-sdk` in the following order:
1. CMake cache option: `-DPICO_SDK_PATH=/path/to/pico-sdk`
2. Environment variable: `$PICO_SDK_PATH`
3. Default path used by the official Raspberry Pi Pico VS Code extension: `~/.pico-sdk/sdk/2.3.1`
4. `~/pico-sdk`

There is no implicit network fetch: a missing SDK stops configuration with an actionable error instead of cloning a large repository.

If you don't have `pico-sdk` installed yet:

```bash
git clone --branch 2.3.1 --depth 1 --recurse-submodules \
    https://github.com/raspberrypi/pico-sdk.git ~/.pico-sdk/sdk/2.3.1
```

---

## Build & Flash

```bash
# 1. Configure the firmware (Release by default)
cmake --preset fw-release

# 2. Compile: build/fw-release/ohmykei.elf and build/fw-release/ohmykei.uf2
cmake --build --preset fw-release

# 3. Flash over USB
cmake --build --preset fw-release --target flash
# or: picotool load -f -x build/fw-release/ohmykei.uf2

# 4. Inspect size and verify the linked stack/flash layout
cmake --build --preset fw-release --target size
cmake --build --preset fw-release --target layout-check
```

The whole firmware workflow can also be run in one shot:

```bash
cmake --workflow --preset fw-release
```

For debugging, use `cmake --preset fw-debug` / `cmake --build --preset fw-debug`; the artifacts land in `build/fw-debug/`.

### Firmware version reported by `getInfo`

`OMK_FIRMWARE_VERSION` is a build/configuration value for CTAP `getInfo` key
14. It defaults to `1`; pass a non-negative decimal integer when configuring:

```bash
cmake --preset fw-release -DOMK_FIRMWARE_VERSION=2
```

Leading zeros (for example `08`) are rejected at configure time, as are values
that do not fit in a CTAP unsigned integer. The value is metadata only: it does
not imply certification, and it is not an anti-rollback or release-trust
mechanism.

> **First-time flash**: If the board is currently running factory firmware without USB reset support, hold down the physical **BOOT** button while plugging it into USB, run `picotool load -f -x build/fw-release/ohmykei.uf2`, and subsequent flashes will reboot automatically without pressing buttons.

---

## Host Tests & Fuzzing

For automated end-to-end testing without a board, with Colima already running:

```bash
python3 host/virtual/run.py test
```

This builds the real core with ASan/UBSan, runs the nine executable host tests,
then runs ten `python-fido2` tests through Linux hidraw/UHID. It verifies ES256
and Ed25519 signatures, PIN protocols, credential management, persistence,
cancellation, user presence and the Reset window. See [virtual HID automation](docs/automation.md)
for setup, persistent-device mode and the official-tool integration boundary.

`python3 host/virtual/run.py official` runs a clean instance of the local
official v1.9.3.1 tool under Linux Electron 41.7.0. Its selected GetInfo and
PIN 1/2 key-agreement smoke passed 5 tests with 2 unsupported-feature skips
on 2026-11-04; this is not a full conformance-suite result.

The host build is deliberately independent of `pico-sdk`, so protocol code can be tested on macOS/Linux with sanitizers:

```bash
cmake --preset host
cmake --build --preset host
ctest --preset host
```

With the default `OMK_SANITIZE=ON`, the host configuration registers **12
CTest entries**: eight unit/regression executables (`test_build_smoke`,
`test_crypto`, `test_cbor`, `test_ctaphid`, `test_p256`,
`test_crypto_ed25519`, `test_ctap`, `test_store`), the CTAPHID fuzz-replay
regression, the non-recoverable-UBSan probe, the firmware-version definition
probe, and the core SanitizerCoverage check. The unit tests cover
known-answer crypto vectors, CBOR strictness, CTAPHID state machines, CTAP
workflows, and a NOR-like flash model with power-cut injection at individual
read/write/erase operations. With sanitizers disabled the UBSan probe is not
registered (11 entries).

The CBOR and CTAPHID harnesses use libFuzzer (a smoke target is kept for
toolchain checks):

```bash
cmake --preset fuzz
cmake --build --preset fuzz
ctest --preset fuzz

# or drive a harness directly
./build/fuzz/host/omk_fuzz_cbor -runs=1000
./build/fuzz/host/omk_fuzz_ctaphid -runs=1000
```

The fuzz preset additionally registers `omk_fuzz_cbor`, `omk_fuzz_ctaphid`,
`fuzz.smoke` and `fuzz.core_has_sancov` alongside the normal host entries.
A libFuzzer runtime is required; stock Apple clang does **not**
ship one, so configuration fails with an actionable error. The command-layer
CTAPHID harness now calls the real `omk_ctap_handle`, but the fuzz preset has
**not** been run in this checkout. The repository CI installs the matching
Ubuntu compiler-rt package; that is configuration only until the workflow has
actually run. To use a Homebrew LLVM locally:

```bash
brew install llvm
cmake --fresh --preset fuzz \
  -DCMAKE_C_COMPILER="$(brew --prefix llvm)/bin/clang"
cmake --build --preset fuzz
ctest --preset fuzz --output-on-failure
```

On Linux, a Clang installation with compiler-rt/libFuzzer works. The normal
host suite also builds `test_fuzz_ctaphid_replay` without libFuzzer: it replays
captured inputs in a different order and requires byte-identical output,
catching leaked channel/time/RNG state. Only that replay regression is verified
in the current checkout; it is not evidence that libFuzzer has run.

---

## Repository Structure

```text
.
├── CMakeLists.txt              # Firmware + host entry points
├── CMakePresets.json           # fw-release / fw-debug / host / fuzz
├── cmake/
│   ├── core-sources.cmake      # Shared firmware/host protocol-core source list
│   ├── pico_sdk.cmake          # pico-sdk discovery
│   └── linker/                 # 32 KiB stack, flash-end assertions, layout check
├── src/
│   ├── main.c                  # Firmware entry point
│   ├── omk_port.h              # Platform abstraction used by the core
│   ├── crypto/                 # SHA-256/512, HMAC, HKDF, AES-256, P-256, Ed25519
│   ├── fido/                   # CBOR, CTAPHID, CTAP commands, storage
│   └── platform/               # TinyUSB HID, flash, button, LED
├── host/
│   ├── tests/                  # 8 CTest suites plus fuzz replay regression
│   ├── check_*.cmake           # UBSan, firmware-version and sancov probes
│   └── fuzz_*.c                # libFuzzer targets
├── docs/
│   ├── ROADMAP.md              # Goals, current status and development order
│   ├── road.md                 # CTAP 2.3 scope decisions
│   ├── IMPLEMENTATION.md       # Design, storage/PIN details, limitations
│   └── audit-plan.md           # Audit evidence, fixes and remaining blockers
└── tools/                      # Local FIDO conformance tooling
```

## Usage notes

- Enumerate the device as `OhMyKei FIDO2 Security Key`; browsers, `libfido2`
  and OpenSSH see a standard CTAP2 HID authenticator.
- The on-board BOOT button acts as the user-presence (UP) button during
  operation. A short press confirms registration/login.
- `authenticatorReset` is accepted only in the first 10 seconds after boot and
  requires a button press. It installs a fresh master secret, keeps the model
  AAGUID unchanged, clears the PIN and resident credentials, and bumps the
  reset/log epochs. The previous credential bank is left in place and becomes
  logically inert; it is not guaranteed to be physically erased.
- Set a PIN from the platform (`ClientPIN`); PIN verification also sets the UV
  flag, so `credProtect` levels 2/3 and PRF workflows that need UV work.
- Signature counters use 64-value leases. Resident credentials are appended to
  one of two 496 KiB log banks and compacted into the other bank when full;
  there is room for 64 resident credentials, after which creation reports
  `KEY_STORE_FULL`.
- A legacy v1 meta image, an unknown version or a foreign non-blank meta image
  makes store initialisation fail closed without writing or erasing anything.
  There is no v1-to-v2 migration; an affected device needs an explicit recovery
  decision rather than an automatic factory format.

## Current limitations

This is the dev phase. OTP provisioning and boot/flash locking are outside
the current implementation scope; their absence is a development boundary,
not a defect introduced by these protocol changes.

- The RP2350 RNG adapter cannot detect or propagate entropy-source failure;
  `pico_rand` must not be treated as satisfying the core CSPRNG/failure
  contract for a security release. The development USB PID `2E8A:10A1` is also
  unallocated and must be replaced with an allocated identity before release.
- No FIDO Alliance conformance run on physical hardware, and no physical
  power-cut/brownout test. The host flash model is useful but not a substitute.
- No BOOTSEL/flash-readback anti-rollback, OTP-backed key wrapping or secure
  boot. The master secret and PIN hash are still stored in external NOR flash
  and can be read back with picotool unless the hardware is otherwise
  protected.
- Old credential-bank records are made epoch-inert and historical meta-log
  snapshots are superseded, but neither is necessarily securely erased by
  design.
- The software P-256, table-based AES and Ed25519 implementations are not
  proven constant-time. Only source-level mitigations and limited buffer wiping
  are present; deeper scratch cleanup is not a formal guarantee.
- The second-batch features listed above remain unimplemented and are not
  advertised in `getInfo`.

See [IMPLEMENTATION.md](docs/IMPLEMENTATION.md) for the detailed design and
test/simulation limits.

## License

MIT License. See [LICENSE](LICENSE).
