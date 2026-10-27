# OhMyKei

A programmer-oriented hardware passkey & security key firmware targeting the **Waveshare RP2350-Zero-CM** (RP2350A, 2MB NOR Flash, USB Type-C Male), written from scratch in C17 under the MIT license.

## Security Philosophy

1. **Zero Compromise over USB**: All protocol parsers (CTAPHID, CBOR, CCID, APDU, TLV) and state machines are decoupled from hardware headers so they compile natively on the host with `libFuzzer + ASan/UBSan`. Every sensitive operation requires physical User Presence (BOOTSEL press).
2. **Stop the "20-Minute Easy Hack"**: General-purpose MCUs are not CC EAL6+ Secure Elements. Instead of over-engineering against lab-grade decapping/FIB attacks, hardware defenses focus on buying the user a **>20-minute reaction window** against opportunistic physical access (AEAD at-rest encryption derived from PIN KDF + on-chip secret, partition table `bootloader: ""` blocking `picotool save --all` dumps, and a one-command `omk lock`). Dev boards stay unlocked; **any key in real use must run `omk lock`**.
3. **Kill-Switch (`omk revoke`) & Heartbeat**: If a key is lost, the user runs `omk revoke` (or a dead-man's switch / heartbeat triggers it) within the reaction window to automatically revoke SSH/GPG keys on GitHub, GitLab, and remote servers, and walk through WebAuthn credential rotation.

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full architecture and milestone plan.

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

# 4. Inspect size
cmake --build --preset fw-release --target size
```

The whole firmware workflow can also be run in one shot:

```bash
cmake --workflow --preset fw-release
```

For debugging, use `cmake --preset fw-debug` / `cmake --build --preset fw-debug`; the artifacts land in `build/fw-debug/`.

> **First-time flash**: If the board is currently running factory firmware without USB reset support, hold down the physical **BOOT** button while plugging it into USB, run `picotool load -f -x build/fw-release/ohmykei.uf2`, and subsequent flashes will reboot automatically without pressing buttons.

---

## Host Tests & Fuzzing

The host build is deliberately independent of `pico-sdk`, so protocol code can be tested on macOS/Linux with sanitizers:

```bash
cmake --preset host
cmake --build --preset host
ctest --preset host
```

Fuzz targets use libFuzzer:

```bash
cmake --preset fuzz
cmake --build --preset fuzz
ctest --preset fuzz

# or drive the harness directly
./build/fuzz/omk_fuzz_smoke -runs=1000
```

On macOS, Apple's clang does **not** ship the libFuzzer runtime. Install LLVM and point the fuzz preset at it:

```bash
brew install llvm
rm -rf build/fuzz   # discard the cache from the Apple-clang attempt
cmake --preset fuzz -DCMAKE_C_COMPILER="$(brew --prefix llvm)/bin/clang"
cmake --build --preset fuzz
```

On Linux, any Clang with compiler-rt works: `cmake --preset fuzz -DCMAKE_C_COMPILER=clang`.

---

## Repository Structure

```text
.
├── CMakeLists.txt              # Firmware + host entry points
├── CMakePresets.json           # fw-release / fw-debug / host / fuzz
├── cmake/pico_sdk.cmake        # pico-sdk discovery (official import script)
├── src/                        # OhMyKei firmware source code (pure C17)
│   ├── main.c                  # Entry point & bringup loop
│   └── platform/               # Hardware abstraction (BOOTSEL sampling, etc.)
├── host/                       # SDK-free unit tests and fuzz harnesses
├── docs/ROADMAP.md             # Architecture, threat model & roadmap
└── ResearchDocs/               # Hardware & protocol reference notes
```

## License

MIT License. See [LICENSE](LICENSE).
