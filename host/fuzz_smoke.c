/*
 * Minimal libFuzzer harness proving the fuzz plumbing. Replace with the CBOR /
 * CTAPHID / APDU parsers as they land.
 */

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)data;
    (void)size;
    return 0;
}
