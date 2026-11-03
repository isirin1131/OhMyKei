/*
 * Build-system smoke test: verifies that the host toolchain, C17 mode and
 * sanitizers are wired up. Real protocol tests replace this as src/core grows.
 */

#include <limits.h>
#include <stdint.h>

int main(void) {
    if (CHAR_BIT != 8) {
        return 1;
    }
    if (sizeof(uint8_t) != 1) {
        return 2;
    }
    if (sizeof(uint32_t) != 4) {
        return 3;
    }
    if (sizeof(uintptr_t) < sizeof(uint32_t)) {
        return 4;
    }
    return 0;
}
