#ifndef OHMYKEI_PLATFORM_BOOTSEL_H
#define OHMYKEI_PLATFORM_BOOTSEL_H

#include <stdbool.h>

/**
 * @brief Safely sample the physical BOOTSEL button state from SRAM.
 *
 * Uses pico-sdk's flash_safe_execute() to disable interrupts (and lock out
 * any other core if enabled) during QSPI CSN pin manipulation.
 *
 * @return true if BOOTSEL is currently held down, false otherwise.
 */
bool omk_bootsel_pressed(void);

#endif
