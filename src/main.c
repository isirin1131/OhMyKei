#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "pico/status_led.h"
#include "pico/stdlib.h"
#include "platform/bootsel.h"

_Static_assert(PICO_FLASH_SIZE_BYTES == 2097152,
               "RP2350-Zero-CM has 2 MB flash; pico_override_flash_size() missing");

static const uint32_t k_palette[] = {
    PICO_COLORED_STATUS_LED_COLOR_FROM_RGB(0, 40, 12),   /* Emerald */
    PICO_COLORED_STATUS_LED_COLOR_FROM_RGB(0, 24, 48),   /* Ocean Blue */
    PICO_COLORED_STATUS_LED_COLOR_FROM_RGB(48, 20, 0),   /* Amber */
    PICO_COLORED_STATUS_LED_COLOR_FROM_RGB(36, 0, 48),   /* Violet */
};

int main(void) {
    stdio_init_all();
    status_led_init();

    size_t idx = 0;
    bool prev_pressed = false;
    uint32_t tick = 0;

    while (true) {
        bool pressed = omk_bootsel_pressed();
        if (pressed && !prev_pressed) {
            idx = (idx + 1u) % (sizeof(k_palette) / sizeof(k_palette[0]));
            printf("[OhMyKei] BOOT pressed -> color %zu\n", idx);
        }
        prev_pressed = pressed;

        if (pressed) {
            colored_status_led_set_on_with_color(
                PICO_COLORED_STATUS_LED_COLOR_FROM_RGB(64, 64, 64));
        } else if ((tick % 25u) < 20u) {
            colored_status_led_set_on_with_color(k_palette[idx]);
        } else {
            colored_status_led_set_state(false);
        }

        tick++;
        sleep_ms(20);
    }
}
