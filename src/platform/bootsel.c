#include "platform/bootsel.h"

#include "hardware/gpio.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/structs/sio.h"
#include "pico/flash.h"

static void __no_inline_not_in_flash_func(sample_bootsel_in_ram)(void *param) {
    bool *pressed = (bool *)param;

    hw_write_masked(&ioqspi_hw->io[1].ctrl,
                    GPIO_OVERRIDE_LOW << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    for (volatile int i = 0; i < 1000; ++i) {
        __asm volatile("nop");
    }

    *pressed = !(sio_hw->gpio_hi_in & SIO_GPIO_HI_IN_QSPI_CSN_BITS);

    hw_write_masked(&ioqspi_hw->io[1].ctrl,
                    GPIO_OVERRIDE_NORMAL << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);
}

bool omk_bootsel_pressed(void) {
    bool pressed = false;
    if (flash_safe_execute(sample_bootsel_in_ram, &pressed, 100) != PICO_OK) {
        return false;
    }
    return pressed;
}
