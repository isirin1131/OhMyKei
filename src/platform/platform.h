#ifndef OMK_PLATFORM_H
#define OMK_PLATFORM_H

#include <stdint.h>

#include "fido/omk_ctap.h"
#include "omk_port.h"

/* Wire the platform to the core and initialise the status LED. */
int omk_platform_start(omk_ctaphid *hid, omk_ctap *ctap);

/* Start the USB device stack (after the core has been initialised). */
void omk_platform_usb_start(void);

/* The platform port handed to the core. */
const omk_port *omk_platform_port(void);

/* Run one iteration of USB work (also used from the UP wait loop). */
void omk_platform_pump(void);

/* Called by the TinyUSB HID OUT callback with one 64-byte report. */
void omk_platform_usb_rx(const uint8_t packet[64]);

/* Reset transport state after a USB bus reset / re-enumeration. */
void omk_platform_usb_reset(void);

/* Diagnostics for the fixed USB queues.  A non-zero drop count means the
 * bounded queue rejected a packet instead of blocking. */
uint32_t omk_platform_usb_tx_dropped(void);
uint32_t omk_platform_usb_rx_dropped(void);

#endif
