#include <stdbool.h>
#include <stdint.h>

#include "fido/omk_ctap.h"
#include "fido/omk_ctaphid.h"
#include "platform/platform.h"

static omk_ctaphid g_hid;
static omk_ctap g_ctap;

int main(void) {
    if (omk_platform_start(&g_hid, &g_ctap) != 0) {
        return 1;
    }
    omk_ctaphid_init(&g_hid, omk_platform_port(), omk_ctap_handle, &g_ctap);
    if (omk_ctap_init(&g_ctap, omk_platform_port(), &g_hid) != 0) {
        return 1;
    }
    omk_platform_usb_start();

    for (;;) {
        /* Service reassembly timeouts in the idle loop too, not only while a
         * command waits for user presence.  tick() never pumps the port. */
        omk_ctaphid_tick(&g_hid);
        omk_platform_pump();
    }
}
