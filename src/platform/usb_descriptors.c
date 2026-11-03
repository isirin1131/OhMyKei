/*
 * USB descriptors for the OhMyKei CTAPHID interface.
 *
 * One HID interface (Usage Page 0xF1D0), 64-byte interrupt IN/OUT endpoints,
 * no other USB functions.  Keeping the descriptor set this small avoids the
 * CDC debug channel that the CTAP specification discourages (CTAP 2.3
 * §11.1: authenticator state must not be observable through other
 * interfaces).
 */
#include <string.h>

#include "class/hid/hid_device.h"
#include "platform/platform.h"
#include "tusb.h"

#define OMK_USB_VID 0x2E8Au
#define OMK_USB_PID 0x10A1u
#define OMK_USB_BCD 0x0100u

static const tusb_desc_device_t desc_device = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = 0x00,
    .bDeviceSubClass = 0x00,
    .bDeviceProtocol = 0x00,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = OMK_USB_VID,
    .idProduct = OMK_USB_PID,
    .bcdDevice = OMK_USB_BCD,
    .iManufacturer = 0x01,
    .iProduct = 0x02,
    .iSerialNumber = 0x03,
    .bNumConfigurations = 0x01,
};

static const uint8_t desc_hid_report[] = {
    0x06, 0xD0, 0xF1, /* Usage Page (FIDO Alliance) */
    0x09, 0x01,       /* Usage (U2F Authenticator) */
    0xA1, 0x01,       /* Collection (Application) */
    0x09, 0x20,       /* Usage (Input Report Data) */
    0x15, 0x00,       /* Logical Minimum (0) */
    0x26, 0xFF, 0x00, /* Logical Maximum (255) */
    0x75, 0x08,       /* Report Size (8) */
    0x95, 0x40,       /* Report Count (64) */
    0x81, 0x02,       /* Input (Data, Variable, Absolute) */
    0x09, 0x21,       /* Usage (Output Report Data) */
    0x15, 0x00,
    0x26, 0xFF, 0x00,
    0x75, 0x08,
    0x95, 0x40,
    0x91, 0x02, /* Output (Data, Variable, Absolute) */
    0xC0,
};

#define CONFIG_TOTAL_LEN \
    (TUD_CONFIG_DESC_LEN + TUD_HID_INOUT_DESC_LEN)

static const uint8_t desc_configuration[] = {
    TUD_CONFIG_DESCRIPTOR(1, 1, 0, CONFIG_TOTAL_LEN, 0x00, 100),
    TUD_HID_INOUT_DESCRIPTOR(0, 0, false, sizeof(desc_hid_report), 0x01, 0x81,
                             64, 5),
};

static char const *string_desc_arr[] = {
    (const char[]){0x09, 0x04}, /* English (0x0409) */
    "OhMyKei",
    "OhMyKei FIDO2 Security Key",
    "OHMYKEI-0001",
};

static uint16_t desc_str[32];

uint8_t const *tud_descriptor_device_cb(void) {
    return (uint8_t const *)&desc_device;
}

uint8_t const *tud_descriptor_configuration_cb(uint8_t index) {
    (void)index;
    return desc_configuration;
}

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance) {
    (void)instance;
    return desc_hid_report;
}

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void)langid;
    size_t chr_count;

    if (index == 0) {
        memcpy(&desc_str[1], string_desc_arr[0], 2);
        chr_count = 1;
    } else {
        if (index >= sizeof(string_desc_arr) / sizeof(string_desc_arr[0])) {
            return NULL;
        }
        const char *str = string_desc_arr[index];
        chr_count = strlen(str);
        if (chr_count > 31) {
            chr_count = 31;
        }
        for (size_t i = 0; i < chr_count; i++) {
            desc_str[1 + i] = str[i];
        }
    }
    desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * chr_count + 2));
    return desc_str;
}

uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id,
                               hid_report_type_t report_type, uint8_t *buffer,
                               uint16_t reqlen) {
    (void)instance;
    (void)report_id;
    (void)report_type;
    (void)buffer;
    (void)reqlen;
    return 0;
}

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id,
                           hid_report_type_t report_type,
                           uint8_t const *buffer, uint16_t bufsize) {
    (void)instance;
    (void)report_id;
    if (report_type != HID_REPORT_TYPE_OUTPUT || bufsize != 64) {
        return;
    }
    omk_platform_usb_rx(buffer);
}

void tud_mount_cb(void) {
    /* A mount after reset/re-enumeration means the previous transport state
     * (channels, reassembly, queued reports) cannot be trusted. */
    omk_platform_usb_reset();
}

void tud_umount_cb(void) {
    omk_platform_usb_reset();
}
