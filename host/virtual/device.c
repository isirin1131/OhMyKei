/* Linux UHID platform for the unmodified firmware protocol core. Test only. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/uhid.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "crypto/omk_crypto.h"
#include "fido/omk_ctap.h"

static volatile sig_atomic_t running = 1;
static struct {
    int hid_fd, flash_fd;
    omk_port port;
    omk_ctaphid hid;
    omk_ctap ct;
    uint64_t boot_ms, press_at;
    int auto_ms;
    bool waiting_up, press_pending;
    char control[128];
    size_t control_len;
} device;

/* Same unnumbered 64-byte FIDO reports as the firmware USB interface. */
static const uint8_t report_descriptor[] = {
    0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20,
    0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02,
    0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08,
    0x95, 0x40, 0x91, 0x02, 0xC0,
};

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(1);
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static uint64_t now_ms(void *ctx) {
    (void)ctx;
    return monotonic_ms() - device.boot_ms;
}

static bool random_bytes(void *ctx, void *out, size_t len) {
    (void)ctx;
    uint8_t *p = out;
    while (len != 0) {
        ssize_t n = getrandom(p, len, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        p += n;
        len -= (size_t)n;
    }
    return true;
}

static bool flash_range(uint32_t off, size_t len) {
    return off >= OMK_FLASH_REGION_OFF && len <= OMK_FLASH_REGION_SIZE &&
        off - OMK_FLASH_REGION_OFF <= OMK_FLASH_REGION_SIZE - len;
}

static int flash_read(void *ctx, uint32_t off, void *dst, size_t len) {
    (void)ctx;
    if (!flash_range(off, len)) return -1;
    return pread(device.flash_fd, dst, len, off - OMK_FLASH_REGION_OFF) ==
        (ssize_t)len ? 0 : -1;
}

static int flash_write(void *ctx, uint32_t off, const void *src, size_t len) {
    uint8_t old[256];
    if (len == 0 || len % sizeof old != 0 || off % sizeof old != 0 ||
        !flash_range(off, len)) return -1;
    const uint8_t *data = src;
    for (size_t page = 0; page < len; page += sizeof old) {
        if (flash_read(ctx, off + (uint32_t)page, old, sizeof old) != 0) return -1;
        for (size_t i = 0; i < sizeof old; i++) {
            if ((old[i] & data[page + i]) != data[page + i]) return -1;
        }
    }
    if (pwrite(device.flash_fd, src, len, off - OMK_FLASH_REGION_OFF) !=
        (ssize_t)len) return -1;
    return fdatasync(device.flash_fd);
}

static int flash_erase(void *ctx, uint32_t off) {
    (void)ctx;
    uint8_t erased[OMK_FLASH_SECTOR_SIZE];
    if (off % sizeof erased != 0 || !flash_range(off, sizeof erased)) return -1;
    memset(erased, 0xFF, sizeof erased);
    if (pwrite(device.flash_fd, erased, sizeof erased,
               off - OMK_FLASH_REGION_OFF) != (ssize_t)sizeof erased) return -1;
    return fdatasync(device.flash_fd);
}

static bool write_event(const struct uhid_event *ev) {
    ssize_t n;
    do { n = write(device.hid_fd, ev, sizeof *ev); }
    while (n < 0 && errno == EINTR);
    return n == (ssize_t)sizeof *ev;
}

static bool hid_send(void *ctx, const uint8_t packet[64]) {
    (void)ctx;
    struct uhid_event ev = {.type = UHID_INPUT2};
    ev.u.input2.size = 64;
    memcpy(ev.u.input2.data, packet, 64);
    if (!write_event(&ev)) return false;
    if (packet[4] == OMK_CTAPHID_CMD_KEEPALIVE &&
        packet[7] == OMK_KEEPALIVE_UP_NEEDED && !device.waiting_up) {
        device.waiting_up = true;
        if (device.auto_ms >= 0) {
            device.press_pending = true;
            device.press_at = now_ms(NULL) + (uint64_t)device.auto_ms;
        }
    } else if ((packet[4] & 0x80u) != 0 &&
               packet[4] != OMK_CTAPHID_CMD_KEEPALIVE && !device.hid.busy) {
        device.waiting_up = false;
        device.press_pending = false;
    }
    return true;
}

static bool up_pressed(void *ctx) {
    (void)ctx;
    if (device.press_pending && now_ms(NULL) >= device.press_at) {
        /* One sampled press followed by release; the core owns its UP latch. */
        device.press_pending = false;
        puts("TOUCHED");
        return true;
    }
    return false;
}

static void delay_ms(void *ctx, uint32_t ms) {
    (void)ctx;
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR && running) {}
}

static void control_line(void) {
    device.control[device.control_len] = 0;
    if (strcmp(device.control, "touch") == 0) {
        if (device.waiting_up) {
            device.press_pending = true;
            device.press_at = now_ms(NULL);
        } else {
            puts("NOT_WAITING");
        }
    } else if (strcmp(device.control, "manual") == 0) {
        device.auto_ms = -1;
        device.press_pending = false;
        puts("MODE");
    } else if (strncmp(device.control, "auto ", 5) == 0) {
        char *end;
        long ms = strtol(device.control + 5, &end, 10);
        if (*end == 0 && ms >= 10 && ms <= 10000) {
            device.auto_ms = (int)ms;
            puts("MODE");
        }
    }
    device.control_len = 0;
}

static void read_control(void) {
    char data[128];
    ssize_t n = read(STDIN_FILENO, data, sizeof data);
    if (n == 0) { running = 0; return; }
    for (ssize_t i = 0; i < n; i++) {
        if (data[i] == '\n') control_line();
        else if (device.control_len < sizeof device.control - 1)
            device.control[device.control_len++] = data[i];
        else { running = 0; return; }
    }
}

static bool receive_report(const uint8_t *data, size_t len) {
    /* hidraw writers may prefix the unnumbered report with Report ID 0. */
    if (len == 65 && data[0] == 0) { data++; len--; }
    if (len != 64) return false;
    omk_ctaphid_rx_packet(&device.hid, data);
    if (!device.hid.busy) {
        device.waiting_up = false;
        device.press_pending = false;
    }
    return true;
}

static void hid_pump(void *ctx) {
    (void)ctx;
    struct pollfd fds[] = {{STDIN_FILENO, POLLIN, 0}, {device.hid_fd, POLLIN, 0}};
    if (poll(fds, 2, 0) > 0 && (fds[0].revents & (POLLIN | POLLHUP))) read_control();
    if (!running) { omk_ctaphid_reset(&device.hid); return; }
    for (unsigned i = 0; i < 64; i++) {
        struct uhid_event ev = {0};
        ssize_t n = read(device.hid_fd, &ev, sizeof ev);
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) break;
        if (n < (ssize_t)sizeof ev.type) { running = 0; break; }
        switch (ev.type) {
        case UHID_OUTPUT:
            if (ev.u.output.rtype == UHID_OUTPUT_REPORT &&
                ev.u.output.size <= sizeof ev.u.output.data)
                (void)receive_report(ev.u.output.data, ev.u.output.size);
            break;
        case UHID_GET_REPORT: {
            struct uhid_event reply = {.type = UHID_GET_REPORT_REPLY};
            reply.u.get_report_reply.id = ev.u.get_report.id;
            reply.u.get_report_reply.err = EOPNOTSUPP;
            if (!write_event(&reply)) running = 0;
            break;
        }
        case UHID_SET_REPORT: {
            struct uhid_event reply = {.type = UHID_SET_REPORT_REPLY};
            reply.u.set_report_reply.id = ev.u.set_report.id;
            reply.u.set_report_reply.err = EOPNOTSUPP;
            if (!write_event(&reply)) running = 0;
            break;
        }
        default: break;
        }
    }
}

static bool long_op_poll(void *ctx) {
    hid_pump(ctx);
    return running && !omk_ctaphid_cancel_pending(&device.hid) &&
        !omk_ctaphid_aborted(&device.hid);
}

static void stop(int signo) { (void)signo; running = 0; }

int main(int argc, char **argv) {
    if (argc != 3 || strlen(argv[2]) >= 128) {
        fprintf(stderr, "usage: omk_virtual FLASH_FILE SERIAL\n");
        return 2;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGTERM, stop);
    signal(SIGINT, stop);
    device.auto_ms = 250;
    device.boot_ms = monotonic_ms();
    device.flash_fd = open(argv[1], O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
    if (device.flash_fd < 0 || flock(device.flash_fd, LOCK_EX | LOCK_NB) != 0) {
        perror("open/lock flash"); return 1;
    }
    struct stat st;
    if (fstat(device.flash_fd, &st) != 0 || !S_ISREG(st.st_mode)) return 1;
    if (st.st_size == 0) {
        for (uint32_t off = OMK_FLASH_REGION_OFF;
             off < OMK_FLASH_REGION_OFF + OMK_FLASH_REGION_SIZE;
             off += OMK_FLASH_SECTOR_SIZE) {
            if (flash_erase(NULL, off) != 0) { perror("initialize flash"); return 1; }
        }
    } else if (st.st_size != OMK_FLASH_REGION_SIZE) {
        fputs("unexpected flash size\n", stderr); return 1;
    }
    device.hid_fd = open("/dev/uhid", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (device.hid_fd < 0) { perror("open /dev/uhid"); return 1; }
    device.port = (omk_port){
        .now_ms = now_ms, .random_bytes = random_bytes,
        .flash_read = flash_read, .flash_write = flash_write, .flash_erase = flash_erase,
        .up_pressed = up_pressed, .hid_send = hid_send, .hid_pump = hid_pump,
        .delay_ms = delay_ms, .long_op_poll = long_op_poll,
    };
    omk_ctaphid_init(&device.hid, &device.port, omk_ctap_handle, &device.ct);
    if (omk_ctap_init(&device.ct, &device.port, &device.hid) != 0) {
        fputs("core initialization failed\n", stderr); return 1;
    }
    struct uhid_event create = {.type = UHID_CREATE2};
    snprintf((char *)create.u.create2.name, sizeof create.u.create2.name,
             "OhMyKei Virtual FIDO2 (TEST)");
    snprintf((char *)create.u.create2.uniq, sizeof create.u.create2.uniq,
             "%s", argv[2]);
    create.u.create2.rd_size = sizeof report_descriptor;
    create.u.create2.bus = BUS_USB;
    create.u.create2.vendor = 0x2E8A;
    create.u.create2.product = 0x10A1;
    create.u.create2.version = 0x0100;
    memcpy(create.u.create2.rd_data, report_descriptor, sizeof report_descriptor);
    if (!write_event(&create)) { perror("UHID_CREATE2"); return 1; }
    puts("READY");
    while (running) {
        omk_ctaphid_tick(&device.hid);
        hid_pump(NULL);
        delay_ms(NULL, 1);
    }
    close(device.hid_fd); /* Closing UHID removes this process's virtual device. */
    close(device.flash_fd);
    omk_memzero(&device.ct, sizeof device.ct);
    return 0;
}
