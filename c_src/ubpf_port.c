/*
 * ubpf_port.c — Erlang Port program for uBPF userspace eBPF VM.
 *
 * Protocol ({packet, 4} framing):
 *   Commands (Erlang -> C):
 *     0x01 LOAD:       1B cmd + BPF bytecode
 *     0x02 RUN:        1B cmd + context binary
 *     0x03 RUN_XDP:    1B cmd + packet binary (C constructs xdp_md)
 *     0x04 CREATE_MAP: 1B cmd + key_size(4B LE) + val_size(4B LE) + max(4B LE)
 *     0x05 RESET_MAPS: 1B cmd (destroy all maps)
 *     0x06 MAP_GET:    1B cmd + fd(4B LE) + key(key_size bytes)
 *     0x07 MAP_DUMP:   1B cmd + fd(4B LE)
 *     0xFF SHUTDOWN:   graceful exit
 *
 *   Replies (C -> Erlang):
 *     0x00 OK:     success (optional data)
 *     0x01 ERR:    error message (UTF-8)
 *     0x02 RESULT: 8B return value (little-endian u64)
 */

#include <ubpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/mman.h>

#include "ubpf_maps.h"

/* Maximum packet size: 16 MiB. Prevents OOM on malformed {packet, 4} headers. */
#define MAX_PACKET_SIZE (16 * 1024 * 1024)

/* Reply status codes */
#define REPLY_OK     0x00
#define REPLY_ERR    0x01
#define REPLY_RESULT 0x02

/* Command codes */
#define CMD_LOAD       0x01
#define CMD_RUN        0x02
#define CMD_RUN_XDP    0x03
#define CMD_CREATE_MAP 0x04
#define CMD_RESET_MAPS 0x05
#define CMD_MAP_GET    0x06
#define CMD_MAP_DUMP   0x07
#define CMD_SHUTDOWN   0xFF

static struct ubpf_vm *vm = NULL;
static int program_loaded = 0;

/* --- I/O helpers for {packet,4} framing --- */

static int
read_exact(int fd, void *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, (char *)buf + got, len - got);
        if (n <= 0)
            return -1;
        got += (size_t)n;
    }
    return 0;
}

static int
write_exact(int fd, const void *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, (const char *)buf + sent, len - sent);
        if (n <= 0)
            return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int
read_packet(uint8_t **buf, uint32_t *len)
{
    uint32_t nlen;
    if (read_exact(STDIN_FILENO, &nlen, 4) != 0)
        return -1;
    *len = ntohl(nlen);
    if (*len == 0) {
        *buf = NULL;
        return 0;
    }
    if (*len > MAX_PACKET_SIZE)
        return -1;
    *buf = malloc(*len);
    if (!*buf)
        return -1;
    if (read_exact(STDIN_FILENO, *buf, *len) != 0) {
        free(*buf);
        *buf = NULL;
        return -1;
    }
    return 0;
}

static void
send_reply(uint8_t status, const void *data, uint32_t data_len)
{
    uint32_t total = 1 + data_len;
    uint32_t nlen = htonl(total);
    write_exact(STDOUT_FILENO, &nlen, 4);
    write_exact(STDOUT_FILENO, &status, 1);
    if (data_len > 0)
        write_exact(STDOUT_FILENO, data, data_len);
}

static void
send_error(const char *msg)
{
    send_reply(REPLY_ERR, msg, (uint32_t)strlen(msg));
}

static void
send_ok(void)
{
    send_reply(REPLY_OK, NULL, 0);
}

static inline void
put_u32_le(uint8_t *buf, uint32_t val)
{
    buf[0] = (uint8_t)(val);
    buf[1] = (uint8_t)(val >> 8);
    buf[2] = (uint8_t)(val >> 16);
    buf[3] = (uint8_t)(val >> 24);
}

static inline uint32_t
get_u32_le(const uint8_t *buf)
{
    return (uint32_t)buf[0]
         | ((uint32_t)buf[1] << 8)
         | ((uint32_t)buf[2] << 16)
         | ((uint32_t)buf[3] << 24);
}

static inline void
put_u64_le(uint8_t *buf, uint64_t val)
{
    buf[0] = (uint8_t)(val);
    buf[1] = (uint8_t)(val >> 8);
    buf[2] = (uint8_t)(val >> 16);
    buf[3] = (uint8_t)(val >> 24);
    buf[4] = (uint8_t)(val >> 32);
    buf[5] = (uint8_t)(val >> 40);
    buf[6] = (uint8_t)(val >> 48);
    buf[7] = (uint8_t)(val >> 56);
}

/* --- uBPF helper functions --- */

static uint64_t
helper_ktime_get_ns(uint64_t p0, uint64_t p1, uint64_t p2,
                    uint64_t p3, uint64_t p4)
{
    (void)p0; (void)p1; (void)p2; (void)p3; (void)p4;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t
helper_get_smp_processor_id(uint64_t p0, uint64_t p1, uint64_t p2,
                            uint64_t p3, uint64_t p4)
{
    (void)p0; (void)p1; (void)p2; (void)p3; (void)p4;
    return 0;
}

static int
register_helpers(struct ubpf_vm *v)
{
    int rc;

    /* Helper 1: bpf_map_lookup_elem */
    rc = ubpf_register(v, 1, "bpf_map_lookup_elem",
                       helper_map_lookup_elem);
    if (rc != 0)
        return rc;

    /* Helper 2: bpf_map_update_elem */
    rc = ubpf_register(v, 2, "bpf_map_update_elem",
                       helper_map_update_elem);
    if (rc != 0)
        return rc;

    /* Helper 3: bpf_map_delete_elem */
    rc = ubpf_register(v, 3, "bpf_map_delete_elem",
                       helper_map_delete_elem);
    if (rc != 0)
        return rc;

    /* Helper 5: bpf_ktime_get_ns */
    rc = ubpf_register(v, 5, "bpf_ktime_get_ns", helper_ktime_get_ns);
    if (rc != 0)
        return rc;

    /* Helper 14: bpf_get_smp_processor_id */
    rc = ubpf_register(v, 14, "bpf_get_smp_processor_id",
                       helper_get_smp_processor_id);
    if (rc != 0)
        return rc;

    return 0;
}

/* --- Command handlers --- */

static void
handle_load(const uint8_t *data, uint32_t len)
{
    char *errmsg = NULL;

    if (len == 0) {
        send_error("empty bytecode");
        return;
    }

    /* If a program is already loaded, destroy and recreate VM.
     * Maps survive across LOAD — only the program changes. */
    if (vm) {
        ubpf_destroy(vm);
        vm = NULL;
        program_loaded = 0;
    }

    vm = ubpf_create();
    if (!vm) {
        send_error("ubpf_create failed");
        return;
    }

    /*
     * Disable bounds checking: our programs access packet data via
     * real userspace pointers read from ctx.data. uBPF's default
     * bounds checker only knows about ctx + stack regions and would
     * reject packet pointer dereferences.  The kernel BPF verifier
     * handles bounds checking statically; we don't need it here.
     */
    ubpf_toggle_bounds_check(vm, false);

    if (register_helpers(vm) != 0) {
        send_error("failed to register helpers");
        goto err_destroy;
    }

    if (ubpf_load(vm, data, len, &errmsg) != 0) {
        if (errmsg) {
            send_error(errmsg);
            free(errmsg);
        } else {
            send_error("ubpf_load failed");
        }
        goto err_destroy;
    }

    program_loaded = 1;
    send_ok();
    return;

err_destroy:
    ubpf_destroy(vm);
    vm = NULL;
    program_loaded = 0;
}

static void
handle_run(const uint8_t *data, uint32_t len)
{
    uint64_t ret = 0;
    uint8_t result_buf[8];

    if (!vm || !program_loaded) {
        send_error("no program loaded");
        return;
    }

    if (ubpf_exec(vm, (void *)data, len, &ret) != 0) {
        send_error("ubpf_exec failed");
        return;
    }

    put_u64_le(result_buf, ret);
    send_reply(REPLY_RESULT, result_buf, 8);
}

static void
handle_run_xdp(const uint8_t *pkt, uint32_t pkt_len)
{
    uint64_t ret = 0;
    uint8_t result_buf[8];

    if (!vm || !program_loaded) {
        send_error("no program loaded");
        return;
    }

    struct {
        uint32_t data;
        uint32_t data_end;
        uint32_t data_meta;
        uint32_t ingress_ifindex;
        uint32_t rx_queue_index;
        uint32_t egress_ifindex;
    } xdp_md;

    if (pkt_len == 0) {
        send_error("empty packet");
        return;
    }

    /*
     * On 64-bit systems, heap pointers are > 0xFFFFFFFF.
     * xdp_md fields are uint32_t (matching the kernel ABI).
     * We must allocate packet memory in the low 4 GB so pointers
     * fit in 32 bits.  Use mmap with MAP_32BIT for this.
     */
    void *pkt_lo = mmap(NULL, pkt_len, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (pkt_lo == MAP_FAILED) {
        send_error("mmap MAP_32BIT failed");
        return;
    }
    memcpy(pkt_lo, pkt, pkt_len);

    xdp_md.data     = (uint32_t)(uintptr_t)pkt_lo;
    xdp_md.data_end = (uint32_t)(uintptr_t)((uint8_t *)pkt_lo + pkt_len);
    xdp_md.data_meta = 0;
    xdp_md.ingress_ifindex = 0;
    xdp_md.rx_queue_index = 0;
    xdp_md.egress_ifindex = 0;

    if (ubpf_exec(vm, &xdp_md, sizeof(xdp_md), &ret) != 0) {
        munmap(pkt_lo, pkt_len);
        send_error("ubpf_exec failed");
        return;
    }
    munmap(pkt_lo, pkt_len);

    put_u64_le(result_buf, ret);
    send_reply(REPLY_RESULT, result_buf, 8);
}

/* CMD_CREATE_MAP: key_size(4B LE) + val_size(4B LE) + max_entries(4B LE) */
static void
handle_create_map(const uint8_t *data, uint32_t len)
{
    if (len < 12) {
        send_error("create_map: need 12 bytes (key_size + val_size + max_entries)");
        return;
    }

    uint32_t key_size    = get_u32_le(data);
    uint32_t val_size    = get_u32_le(data + 4);
    uint32_t max_entries = get_u32_le(data + 8);

    bpf_map_fd_t fd = ubpf_map_create(key_size, val_size, max_entries);
    if (fd < 0) {
        send_error("create_map failed");
        return;
    }

    uint8_t reply[4];
    put_u32_le(reply, (uint32_t)fd);
    send_reply(REPLY_OK, reply, 4);
}

/* CMD_RESET_MAPS: destroy all maps */
static void
handle_reset_maps(void)
{
    ubpf_maps_destroy_all();
    send_ok();
}

/* CMD_MAP_GET: fd(4B LE) + key(key_size bytes) → REPLY_OK + value or REPLY_ERR */
static void
handle_map_get(const uint8_t *data, uint32_t len)
{
    if (len < 4) {
        send_error("map_get: need at least 4 bytes (fd)");
        return;
    }

    bpf_map_fd_t fd = (bpf_map_fd_t)get_u32_le(data);

    uint32_t key_size, val_size;
    if (ubpf_map_info(fd, &key_size, &val_size, NULL, NULL) != 0) {
        send_error("map_get: invalid fd");
        return;
    }

    if (len < 4 + key_size) {
        send_error("map_get: key too short");
        return;
    }

    const void *key = data + 4;
    void *val = ubpf_map_lookup(fd, key);
    if (!val) {
        send_error("map_get: key not found");
        return;
    }

    send_reply(REPLY_OK, val, val_size);
}

/* Callback context for map_dump serialization. */
struct dump_ctx {
    uint8_t *buf;
    uint32_t offset;
    uint32_t key_size;
    uint32_t val_size;
};

static void
dump_cb(const void *key, const void *value, void *user_data)
{
    struct dump_ctx *ctx = user_data;
    memcpy(ctx->buf + ctx->offset, key, ctx->key_size);
    ctx->offset += ctx->key_size;
    memcpy(ctx->buf + ctx->offset, value, ctx->val_size);
    ctx->offset += ctx->val_size;
}

/* CMD_MAP_DUMP: fd(4B LE) → REPLY_OK + num(4B LE) + [key+value]* */
static void
handle_map_dump(const uint8_t *data, uint32_t len)
{
    if (len < 4) {
        send_error("map_dump: need 4 bytes (fd)");
        return;
    }

    bpf_map_fd_t fd = (bpf_map_fd_t)get_u32_le(data);

    uint32_t key_size, val_size, num_entries;
    if (ubpf_map_info(fd, &key_size, &val_size, NULL, &num_entries) != 0) {
        send_error("map_dump: invalid fd");
        return;
    }

    uint32_t entry_size = key_size + val_size;
    uint32_t body_size = 4 + num_entries * entry_size;
    uint8_t *reply_buf = malloc(body_size);
    if (!reply_buf) {
        send_error("map_dump: out of memory");
        return;
    }

    put_u32_le(reply_buf, num_entries);

    struct dump_ctx ctx = {
        .buf = reply_buf,
        .offset = 4,
        .key_size = key_size,
        .val_size = val_size,
    };

    ubpf_map_iterate(fd, dump_cb, &ctx);
    send_reply(REPLY_OK, reply_buf, body_size);
    free(reply_buf);
}

int
main(void)
{
    /* Ignore SIGPIPE so write() returns EPIPE instead of killing us. */
    signal(SIGPIPE, SIG_IGN);

    uint8_t *buf = NULL;
    uint32_t len = 0;

    while (read_packet(&buf, &len) == 0) {
        if (len < 1 || !buf) {
            free(buf);
            continue;
        }

        uint8_t cmd = buf[0];
        switch (cmd) {
        case CMD_LOAD:
            handle_load(buf + 1, len - 1);
            break;
        case CMD_RUN:
            handle_run(buf + 1, len - 1);
            break;
        case CMD_RUN_XDP:
            handle_run_xdp(buf + 1, len - 1);
            break;
        case CMD_CREATE_MAP:
            handle_create_map(buf + 1, len - 1);
            break;
        case CMD_RESET_MAPS:
            handle_reset_maps();
            break;
        case CMD_MAP_GET:
            handle_map_get(buf + 1, len - 1);
            break;
        case CMD_MAP_DUMP:
            handle_map_dump(buf + 1, len - 1);
            break;
        case CMD_SHUTDOWN:
            free(buf);
            goto done;
        default:
            send_error("unknown command");
            break;
        }
        free(buf);
        buf = NULL;
    }

done:
    ubpf_maps_destroy_all();
    if (vm)
        ubpf_destroy(vm);
    return 0;
}
