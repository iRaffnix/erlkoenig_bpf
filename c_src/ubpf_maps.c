/*
 * ubpf_maps.c — Hash-map implementation for uBPF port.
 *
 * Chained hash table with FNV-1a hashing.  Each map has a stable
 * lookup buffer (mmap'd in the low 4 GB) so that the BPF program
 * can dereference the pointer returned by map_lookup_elem as a
 * 32-bit address.
 */

#include "ubpf_maps.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

/* ------------------------------------------------------------------ */
/* Hash table internals                                               */
/* ------------------------------------------------------------------ */

typedef struct map_entry {
    uint8_t            *key;
    uint8_t            *value;
    struct map_entry   *next;
} map_entry_t;

typedef struct {
    int             active;
    uint32_t        key_size;
    uint32_t        val_size;
    uint32_t        max_entries;
    uint32_t        num_entries;
    map_entry_t    *buckets[UBPF_MAP_BUCKETS];
    /*
     * Stable lookup return buffer.  mmap'd with MAP_32BIT so the
     * pointer fits in a BPF uint32_t register.  Size = val_size.
     */
    void           *lookup_buf;
    size_t          lookup_buf_size;
} bpf_map_t;

static bpf_map_t maps[UBPF_MAX_MAPS];

/* FNV-1a hash */
static uint32_t
fnv1a(const void *data, size_t len)
{
    const uint8_t *p = data;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

static uint32_t
bucket_idx(const void *key, uint32_t key_size)
{
    return fnv1a(key, key_size) % UBPF_MAP_BUCKETS;
}

/* Find entry by key.  Returns pointer to the entry, or NULL. */
static map_entry_t *
find_entry(bpf_map_t *m, const void *key)
{
    uint32_t idx = bucket_idx(key, m->key_size);
    for (map_entry_t *e = m->buckets[idx]; e; e = e->next) {
        if (memcmp(e->key, key, m->key_size) == 0)
            return e;
    }
    return NULL;
}

/* Free a single entry (key + value + node). */
static void
free_entry(map_entry_t *e)
{
    free(e->key);
    free(e->value);
    free(e);
}

/* Free all entries in a map. */
static void
clear_map(bpf_map_t *m)
{
    for (uint32_t i = 0; i < UBPF_MAP_BUCKETS; i++) {
        map_entry_t *e = m->buckets[i];
        while (e) {
            map_entry_t *next = e->next;
            free_entry(e);
            e = next;
        }
        m->buckets[i] = NULL;
    }
    m->num_entries = 0;
}

/* Allocate lookup buffer in low 4 GB. */
static int
alloc_lookup_buf(bpf_map_t *m)
{
    /*
     * Round up to page size.  val_size is typically 4 or 8 bytes,
     * so one page is always enough.
     */
    size_t sz = (m->val_size + 4095) & ~(size_t)4095;
    void *p = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (p == MAP_FAILED)
        return -1;
    m->lookup_buf = p;
    m->lookup_buf_size = sz;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

bpf_map_fd_t
ubpf_map_create(uint32_t key_size, uint32_t val_size, uint32_t max_entries)
{
    if (key_size == 0 || val_size == 0 || max_entries == 0)
        return -1;

    /* Find a free slot. */
    int fd = -1;
    for (int i = 0; i < UBPF_MAX_MAPS; i++) {
        if (!maps[i].active) {
            fd = i;
            break;
        }
    }
    if (fd < 0)
        return -1;

    bpf_map_t *m = &maps[fd];
    memset(m, 0, sizeof(*m));
    m->active      = 1;
    m->key_size    = key_size;
    m->val_size    = val_size;
    m->max_entries = max_entries;

    if (alloc_lookup_buf(m) != 0) {
        m->active = 0;
        return -1;
    }

    return fd;
}

void *
ubpf_map_lookup(bpf_map_fd_t fd, const void *key)
{
    if (fd < 0 || fd >= UBPF_MAX_MAPS || !maps[fd].active)
        return NULL;

    bpf_map_t *m = &maps[fd];
    map_entry_t *e = find_entry(m, key);
    if (!e)
        return NULL;

    /* Copy value into stable lookup buffer so the BPF program
     * can dereference the returned pointer. */
    memcpy(m->lookup_buf, e->value, m->val_size);
    return m->lookup_buf;
}

int
ubpf_map_update(bpf_map_fd_t fd, const void *key, const void *value,
                uint64_t flags)
{
    (void)flags;  /* BPF_ANY semantics: insert or update */

    if (fd < 0 || fd >= UBPF_MAX_MAPS || !maps[fd].active)
        return -1;

    bpf_map_t *m = &maps[fd];
    map_entry_t *e = find_entry(m, key);

    if (e) {
        /* Update existing entry. */
        memcpy(e->value, value, m->val_size);
        return 0;
    }

    /* Insert new entry. */
    if (m->num_entries >= m->max_entries)
        return -1;

    e = malloc(sizeof(*e));
    if (!e)
        return -1;

    e->key = malloc(m->key_size);
    e->value = malloc(m->val_size);
    if (!e->key || !e->value) {
        free(e->key);
        free(e->value);
        free(e);
        return -1;
    }

    memcpy(e->key, key, m->key_size);
    memcpy(e->value, value, m->val_size);

    uint32_t idx = bucket_idx(key, m->key_size);
    e->next = m->buckets[idx];
    m->buckets[idx] = e;
    m->num_entries++;

    return 0;
}

int
ubpf_map_delete(bpf_map_fd_t fd, const void *key)
{
    if (fd < 0 || fd >= UBPF_MAX_MAPS || !maps[fd].active)
        return -1;

    bpf_map_t *m = &maps[fd];
    uint32_t idx = bucket_idx(key, m->key_size);

    map_entry_t **pp = &m->buckets[idx];
    while (*pp) {
        map_entry_t *e = *pp;
        if (memcmp(e->key, key, m->key_size) == 0) {
            *pp = e->next;
            free_entry(e);
            m->num_entries--;
            return 0;
        }
        pp = &e->next;
    }

    return -1;
}

void
ubpf_maps_destroy_all(void)
{
    for (int i = 0; i < UBPF_MAX_MAPS; i++) {
        bpf_map_t *m = &maps[i];
        if (!m->active)
            continue;
        clear_map(m);
        if (m->lookup_buf) {
            munmap(m->lookup_buf, m->lookup_buf_size);
            m->lookup_buf = NULL;
        }
        m->active = 0;
    }
}

int
ubpf_map_iterate(bpf_map_fd_t fd,
                 void (*cb)(const void *key, const void *value,
                            void *user_data),
                 void *user_data)
{
    if (fd < 0 || fd >= UBPF_MAX_MAPS || !maps[fd].active)
        return -1;

    bpf_map_t *m = &maps[fd];
    int count = 0;

    for (uint32_t i = 0; i < UBPF_MAP_BUCKETS; i++) {
        for (map_entry_t *e = m->buckets[i]; e; e = e->next) {
            cb(e->key, e->value, user_data);
            count++;
        }
    }

    return count;
}

int
ubpf_map_info(bpf_map_fd_t fd, uint32_t *key_size, uint32_t *val_size,
              uint32_t *max_entries, uint32_t *num_entries)
{
    if (fd < 0 || fd >= UBPF_MAX_MAPS || !maps[fd].active)
        return -1;

    bpf_map_t *m = &maps[fd];
    if (key_size)    *key_size    = m->key_size;
    if (val_size)    *val_size    = m->val_size;
    if (max_entries) *max_entries = m->max_entries;
    if (num_entries) *num_entries = m->num_entries;
    return 0;
}

/* ------------------------------------------------------------------ */
/* BPF helper functions (registered with ubpf_register)               */
/* ------------------------------------------------------------------ */

uint64_t
helper_map_lookup_elem(uint64_t map_fd, uint64_t key_ptr,
                       uint64_t p2, uint64_t p3, uint64_t p4)
{
    (void)p2; (void)p3; (void)p4;
    void *val = ubpf_map_lookup((bpf_map_fd_t)map_fd, (const void *)(uintptr_t)key_ptr);
    return (uint64_t)(uintptr_t)val;
}

uint64_t
helper_map_update_elem(uint64_t map_fd, uint64_t key_ptr,
                       uint64_t val_ptr, uint64_t flags, uint64_t p4)
{
    (void)p4;
    int rc = ubpf_map_update((bpf_map_fd_t)map_fd,
                             (const void *)(uintptr_t)key_ptr,
                             (const void *)(uintptr_t)val_ptr,
                             flags);
    return (uint64_t)rc;
}

uint64_t
helper_map_delete_elem(uint64_t map_fd, uint64_t key_ptr,
                       uint64_t p2, uint64_t p3, uint64_t p4)
{
    (void)p2; (void)p3; (void)p4;
    int rc = ubpf_map_delete((bpf_map_fd_t)map_fd,
                             (const void *)(uintptr_t)key_ptr);
    return (uint64_t)rc;
}
