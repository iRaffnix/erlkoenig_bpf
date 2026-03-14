/*
 * ubpf_maps.h — Hash-map implementation for uBPF port.
 *
 * Provides BPF-compatible hash maps backed by chained hash tables.
 * Maps persist across ubpf_exec() calls so the port can run
 * stateful multi-packet XDP programs.
 *
 * Thread safety: NOT thread-safe (single-threaded port).
 */

#ifndef UBPF_MAPS_H
#define UBPF_MAPS_H

#include <stdint.h>
#include <stddef.h>

#define UBPF_MAX_MAPS      64
#define UBPF_MAP_BUCKETS   256

/* Opaque map handle (index into internal table). */
typedef int bpf_map_fd_t;

/*
 * Create a new hash map.
 * Returns map fd (>= 0) on success, -1 on error.
 */
bpf_map_fd_t ubpf_map_create(uint32_t key_size, uint32_t val_size,
                              uint32_t max_entries);

/*
 * Lookup a key in the map.
 * Returns pointer to a stable value buffer (valid until next lookup
 * on the same map), or NULL if key not found.
 *
 * The returned pointer is in the low 4 GB (MAP_32BIT mmap) so it
 * fits in a BPF uint32_t register after the ld_map_fd / lookup
 * pattern.
 */
void *ubpf_map_lookup(bpf_map_fd_t fd, const void *key);

/*
 * Insert or update a key-value pair.
 * Returns 0 on success, -1 on error (map full on insert).
 */
int ubpf_map_update(bpf_map_fd_t fd, const void *key, const void *value,
                    uint64_t flags);

/*
 * Delete a key from the map.
 * Returns 0 on success, -1 if key not found.
 */
int ubpf_map_delete(bpf_map_fd_t fd, const void *key);

/*
 * Destroy all maps and free all memory.
 */
void ubpf_maps_destroy_all(void);

/*
 * Iterate over all entries in a map.
 * Calls cb(key, value, user_data) for each entry.
 * Returns number of entries visited.
 */
int ubpf_map_iterate(bpf_map_fd_t fd,
                     void (*cb)(const void *key, const void *value,
                                void *user_data),
                     void *user_data);

/*
 * Get map metadata.
 * Returns 0 on success, -1 if fd invalid.
 */
int ubpf_map_info(bpf_map_fd_t fd, uint32_t *key_size, uint32_t *val_size,
                  uint32_t *max_entries, uint32_t *num_entries);

/* BPF helper signatures (match ubpf_vm helper registration). */
uint64_t helper_map_lookup_elem(uint64_t map_fd, uint64_t key_ptr,
                                uint64_t p2, uint64_t p3, uint64_t p4);
uint64_t helper_map_update_elem(uint64_t map_fd, uint64_t key_ptr,
                                uint64_t val_ptr, uint64_t flags,
                                uint64_t p4);
uint64_t helper_map_delete_elem(uint64_t map_fd, uint64_t key_ptr,
                                uint64_t p2, uint64_t p3, uint64_t p4);

#endif /* UBPF_MAPS_H */
