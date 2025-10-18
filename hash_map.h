#ifndef HASH_MAP_H
#define HASH_MAP_H

#include "conn.h"
#include <stdbool.h>

// Hash map entry for IMEI -> Connection mapping
typedef struct {
    char *key;          // IMEI string
    Conn *value;        // Connection pointer
    bool in_use;        // Whether this slot is in use
} HashMapEntry;

// Hash map structure
typedef struct {
    HashMapEntry *buckets;
    size_t capacity;
    size_t size;
} HashMap;

// Function declarations
HashMap* hash_map_create(size_t initial_capacity);
void hash_map_destroy(HashMap *map);
bool hash_map_set(HashMap *map, const char *key, Conn *value);
Conn* hash_map_get(HashMap *map, const char *key);
bool hash_map_remove(HashMap *map, const char *key);
bool hash_map_remove_by_conn(HashMap *map, Conn *conn);
const char* hash_map_get_key_by_fd(HashMap *map, int fd);
size_t hash_map_size(HashMap *map);
bool hash_map_empty(HashMap *map);

#endif // HASH_MAP_H

