#include "hash_map.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Hash function for strings (djb2 algorithm)
static size_t hash_string(const char *str) {
    size_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash;
}

// Create a new hash map
HashMap* hash_map_create(size_t initial_capacity) {
    HashMap *map = malloc(sizeof(HashMap));
    if (!map) {
        return NULL;
    }
    
    // Ensure capacity is at least 16 and is a power of 2
    size_t capacity = 16;
    while (capacity < initial_capacity) {
        capacity <<= 1;
    }
    
    map->buckets = calloc(capacity, sizeof(HashMapEntry));
    if (!map->buckets) {
        free(map);
        return NULL;
    }
    
    map->capacity = capacity;
    map->size = 0;
    
    return map;
}

// Destroy hash map and free all memory
void hash_map_destroy(HashMap *map) {
    if (!map) return;
    
    // Free all allocated keys
    for (size_t i = 0; i < map->capacity; i++) {
        if (map->buckets[i].in_use && map->buckets[i].key) {
            free(map->buckets[i].key);
        }
    }
    
    free(map->buckets);
    free(map);
}

// Resize hash map when load factor gets too high
static bool hash_map_resize(HashMap *map) {
    size_t old_capacity = map->capacity;
    HashMapEntry *old_buckets = map->buckets;
    
    // Double the capacity
    map->capacity <<= 1;
    map->buckets = calloc(map->capacity, sizeof(HashMapEntry));
    if (!map->buckets) {
        map->capacity = old_capacity;
        map->buckets = old_buckets;
        return false;
    }
    
    // Rehash all existing entries
    map->size = 0;
    for (size_t i = 0; i < old_capacity; i++) {
        if (old_buckets[i].in_use) {
            hash_map_set(map, old_buckets[i].key, old_buckets[i].value);
            free(old_buckets[i].key);
        }
    }
    
    free(old_buckets);
    return true;
}

// Set a key-value pair in the hash map
bool hash_map_set(HashMap *map, const char *key, Conn *value) {
    if (!map || !key) {
        return false;
    }
    
    // Resize if load factor is too high (75%)
    if (map->size * 4 >= map->capacity * 3) {
        if (!hash_map_resize(map)) {
            return false;
        }
    }
    
    size_t hash = hash_string(key);
    size_t index = hash & (map->capacity - 1);
    
    // Linear probing to find available slot
    size_t original_index = index;
    do {
        HashMapEntry *entry = &map->buckets[index];
        
        if (!entry->in_use) {
            // Found empty slot
            size_t key_len = strlen(key) + 1;
            entry->key = malloc(key_len);
            if (!entry->key) {
                return false;
            }
            strcpy(entry->key, key);
            entry->value = value;
            entry->in_use = true;
            map->size++;
            return true;
        } else if (strcmp(entry->key, key) == 0) {
            // Update existing entry
            entry->value = value;
            return true;
        }
        
        index = (index + 1) & (map->capacity - 1);
    } while (index != original_index);
    
    // Should never reach here with proper resizing
    return false;
}

// Get a value by key
Conn* hash_map_get(HashMap *map, const char *key) {
    if (!map || !key) {
        return NULL;
    }
    
    size_t hash = hash_string(key);
    size_t index = hash & (map->capacity - 1);
    size_t original_index = index;
    
    // Linear probing to find the key
    do {
        HashMapEntry *entry = &map->buckets[index];
        
        if (!entry->in_use) {
            return NULL; // Key not found
        } else if (strcmp(entry->key, key) == 0) {
            return entry->value; // Found the key
        }
        
        index = (index + 1) & (map->capacity - 1);
    } while (index != original_index);
    
    return NULL; // Key not found
}

// Remove a key-value pair by key
bool hash_map_remove(HashMap *map, const char *key) {
    if (!map || !key) {
        return false;
    }
    
    size_t hash = hash_string(key);
    size_t index = hash & (map->capacity - 1);
    size_t original_index = index;
    
    // Linear probing to find the key
    do {
        HashMapEntry *entry = &map->buckets[index];
        
        if (!entry->in_use) {
            return false; // Key not found
        } else if (strcmp(entry->key, key) == 0) {
            // Found the key, remove it
            free(entry->key);
            entry->key = NULL;
            entry->value = NULL;
            entry->in_use = false;
            map->size--;
            
            // Rehash subsequent entries to fill the gap
            size_t next_index = (index + 1) & (map->capacity - 1);
            while (map->buckets[next_index].in_use && next_index != original_index) {
                HashMapEntry *next_entry = &map->buckets[next_index];
                size_t next_hash = hash_string(next_entry->key);
                size_t preferred_index = next_hash & (map->capacity - 1);
                
                // If this entry should be moved earlier due to the gap
                if ((index < preferred_index && preferred_index <= next_index) ||
                    (next_index < index && (index < preferred_index || preferred_index <= next_index))) {
                    // Move the entry to fill the gap
                    map->buckets[index] = *next_entry;
                    map->buckets[next_index].in_use = false;
                    map->buckets[next_index].key = NULL;
                    map->buckets[next_index].value = NULL;
                    index = next_index;
                }
                
                next_index = (next_index + 1) & (map->capacity - 1);
            }
            
            return true;
        }
        
        index = (index + 1) & (map->capacity - 1);
    } while (index != original_index);
    
    return false; // Key not found
}

// Remove a key-value pair by connection pointer
bool hash_map_remove_by_conn(HashMap *map, Conn *conn) {
    if (!map || !conn) {
        return false;
    }
    
    // Search through all entries to find the connection
    for (size_t i = 0; i < map->capacity; i++) {
        HashMapEntry *entry = &map->buckets[i];
        if (entry->in_use && entry->value == conn) {
            // Found the connection, now remove it with proper rehashing
            free(entry->key);
            entry->key = NULL;
            entry->value = NULL;
            entry->in_use = false;
            map->size--;
            
            // Rehash subsequent entries to fill the gap (same logic as hash_map_remove)
            size_t next_index = (i + 1) & (map->capacity - 1);
            while (map->buckets[next_index].in_use && next_index != i) {
                HashMapEntry *next_entry = &map->buckets[next_index];
                size_t next_hash = hash_string(next_entry->key);
                size_t preferred_index = next_hash & (map->capacity - 1);
                
                // If this entry should be moved earlier due to the gap
                if ((i < preferred_index && preferred_index <= next_index) ||
                    (next_index < i && (i < preferred_index || preferred_index <= next_index))) {
                    // Move the entry to fill the gap
                    map->buckets[i] = *next_entry;
                    map->buckets[next_index].in_use = false;
                    map->buckets[next_index].key = NULL;
                    map->buckets[next_index].value = NULL;
                    i = next_index;
                }
                
                next_index = (next_index + 1) & (map->capacity - 1);
            }
            
            return true;
        }
    }
    
    return false;
}

// Get key (IMEI) by file descriptor
const char* hash_map_get_key_by_fd(HashMap *map, int fd) {
    if (!map) {
        return NULL;
    }
    
    // Search through all entries to find the connection with matching fd
    for (size_t i = 0; i < map->capacity; i++) {
        HashMapEntry *entry = &map->buckets[i];
        if (entry->in_use && entry->value && entry->value->fd == fd) {
            return entry->key;
        }
    }
    
    return NULL;
}

// Get the number of entries in the hash map
size_t hash_map_size(HashMap *map) {
    return map ? map->size : 0;
}

// Check if the hash map is empty
bool hash_map_empty(HashMap *map) {
    return map ? (map->size == 0) : true;
}
