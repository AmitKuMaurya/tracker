// Enable pthread rwlock support - must be before any includes
#define _GNU_SOURCE

#include "hashmap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#define MAX_FD_LIMIT 4096  // choose depending on how many sockets you expect

// Two lookup arrays
static char* tcp_fd_to_imei[MAX_FD_LIMIT];
static char* ws_fd_to_imei[MAX_FD_LIMIT];

// Lock for thread safety
static pthread_rwlock_t fd_map_lock = PTHREAD_RWLOCK_INITIALIZER;

// Global hash map instance
static UnifiedHashMap g_hash_map = {0};
static connection_state_callback_t g_state_callback = NULL;

// ==================== PRIVATE HELPER FUNCTIONS ====================

// Hash function (djb2 algorithm)
static unsigned int hash_function(const char *str) {
    if (!str || *str == '\0') return 0;
    
    unsigned long hash = 5381;
    int c;
    
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    
    return hash % HASH_MAP_CAPACITY;
}

// Initialize bucket RW locks
static int init_bucket_locks(HashBucket *buckets) {
    for (int i = 0; i < HASH_MAP_CAPACITY; i++) {
        if (pthread_rwlock_init(&buckets[i].rwlock, NULL) != 0) {
            return -1;
        }
        buckets[i].head = NULL;
        buckets[i].chain_length = 0;
    }
    return 0;
}

// Destroy bucket RW locks
static void destroy_bucket_locks(HashBucket *buckets) {
    for (int i = 0; i < HASH_MAP_CAPACITY; i++) {
        pthread_rwlock_destroy(&buckets[i].rwlock);
    }
}

// Create new device entry
static DeviceEntry* create_device_entry(const char *imei, const char *device_id) {
    DeviceEntry *entry = malloc(sizeof(DeviceEntry));
    if (!entry) {
        fprintf(stderr, "Failed to allocate memory for device entry\n");
        return NULL;
    }
    
    memset(entry, 0, sizeof(DeviceEntry));
    atomic_store(&entry->ref_count, 1);  // Start with 1 reference
    entry->in_use = 1;
    
    // Copy IMEI
    strncpy(entry->imei, imei, sizeof(entry->imei) - 1);
    entry->imei[sizeof(entry->imei) - 1] = '\0';
    
    // Copy device ID if provided
    if (device_id && strlen(device_id) > 0) {
        strncpy(entry->device_id, device_id, sizeof(entry->device_id) - 1);
        entry->device_id[sizeof(entry->device_id) - 1] = '\0';
    }
    
    entry->tcp_conn = NULL;
    entry->ws_conn = NULL;
    entry->is_online = 0;
    entry->last_activity = time(NULL);
    entry->removal_scheduled = 0;
    
    // Initialize temporary node fields
    entry->is_temporary = 0;
    entry->creation_time = 0;
    entry->ws_only_timeout = 0;
    
    entry->next = NULL;
    
    return entry;
}

// Remove entry from IMEI buckets
static void remove_from_imei_buckets(DeviceEntry *entry) {
    if (!entry) return;
    
    unsigned int index = hash_function(entry->imei);
    
    pthread_rwlock_wrlock(&g_hash_map.imei_buckets[index].rwlock);
    
    DeviceEntry *current = g_hash_map.imei_buckets[index].head;
    DeviceEntry *prev = NULL;
    
    while (current) {
        if (current == entry) {
            if (prev) {
                prev->next = current->next;
            } else {
                g_hash_map.imei_buckets[index].head = current->next;
            }
            
            g_hash_map.imei_buckets[index].chain_length--;
            atomic_fetch_sub(&g_hash_map.total_entries, 1);
            break;
        }
        prev = current;
        current = current->next;
    }
    
    pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
}

// ==================== CORE MANAGEMENT ====================

int hash_map_init(void) {
    memset(&g_hash_map, 0, sizeof(g_hash_map));
    
    // Initialize IMEI bucket array only
    if (init_bucket_locks(g_hash_map.imei_buckets) != 0) {
        fprintf(stderr, "Failed to initialize bucket locks\n");
        return -1;
    }
    
    atomic_store(&g_hash_map.total_entries, 0);
    g_hash_map.last_cleanup = time(NULL);
    g_hash_map.tcp_cleanup_cb = NULL;
    g_hash_map.ws_cleanup_cb = NULL;

    pthread_rwlock_wrlock(&fd_map_lock);
    memset(tcp_fd_to_imei, 0, sizeof(tcp_fd_to_imei));
    memset(ws_fd_to_imei, 0, sizeof(ws_fd_to_imei));
    pthread_rwlock_unlock(&fd_map_lock);
    
    printf("Hash map initialized with %d buckets\n", HASH_MAP_CAPACITY);
    return 0;
}

void hash_map_cleanup(void) {
    // Free all entries from IMEI bucket array
    for (int i = 0; i < HASH_MAP_CAPACITY; i++) {
        pthread_rwlock_wrlock(&g_hash_map.imei_buckets[i].rwlock);
        DeviceEntry *current = g_hash_map.imei_buckets[i].head;
        while (current) {
            DeviceEntry *next = current->next;
            
            // Cleanup connections if callbacks are set
            if (current->tcp_conn && g_hash_map.tcp_cleanup_cb) {
                g_hash_map.tcp_cleanup_cb(current->tcp_conn);
            }
            if (current->ws_conn && g_hash_map.ws_cleanup_cb) {
                g_hash_map.ws_cleanup_cb(current->ws_conn);
            }
            
            free(current);
            current = next;
        }
        g_hash_map.imei_buckets[i].head = NULL;
        g_hash_map.imei_buckets[i].chain_length = 0;
        pthread_rwlock_unlock(&g_hash_map.imei_buckets[i].rwlock);
    }
    
    atomic_store(&g_hash_map.total_entries, 0);
    
    // Destroy locks
    destroy_bucket_locks(g_hash_map.imei_buckets);
    pthread_rwlock_wrlock(&fd_map_lock);
    for (int i = 0; i < MAX_FD_LIMIT; i++) {
        free(tcp_fd_to_imei[i]);
        free(ws_fd_to_imei[i]);
    }
    pthread_rwlock_unlock(&fd_map_lock);
    
    printf("Hash map cleanup completed\n");
}

void hash_map_print_stats(void) {
    int empty_imei_buckets = 0;
    int max_imei_chain_length = 0;
    int total_imei_chain_length = 0;
    int online_devices = 0;
    int connected_clients = 0;
    int temporary_nodes = 0;
    
    for (int i = 0; i < HASH_MAP_CAPACITY; i++) {
        // IMEI buckets stats
        pthread_rwlock_rdlock(&g_hash_map.imei_buckets[i].rwlock);
        if (g_hash_map.imei_buckets[i].head == NULL) {
            empty_imei_buckets++;
        } else {
            int chain_len = g_hash_map.imei_buckets[i].chain_length;
            total_imei_chain_length += chain_len;
            if (chain_len > max_imei_chain_length) {
                max_imei_chain_length = chain_len;
            }
            
            // Count online devices, connected clients, and temporary nodes
            DeviceEntry *current = g_hash_map.imei_buckets[i].head;
            while (current) {
                if (current->tcp_conn != NULL) online_devices++;
                if (current->ws_conn != NULL) connected_clients++;
                if (current->is_temporary) temporary_nodes++;
                current = current->next;
            }
        }
        pthread_rwlock_unlock(&g_hash_map.imei_buckets[i].rwlock);
    }
    
    int total_entries = atomic_load(&g_hash_map.total_entries);
    
    printf("\n=== Hash Map Statistics ===\n");
    printf("Total entries: %d\n", total_entries);
    printf("Online devices: %d\n", online_devices);
    printf("Connected clients: %d\n", connected_clients);
    printf("Temporary WebSocket-only nodes: %d\n", temporary_nodes);
    
    printf("\nIMEI Index:\n");
    printf("  Empty buckets: %d/%d (%.1f%%)\n", 
           empty_imei_buckets, HASH_MAP_CAPACITY, 
           (100.0 * empty_imei_buckets) / HASH_MAP_CAPACITY);
    printf("  Max chain length: %d\n", max_imei_chain_length);
    
    if (total_entries > 0) {
        int used_imei_buckets = HASH_MAP_CAPACITY - empty_imei_buckets;
        
        if (used_imei_buckets > 0) {
            printf("  Average IMEI chain length: %.2f\n", 
                   (double)total_imei_chain_length / used_imei_buckets);
        }
        
        printf("Load factor: %.3f\n", (double)total_entries / HASH_MAP_CAPACITY);
    }
    
    time_t now = time(NULL);
    printf("Last cleanup: %ld seconds ago\n", now - g_hash_map.last_cleanup);
    printf("===========================\n\n");
}

// ==================== ENTRY MANAGEMENT ====================

DeviceEntry* hash_map_find_by_imei(const char *imei) {
    if (!imei || *imei == '\0') return NULL;
    
    unsigned int index = hash_function(imei);
    
    pthread_rwlock_rdlock(&g_hash_map.imei_buckets[index].rwlock);
    
    DeviceEntry *current = g_hash_map.imei_buckets[index].head;
    while (current) {
        if (current->in_use && strcmp(current->imei, imei) == 0) {
            device_entry_ref(current);  // Increase ref count for caller
            pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
            return current;
        }
        current = current->next;
    }
    
    pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
    return NULL;
}

DeviceEntry* hash_map_create_entry(const char *imei, const char *device_id) {
    if (!imei || *imei == '\0') return NULL;
    
    // Check if entry already exists
    DeviceEntry *existing = hash_map_find_by_imei(imei);
    if (existing) {
        device_entry_unref(existing);  // Release the reference
        printf("ERROR: Entry with IMEI %s already exists\n", imei);
        return NULL;  // Return error - entry already exists
    }
    
    // Create new entry
    DeviceEntry *entry = create_device_entry(imei, device_id);
    if (!entry) return NULL;
    
    unsigned int index = hash_function(imei);
    
    pthread_rwlock_wrlock(&g_hash_map.imei_buckets[index].rwlock);
    
    // Add to head of IMEI collision chain
    entry->next = g_hash_map.imei_buckets[index].head;
    g_hash_map.imei_buckets[index].head = entry;
    g_hash_map.imei_buckets[index].chain_length++;
    
    atomic_fetch_add(&g_hash_map.total_entries, 1);
    
    pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
    
    printf("CREATED new entry for IMEI: %s, device_id: %s\n", 
           imei, device_id ? device_id : "none");
    return entry;
}

DeviceEntry* hash_map_create_temporary_entry(const char *imei) {
    if (!imei || *imei == '\0') return NULL;
    
    // Create temporary entry with no device_id
    DeviceEntry *entry = create_device_entry(imei, NULL);
    if (!entry) return NULL;
    
    // Mark as temporary with 5-minute expiration
    time_t now = time(NULL);
    entry->is_temporary = 1;
    entry->creation_time = now;
    entry->ws_only_timeout = TEMPORARY_NODE_TIMEOUT;
    
    unsigned int index = hash_function(imei);
    
    pthread_rwlock_wrlock(&g_hash_map.imei_buckets[index].rwlock);
    
    // Add to head of IMEI collision chain
    entry->next = g_hash_map.imei_buckets[index].head;
    g_hash_map.imei_buckets[index].head = entry;
    g_hash_map.imei_buckets[index].chain_length++;
    
    atomic_fetch_add(&g_hash_map.total_entries, 1);
    
    pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
    
    printf("CREATED temporary entry for IMEI: %s (WebSocket-only, expires in %d seconds)\n", 
           imei, TEMPORARY_NODE_TIMEOUT);
    return entry;
}

// ==================== CONNECTION MANAGEMENT ====================

int hash_map_set_tcp_connection(const char *imei, const char *device_id, Conn *tcp_conn) {
    if (!imei || !tcp_conn) return -1;
    
    DeviceEntry *entry = hash_map_find_by_imei(imei);
    if (!entry) {
        // Create new permanent entry
        entry = hash_map_create_entry(imei, device_id);
        if (!entry) return -1;
    } else {
        // Convert temporary to permanent if needed
        if (entry->is_temporary) {
            unsigned int index = hash_function(imei);
            pthread_rwlock_wrlock(&g_hash_map.imei_buckets[index].rwlock);
            
            entry->is_temporary = 0;  // Make it permanent
            entry->creation_time = 0;
            entry->ws_only_timeout = 0;
            
            pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
            
            printf("Converted TEMPORARY entry to PERMANENT for IMEI: %s\n", imei);
        }
        
        // Update device_id if provided
        if (device_id && strlen(device_id) > 0) {
            strncpy(entry->device_id, device_id, sizeof(entry->device_id) - 1);
            entry->device_id[sizeof(entry->device_id) - 1] = '\0';
        }
    }
    
    unsigned int index = hash_function(imei);
    pthread_rwlock_wrlock(&g_hash_map.imei_buckets[index].rwlock);
    
    // Check if replacing existing connection
    if (entry->tcp_conn && entry->tcp_conn != tcp_conn && g_hash_map.tcp_cleanup_cb) {
        g_hash_map.tcp_cleanup_cb(entry->tcp_conn);
    }
    
    entry->tcp_conn = tcp_conn;
    entry->is_online = 1;
    entry->last_activity = time(NULL);
    entry->removal_scheduled = 0;  // Cancel any pending removal
    
    pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
    
    // Notify callback about TCP connection
    if (g_state_callback) {
        g_state_callback(imei, CONN_TYPE_TCP, 1);
    }
    
    device_entry_unref(entry);
    
    // Set up fast FD-to-IMEI mapping for O(1) lookups
    fd_map_set_tcp(tcp_conn->fd, imei);
    
    printf("TCP connection SET for IMEI: %s (fd=%d)\n", imei, tcp_conn->fd);
    return 0;
}

int hash_map_set_ws_connection(const char *imei, struct WSConnection *ws_conn) {
    if (!imei || !ws_conn) return -1;
    
    DeviceEntry *entry = hash_map_find_by_imei(imei);
    if (!entry) {
        // Create TEMPORARY entry for WebSocket-only connection
        entry = hash_map_create_temporary_entry(imei);
        if (!entry) return -1;
        
        printf("Created TEMPORARY WebSocket-only entry for IMEI: %s (expires in 5 minutes)\n", imei);
    }
    
    unsigned int index = hash_function(imei);
    pthread_rwlock_wrlock(&g_hash_map.imei_buckets[index].rwlock);
    
    // Check if replacing existing connection
    if (entry->ws_conn && entry->ws_conn != ws_conn && g_hash_map.ws_cleanup_cb) {
        g_hash_map.ws_cleanup_cb(entry->ws_conn);
    }
    
    entry->ws_conn = ws_conn;
    entry->last_activity = time(NULL);
    entry->removal_scheduled = 0;  // Cancel any pending removal
    
    pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
    
    // Notify callback about WebSocket connection
    if (g_state_callback) {
        g_state_callback(imei, CONN_TYPE_WS, 1);
    }
    
    device_entry_unref(entry);
    
    printf("WebSocket connection SET for IMEI: %s\n", imei);
    return 0;
}

int hash_map_remove_tcp_connection(const char *imei) {
    if (!imei) return -1;
    
    DeviceEntry *entry = hash_map_find_by_imei(imei);
    if (!entry) return -1;
    
    unsigned int index = hash_function(imei);
    pthread_rwlock_wrlock(&g_hash_map.imei_buckets[index].rwlock);
    
    if (entry->tcp_conn && g_hash_map.tcp_cleanup_cb) {
        g_hash_map.tcp_cleanup_cb(entry->tcp_conn);
    }
    
    entry->tcp_conn = NULL;
    entry->is_online = 0;
    entry->last_activity = time(NULL);
    
    // Schedule removal if no WebSocket connection
    if (entry->ws_conn == NULL) {
        entry->removal_scheduled = 1;
        printf("Both connections gone for IMEI: %s, scheduling removal\n", imei);
    } else if (!entry->is_temporary) {
        // If WebSocket still exists and it's not temporary, convert to temporary
        entry->is_temporary = 1;
        entry->creation_time = time(NULL);
        entry->ws_only_timeout = TEMPORARY_NODE_TIMEOUT;
        printf("TCP disconnected, converted to TEMPORARY WebSocket-only for IMEI: %s\n", imei);
    }
    
    pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
    
    // Notify callback about TCP disconnection
    if (g_state_callback) {
        g_state_callback(imei, CONN_TYPE_TCP, 0);
    }
    
    device_entry_unref(entry);
    
    // Clean up FD mapping if we have the connection
    if (entry->tcp_conn) {
        fd_map_remove_tcp(entry->tcp_conn->fd);
    }
    
    printf("TCP connection REMOVED for IMEI: %s\n", imei);
    return 0;
}

int hash_map_remove_ws_connection(const char *imei) {
    if (!imei) return -1;
    
    DeviceEntry *entry = hash_map_find_by_imei(imei);
    if (!entry) return -1;
    
    unsigned int index = hash_function(imei);
    pthread_rwlock_wrlock(&g_hash_map.imei_buckets[index].rwlock);
    
    if (entry->ws_conn && g_hash_map.ws_cleanup_cb) {
        g_hash_map.ws_cleanup_cb(entry->ws_conn);
    }
    
    entry->ws_conn = NULL;
    entry->last_activity = time(NULL);
    
    // Schedule removal if no TCP connection
    if (entry->tcp_conn == NULL) {
        entry->removal_scheduled = 1;
        printf("Both connections gone for IMEI: %s, scheduling removal\n", imei);
    }
    
    pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
    
    // Notify callback about WebSocket disconnection
    if (g_state_callback) {
        g_state_callback(imei, CONN_TYPE_WS, 0);
    }
    
    device_entry_unref(entry);
    
    // Note: WebSocket FD mapping cleanup is handled in websocket_server.c
    
    printf("WebSocket connection REMOVED for IMEI: %s\n", imei);
    return 0;
}

void hash_map_remove_tcp_connection_by_fd(int fd) {
    if (fd <= 0) return;
    
    // Use fast FD-to-IMEI lookup instead of O(n) search
    const char *imei = fd_map_get_tcp_imei(fd);
    if (imei) {
        printf("FAST LOOKUP: Found IMEI %s for fd %d\n", imei, fd);
        hash_map_remove_tcp_connection(imei);
        fd_map_remove_tcp(fd);  // Clean up FD mapping
    } else {
        printf("WARNING: No IMEI mapping found for fd %d, falling back to slow search\n", fd);
        // Fallback to slow search for safety
        for (int i = 0; i < HASH_MAP_CAPACITY; i++) {
            pthread_rwlock_rdlock(&g_hash_map.imei_buckets[i].rwlock);
            
            DeviceEntry *current = g_hash_map.imei_buckets[i].head;
            while (current) {
                if (current->tcp_conn && current->tcp_conn->fd == fd) {
                    device_entry_ref(current);
                    pthread_rwlock_unlock(&g_hash_map.imei_buckets[i].rwlock);
                    
                    hash_map_remove_tcp_connection(current->imei);
                    device_entry_unref(current);
                    return;
                }
                current = current->next;
            }
            
            pthread_rwlock_unlock(&g_hash_map.imei_buckets[i].rwlock);
        }
    }
}

// Note: WebSocket FD-based removal is handled in websocket_server.c



// ==================== SAFE STATUS QUERIES ====================

int hash_map_is_device_online(const char *imei) {
    DeviceEntry *entry = hash_map_find_by_imei(imei);
    if (!entry) return 0;
    
    unsigned int index = hash_function(imei);
    pthread_rwlock_rdlock(&g_hash_map.imei_buckets[index].rwlock);
    int online = (entry->tcp_conn != NULL) && entry->is_online;
    pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
    
    device_entry_unref(entry);
    return online;
}

int hash_map_has_client_connected(const char *imei) {
    DeviceEntry *entry = hash_map_find_by_imei(imei);
    if (!entry) return 0;
    
    unsigned int index = hash_function(imei);
    pthread_rwlock_rdlock(&g_hash_map.imei_buckets[index].rwlock);
    int has_client = (entry->ws_conn != NULL);
    pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
    
    device_entry_unref(entry);
    return has_client;
}

int hash_map_is_device_registered(const char *imei) {
    DeviceEntry *entry = hash_map_find_by_imei(imei);
    if (!entry) return 0;
    
    device_entry_unref(entry);
    return 1;
}

const char* hash_map_get_device_id(const char *imei) {
    DeviceEntry *entry = hash_map_find_by_imei(imei);
    if (!entry) return NULL;
    
    const char *device_id = entry->device_id;
    device_entry_unref(entry);
    return device_id;
}



time_t hash_map_get_last_activity(const char *imei) {
    DeviceEntry *entry = hash_map_find_by_imei(imei);
    if (!entry) return 0;
    
    unsigned int index = hash_function(imei);
    pthread_rwlock_rdlock(&g_hash_map.imei_buckets[index].rwlock);
    time_t activity = entry->last_activity;
    pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
    
    device_entry_unref(entry);
    return activity;
}

Conn* hash_map_get_tcp_connection(const char *imei) {
    DeviceEntry *entry = hash_map_find_by_imei(imei);
    if (!entry) return NULL;
    
    unsigned int index = hash_function(imei);
    pthread_rwlock_rdlock(&g_hash_map.imei_buckets[index].rwlock);
    Conn *conn = entry->tcp_conn;
    pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
    
    device_entry_unref(entry);
    return conn;
}

struct WSConnection* hash_map_get_ws_connection(const char *imei) {
    DeviceEntry *entry = hash_map_find_by_imei(imei);
    if (!entry) return NULL;
    
    unsigned int index = hash_function(imei);
    pthread_rwlock_rdlock(&g_hash_map.imei_buckets[index].rwlock);
    struct WSConnection *conn = entry->ws_conn;
    pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
    
    device_entry_unref(entry);
    return conn;
}

// ==================== MAINTENANCE ====================

void hash_map_cleanup_scheduled_removals(void) {
    time_t now = time(NULL);
    int removed_count = 0;
    int expired_temporary_count = 0;
    
    for (int i = 0; i < HASH_MAP_CAPACITY; i++) {
        pthread_rwlock_wrlock(&g_hash_map.imei_buckets[i].rwlock);
        
        DeviceEntry *current = g_hash_map.imei_buckets[i].head;
        DeviceEntry *prev = NULL;
        
        while (current) {
            DeviceEntry *next = current->next;
            int should_remove = 0;
            
            // Check for expired temporary nodes (WebSocket-only that timed out)
            if (current->is_temporary && current->tcp_conn == NULL) {
                time_t elapsed = now - current->creation_time;
                if (elapsed > current->ws_only_timeout) {
                    printf("REMOVING expired temporary WebSocket-only entry for IMEI: %s (%.0f minutes old)\n", 
                           current->imei, elapsed / 60.0);
                    should_remove = 1;
                    expired_temporary_count++;
                }
            }
            // Check for normal scheduled removals
            else if (current->removal_scheduled && 
                     current->tcp_conn == NULL && 
                     current->ws_conn == NULL &&
                     (now - current->last_activity) > REMOVAL_GRACE_PERIOD) {
                printf("REMOVING entry for IMEI: %s (grace period expired)\n", current->imei);
                should_remove = 1;
            }
            
            if (should_remove) {
                // Remove from IMEI linked list
                if (prev) {
                    prev->next = current->next;
                } else {
                    g_hash_map.imei_buckets[i].head = current->next;
                }
                
                g_hash_map.imei_buckets[i].chain_length--;
                atomic_fetch_sub(&g_hash_map.total_entries, 1);
                
                // Cleanup WebSocket connection if still active
                if (current->ws_conn && g_hash_map.ws_cleanup_cb) {
                    g_hash_map.ws_cleanup_cb(current->ws_conn);
                }
                
                device_entry_unref(current);
                removed_count++;
            } else {
                prev = current;
            }
            
            current = next;
        }
        
        pthread_rwlock_unlock(&g_hash_map.imei_buckets[i].rwlock);
    }
    
    g_hash_map.last_cleanup = now;
    
    if (removed_count > 0) {
        printf("Cleanup completed: removed %d entries (%d expired temporary nodes)\n", 
               removed_count, expired_temporary_count);
    }
}

void hash_map_update_activity(const char *imei) {
    DeviceEntry *entry = hash_map_find_by_imei(imei);
    if (entry) {
        unsigned int index = hash_function(imei);
        pthread_rwlock_wrlock(&g_hash_map.imei_buckets[index].rwlock);
        entry->last_activity = time(NULL);
        pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
        device_entry_unref(entry);
    }
}

int hash_map_get_online_count(void) {
    int count = 0;
    
    for (int i = 0; i < HASH_MAP_CAPACITY; i++) {
        pthread_rwlock_rdlock(&g_hash_map.imei_buckets[i].rwlock);
        
        DeviceEntry *current = g_hash_map.imei_buckets[i].head;
        while (current) {
            if (current->tcp_conn != NULL && current->is_online) {
                count++;
            }
            current = current->next;
        }
        
        pthread_rwlock_unlock(&g_hash_map.imei_buckets[i].rwlock);
    }
    
    return count;
}

int hash_map_get_total_entries(void) {
    return atomic_load(&g_hash_map.total_entries);
}

int hash_map_get_temporary_entries_count(void) {
    int count = 0;
    
    for (int i = 0; i < HASH_MAP_CAPACITY; i++) {
        pthread_rwlock_rdlock(&g_hash_map.imei_buckets[i].rwlock);
        
        DeviceEntry *current = g_hash_map.imei_buckets[i].head;
        while (current) {
            if (current->is_temporary) {
                count++;
            }
            current = current->next;
        }
        
        pthread_rwlock_unlock(&g_hash_map.imei_buckets[i].rwlock);
    }
    
    return count;
}

// ==================== REFERENCE COUNTING ====================

void device_entry_ref(DeviceEntry *entry) {
    if (entry) {
        atomic_fetch_add(&entry->ref_count, 1);
    }
}

void device_entry_unref(DeviceEntry *entry) {
    if (entry && atomic_fetch_sub(&entry->ref_count, 1) == 1) {
        // Last reference - cleanup and free
        if (entry->tcp_conn && g_hash_map.tcp_cleanup_cb) {
            g_hash_map.tcp_cleanup_cb(entry->tcp_conn);
        }
        if (entry->ws_conn && g_hash_map.ws_cleanup_cb) {
            g_hash_map.ws_cleanup_cb(entry->ws_conn);
        }
        free(entry);
    }
}

// ==================== CLEANUP CALLBACKS ====================

void hash_map_set_cleanup_callbacks(void (*tcp_cleanup)(Conn *), void (*ws_cleanup)(struct WSConnection *)) {
    g_hash_map.tcp_cleanup_cb = tcp_cleanup;
    g_hash_map.ws_cleanup_cb = ws_cleanup;
}

// ==================== NOTIFICATION CALLBACKS ====================

void hash_map_set_state_callback(connection_state_callback_t callback) {
    g_state_callback = callback;
}


//=============persinal=================

void fd_map_set_tcp(int fd, const char *imei) {
    if (fd < 0 || fd >= MAX_FD_LIMIT || !imei) return;

    pthread_rwlock_wrlock(&fd_map_lock);
    free(tcp_fd_to_imei[fd]);
    tcp_fd_to_imei[fd] = strdup(imei);
    pthread_rwlock_unlock(&fd_map_lock);
}

void fd_map_set_ws(int fd, const char *imei) {
    if (fd < 0 || fd >= MAX_FD_LIMIT || !imei) return;

    pthread_rwlock_wrlock(&fd_map_lock);
    free(ws_fd_to_imei[fd]);
    ws_fd_to_imei[fd] = strdup(imei);
    pthread_rwlock_unlock(&fd_map_lock);
}
const char* fd_map_get_tcp_imei(int fd) {
    if (fd < 0 || fd >= MAX_FD_LIMIT) return NULL;
    pthread_rwlock_rdlock(&fd_map_lock);
    const char *imei = tcp_fd_to_imei[fd];
    pthread_rwlock_unlock(&fd_map_lock);
    return imei;
}

const char* fd_map_get_ws_imei(int fd) {
    if (fd < 0 || fd >= MAX_FD_LIMIT) return NULL;
    pthread_rwlock_rdlock(&fd_map_lock);
    const char *imei = ws_fd_to_imei[fd];
    pthread_rwlock_unlock(&fd_map_lock);
    return imei;
}
void fd_map_remove_tcp(int fd) {
    if (fd < 0 || fd >= MAX_FD_LIMIT) return;
    pthread_rwlock_wrlock(&fd_map_lock);
    free(tcp_fd_to_imei[fd]);
    tcp_fd_to_imei[fd] = NULL;
    pthread_rwlock_unlock(&fd_map_lock);
}

void fd_map_remove_ws(int fd) {
    if (fd < 0 || fd >= MAX_FD_LIMIT) return;
    pthread_rwlock_wrlock(&fd_map_lock);
    free(ws_fd_to_imei[fd]);
    ws_fd_to_imei[fd] = NULL;
    pthread_rwlock_unlock(&fd_map_lock);
}

// Fast IMEI lookup from FD (tries TCP first, then WebSocket)
const char* hash_map_get_imei_by_fd(int fd) {
    if (fd <= 0) return NULL;
    
    // Try TCP first (most common)
    const char *imei = fd_map_get_tcp_imei(fd);
    if (imei) {
        return imei;
    }
    
    // Try WebSocket
    return fd_map_get_ws_imei(fd);
}

// Fast connection status check by FD
int hash_map_is_connection_online_by_fd(int fd) {
    if (fd <= 0) return 0;
    
    const char *imei = hash_map_get_imei_by_fd(fd);
    if (!imei) return 0;
    
    return hash_map_is_device_online(imei);
}

