// Enable pthread rwlock support - must be before any includes
#define _GNU_SOURCE

#include "hashmap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "websocket_server.h"
#include "json_writer.h"
#define MAX_FD_LIMIT 4096  // choose depending on how many sockets you expect

// Two lookup arrays
static char* tcp_fd_to_imei[MAX_FD_LIMIT];
static char* ws_fd_to_imei[MAX_FD_LIMIT];

// Lock for thread safety
static pthread_rwlock_t fd_map_lock = PTHREAD_RWLOCK_INITIALIZER;

// Global hash map instance
static UnifiedHashMap g_hash_map = {0};

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
        tcp_fd_to_imei[i] = NULL;  // ← CRITICAL: Set to NULL after freeing

        free(ws_fd_to_imei[i]);
        ws_fd_to_imei[i] = NULL;   // ← CRITICAL: Set to NULL after freeing
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
    
    device_entry_ref(entry);  // ← Now entry has ref_count = 2

    pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
    
    printf("CREATED new entry for IMEI: %s, device_id: %s\n", 
           imei, device_id ? device_id : "none");
    return entry;
}

DeviceEntry* hash_map_create_temporary_entry(const char *imei) {
    if (!imei || *imei == '\0') return NULL;
    
    // Check if entry already exists (shouldn't happen, but be safe)
    DeviceEntry *existing = hash_map_find_by_imei(imei);
    if (existing) {
        device_entry_unref(existing);
        printf("ERROR: Entry with IMEI %s already exists (tried to create temporary)\n", imei);
        return NULL;
    }
    
    // Create temporary entry with no device_id
    DeviceEntry *entry = create_device_entry(imei, NULL);  // ref_count = 1
    if (!entry) return NULL;
    
    // Mark as temporary with timeout
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
    
    // ✅ CRITICAL: Increment ref_count for the caller
    // ref_count = 2 (one for hash map, one for caller)
    device_entry_ref(entry);
    
    pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
    
    printf("CREATED temporary entry for IMEI: %s (WebSocket-only, expires in %d seconds)\n", 
           imei, TEMPORARY_NODE_TIMEOUT);
    return entry;  // Returns with ref_count = 2
}

// ==================== CONNECTION MANAGEMENT ====================

int hash_map_set_tcp_connection(const char *imei, const char *device_id, Conn *tcp_conn) {
    if (!imei || !tcp_conn) return -1;
    
    DeviceEntry *entry = hash_map_find_by_imei(imei);
    if (!entry) {
        entry = hash_map_create_entry(imei, device_id);
        if (!entry) return -1;
    } else {
        // Convert temporary to permanent if needed
        if (entry->is_temporary) {
            unsigned int index = hash_function(imei);
            pthread_rwlock_wrlock(&g_hash_map.imei_buckets[index].rwlock);
            
            entry->is_temporary = 0;
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
    Conn *old_tcp = NULL;  // ← Store old connection
    
    pthread_rwlock_wrlock(&g_hash_map.imei_buckets[index].rwlock);
    
    // ✅ Check if replacing existing connection
    if (entry->tcp_conn && entry->tcp_conn != tcp_conn) {
        old_tcp = entry->tcp_conn;  // ← Save old connection
        printf("Replacing existing TCP connection for IMEI: %s (old_fd=%d, new_fd=%d)\n",
               imei, old_tcp->fd, tcp_conn->fd);
    }
    
    entry->tcp_conn = tcp_conn;  // ← Set new connection
    entry->is_online = 1;
    entry->last_activity = time(NULL);
    entry->removal_scheduled = 0;
    
    pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
    
    // ✅ Cleanup old connection OUTSIDE the lock
    if (old_tcp && g_hash_map.tcp_cleanup_cb) {
        g_hash_map.tcp_cleanup_cb(old_tcp);
    }
    
    device_entry_unref(entry);
    
    // Set up FD mapping
    fd_map_set_tcp(tcp_conn->fd, imei);
    
    printf("TCP connection SET for IMEI: %s (fd=%d)\n", imei, tcp_conn->fd);
    return 0;
}

int hash_map_set_ws_connection(const char *imei, struct WSConnection *ws_conn, int fd) {
    if (!imei || !ws_conn || fd <= 0) return -1;
    
    DeviceEntry *entry = hash_map_find_by_imei(imei);
    if (!entry) {
        // Create TEMPORARY entry for WebSocket-only connection
        entry = hash_map_create_temporary_entry(imei);
        if (!entry) return -1;
        
        printf("Created TEMPORARY WebSocket-only entry for IMEI: %s (expires in 5 minutes)\n", imei);
    }
    
    unsigned int index = hash_function(imei);
    struct WSConnection *old_ws = NULL;  // ← Store old connection
    
    pthread_rwlock_wrlock(&g_hash_map.imei_buckets[index].rwlock);
    
    // ✅ Verify entry is still in the hash map
    DeviceEntry *current = g_hash_map.imei_buckets[index].head;
    int found = 0;
    
    while (current) {
        if (current == entry) {
            found = 1;
            break;
        }
        current = current->next;
    }
    
    if (!found) {
        // Entry was removed by another thread
        pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
        device_entry_unref(entry);  // Release our reference
        printf("WebSocket: Entry for IMEI %s was removed, retry\n", imei);
        return -1;  // Or retry logic
    }
    
    // ✅ Check if replacing existing connection
    if (entry->ws_conn && entry->ws_conn != ws_conn) {
        old_ws = entry->ws_conn;  // ← Save old connection
        printf("Replacing existing WebSocket connection for IMEI: %s\n", imei);
    }
    
    entry->ws_conn = ws_conn;  // ← Set new connection
    entry->last_activity = time(NULL);
    entry->removal_scheduled = 0;  // Cancel any pending removal
    
    pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
    
    // ✅ Cleanup old connection OUTSIDE the lock
    if (old_ws && g_hash_map.ws_cleanup_cb) {
        g_hash_map.ws_cleanup_cb(old_ws);
    }
    
    // ✅ Set up FD mapping
    fd_map_set_ws(fd, imei);
    
    device_entry_unref(entry);
    
    printf("WebSocket connection SET for IMEI: %s (fd=%d)\n", imei, fd);
    return 0;
}

int hash_map_remove_tcp_connection(const char *imei) {
    if (!imei) return -1;
    
    DeviceEntry *entry = hash_map_find_by_imei(imei);  // ← ref_count = 2
    if (!entry) return -1;
    
    unsigned int index = hash_function(imei);
    int fd_to_cleanup = -1;
    Conn *tcp_to_cleanup = NULL;
    int should_remove_entry = 0;
    char device_id_copy[MAX_DEVICE_ID_LENGTH] = {0};  // ← Local copy
    
    // ✅ Lock BEFORE accessing entry fields
    pthread_rwlock_wrlock(&g_hash_map.imei_buckets[index].rwlock);
    
    // ✅ Copy device_id while holding lock
    if (entry->device_id[0] != '\0') {
        strncpy(device_id_copy, entry->device_id, sizeof(device_id_copy) - 1);
    }
    
    // Save FD and connection BEFORE cleaning up
    if (entry->tcp_conn) {
        fd_to_cleanup = entry->tcp_conn->fd;
        tcp_to_cleanup = entry->tcp_conn;
        entry->tcp_conn = NULL;
    }
    
    entry->is_online = 0;
    entry->last_activity = time(NULL);
    
    // Check if BOTH connections are gone
    if (entry->ws_conn == NULL) {
        should_remove_entry = 1;
        printf("Both connections gone for IMEI: %s, removing from hash map\n", imei);
        
        // Remove from linked list NOW
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
    }
    
    pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
    
    // ✅ Send notification AFTER unlocking (using local copy)
    if (device_id_copy[0] != '\0') {
        printf("WebSocket: Notifying device_id %s about going offline for IMEI %s\n", 
               device_id_copy, imei);
        char* msg = device_online_status_json(0, imei, NULL);
        int websocket_result = websocket_send_to_device_id(device_id_copy, msg, strlen(msg));
        if (websocket_result < 0) {
            printf("WebSocket: Failed to send offline status for IMEI %s\n", imei);
        } else {
            printf("WebSocket: Successfully sent offline status for IMEI %s\n", imei);
        }
        free(msg);
    }
    
    // Cleanup OUTSIDE the lock
    if (tcp_to_cleanup && g_hash_map.tcp_cleanup_cb) {
        g_hash_map.tcp_cleanup_cb(tcp_to_cleanup);
    }
    
    if (fd_to_cleanup != -1) {
        fd_map_remove_tcp(fd_to_cleanup);
    }
    
    // Release the reference from hash_map_find_by_imei
    device_entry_unref(entry);  // ← ref_count: 2→1
    
    // If we removed from hash map, release that reference too
    if (should_remove_entry) {
        device_entry_unref(entry);  // ← ref_count: 1→0, entry freed!
    }
    
    printf("TCP connection REMOVED for IMEI: %s (fd=%d)\n", imei, fd_to_cleanup);
    return 0;
}

int hash_map_remove_ws_connection(const char *imei) {
    if (!imei) return -1;
    
    DeviceEntry *entry = hash_map_find_by_imei(imei);
    if (!entry) return -1;
    
    unsigned int index = hash_function(imei);
    struct WSConnection *ws_to_cleanup = NULL;
    int should_remove_entry = 0;
    
    pthread_rwlock_wrlock(&g_hash_map.imei_buckets[index].rwlock);
    
    // Save and set to NULL BEFORE freeing
    if (entry->ws_conn) {
        ws_to_cleanup = entry->ws_conn;
        entry->ws_conn = NULL;
    }
    
    entry->last_activity = time(NULL);
    
    // ✅ Check if BOTH connections are gone
    if (entry->tcp_conn == NULL) {
        should_remove_entry = 1;
        printf("Both connections gone for IMEI: %s, removing from hash map\n", imei);
        
        // Remove from linked list NOW
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
    }
    
    pthread_rwlock_unlock(&g_hash_map.imei_buckets[index].rwlock);
    
    // Cleanup OUTSIDE the lock
    if (ws_to_cleanup && g_hash_map.ws_cleanup_cb) {
        g_hash_map.ws_cleanup_cb(ws_to_cleanup);
    }
    
    // Clean up FD mapping (get fd from ws_to_cleanup before callback possibly frees it)
    // Note: We need to get the FD before calling cleanup callback
    // The FD is removed from fd_map during cleanup_websocket_connection in websocket_server.c
    
    // Release the reference from hash_map_find_by_imei
    device_entry_unref(entry);
    
    // If removed from hash map, release that reference too
    if (should_remove_entry) {
        device_entry_unref(entry);
    }
    
    printf("WebSocket connection REMOVED for IMEI: %s\n", imei);
    return 0;
}

void hash_map_remove_tcp_connection_by_fd(int fd) {
    if (fd <= 0) return;
    
    const char *imei = fd_map_get_tcp_imei(fd);
    if (imei) {
        hash_map_remove_tcp_connection(imei);
        // Note: fd_map_remove_tcp is already called inside hash_map_remove_tcp_connection
        return;
    }
    
    // Fallback: Find IMEI without holding locks during removal
    char found_imei[MAX_IMEI_LENGTH] = {0};
    
    for (int i = 0; i < HASH_MAP_CAPACITY; i++) {
        pthread_rwlock_rdlock(&g_hash_map.imei_buckets[i].rwlock);
        
        DeviceEntry *current = g_hash_map.imei_buckets[i].head;
        while (current) {
            if (current->tcp_conn && current->tcp_conn->fd == fd) {
                strncpy(found_imei, current->imei, sizeof(found_imei)-1);
                break;
            }
            current = current->next;
        }
        
        pthread_rwlock_unlock(&g_hash_map.imei_buckets[i].rwlock);
        
        if (found_imei[0] != '\0') {
            hash_map_remove_tcp_connection(found_imei);
            return;
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
            
            // ✅ ONLY check for expired temporary nodes
            // (Normal entries are removed immediately in remove_tcp/ws_connection)
            if (current->is_temporary && current->tcp_conn == NULL) {
                time_t elapsed = now - current->creation_time;
                if (elapsed > current->ws_only_timeout) {
                    printf("REMOVING expired temporary WebSocket-only entry for IMEI: %s "
                           "(elapsed: %ld seconds)\n", 
                           current->imei, elapsed);
                    should_remove = 1;
                    expired_temporary_count++;
                }
            }
            
            if (should_remove) {
                // ✅ Save connections to cleanup later
                Conn *tcp_to_cleanup = current->tcp_conn;
                current->tcp_conn = NULL;
                
                struct WSConnection *ws_to_cleanup = current->ws_conn;
                current->ws_conn = NULL;
                
                // Remove from linked list
                if (prev) {
                    prev->next = current->next;
                } else {
                    g_hash_map.imei_buckets[i].head = current->next;
                }
                
                g_hash_map.imei_buckets[i].chain_length--;
                atomic_fetch_sub(&g_hash_map.total_entries, 1);
                
                // ✅ Unlock BEFORE calling cleanup callbacks
                pthread_rwlock_unlock(&g_hash_map.imei_buckets[i].rwlock);
                
                // Cleanup connections (should be rare for temporary nodes)
                if (tcp_to_cleanup && g_hash_map.tcp_cleanup_cb) {
                    g_hash_map.tcp_cleanup_cb(tcp_to_cleanup);
                }
                if (ws_to_cleanup && g_hash_map.ws_cleanup_cb) {
                    g_hash_map.ws_cleanup_cb(ws_to_cleanup);
                }
                
                // ✅ Only ONE unref - releases hash map's reference
                // If temporary node was created with ref_count=1, this frees it
                // If it was created with ref_count=2, caller still holds a reference
                device_entry_unref(current);
                removed_count++;
                
                // ✅ Reacquire lock for next iteration
                pthread_rwlock_wrlock(&g_hash_map.imei_buckets[i].rwlock);
                
                // ⚠️ After unlocking/relocking, the list may have changed
                // Restart from head to be safe
                current = g_hash_map.imei_buckets[i].head;
                prev = NULL;
                continue;  // Skip normal advancement
            }
            
            prev = current;
            current = next;
        }
        
        pthread_rwlock_unlock(&g_hash_map.imei_buckets[i].rwlock);
    }
    
    g_hash_map.last_cleanup = now;
    
    if (removed_count > 0) {
        printf("Cleanup completed: removed %d expired temporary entries\n", 
               removed_count);
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
    if (!entry) return;
    
    int old_count = atomic_fetch_sub(&entry->ref_count, 1);
    
    if (old_count == 1) {
        // ✅ SAFETY NET: Cleanup any connections that weren't already freed
        // In normal flow, these should already be NULL
        // But if they're not NULL, we need to free them to prevent leaks
        
        if (entry->tcp_conn) {
            // This should rarely happen - log it for debugging
            fprintf(stderr, "WARNING: tcp_conn still set when freeing entry %s\n", 
                    entry->imei);
            
            if (g_hash_map.tcp_cleanup_cb) {
                g_hash_map.tcp_cleanup_cb(entry->tcp_conn);
            }
        }
        
        if (entry->ws_conn) {
            fprintf(stderr, "WARNING: ws_conn still set when freeing entry %s\n", 
                    entry->imei);
            
            if (g_hash_map.ws_cleanup_cb) {
                g_hash_map.ws_cleanup_cb(entry->ws_conn);
            }
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




//=============persinal=================

void fd_map_set_tcp(int fd, const char *imei) {
    if (fd < 0 || fd >= MAX_FD_LIMIT || !imei) return;

    pthread_rwlock_wrlock(&fd_map_lock);
    free(tcp_fd_to_imei[fd]);
    tcp_fd_to_imei[fd] = strdup(imei);
    if (!tcp_fd_to_imei[fd]) {
        fprintf(stderr, "fd_map_set_tcp: strdup failed for fd=%d (errno=%d)\n", fd, errno);
    }
    pthread_rwlock_unlock(&fd_map_lock);
}

void fd_map_set_ws(int fd, const char *imei) {
    if (fd < 0 || fd >= MAX_FD_LIMIT || !imei) return;

    pthread_rwlock_wrlock(&fd_map_lock);
    free(ws_fd_to_imei[fd]);
    ws_fd_to_imei[fd] = strdup(imei);
    if (!ws_fd_to_imei[fd]) {
        fprintf(stderr, "fd_map_set_ws: strdup failed for fd=%d (errno=%d)\n", fd, errno);
    }
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

const char* hash_map_get_imei_by_device_id(const char *device_id) {
    if (!device_id) return NULL;
    
    // Search through all entries to find device_id match
    for (int i = 0; i < HASH_MAP_CAPACITY; i++) {
        pthread_rwlock_rdlock(&g_hash_map.imei_buckets[i].rwlock);
        
        DeviceEntry *current = g_hash_map.imei_buckets[i].head;
        while (current) {
            if (current->device_id[0] != '\0' && strcmp(current->device_id, device_id) == 0) {
                device_entry_ref(current);
                pthread_rwlock_unlock(&g_hash_map.imei_buckets[i].rwlock);
                
                const char *imei = current->imei;
                device_entry_unref(current);
                return imei;
            }
            current = current->next;
        }
        
        pthread_rwlock_unlock(&g_hash_map.imei_buckets[i].rwlock);
    }
    
    return NULL;
}

typedef struct {
    char imei[MAX_IMEI_LENGTH];
    struct WSConnection *conn;
} WsConnectionSnapshot;

void hash_map_for_each_ws_connection(void (*callback)(const char *imei,
                                                      struct WSConnection *conn,
                                                      void *ctx),
                                     void *ctx) {
    if (!callback) {
        return;
    }

    size_t capacity = 16;
    size_t count = 0;
    WsConnectionSnapshot *snapshots = malloc(capacity * sizeof(*snapshots));
    if (!snapshots) {
        fprintf(stderr, "hash_map_for_each_ws_connection: allocation failed\n");
        return;
    }

    for (int i = 0; i < HASH_MAP_CAPACITY; i++) {
        pthread_rwlock_rdlock(&g_hash_map.imei_buckets[i].rwlock);

        DeviceEntry *current = g_hash_map.imei_buckets[i].head;
        while (current) {
            if (current->ws_conn) {
                if (count == capacity) {
                    size_t new_capacity = capacity * 2;
                    WsConnectionSnapshot *new_snapshots =
                        realloc(snapshots, new_capacity * sizeof(*snapshots));
                    if (!new_snapshots) {
                        pthread_rwlock_unlock(&g_hash_map.imei_buckets[i].rwlock);
                        fprintf(stderr, "hash_map_for_each_ws_connection: realloc failed\n");
                        free(snapshots);
                        return;
                    }
                    snapshots = new_snapshots;
                    capacity = new_capacity;
                }

                strncpy(snapshots[count].imei, current->imei, sizeof(snapshots[count].imei) - 1);
                snapshots[count].imei[sizeof(snapshots[count].imei) - 1] = '\0';
                snapshots[count].conn = current->ws_conn;
                count++;
            }
            current = current->next;
        }

        pthread_rwlock_unlock(&g_hash_map.imei_buckets[i].rwlock);
    }

    for (size_t i = 0; i < count; i++) {
        callback(snapshots[i].imei, snapshots[i].conn, ctx);
    }

    free(snapshots);
}

