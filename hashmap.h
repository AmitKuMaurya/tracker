#ifndef HASHMAP_H
#define HASHMAP_H

// Enable pthread rwlock support - must be before any includes
#define _GNU_SOURCE

#include <pthread.h>
#include <time.h>
#include <stdatomic.h>
#include "conn.h"

// Forward declaration for WebSocket connection
struct WSConnection;

#define HASH_MAP_CAPACITY 1024
#define MAX_IMEI_LENGTH 32
#define MAX_DEVICE_ID_LENGTH 32
#define REMOVAL_GRACE_PERIOD 30
#define TEMPORARY_NODE_TIMEOUT 300  // 5 minutes for WebSocket-only nodes

// Device entry structure - stores ALL device data
typedef struct DeviceEntry {
    atomic_int ref_count;
    int in_use;
    char imei[MAX_IMEI_LENGTH];
    char device_id[MAX_DEVICE_ID_LENGTH];
    
    Conn *tcp_conn;
    struct WSConnection *ws_conn;
    
    int is_online;
    time_t last_activity;
    int removal_scheduled;
    
    // Temporary node management
    int is_temporary;           // Flag: 1 if node created for WS-only, 0 for normal
    time_t creation_time;       // When this temporary node was created
    time_t ws_only_timeout;     // Timeout for WS-only nodes (default 300 seconds)
    
    struct DeviceEntry *next;
} DeviceEntry;

// Hash bucket structure
typedef struct {
    DeviceEntry *head;
    int chain_length;
    pthread_rwlock_t rwlock;
} HashBucket;

// Main hash map container
typedef struct {
    HashBucket imei_buckets[HASH_MAP_CAPACITY];
    atomic_int total_entries;
    time_t last_cleanup;
    
    void (*tcp_cleanup_cb)(Conn *conn);
    void (*ws_cleanup_cb)(struct WSConnection *ws_conn);
} UnifiedHashMap;

// ==================== CORE MANAGEMENT ====================
int hash_map_init(void);
void hash_map_cleanup(void);
void hash_map_print_stats(void);

// ==================== ENTRY MANAGEMENT ====================
DeviceEntry* hash_map_find_by_imei(const char *imei);
DeviceEntry* hash_map_create_entry(const char *imei, const char *device_id);
DeviceEntry* hash_map_create_temporary_entry(const char *imei);

// ==================== CONNECTION MANAGEMENT ====================
int hash_map_set_tcp_connection(const char *imei, const char *device_id, Conn *tcp_conn);
int hash_map_set_ws_connection(const char *imei, struct WSConnection *ws_conn);
int hash_map_remove_tcp_connection(const char *imei);
int hash_map_remove_ws_connection(const char *imei);
void hash_map_remove_tcp_connection_by_fd(int fd);

// ==================== SAFE STATUS QUERIES ====================
// These are thread-safe and don't require DeviceEntry access

// Check connection status
int hash_map_is_device_online(const char *imei);
int hash_map_has_client_connected(const char *imei);
int hash_map_is_device_registered(const char *imei);


// Get basic info
const char* hash_map_get_device_id(const char *imei);
time_t hash_map_get_last_activity(const char *imei);

// Get connections (with reference counting)
Conn* hash_map_get_tcp_connection(const char *imei);
struct WSConnection* hash_map_get_ws_connection(const char *imei);

// ==================== MAINTENANCE ====================
void hash_map_cleanup_scheduled_removals(void);
void hash_map_update_activity(const char *imei);
int hash_map_get_online_count(void);
int hash_map_get_total_entries(void);
int hash_map_get_temporary_entries_count(void);

// ==================== REFERENCE COUNTING ====================
void device_entry_ref(DeviceEntry *entry);
void device_entry_unref(DeviceEntry *entry);

// ==================== CLEANUP CALLBACKS ====================
void hash_map_set_cleanup_callbacks(void (*tcp_cleanup)(Conn *), void (*ws_cleanup)(struct WSConnection *));

// ==================== NOTIFICATION CALLBACKS ====================
typedef void (*connection_state_callback_t)(const char *imei, int connection_type, int is_connected);
void hash_map_set_state_callback(connection_state_callback_t callback);

//=============persinal=================
void fd_map_set_tcp(int fd, const char *imei);
void fd_map_set_ws(int fd, const char *imei);
const char* fd_map_get_tcp_imei(int fd);
const char* fd_map_get_ws_imei(int fd);
void fd_map_remove_tcp(int fd);
void fd_map_remove_ws(int fd);

// Fast IMEI lookup from FD (for data processing)
const char* hash_map_get_imei_by_fd(int fd);

// Fast connection status check by FD
int hash_map_is_connection_online_by_fd(int fd);

// IMEI to Device ID mapping functions
const char* hash_map_get_device_id_by_imei(const char *imei);
const char* hash_map_get_imei_by_device_id(const char *device_id);

#define CONN_TYPE_TCP 1
#define CONN_TYPE_WS  2

#endif // HASHMAP_H
