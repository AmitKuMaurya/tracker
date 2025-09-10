/**
 * @file offline_data.c
 * @brief LBS (Location Based Services) data processing module
 * 
 * This module handles the processing of LBS commands from GPS tracking devices,
 * with support for unique cell ID filtering and base station deduplication.
 * 
 * @author Professional GPS Tracker System
 * @date 2024
 */

#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "offline_data.h"
#include "json_writer.h"
#include "lbs_latlong.h"
#include "websocket_server.h"

/* Constants and Data Structures are now defined in offline_data.h */

/* Function Prototypes - Now declared in header file */

/* Global Variables */
static const char *LOG_PREFIX = "LBS_PROCESSOR";

/**
 * @brief Check if a cell ID is unique in the given array
 * 
 * @param cells Array of cell information
 * @param count Number of cells in the array
 * @param cell_id Cell ID to check for uniqueness
 * @return 1 if unique, 0 if duplicate
 */
int is_cell_id_unique(const CellInfo *cells, int count, uint32_t cell_id) {
    if (!cells || count < 0) {
        return 0;
    }
    
    for (int i = 0; i < count; i++) {
        if (cells[i].cell_id == cell_id) {
            return 0; // Not unique
        }
    }
    return 1; // Unique
}

/**
 * @brief Check if a WiFi MAC address is unique in the given array
 * 
 * @param wifis Array of WiFi information
 * @param count Number of WiFi entries in the array
 * @param mac MAC address to check for uniqueness (6 bytes)
 * @return 1 if unique, 0 if duplicate
 */
int is_wifi_mac_unique(const WiFiInfo *wifis, int count, const unsigned char *mac) {
    if (!wifis || !mac || count < 0) {
        return 0;
    }
    
    for (int i = 0; i < count; i++) {
        if (memcmp(wifis[i].mac, mac, MAC_ADDRESS_SIZE) == 0) {
            return 0; // Not unique
        }
    }
    return 1; // Unique
}

/**
 * @brief Parse BCD encoded datetime from command
 * 
 * @param cmd Command buffer
 * @param data LBS data structure to populate
 * @return 0 on success, -1 on error
 */
int parse_datetime(const unsigned char *cmd, LBSData *data) {
    if (!cmd || !data) {
        log_parsing_error("Invalid parameters for datetime parsing", __LINE__);
        return -1;
    }
    
    // Parse datetime (BCD encoded starting at offset 4)
    data->year = (cmd[4] >> 4) * 10 + (cmd[4] & 0x0F) + 2000;
    data->month = (cmd[5] >> 4) * 10 + (cmd[5] & 0x0F);
    data->day = (cmd[6] >> 4) * 10 + (cmd[6] & 0x0F);
    data->hour = (cmd[7] >> 4) * 10 + (cmd[7] & 0x0F);
    data->minute = (cmd[8] >> 4) * 10 + (cmd[8] & 0x0F);
    data->second = (cmd[9] >> 4) * 10 + (cmd[9] & 0x0F);
    
    // Validate datetime ranges
    if (data->year < 2000 || data->year > 2099 ||
        data->month < 1 || data->month > 12 ||
        data->day < 1 || data->day > 31 ||
        data->hour < 0 || data->hour > 23 ||
        data->minute < 0 || data->minute > 59 ||
        data->second < 0 || data->second > 59) {
        log_parsing_error("Invalid datetime values", __LINE__);
        return -1;
    }
    
    printf("%s DateTime: %04d-%02d-%02d %02d:%02d:%02d (GMT+0)\n", 
           LOG_PREFIX, data->year, data->month, data->day, 
           data->hour, data->minute, data->second);
    
    return 0;
}

/**
 * @brief Parse WiFi hotspot data with MAC address deduplication
 * 
 * @param cmd Command buffer
 * @param len Command length
 * @param data LBS data structure to populate
 * @return 0 on success, -1 on error
 */
int parse_wifi_data(const unsigned char *cmd, int len, LBSData *data) {
    if (!cmd || !data || len < 3) {
        log_parsing_error("Invalid parameters for WiFi parsing", __LINE__);
        return -1;
    }
    
    data->wifi_count = cmd[2];
    data->original_wifi_count = data->wifi_count;
    printf("%s WiFi hotspots count: %d\n", LOG_PREFIX, data->wifi_count);
    
    // Validate WiFi count
    if (data->wifi_count < 0 || data->wifi_count > MAX_WIFI_HOTSPOTS) {
        log_parsing_error("Invalid WiFi count", __LINE__);
        return -1;
    }
    
    if (data->wifi_count == 0) {
        data->unique_wifi_count = 0;
        data->unique_wifis = NULL;
        return 0;
    }
    
    // Check if we have enough data for all WiFi entries
    int wifi_data_start = 10; // After header, len, protocol, datetime
    int required_wifi_bytes = data->wifi_count * WIFI_DATA_BYTES_PER_HOTSPOT;
    if (wifi_data_start + required_wifi_bytes > len) {
        log_parsing_error("Insufficient data for WiFi parsing", __LINE__);
        return -1;
    }
    
    // Allocate memory for unique WiFi entries
    data->unique_wifis = malloc(data->wifi_count * sizeof(WiFiInfo));
    if (!data->unique_wifis) {
        log_parsing_error("Memory allocation failed for unique WiFi entries", __LINE__);
        return -1;
    }
    
    data->unique_wifi_count = 0;
    int offset = wifi_data_start;
    
    // Parse each WiFi hotspot
    for (int i = 0; i < data->wifi_count; i++) {
        if (offset + WIFI_DATA_BYTES_PER_HOTSPOT > len) {
            printf("%s Warning: Incomplete WiFi data at index %d\n", LOG_PREFIX, i);
            break;
        }
        
        // Extract MAC address (6 bytes) and RSSI (1 byte)
        // WiFi data format: MAC[6] + RSSI[1] = 7 bytes per hotspot
        unsigned char mac[MAC_ADDRESS_SIZE];
        memcpy(mac, cmd + offset, MAC_ADDRESS_SIZE);
        int rssi = -(cmd[offset + MAC_ADDRESS_SIZE]); // Convert to negative dBm
        
        // Check if this MAC address is unique
        if (is_wifi_mac_unique(data->unique_wifis, data->unique_wifi_count, mac)) {
            // Add to unique WiFi array
            memcpy(data->unique_wifis[data->unique_wifi_count].mac, mac, MAC_ADDRESS_SIZE);
            data->unique_wifis[data->unique_wifi_count].rssi = rssi;
            data->unique_wifi_count++;
            
            printf("%s WiFi %d: MAC=%02X:%02X:%02X:%02X:%02X:%02X, RSSI=%ddBm (UNIQUE)\n", 
                   LOG_PREFIX, i + 1, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], rssi);
        } else {
            printf("%s WiFi %d: MAC=%02X:%02X:%02X:%02X:%02X:%02X, RSSI=%ddBm (DUPLICATE - SKIPPED)\n", 
                   LOG_PREFIX, i + 1, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], rssi);
        }
        
        offset += WIFI_DATA_BYTES_PER_HOTSPOT;
    }
    
    printf("%s Original WiFi hotspots: %d, Unique WiFi hotspots: %d\n", 
           LOG_PREFIX, data->original_wifi_count, data->unique_wifi_count);
    
    return 0;
}

/**
 * @brief Parse LBS base station data with duplicate filtering
 * 
 * @param cmd Command buffer
 * @param len Command length
 * @param data LBS data structure to populate
 * @return 0 on success, -1 on error
 */
int parse_lbs_data(const unsigned char *cmd, int len, LBSData *data) {
    if (!cmd || !data) {
        log_parsing_error("Invalid parameters for LBS parsing", __LINE__);
        return -1;
    }
    
    // Calculate offset to LBS data
    int offset = 10 + (data->wifi_count * WIFI_DATA_BYTES_PER_HOTSPOT);
    
    if (offset >= len - 3) {
        log_parsing_error("Invalid LBS command length after WiFi data", __LINE__);
        return -1;
    }

    // Parse LBS count
    data->original_lbs_count = cmd[offset++];
    printf("%s LBS base stations count: %d\n", LOG_PREFIX, data->original_lbs_count);
    
    // Validate LBS count
    if (data->original_lbs_count < 0 || data->original_lbs_count > MAX_BASE_STATIONS) {
        log_parsing_error("Invalid LBS count", __LINE__);
        return -1;
    }
    
    if (offset + 3 + (data->original_lbs_count * LBS_DATA_BYTES_PER_STATION) + 1 + 2 > len) {
        log_parsing_error("Invalid LBS command length for base station data", __LINE__);
        return -1;
    }

    // Parse MCC and MNC (BCD encoded)
    unsigned char mcc_high = cmd[offset];
    unsigned char mcc_low = cmd[offset + 1];
    unsigned char mnc = cmd[offset + 2];
    offset += 3;

    data->mcc = (mcc_high >> 4) * 1000 + (mcc_high & 0x0F) * 100 +
              (mcc_low >> 4) * 10 + (mcc_low & 0x0F);
    data->mnc = (mnc >> 4) * 10 + (mnc & 0x0F);
    
    printf("%s MCC: %d, MNC: %d\n", LOG_PREFIX, data->mcc, data->mnc);
    
    // Allocate memory for unique cells
    data->unique_cells = malloc(data->original_lbs_count * sizeof(CellInfo));
    if (!data->unique_cells) {
        log_parsing_error("Memory allocation failed for unique cells", __LINE__);
        return -1;
    }
    
    data->unique_lbs_count = 0;
    
    // Parse each base station and collect unique cell IDs
    for (int i = 0; i < data->original_lbs_count; i++) {
        if (offset + LBS_DATA_BYTES_PER_STATION > len) {
            printf("%s Warning: Incomplete base station data at index %d\n", LOG_PREFIX, i);
            break;
        }

        // Parse LAC (4 bytes)
        uint32_t lac = (cmd[offset] << 24) | (cmd[offset + 1] << 16) | 
                      (cmd[offset + 2] << 8) | cmd[offset + 3];
        offset += 4;

        // Parse Cell ID (4 bytes)
        uint32_t cell_id = (cmd[offset] << 24) | (cmd[offset + 1] << 16) | 
                          (cmd[offset + 2] << 8) | cmd[offset + 3];
        offset += 4;

        // Parse RSSI (1 byte) - convert to negative value
        int rssi = -(cmd[offset++]);

        // Check if this cell_id is unique
        if (is_cell_id_unique(data->unique_cells, data->unique_lbs_count, cell_id)) {
            // Add to unique cells array
            data->unique_cells[data->unique_lbs_count].cell_id = cell_id;
            data->unique_cells[data->unique_lbs_count].lac = lac;
            data->unique_cells[data->unique_lbs_count].rssi = rssi;
            data->unique_lbs_count++;
            
            printf("%s Base Station %d: LAC=%u, Cell ID=%u, RSSI=%ddBm (UNIQUE)\n", 
                   LOG_PREFIX, i + 1, lac, cell_id, rssi);
        } else {
            printf("%s Base Station %d: LAC=%u, Cell ID=%u, RSSI=%ddBm (DUPLICATE - SKIPPED)\n", 
                   LOG_PREFIX, i + 1, lac, cell_id, rssi);
        }
    }
    
    printf("%s Original base stations: %d, Unique base stations: %d\n", 
           LOG_PREFIX, data->original_lbs_count, data->unique_lbs_count);
    
    // Parse alarm information (if present)
    if (offset < len - 2) {
        data->alarm = cmd[offset++];
        data->has_alarm = 1;
        printf("%s Alarm information: 0x%02X\n", LOG_PREFIX, data->alarm);
    } else {
        data->has_alarm = 0;
    }
    
    return 0;
}

/**
 * @brief Validate command length and basic structure
 * 
 * @param cmd Command buffer
 * @param len Command length
 * @return 0 if valid, -1 if invalid
 */
int validate_command_length(const unsigned char *cmd, int len) {
    if (!cmd) {
        log_parsing_error("Null command buffer", __LINE__);
        return -1;
    }
    
    if (len < MIN_LBS_COMMAND_LENGTH) {
        printf("%s LBS command too short: %d bytes (minimum: %d)\n", 
               LOG_PREFIX, len, MIN_LBS_COMMAND_LENGTH);
        return -1;
    }
    
    // Check for valid command header
    if (cmd[0] != 0x78 || cmd[1] != 0x78) {
        log_parsing_error("Invalid command header", __LINE__);
        return -1;
    }
    
    return 0;
}

/**
 * @brief Log parsing errors with line number
 * 
 * @param error_msg Error message
 * @param line Line number where error occurred
 */
void log_parsing_error(const char *error_msg, int line) {
    printf("%s ERROR (line %d): %s\n", LOG_PREFIX, line, error_msg);
}

/**
 * @brief Write LBS data to JSON file
 * 
 * @param c Connection structure
 * @param data Parsed LBS data
 * @return 0 on success, -1 on error
 */
int write_lbs_json(Conn *c, const LBSData *data) {
    if (!c || !data) {
        log_parsing_error("Invalid parameters for JSON writing", __LINE__);
        return -1;
    }
    
    cJSON *json = create_lbs_json_object(c, data);
    if (!json) {
        log_parsing_error("Failed to create JSON object", __LINE__);
        return -1;
    }
    
    int result = write_json_to_file(json, "lbs_data.json");
    if (result != 0) {
        log_parsing_error("Failed to write JSON to file", __LINE__);
    }
    
    free_json_object(json);
    return result;
}

/**
 * @brief Clean up allocated memory in LBS data structure
 * 
 * @param data LBS data structure to clean up
 */
void cleanup_lbs_data(LBSData *data) {
    if (data) {
        if (data->unique_cells) {
            free(data->unique_cells);
            data->unique_cells = NULL;
        }
        if (data->unique_wifis) {
            free(data->unique_wifis);
            data->unique_wifis = NULL;
        }
        if (data->location) {
            free(data->location);
            data->location = NULL;
        }
    }
}

/**
 * @brief Send LBS response to GPS device
 * 
 * @param c Connection structure
 * @param cmd Original command buffer
 * @return 0 on success, -1 on error
 */
int send_lbs_device_response(Conn *c, const unsigned char *cmd) {
    if (!c || !cmd) {
        log_parsing_error("Invalid parameters for device response", __LINE__);
        return -1;
    }
    
    unsigned char response[] = {
        0x78, 0x78, 0x00, cmd[3],  // Protocol number
                               cmd[4], cmd[5], cmd[6], cmd[7], cmd[8], cmd[9], // Copy datetime
        0x0D, 0x0A
    };
    
    ssize_t bytes_sent = send(c->fd, response, sizeof(response), 0);
    if (bytes_sent != sizeof(response)) {
        printf("%s Warning: Failed to send complete response (%zd/%zu bytes)\n", 
               LOG_PREFIX, bytes_sent, sizeof(response));
        return -1;
    }
    
    return 0;
}

/**
 * @brief Main LBS command processing function
 * 
 * This function processes LBS (Location Based Services) commands from GPS tracking devices.
 * It parses the command, filters duplicate cell IDs, and stores the data in JSON format.
 * 
 * @param c Connection structure containing device information
 * @param cmd Command buffer containing the LBS data
 * @param len Length of the command buffer
 */
void lbs_command(Conn *c, const unsigned char *cmd, int len) {
    LBSData data = {0}; // Initialize all fields to zero
    
    printf("%s Processing LBS command (length: %d bytes)\n", LOG_PREFIX, len);
    
    // Validate command
    if (validate_command_length(cmd, len) != 0) {
        return;
    }
    
    // Parse WiFi data
    if (parse_wifi_data(cmd, len, &data) != 0) {
        return;
    }
    
    // Parse datetime
    if (parse_datetime(cmd, &data) != 0) {
        return;
    }
    
    // Parse LBS data
    if (parse_lbs_data(cmd, len, &data) != 0) {
        cleanup_lbs_data(&data);
        return;
    }

    // Query Unwired Labs for lat/lon/accuracy/address using unique cells
    if (lbs_query_unwired(&data) == 0 && data.location && data.location->is_resolved) {
        printf("%s LBS resolved lat/lon: %.6f, %.6f, accuracy: %.1fm\n", 
               LOG_PREFIX, data.location->lat, data.location->lon, data.location->accuracy_m);
        if (data.location->address[0] != '\0') {
            printf("%s Address: %s\n", LOG_PREFIX, data.location->address);
        }
        
        // Send location data to WebSocket clients with matching IMEI
        if (c && c->has_login_id) {
            char *ws_message = create_websocket_lbs_message(c->login_id, &data);
            if (ws_message) {
                int sent_count = websocket_send_to_imei(c->login_id, ws_message, strlen(ws_message));
                if (sent_count > 0) {
                    printf("%s Sent LBS location to %d WebSocket client(s) for IMEI: %s\n", 
                           LOG_PREFIX, sent_count, c->login_id);
                } else {
                    printf("%s No WebSocket clients found for IMEI: %s\n", 
                           LOG_PREFIX, c->login_id);
                }
                free(ws_message);
            } else {
                printf("%s Failed to create WebSocket message for IMEI: %s\n", 
                       LOG_PREFIX, c->login_id);
            }
        }
    } else {
        printf("%s LBS location not resolved from provided cells\n", LOG_PREFIX);
    }
    
    // Skipping JSON write per request
    
    // Send response to device
    if (send_lbs_device_response(c, cmd) != 0) {
        printf("%s: Warning: Failed to send device response\n", LOG_PREFIX);
    }
    
    // Cleanup
    cleanup_lbs_data(&data);
    
    printf("%s LBS data processed successfully\n", LOG_PREFIX);
}