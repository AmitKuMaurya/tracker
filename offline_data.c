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

/* Constants and Data Structures are now defined in offline_data.h */

/* Function Prototypes - Now declared in header file */

/* Global Variables */
static const char *LOG_PREFIX = "[LBS_PROCESSOR]";

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
 * @brief Parse WiFi hotspot data
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
    printf("%s WiFi hotspots count: %d\n", LOG_PREFIX, data->wifi_count);
    
    // Validate WiFi count
    if (data->wifi_count < 0 || data->wifi_count > 20) {
        log_parsing_error("Invalid WiFi count", __LINE__);
        return -1;
    }
    
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
    
    JsonWriter *writer = json_writer_create("lbs_data.json");
    if (!writer) {
        log_parsing_error("Failed to create JSON writer", __LINE__);
        return -1;
    }
    
        json_writer_start_object(writer);
        
        // Add device info
        if (c->has_login_id) {
            json_writer_add_string(writer, "device_id", c->login_id);
        }
        
        // Add datetime from packet
    char datetime_str[DATETIME_STRING_SIZE];
        snprintf(datetime_str, sizeof(datetime_str), "%04d-%02d-%02d %02d:%02d:%02d", 
            data->year, data->month, data->day, data->hour, data->minute, data->second);
        json_writer_add_string(writer, "packet_datetime", datetime_str);
        
        // Add WiFi data
    json_writer_add_int(writer, "wifi_count", data->wifi_count);
    
    // Add LBS data with unique count
    json_writer_add_int(writer, "original_lbs_count", data->original_lbs_count);
    json_writer_add_int(writer, "unique_lbs_count", data->unique_lbs_count);
    json_writer_add_int(writer, "mcc", data->mcc);
    json_writer_add_int(writer, "mnc", data->mnc);
    
    // Add base stations array with only unique cell IDs
        json_writer_start_array(writer, "base_stations");
    for (int i = 0; i < data->unique_lbs_count; i++) {
            if (i > 0) fprintf(writer->file, ",\n");
            fprintf(writer->file, "    {\n");
        fprintf(writer->file, "      \"lac\": %u,\n", data->unique_cells[i].lac);
        fprintf(writer->file, "      \"cell_id\": %u,\n", data->unique_cells[i].cell_id);
        fprintf(writer->file, "      \"rssi\": %d", data->unique_cells[i].rssi);
            fprintf(writer->file, "\n    }");
        }
        json_writer_end_array(writer);
        
        // Add alarm if present
    if (data->has_alarm) {
        json_writer_add_hex(writer, "alarm", data->alarm);
        }
        
        json_writer_end_object(writer);
        fprintf(writer->file, ",\n"); // Add comma for multiple entries
        json_writer_destroy(writer);
    
    return 0;
}

/**
 * @brief Clean up allocated memory in LBS data structure
 * 
 * @param data LBS data structure to clean up
 */
void cleanup_lbs_data(LBSData *data) {
    if (data && data->unique_cells) {
        free(data->unique_cells);
        data->unique_cells = NULL;
    }
}

/**
 * @brief Send response to GPS device
 * 
 * @param c Connection structure
 * @param cmd Original command buffer
 * @return 0 on success, -1 on error
 */
int send_device_response(Conn *c, const unsigned char *cmd) {
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
    
    // Skipping JSON write per request
    
    // Send response to device
    if (send_device_response(c, cmd) != 0) {
        printf("%s Warning: Failed to send device response\n", LOG_PREFIX);
    }
    
    // Cleanup
    cleanup_lbs_data(&data);
    
    printf("%s LBS data processed successfully\n", LOG_PREFIX);
}