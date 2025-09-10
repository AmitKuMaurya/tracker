 /**
 * @file offline_data.h
 * @brief Header file for LBS (Location Based Services) data processing module
 * 
 * This module handles the processing of LBS commands from GPS tracking devices,
 * with support for unique cell ID filtering and base station deduplication.
 * 
 * @author Professional GPS Tracker System
 * @date 2024
 */

#ifndef OFFLINE_DATA_H
#define OFFLINE_DATA_H

#include "conn.h"
#include <stdint.h>

/* Constants */
#define MIN_LBS_COMMAND_LENGTH 12
#define WIFI_DATA_BYTES_PER_HOTSPOT 7
#define LBS_DATA_BYTES_PER_STATION 9
#define MAX_BASE_STATIONS 50
#define MAX_WIFI_HOTSPOTS 20
#define DATETIME_STRING_SIZE 32
#define MAC_ADDRESS_SIZE 6

/* Data Structures */

/**
 * @brief Structure to store unique cell tower information
 */
typedef struct {
    uint32_t cell_id;    /**< Unique cell tower identifier */
    uint32_t lac;        /**< Location Area Code */
    int rssi;            /**< Received Signal Strength Indicator in dBm */
} CellInfo;

/**
 * @brief Structure to store unique WiFi hotspot information
 */
typedef struct {
    unsigned char mac[MAC_ADDRESS_SIZE];  /**< WiFi MAC address (6 bytes) */
    int rssi;                             /**< Received Signal Strength Indicator in dBm */
} WiFiInfo;

/**
 * @brief Structure to store resolved location information
 */
typedef struct {
    double lat;                  /**< Resolved latitude (degrees) */
    double lon;                  /**< Resolved longitude (degrees) */
    double accuracy_m;           /**< Location accuracy in meters */
    char address[256];           /**< Human-readable address (if available) */
    int is_resolved;             /**< Flag indicating if location was successfully resolved */
} LocationData;

/**
 * @brief Structure to hold parsed LBS data
 */
typedef struct {
    int wifi_count;              /**< Number of WiFi hotspots */
    int original_wifi_count;     /**< Original number of WiFi hotspots */
    int unique_wifi_count;       /**< Number of unique WiFi hotspots after deduplication */
    WiFiInfo *unique_wifis;      /**< Array of unique WiFi information */
    int original_lbs_count;      /**< Original number of base stations */
    int unique_lbs_count;        /**< Number of unique base stations after deduplication */
    int mcc;                     /**< Mobile Country Code */
    int mnc;                     /**< Mobile Network Code */
    CellInfo *unique_cells;      /**< Array of unique cell information */
    int year, month, day;        /**< Date components */
    int hour, minute, second;    /**< Time components */
    unsigned char alarm;         /**< Alarm information */
    int has_alarm;               /**< Flag indicating if alarm data is present */
    LocationData *location;      /**< Resolved location information (if available) */
} LBSData;



/* Public Function Declarations */

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
void lbs_command(Conn *c, const unsigned char *cmd, int len);

/* Internal Function Declarations (for testing and debugging) */

/**
 * @brief Check if a cell ID is unique in the given array
 * 
 * @param cells Array of cell information
 * @param count Number of cells in the array
 * @param cell_id Cell ID to check for uniqueness
 * @return 1 if unique, 0 if duplicate
 */
int is_cell_id_unique(const CellInfo *cells, int count, uint32_t cell_id);

/**
 * @brief Check if a WiFi MAC address is unique in the given array
 * 
 * @param wifis Array of WiFi information
 * @param count Number of WiFi entries in the array
 * @param mac MAC address to check for uniqueness (6 bytes)
 * @return 1 if unique, 0 if duplicate
 */
int is_wifi_mac_unique(const WiFiInfo *wifis, int count, const unsigned char *mac);

/**
 * @brief Parse BCD encoded datetime from command
 * 
 * @param cmd Command buffer
 * @param data LBS data structure to populate
 * @return 0 on success, -1 on error
 */
int parse_datetime(const unsigned char *cmd, LBSData *data);

/**
 * @brief Parse WiFi hotspot data
 * 
 * @param cmd Command buffer
 * @param len Command length
 * @param data LBS data structure to populate
 * @return 0 on success, -1 on error
 */
int parse_wifi_data(const unsigned char *cmd, int len, LBSData *data);

/**
 * @brief Parse LBS base station data with duplicate filtering
 * 
 * @param cmd Command buffer
 * @param len Command length
 * @param data LBS data structure to populate
 * @return 0 on success, -1 on error
 */
int parse_lbs_data(const unsigned char *cmd, int len, LBSData *data);

/**
 * @brief Validate command length and basic structure
 * 
 * @param cmd Command buffer
 * @param len Command length
 * @return 0 if valid, -1 if invalid
 */
int validate_command_length(const unsigned char *cmd, int len);

/**
 * @brief Log parsing errors with line number
 * 
 * @param error_msg Error message
 * @param line Line number where error occurred
 */
void log_parsing_error(const char *error_msg, int line);

/**
 * @brief Write LBS data to JSON file
 * 
 * @param c Connection structure
 * @param data Parsed LBS data
 * @return 0 on success, -1 on error
 */
int write_lbs_json(Conn *c, const LBSData *data);

/**
 * @brief Clean up allocated memory in LBS data structure
 * 
 * @param data LBS data structure to clean up
 */
void cleanup_lbs_data(LBSData *data);

/**
 * @brief Send LBS response to GPS device
 * 
 * @param c Connection structure
 * @param cmd Original command buffer
 * @return 0 on success, -1 on error
 */
int send_lbs_device_response(Conn *c, const unsigned char *cmd);

#endif // OFFLINE_DATA_H