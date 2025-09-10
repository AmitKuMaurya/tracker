/**
 * @file gps_data.h
 * @brief Header file for GPS data processing module
 * 
 * This module handles GPS-specific data processing including coordinate
 * conversion, datetime parsing, speed/heading calculation, and GPS
 * positioning status validation.
 * 
 * @author GPS Tracker System
 * @date 2024
 */

#ifndef GPS_DATA_H
#define GPS_DATA_H

#include "conn.h"
#include <stdint.h>

/* GPS Data Constants */
#define GPS_MIN_PACKET_LENGTH 24
#define GPS_DATETIME_LENGTH 6
#define GPS_COORDINATE_LENGTH 8
#define GPS_STATUS_LENGTH 2

/**
 * @brief Structure to hold parsed GPS data
 */
typedef struct {
    // Timestamp information
    int year, month, day;
    int hour, minute, second;
    
    // GPS positioning information
    int is_positioned;              /**< GPS positioning status */
    int gps_data_length;           /**< GPS data length field */
    int satellite_count;           /**< Number of visible satellites */
    
    // Location data
    double latitude;               /**< Latitude in decimal degrees */
    double longitude;              /**< Longitude in decimal degrees */
    int is_north;                 /**< 1 = North, 0 = South */
    int is_east;                  /**< 1 = East, 0 = West */
    
    // Movement data
    unsigned char speed_kmh;       /**< Speed in km/h */
    int heading;                  /**< Heading in degrees (0-360) */
    
    // Raw data for response
    unsigned char datetime_raw[GPS_DATETIME_LENGTH];
} GPSData;

/**
 * @brief Process GPS command (protocols 0x10, 0x11)
 * 
 * Main function to process GPS positioning data packets. Handles both
 * online (0x10) and offline (0x11) GPS positioning data.
 * 
 * @param c Connection structure
 * @param cmd Command buffer containing GPS data
 * @param len Command length
 */
void process_gps_command(Conn *c, const unsigned char *cmd, int len);

/**
 * @brief Parse GPS datetime from BCD encoded data
 * 
 * Converts BCD encoded datetime (6 bytes) to readable format.
 * Format: YY MM DD HH MM SS (all BCD encoded)
 * 
 * @param cmd Command buffer starting at datetime position
 * @param gps_data GPS data structure to populate
 * @return 0 on success, -1 on error
 */
int parse_gps_datetime(const unsigned char *cmd, GPSData *gps_data);

/**
 * @brief Parse GPS coordinates and convert to decimal degrees
 * 
 * Converts raw GPS coordinate data to decimal degree format.
 * Handles the 30000 scaling factor and minute/degree conversion.
 * 
 * @param cmd Command buffer starting at coordinate position
 * @param gps_data GPS data structure to populate
 * @return 0 on success, -1 on error
 */
int parse_gps_coordinates(const unsigned char *cmd, GPSData *gps_data);

/**
 * @brief Parse GPS status and heading information
 * 
 * Extracts positioning status, direction indicators (N/S, E/W),
 * and heading information from status bytes.
 * 
 * @param cmd Command buffer starting at status position
 * @param gps_data GPS data structure to populate
 * @return 0 on success, -1 on error
 */
int parse_gps_status(const unsigned char *cmd, GPSData *gps_data);

/**
 * @brief Validate GPS packet length and structure
 * 
 * Performs basic validation of GPS packet format and length.
 * 
 * @param cmd Command buffer
 * @param len Command length
 * @return 0 if valid, -1 if invalid
 */
int validate_gps_packet(const unsigned char *cmd, int len);

/**
 * @brief Send GPS response to device
 * 
 * Sends the required GPS response back to the device according
 * to the protocol specification.
 * 
 * @param c Connection structure
 * @param protocol GPS protocol number (0x10 or 0x11)
 * @param gps_data Parsed GPS data for response
 * @return 0 on success, -1 on error
 */
int send_gps_response(Conn *c, unsigned char protocol, const GPSData *gps_data);

/**
 * @brief Log GPS data in human-readable format
 * 
 * Outputs parsed GPS data to console for debugging and monitoring.
 * 
 * @param gps_data Parsed GPS data to log
 */
void log_gps_data(const GPSData *gps_data);

#endif // GPS_DATA_H
