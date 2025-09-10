/**
 * @file gps_data.c
 * @brief Implementation file for GPS data processing module
 * 
 * This module handles GPS-specific data processing including coordinate
 * conversion, datetime parsing, speed/heading calculation, and GPS
 * positioning status validation.
 * 
 * @author GPS Tracker System
 * @date 2024
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include <sys/socket.h>
#include "gps_data.h"
#include "websocket_server.h"
#include "json_writer.h"

/* Constants */
static const char *GPS_LOG_PREFIX = "GPS_DATA";
static const double GPS_COORDINATE_SCALE = 30000.0;

/* Static function prototypes */
static int is_gps_positioned(const unsigned char *status_bytes);
static void convert_coordinates_to_degrees(uint32_t raw_lat, uint32_t raw_lon, 
                                         double *lat_deg, double *lon_deg);

/**
 * @brief Process GPS command (protocols 0x10, 0x11)
 */
void process_gps_command(Conn *c, const unsigned char *cmd, int len) {
    if (!c || !cmd) {
        printf("%s: Invalid parameters for GPS command\n", GPS_LOG_PREFIX);
        return;
    }
    
    // Validate packet
    if (validate_gps_packet(cmd, len) != 0) {
        return;
    }
    
    GPSData gps_data = {0}; // Initialize all fields to zero
    unsigned char protocol = cmd[3];
    
    // Store raw datetime for response
    memcpy(gps_data.datetime_raw, cmd + 4, GPS_DATETIME_LENGTH);
    
    // Parse datetime
    if (parse_gps_datetime(cmd + 4, &gps_data) != 0) {
        printf("%s: Failed to parse GPS datetime\n", GPS_LOG_PREFIX);
        return;
    }
    
    // Parse GPS info and check positioning status
    unsigned char gps_info = cmd[10];
    gps_data.gps_data_length = (gps_info >> 4) & 0x0F;
    gps_data.satellite_count = gps_info & 0x0F;
    
    // Check positioning status from status bytes
    gps_data.is_positioned = is_gps_positioned(cmd + 20);
    
    if (!gps_data.is_positioned) {
        printf("%s: GPS not positioned, skipping coordinate processing\n", GPS_LOG_PREFIX);
        
        // Send response even for non-positioned data
        if (send_gps_response(c, protocol, &gps_data) != 0) {
            printf("%s: Failed to send GPS response\n", GPS_LOG_PREFIX);
        }
        return;
    }
    
    printf("%s: GPS is positioned, processing coordinate data\n", GPS_LOG_PREFIX);
    
    // Parse coordinates
    if (parse_gps_coordinates(cmd + 11, &gps_data) != 0) {
        printf("%s: Failed to parse GPS coordinates\n", GPS_LOG_PREFIX);
        return;
    }
    
    // Parse status and heading
    if (parse_gps_status(cmd + 20, &gps_data) != 0) {
        printf("%s: Failed to parse GPS status\n", GPS_LOG_PREFIX);
        return;
    }
    
    // Parse speed
    gps_data.speed_kmh = cmd[19];
    
    // Log parsed GPS data
    log_gps_data(&gps_data);
    
    // Send response
    if (send_gps_response(c, protocol, &gps_data) != 0) {
        printf("%s: Failed to send GPS response\n", GPS_LOG_PREFIX);
    } else {
        printf("%s: GPS data processed and response sent\n", GPS_LOG_PREFIX);
    }
    
    // Send location data to WebSocket clients with matching IMEI
    if (c && c->has_login_id && gps_data.is_positioned) {
        char *ws_message = create_websocket_gps_message(c->login_id, &gps_data);
        if (ws_message) {
            int sent_count = websocket_send_to_imei(c->login_id, ws_message, strlen(ws_message));
            if (sent_count > 0) {
                printf("%s Sent GPS location to %d WebSocket client(s) for IMEI: %s\n", 
                       GPS_LOG_PREFIX, sent_count, c->login_id);
            } else {
                printf("%s No WebSocket clients found for IMEI: %s\n", 
                       GPS_LOG_PREFIX, c->login_id);
            }
            free(ws_message);
        } else {
            printf("%s Failed to create WebSocket GPS message for IMEI: %s\n", 
                   GPS_LOG_PREFIX, c->login_id);
        }
    }
}

int parse_gps_datetime(const unsigned char *cmd, GPSData *gps_data) {
    if (!cmd || !gps_data) {
        return -1;
    }
    
    // Parse BCD encoded datetime: YY MM DD HH MM SS
    gps_data->year = (cmd[0] >> 4) * 10 + (cmd[0] & 0x0F) + 2000;
    gps_data->month = (cmd[1] >> 4) * 10 + (cmd[1] & 0x0F);
    gps_data->day = (cmd[2] >> 4) * 10 + (cmd[2] & 0x0F);
    gps_data->hour = (cmd[3] >> 4) * 10 + (cmd[3] & 0x0F);
    gps_data->minute = (cmd[4] >> 4) * 10 + (cmd[4] & 0x0F);
    gps_data->second = (cmd[5] >> 4) * 10 + (cmd[5] & 0x0F);
    
    // Validate datetime ranges
    if (gps_data->year < 2000 || gps_data->year > 2099 ||
        gps_data->month < 1 || gps_data->month > 12 ||
        gps_data->day < 1 || gps_data->day > 31 ||
        gps_data->hour < 0 || gps_data->hour > 23 ||
        gps_data->minute < 0 || gps_data->minute > 59 ||
        gps_data->second < 0 || gps_data->second > 59) {
        printf("%s: Invalid datetime values\n", GPS_LOG_PREFIX);
        return -1;
    }
    
    return 0;
}

int parse_gps_coordinates(const unsigned char *cmd, GPSData *gps_data) {
    if (!cmd || !gps_data) {
        return -1;
    }
    
    // Extract latitude (4 bytes) and longitude (4 bytes)
    uint32_t latitude_raw = (cmd[0] << 24) | (cmd[1] << 16) | (cmd[2] << 8) | cmd[3];
    uint32_t longitude_raw = (cmd[4] << 24) | (cmd[5] << 16) | (cmd[6] << 8) | cmd[7];
    
    // Convert to decimal degrees
    convert_coordinates_to_degrees(latitude_raw, longitude_raw, 
                                 &gps_data->latitude, &gps_data->longitude);
    
    return 0;
}

int parse_gps_status(const unsigned char *cmd, GPSData *gps_data) {
    if (!cmd || !gps_data) {
        return -1;
    }
    
    unsigned char status_byte1 = cmd[0];
    unsigned char status_byte2 = cmd[1];
    
    // Extract direction indicators
    gps_data->is_north = (status_byte1 & 0x04) != 0; // Bit 5: 0=South, 1=North
    gps_data->is_east = (status_byte1 & 0x02) == 0;  // Bit 6: 0=East, 1=West
    
    // Apply direction to coordinates
    if (!gps_data->is_north) {
        gps_data->latitude = -gps_data->latitude;
    }
    if (!gps_data->is_east) {
        gps_data->longitude = -gps_data->longitude;
    }
    
    // Extract heading (last 10 bits of the two status bytes)
    gps_data->heading = ((status_byte1 & 0x03) << 8) | status_byte2;
    
    return 0;
}

int validate_gps_packet(const unsigned char *cmd, int len) {
    if (!cmd) {
        printf("%s: NULL command buffer\n", GPS_LOG_PREFIX);
        return -1;
    }
    
    if (len < GPS_MIN_PACKET_LENGTH) {
        printf("%s: GPS packet too short: %d bytes (minimum: %d)\n", 
               GPS_LOG_PREFIX, len, GPS_MIN_PACKET_LENGTH);
        return -1;
    }
    
    // Validate header
    if (cmd[0] != 0x78 || cmd[1] != 0x78) {
        printf("%s: Invalid GPS packet header\n", GPS_LOG_PREFIX);
        return -1;
    }
    
    // Validate terminator
    if (cmd[len-2] != 0x0D || cmd[len-1] != 0x0A) {
        printf("%s: Invalid GPS packet terminator\n", GPS_LOG_PREFIX);
        return -1;
    }
    
    return 0;
}

int send_gps_response(Conn *c, unsigned char protocol, const GPSData *gps_data) {
    if (!c || !gps_data) {
        return -1;
    }
    
    // Build response: 7878 00 [protocol] [datetime] 0D0A
    unsigned char response[] = {
        0x78, 0x78, 0x00, protocol,
        gps_data->datetime_raw[0], gps_data->datetime_raw[1],
        gps_data->datetime_raw[2], gps_data->datetime_raw[3],
        gps_data->datetime_raw[4], gps_data->datetime_raw[5],
        0x0D, 0x0A
    };
    
    ssize_t bytes_sent = send(c->fd, response, sizeof(response), 0);
    if (bytes_sent != sizeof(response)) {
        printf("%s: Failed to send complete GPS response (%zd/%zu bytes)\n", 
               GPS_LOG_PREFIX, bytes_sent, sizeof(response));
        return -1;
    }
    
    return 0;
}

void log_gps_data(const GPSData *gps_data) {
    if (!gps_data) {
        return;
    }
    
    printf("%s: === GPS Data Summary ===\n", GPS_LOG_PREFIX);
    printf("%s: DateTime: %04d-%02d-%02d %02d:%02d:%02d (GMT+0)\n", 
           GPS_LOG_PREFIX, gps_data->year, gps_data->month, gps_data->day,
           gps_data->hour, gps_data->minute, gps_data->second);
    
    printf("%s: Positioning: %s\n", GPS_LOG_PREFIX, 
           gps_data->is_positioned ? "YES" : "NO");
    
    if (gps_data->is_positioned) {
        printf("%s: Satellites: %d, GPS Data Length: %d\n", 
               GPS_LOG_PREFIX, gps_data->satellite_count, gps_data->gps_data_length);
        
        printf("%s: Latitude: %.6f %s\n", GPS_LOG_PREFIX, 
               fabs(gps_data->latitude), gps_data->is_north ? "N" : "S");
        printf("%s: Longitude: %.6f %s\n", GPS_LOG_PREFIX, 
               fabs(gps_data->longitude), gps_data->is_east ? "E" : "W");
        
        printf("%s: Speed: %d km/h\n", GPS_LOG_PREFIX, gps_data->speed_kmh);
        printf("%s: Heading: %d degrees\n", GPS_LOG_PREFIX, gps_data->heading);
    }
    
    printf("%s: ========================\n", GPS_LOG_PREFIX);
}

static int is_gps_positioned(const unsigned char *status_bytes) {
    if (!status_bytes) {
        return 0;
    }
    
    // Check bit 4 of first status byte (GPS positioning status)
    // 0 = GPS not positioned, 1 = GPS positioned
    return (status_bytes[0] & 0x08) != 0;
}

static void convert_coordinates_to_degrees(uint32_t raw_lat, uint32_t raw_lon, 
                                         double *lat_deg, double *lon_deg) {
    // Convert raw values to minutes
    double latitude_minutes = raw_lat / GPS_COORDINATE_SCALE;
    double longitude_minutes = raw_lon / GPS_COORDINATE_SCALE;
    
    // Convert minutes to decimal degrees
    double lat_degrees_whole = floor(latitude_minutes / 60.0);
    double lat_minutes_remainder = latitude_minutes - (lat_degrees_whole * 60.0);
    *lat_deg = lat_degrees_whole + (lat_minutes_remainder / 60.0);
    
    double lon_degrees_whole = floor(longitude_minutes / 60.0);
    double lon_minutes_remainder = longitude_minutes - (lon_degrees_whole * 60.0);
    *lon_deg = lon_degrees_whole + (lon_minutes_remainder / 60.0);
}
