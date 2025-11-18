/**
 * @file data_processing.c
 * @brief Implementation file for data processing module
 * 
 * This module handles all data processing logic including frame extraction,
 * protocol dispatching, and command routing. It separates data processing
 * concerns from socket operations.
 * 
 * @author GPS Tracker System
 * @date 2024
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include "data_processing.h"
#include "gps_data.h"
#include "hashmap.h"
#include "offline_data.h"
#include "websocket_server.h"
#include "json_writer.h"
#include "database.h"
/* Constants */
#define FRAME_HEADER_SIZE 2
#define FRAME_TERMINATOR_SIZE 2
#define MIN_FRAME_SIZE (FRAME_HEADER_SIZE + 1 + 1 + FRAME_TERMINATOR_SIZE) // header + len + proto + terminator

/* Static function prototypes */
static int extract_frame(Conn *c, int start_pos, int *frame_len);
static void log_frame_data(const char *frame, int len);
static unsigned char int_to_bcd(int val);
void send_time_sync_response(Conn *c);
const char* timezone_int_to_str(int tz);
bool set_status_upload_interval(Conn *c, int interval_minutes);
bool set_location_upload_interval(Conn *c, int interval_seconds);
/**
 * @brief Process input buffer and extract complete frames
 */
void process_input_buffer(Conn *c) {
    if (!c) {
        printf("DATA_PROC: Invalid connection structure\n");
        return;
    }
    
    int i = 0;
    while (i <= c->inbuf_used - MIN_FRAME_SIZE) {
        // Look for frame header (0x7878)
        if ((unsigned char)c->inbuf[i] == 0x78 &&
            (unsigned char)c->inbuf[i+1] == 0x78) {
            
            int frame_len;
            int frame_end = extract_frame(c, i, &frame_len);
            
            if (frame_end != -1) {
                // Complete frame found
                char *frame = malloc(frame_len);
                if (!frame) {
                    printf("DATA_PROC: Memory allocation failed for frame\n");
                    return;
                }
                
                memcpy(frame, c->inbuf + i, frame_len);
                
                // Process the frame
                dispatch_command(c, frame, frame_len);
                
                free(frame);
                
                // Move to next potential frame
                i = frame_end;
            } else {
                // Incomplete frame, wait for more data
                break;
            }
        } else {
            i++;
        }
    }
    
    // Shift remaining data to beginning of buffer
    if (i > 0 && i < c->inbuf_used) {
        memmove(c->inbuf, c->inbuf + i, c->inbuf_used - i);
        c->inbuf_used -= i;
    } else if (i >= c->inbuf_used) {
        // All data processed
        c->inbuf_used = 0;
    }
}

/**
 * @brief Extract a complete frame from the buffer
 * @param c Connection structure
 * @param start_pos Starting position in buffer
 * @param frame_len Output parameter for frame length
 * @return End position of frame, or -1 if incomplete
 */
static int extract_frame(Conn *c, int start_pos, int *frame_len) {
    // Search for terminator (0x0D0A)
    for (int j = start_pos + FRAME_HEADER_SIZE; j <= c->inbuf_used - FRAME_TERMINATOR_SIZE; j++) {
        if ((unsigned char)c->inbuf[j] == 0x0D &&
            (unsigned char)c->inbuf[j+1] == 0x0A) {
            
            *frame_len = (j + FRAME_TERMINATOR_SIZE) - start_pos;
            return j + FRAME_TERMINATOR_SIZE;
        }
    }
    
    // No complete frame found
    return -1;
}

/**
 * @brief Main command dispatcher
 */
void dispatch_command(Conn *c, const char *cmd, int len) {
    if (!c || !cmd || len < MIN_FRAME_SIZE) {
        printf("DATA_PROC: Invalid parameters for command dispatch\n");
        return;
    }
    
    // Log frame data for debugging
    log_frame_data(cmd, len);
    
    // Extract protocol number (4th byte)
    unsigned char protocol = (unsigned char)cmd[3];
    
    printf("DATA_PROC: Processing protocol 0x%02X\n", protocol);
    
    switch (protocol) {
        case 0x01:
            printf("DATA_PROC: Login command received\n");
            process_login_command(c, (const unsigned char *)cmd, len);
            break;
            
        case 0x08:
            printf("DATA_PROC: Heartbeat command received\n");
            process_heartbeat_command(c, (const unsigned char *)cmd, len);
            break;
            
        case 0x10:
        case 0x11:
            printf("DATA_PROC: GPS %s command received\n", 
                   (protocol == 0x10) ? "online" : "offline");
            process_gps_command(c, (const unsigned char *)cmd, len);
            break;
        case 0x13:
            printf("DATA_PROC: device details command received\n");
            process_device_details_command(c, (const unsigned char *)cmd, len);
            break;
            
        case 0x17:
        case 0x18:
        case 0x19:
            printf("DATA_PROC: LBS command received (0x%02X)\n", protocol);
            lbs_command(c, (const unsigned char *)cmd, len);

            break;
        case 0x30:
            printf("DATA_PROC: Time synchronization command received\n");
            send_time_sync_response(c);
            break;
            
        default:
            printf("DATA_PROC: Unknown protocol 0x%02X, ignoring\n", protocol);
            break;
    }
}

/**
 * @brief Log frame data in hex format
 */
static void log_frame_data(const char *frame, int len) {
    printf("DATA_PROC: Frame [%d bytes]: ", len);
    for (int i = 0; i < len && i < 32; i++) { // Limit to first 32 bytes for readability
        printf("%02X ", (unsigned char)frame[i]);
    }
    if (len > 32) {
        printf("...");
    }
    printf("\n");
}

/**
 * @brief Process login command (protocol 0x01)
 */
void process_login_command(Conn *c, const unsigned char *cmd, int len) {
    if (!c || !cmd) {
        printf("DATA_PROC: Invalid parameters for login command\n");
        return;
    }
    
    // Expected format: 78 78, len, 01, IMEI(8 bytes BCD), ver(1), 0D 0A
    const int min_login_len = FRAME_HEADER_SIZE + 1 + 1 + 8 + 1 + FRAME_TERMINATOR_SIZE;
    if (len < min_login_len) {
        printf("DATA_PROC: Login packet too short: %d bytes\n", len);
        return;
    }
    
    // Extract IMEI from BCD format (8 bytes starting at position 4)
    const unsigned char *imei_bcd = cmd + 4;
    char imei[17]; // 16 digits + null terminator
    int digit_index = 0;

    for (int i = 0; i < 8 && digit_index < 16; i++) {
        unsigned char byte = imei_bcd[i];
        unsigned char high = (byte >> 4) & 0x0F;
        unsigned char low = byte & 0x0F;
        
        if (high <= 9) {
            imei[digit_index++] = '0' + high;
        }
        if (digit_index < 16 && low <= 9) {
            imei[digit_index++] = '0' + low;
        }
    }
    imei[digit_index] = '\0';
    
    // Store last 15 digits of IMEI in connection structure
    int num_digits = digit_index;
    const char *last15 = (num_digits >= 15) ? (imei + (num_digits - 15)) : imei;
    snprintf(c->imei_id, sizeof(c->imei_id), "%.15s", last15);
    // we will inform app to device status online
    char* device_status_msg = device_online_status_json(1, c->imei_id, NULL);
    // Get device_id for this IMEI and send to device_id
    websocket_send_to_imei_id(c->imei_id, device_status_msg, strlen(device_status_msg));
    
    free(device_status_msg);
    c->has_imei_id = 1;

    // we set status upload interval to 2 minutes (or your desired value)
    int status_upload_interval = 2; // set to 2 minutes, change as needed
    if(set_status_upload_interval(c, status_upload_interval)) {
        printf("DATA_PROC: Status upload interval set to %d minutes for fd=%d\n", status_upload_interval, c->fd);
    } else {
        printf("DATA_PROC: Failed to set status upload interval for fd=%d\n", c->fd);
    }

    int location_upload_interval = 200; // set to 200 seconds, change as needed
    if(set_location_upload_interval(c, location_upload_interval)){
        printf("DATA_PROC: Location upload interval set to %d seconds for fd=%d\n", location_upload_interval, c->fd);
    } else {
        printf("DATA_PROC: Failed to set location upload interval for fd=%d\n", c->fd);
    }

    printf("DATA_PROC: Device login - IMEI: %s, fd: %d\n", c->imei_id, c->fd);
    
    // Get device_id from database for this IMEI
    const char *db_device_id = db_get_device_id(c->imei_id);
    if (db_device_id && strcmp(db_device_id, "device_id_not_found") != 0) {
        printf("DATA_PROC: Found device_id %s for IMEI %s\n", db_device_id, c->imei_id);
    } else {
        printf("DATA_PROC: No device_id found for IMEI %s, using IMEI as device_id\n", c->imei_id);
        db_device_id = c->imei_id;  // Fallback to IMEI
    }
    
    // Register device in hashmap with device_id
    hash_map_set_tcp_connection(c->imei_id, db_device_id, c);
    
    // Send success response: 7878 01 01 0D0A
    unsigned char response[] = {0x78, 0x78, 0x01, 0x01, 0x0D, 0x0A};
    if (send(c->fd, response, sizeof(response), 0) != sizeof(response)) {
        printf("DATA_PROC: Warning - Failed to send complete login response\n");
    } else {
        printf("DATA_PROC: Login response sent successfully\n");
    }
}

/**
 * @brief Process heartbeat command (protocol 0x08)
 */
void process_heartbeat_command(Conn *c, const unsigned char *cmd, int len) {
    if (!c || !cmd) {
        printf("DATA_PROC: Invalid parameters for heartbeat command\n");
        return;
    }
    
    printf("DATA_PROC: Heartbeat from device %s (fd: %d)\n", 
           c->has_imei_id ? c->imei_id : "unknown", c->fd);

    
    
    // Heartbeat packets typically don't require a response
    // But we could implement connection timeout management here
    
    (void)len; // Suppress unused parameter warning
}

void send_time_sync_response(Conn *c) {
    time_t t = time(NULL);
    struct tm *utc = gmtime(&t);   // get UTC time

    unsigned char resp[15];
    int idx = 0;

    resp[idx++] = 0x78;
    resp[idx++] = 0x78;
    resp[idx++] = 0x07;        // packet length
    resp[idx++] = 0x30;        // protocol number

    resp[idx++] = int_to_bcd((utc->tm_year + 1900) % 100);  // year (2 digits)
    resp[idx++] = int_to_bcd(utc->tm_mon + 1);              // month
    resp[idx++] = int_to_bcd(utc->tm_mday);                 // day
    resp[idx++] = int_to_bcd(utc->tm_hour);                 // hour
    resp[idx++] = int_to_bcd(utc->tm_min);                  // minute
    resp[idx++] = int_to_bcd(utc->tm_sec);                  // second

    resp[idx++] = 0x0D;
    resp[idx++] = 0x0A;

    send(c->fd, resp, idx, 0);

    printf(">> Sent time sync response (0x30): ");
    for (int i = 0; i < idx; i++) {
        printf("%02X ", resp[i]);
    }
    printf("\n");
}

// helper to convert int to BCD 
static unsigned char int_to_bcd(int val) {
    return (unsigned char)(((val / 10) << 4) | (val % 10));
}

bool set_heartbeat(Conn *c, int heartbeat_interval) {
    if (!c) return false;

    unsigned char high = (heartbeat_interval >> 8) & 0xFF;
    unsigned char low  = heartbeat_interval & 0xFF;

    unsigned char heartbeat_cmd[8] = {
        0x78, 0x78,       // start
        0x03,             // length (fixed for this cmd)
        0x13,             // protocol number
        high, low,        // interval time
        0x0D, 0x0A        // end
    };

    if(send(c->fd, heartbeat_cmd, sizeof(heartbeat_cmd), 0) == sizeof(heartbeat_cmd)) {
        printf("DATA_PROC: Heartbeat command set action sent successfully\n");
    } else {
        printf("DATA_PROC: Failed to send heartbeat command\n");
    }
    return true;
}

void process_device_details_command(Conn *c, const unsigned char *cmd, int len) {
    (void)c;
    (void)len;
    // Direct byte extraction - ALREADY GIVES DECIMAL VALUES
    int battery_level = cmd[4];
    //unsigned char firmware_version = cmd[5];
    //const char* time_zone = timezone_int_to_str(cmd[6]);
    int status_upload_interval = cmd[7];
    int signal_strength = cmd[8];

    // Print decimal values (what you want)
    printf("[DATAPROC] Device Status (Decimal Values):\n");
    printf("  - Battery Level: %d\n", battery_level);           // Will print: 75%
    //printf("  - Firmware Version: %d\n", firmware_version);      // Will print: 42
    //printf("  - Time Zone: %s\n", time_zone);               // Will print: GMT+5
    printf("  - Upload Interval: %d minutes\n", status_upload_interval); // Will print: 10 minutes
    printf("  - Signal Strength: %d\n", signal_strength);     // Will print: 64%
    
    char* device_details_msg = device_details_json(battery_level,status_upload_interval,signal_strength,c->imei_id);
    if (!device_details_msg) {
        printf("DATA_PROC: Failed to create device details JSON message\n");
        return;
    }
    
    // Get device_id for this IMEI and send to device_id
    websocket_send_to_imei_id(c->imei_id, device_details_msg, strlen(device_details_msg));
    free(device_details_msg);

    if(send(c->fd, cmd, len, 0)==len){
        printf("DATA_PROC: Echoed back command to device successfully\n");
    } else {
        printf("DATA_PROC: Failed to echo back command to device\n");
    }

    
}

const char* timezone_int_to_str(int tz) {
    static char result[16];

    int hours = tz & 0x0F;             // low nibble = hours
    int high  = (tz >> 4) & 0x0F;      // high nibble

    int quarter = (high >> 1) & 0x07;  // quarter-hour steps (0–7)
    int minutes = quarter * 15;        // 0,15,30,45,...
    int sign    = (high & 1) ? -1 : 1; // LSB = sign

    if (minutes == 0)
        snprintf(result, sizeof(result), "GMT%c%d",
                 (sign == 1 ? '+' : '-'), hours);
    else
        snprintf(result, sizeof(result), "GMT%c%d:%02d",
                 (sign == 1 ? '+' : '-'), hours, minutes);

    return result;
}


bool set_status_upload_interval(Conn *c, int interval_minutes) {
    if (!c) return false;
    if (interval_minutes < 0 || interval_minutes > 255) return false; // valid range

    unsigned char status_cmd[7] = {
        0x78, 0x78,       // start
        0x02,             // length (fixed for this cmd)
        0x13,             // protocol number (status interval)
        (unsigned char)interval_minutes, // interval time in minutes
        0x0D, 0x0A        // end
    };

    int result = send(c->fd, status_cmd, sizeof(status_cmd), 0) == sizeof(status_cmd);
    if(result) {
        printf("DATA_PROC: Status upload interval command sent successfully\n");
    } else {
        printf("DATA_PROC: Failed to send status upload interval command\n");
    }

    return result;
}

bool set_location_upload_interval(Conn *c, int interval_seconds) {
    if (!c) return false;
    if (interval_seconds < 0 || interval_seconds > 255) return false; // valid range

    int high = (interval_seconds >> 8) & 0x0F; // high nibble
    int low  = interval_seconds & 0x0F;        // low nibble
    unsigned char location_cmd[8] = {
        0x78, 0x78,       // start
        0x03,             // length (fixed for this cmd)
        0x97,             // protocol number (status interval)
        high, low,       // interval time in seconds
        0x0D, 0x0A        // end
    };
    int result = send(c->fd, location_cmd, sizeof(location_cmd), 0) == sizeof(location_cmd);
    if(result) {
        printf("DATA_PROC: Location upload interval command sent successfully\n");
    } else {
        printf("DATA_PROC: Failed to send location upload interval command\n");
    }
    return result;
}
 



