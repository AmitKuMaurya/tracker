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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "data_processing.h"
#include "gps_data.h"
#include "login_map.h"
#include "offline_data.h"
#include "websocket_server.h"
/* Constants */
#define FRAME_HEADER_SIZE 2
#define FRAME_TERMINATOR_SIZE 2
#define MIN_FRAME_SIZE (FRAME_HEADER_SIZE + 1 + 1 + FRAME_TERMINATOR_SIZE) // header + len + proto + terminator

/* Static function prototypes */
static int extract_frame(Conn *c, int start_pos, int *frame_len);
static void log_frame_data(const char *frame, int len);

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
            
        case 0x17:
        case 0x18:
        case 0x19:
            printf("DATA_PROC: LBS command received (0x%02X)\n", protocol);
            lbs_command(c, (const unsigned char *)cmd, len);
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
    char imei[16]; // 15 digits + null terminator
    int digit_index = 0;
    
    for (int i = 0; i < 8 && digit_index < 10; i++) {
        unsigned char byte = imei_bcd[i];
        unsigned char high = (byte >> 4) & 0x0F;
        unsigned char low = byte & 0x0F;
        
        if (high <= 9) {
            imei[digit_index++] = '0' + high;
        }
        if (digit_index < 15 && low <= 9) {
            imei[digit_index++] = '0' + low;
        }
    }
    imei[digit_index] = '\0';
    
    // Store IMEI in connection structure
    snprintf(c->login_id, sizeof(c->login_id), "%s", imei);
    websocket_send_to_imei(c->login_id, "Device is online", strlen("Device is online"));
    c->has_login_id = 1;
    
    printf("DATA_PROC: Device login - IMEI: %s, fd: %d\n", c->login_id, c->fd);
    
    // Register device in login map
    login_map_set(c->login_id, c);
    
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
           c->has_login_id ? c->login_id : "unknown", c->fd);
    
    // Heartbeat packets typically don't require a response
    // But we could implement connection timeout management here
    
    (void)len; // Suppress unused parameter warning
}

/**
 * @brief Send response to device
 */
int send_device_response(Conn *c, unsigned char protocol, const unsigned char *data, int data_len) {
    if (!c) {
        printf("DATA_PROC: Invalid connection for response\n");
        return -1;
    }
    
    // Calculate total response length
    int total_len = FRAME_HEADER_SIZE + 1 + 1 + data_len + FRAME_TERMINATOR_SIZE;
    unsigned char *response = malloc(total_len);
    if (!response) {
        printf("DATA_PROC: Failed to allocate memory for response\n");
        return -1;
    }
    
    // Build response frame
    int pos = 0;
    response[pos++] = 0x78; // Header
    response[pos++] = 0x78; // Header
    response[pos++] = data_len; // Data length
    response[pos++] = protocol; // Protocol
    
    // Add data if present
    if (data && data_len > 0) {
        memcpy(response + pos, data, data_len);
        pos += data_len;
    }
    
    response[pos++] = 0x0D; // Terminator
    response[pos++] = 0x0A; // Terminator
    
    // Send response
    ssize_t bytes_sent = send(c->fd, response, total_len, 0);
    free(response);
    
    if (bytes_sent != total_len) {
        printf("DATA_PROC: Response send failed: %zd/%d bytes\n", bytes_sent, total_len);
        return -1;
    }
    
    printf("DATA_PROC: Response sent successfully (protocol 0x%02X, %d bytes)\n", 
           protocol, total_len);
    return 0;
}
