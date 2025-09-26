/**
 * @file data_processing.h
 * @brief Header file for data processing module
 * 
 * This module handles all data processing logic including frame extraction,
 * protocol dispatching, and command routing. It separates data processing
 * concerns from socket operations.
 * 
 * @author GPS Tracker System
 * @date 2024
 */

#ifndef DATA_PROCESSING_H
#define DATA_PROCESSING_H

#include "conn.h"
#include <stdbool.h>

/**
 * @brief Process input buffer and extract complete frames
 * 
 * This function scans the connection's input buffer for complete frames
 * (0x7878...0x0D0A format) and processes each frame found.
 * 
 * @param c Connection structure containing input buffer
 */
void process_input_buffer(Conn *c);

/**
 * @brief Main command dispatcher
 * 
 * Analyzes the protocol ID in the command frame and routes it to the
 * appropriate handler function based on the protocol type.
 * 
 * @param c Connection structure
 * @param cmd Command buffer containing the complete frame
 * @param len Length of the command buffer
 */
void dispatch_command(Conn *c, const char *cmd, int len);

/**
 * @brief Process login command (protocol 0x01)
 * 
 * Handles device login/authentication including IMEI extraction,
 * BCD decoding, and device registration in the login map.
 * 
 * @param c Connection structure
 * @param cmd Command buffer
 * @param len Command length
 */
void process_login_command(Conn *c, const unsigned char *cmd, int len);

/**
 * @brief Process heartbeat command (protocol 0x08)
 * 
 * Handles heartbeat packets to maintain connection alive status.
 * 
 * @param c Connection structure
 * @param cmd Command buffer
 * @param len Command length
 */
void process_heartbeat_command(Conn *c, const unsigned char *cmd, int len);


/*
 * @brief Set heartbeat interval for a connection
 * 
 * Configures the heartbeat interval for a specific connection.
 * 
 * @param c Connection structure
 * @param heartbeat_interval Heartbeat interval in seconds
 * @return true on success, false on failure
 */
bool set_heartbeat(Conn *c, int heartbeat_interval);

/**
 @brief Process device details command (protocol 0x13)
 */
void process_device_details_command(Conn *c, const unsigned char *cmd, int len);

#endif // DATA_PROCESSING_H
