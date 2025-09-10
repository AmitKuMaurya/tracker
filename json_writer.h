#ifndef JSON_WRITER_H
#define JSON_WRITER_H

#include <stdio.h>
#include <cjson/cJSON.h>
#include "offline_data.h"
#include "gps_data.h"

/**
 * @brief Create a JSON object for LBS data
 * 
 * @param c Connection structure containing device information
 * @param data Parsed LBS data
 * @return cJSON* JSON object on success, NULL on failure
 */
cJSON* create_lbs_json_object(void *c, const void *data);

/**
 * @brief Write JSON object to file
 * 
 * @param json JSON object to write
 * @param filename Output filename
 * @return 0 on success, -1 on error
 */
int write_json_to_file(cJSON *json, const char *filename);

/**
 * @brief Free JSON object
 * 
 * @param json JSON object to free
 */
void free_json_object(cJSON *json);

/**
 * @brief Create Google Geolocation API JSON payload
 * 
 * @param data LBS data containing cell towers and WiFi access points
 * @return JSON string for Google API (must be freed by caller) or NULL on error
 */
char* create_google_geolocation_payload(const void *data);

/**
 * @brief Parse Google Geolocation API response
 * 
 * @param json JSON response from Google API
 * @param lat Output latitude
 * @param lon Output longitude  
 * @param accuracy_m Output accuracy in meters
 * @return 0 on success, -1 on error
 */
int parse_google_geolocation_response(const char *json, double *lat, double *lon, double *accuracy_m);

/**
 * @brief Create WebSocket JSON message for LBS location data
 * 
 * @param imei Device IMEI
 * @param lbs_data LBS data containing resolved location
 * @return JSON string for WebSocket message (must be freed by caller) or NULL on error
 */
char* create_websocket_lbs_message(const char *imei, const LBSData *lbs_data);

/**
 * @brief Create WebSocket JSON message for GPS location data
 * 
 * @param imei Device IMEI
 * @param gps_data GPS data containing location information
 * @return JSON string for WebSocket message (must be freed by caller) or NULL on error
 */
char* create_websocket_gps_message(const char *imei, const GPSData *gps_data);

#endif // JSON_WRITER_H
