#include "json_writer.h"
#include "offline_data.h"
#include "gps_data.h"
#include <string.h>
#include <stdlib.h>

cJSON* create_lbs_json_object(void *c, const void *data) {
    const LBSData *lbs_data = (const LBSData *)data;
    const Conn *conn = (const Conn *)c;
    if (!lbs_data) {
        return NULL;
    }
    
    cJSON *json = cJSON_CreateObject();
    if (!json) {
        return NULL;
    }
    
    // Add device info
    if (conn && conn->has_login_id) {
        cJSON_AddStringToObject(json, "device_id", conn->login_id);
    }
    
    // Add datetime from packet
    char datetime_str[DATETIME_STRING_SIZE];
    snprintf(datetime_str, sizeof(datetime_str), "%04d-%02d-%02d %02d:%02d:%02d", 
             lbs_data->year, lbs_data->month, lbs_data->day, lbs_data->hour, lbs_data->minute, lbs_data->second);
    cJSON_AddStringToObject(json, "packet_datetime", datetime_str);
    
    // Add WiFi data with unique count
    cJSON_AddNumberToObject(json, "original_wifi_count", lbs_data->original_wifi_count);
    cJSON_AddNumberToObject(json, "unique_wifi_count", lbs_data->unique_wifi_count);
    
    // Add WiFi hotspots array with only unique MAC addresses
    cJSON *wifi_hotspots = cJSON_CreateArray();
    if (wifi_hotspots) {
        for (int i = 0; i < lbs_data->unique_wifi_count; i++) {
            cJSON *hotspot = cJSON_CreateObject();
            if (hotspot) {
                // Format MAC address as string
                char mac_str[18]; // XX:XX:XX:XX:XX:XX
                snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                         lbs_data->unique_wifis[i].mac[0], lbs_data->unique_wifis[i].mac[1],
                         lbs_data->unique_wifis[i].mac[2], lbs_data->unique_wifis[i].mac[3],
                         lbs_data->unique_wifis[i].mac[4], lbs_data->unique_wifis[i].mac[5]);
                cJSON_AddStringToObject(hotspot, "mac", mac_str);
                cJSON_AddNumberToObject(hotspot, "rssi", lbs_data->unique_wifis[i].rssi);
                cJSON_AddItemToArray(wifi_hotspots, hotspot);
            }
        }
        cJSON_AddItemToObject(json, "wifi_hotspots", wifi_hotspots);
    }
    
    // Add LBS data with unique count
    cJSON_AddNumberToObject(json, "original_lbs_count", lbs_data->original_lbs_count);
    cJSON_AddNumberToObject(json, "unique_lbs_count", lbs_data->unique_lbs_count);
    cJSON_AddNumberToObject(json, "mcc", lbs_data->mcc);
    cJSON_AddNumberToObject(json, "mnc", lbs_data->mnc);
    
    // Add base stations array with only unique cell IDs
    cJSON *base_stations = cJSON_CreateArray();
    if (base_stations) {
        for (int i = 0; i < lbs_data->unique_lbs_count; i++) {
            cJSON *station = cJSON_CreateObject();
            if (station) {
                cJSON_AddNumberToObject(station, "lac", lbs_data->unique_cells[i].lac);
                cJSON_AddNumberToObject(station, "cell_id", lbs_data->unique_cells[i].cell_id);
                cJSON_AddNumberToObject(station, "rssi", lbs_data->unique_cells[i].rssi);
                cJSON_AddItemToArray(base_stations, station);
            }
        }
        cJSON_AddItemToObject(json, "base_stations", base_stations);
    }
    
    // Add location data if available
    if (lbs_data->location && lbs_data->location->is_resolved) {
        cJSON *location = cJSON_CreateObject();
        if (location) {
            cJSON_AddNumberToObject(location, "lat", lbs_data->location->lat);
            cJSON_AddNumberToObject(location, "lon", lbs_data->location->lon);
            cJSON_AddNumberToObject(location, "accuracy_m", lbs_data->location->accuracy_m);
            if (lbs_data->location->address[0] != '\0') {
                cJSON_AddStringToObject(location, "address", lbs_data->location->address);
            }
            cJSON_AddItemToObject(json, "location", location);
        }
    }
    
    // Add alarm if present
    if (lbs_data->has_alarm) {
        char alarm_str[8];
        snprintf(alarm_str, sizeof(alarm_str), "0x%02X", lbs_data->alarm);
        cJSON_AddStringToObject(json, "alarm", alarm_str);
    }
    
    return json;
}

int write_json_to_file(cJSON *json, const char *filename) {
    if (!json || !filename) {
        return -1;
    }
    
    FILE *file = fopen(filename, "a");
    if (!file) {
        return -1;
    }
    
    char *json_string = cJSON_Print(json);
    if (json_string) {
        fprintf(file, "%s,\n", json_string);
        free(json_string);
    }
    
    fclose(file);
    return 0;
}

void free_json_object(cJSON *json) {
    if (json) {
        cJSON_Delete(json);
    }
}

char* create_google_geolocation_payload(const void *data) {
    const LBSData *lbs_data = (const LBSData *)data;
    if (!lbs_data) {
        return NULL;
    }
    
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return NULL;
    }
    
    // Add basic parameters
    cJSON_AddNumberToObject(root, "homeMobileCountryCode", lbs_data->mcc);
    cJSON_AddNumberToObject(root, "homeMobileNetworkCode", lbs_data->mnc);
    cJSON_AddStringToObject(root, "radioType", "lte");
    cJSON_AddBoolToObject(root, "considerIp", cJSON_True);
    
    // Add cell towers if available
    if (lbs_data->unique_lbs_count > 0 && lbs_data->unique_cells) {
        cJSON *cell_towers = cJSON_CreateArray();
        if (cell_towers) {
            for (int i = 0; i < lbs_data->unique_lbs_count; i++) {
                cJSON *tower = cJSON_CreateObject();
                if (tower) {
                    cJSON_AddNumberToObject(tower, "cellId", lbs_data->unique_cells[i].cell_id);
                    cJSON_AddNumberToObject(tower, "locationAreaCode", lbs_data->unique_cells[i].lac);
                    cJSON_AddNumberToObject(tower, "mobileCountryCode", lbs_data->mcc);
                    cJSON_AddNumberToObject(tower, "mobileNetworkCode", lbs_data->mnc);
                    cJSON_AddNumberToObject(tower, "signalStrength", lbs_data->unique_cells[i].rssi);
                    cJSON_AddNumberToObject(tower, "age", 0);
                    cJSON_AddNumberToObject(tower, "timingAdvance", 0);
                    cJSON_AddItemToArray(cell_towers, tower);
                }
            }
            cJSON_AddItemToObject(root, "cellTowers", cell_towers);
        }
    }
    
    // Add WiFi access points if available
    if (lbs_data->unique_wifi_count > 0 && lbs_data->unique_wifis) {
        cJSON *wifi_access_points = cJSON_CreateArray();
        if (wifi_access_points) {
            for (int i = 0; i < lbs_data->unique_wifi_count; i++) {
                cJSON *ap = cJSON_CreateObject();
                if (ap) {
                    // Format MAC address as string (lowercase for Google API)
                    char mac_str[18]; // xx:xx:xx:xx:xx:xx
                    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                             lbs_data->unique_wifis[i].mac[0], lbs_data->unique_wifis[i].mac[1],
                             lbs_data->unique_wifis[i].mac[2], lbs_data->unique_wifis[i].mac[3],
                             lbs_data->unique_wifis[i].mac[4], lbs_data->unique_wifis[i].mac[5]);
                    
                    cJSON_AddStringToObject(ap, "macAddress", mac_str);
                    cJSON_AddNumberToObject(ap, "signalStrength", lbs_data->unique_wifis[i].rssi);
                    cJSON_AddNumberToObject(ap, "age", 0);
                    cJSON_AddNumberToObject(ap, "channel", 0);
                    cJSON_AddNumberToObject(ap, "signalToNoiseRatio", 0);
                    cJSON_AddItemToArray(wifi_access_points, ap);
                }
            }
            cJSON_AddItemToObject(root, "wifiAccessPoints", wifi_access_points);
        }
    }
    
    char *json_string = cJSON_Print(root);
    cJSON_Delete(root);
    
    return json_string;
}

char* create_websocket_gps_message(const char *imei, const GPSData *gps_data) {
    if (!imei || !gps_data || !gps_data->is_positioned) {
        return NULL;
    }
    
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return NULL;
    }
    
    // Add message type and device info
    cJSON_AddStringToObject(root, "type", "location");
    cJSON_AddStringToObject(root, "imei", imei);
    
    // Add timestamp
    char timestamp[32];
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d",
             gps_data->year, gps_data->month, gps_data->day,
             gps_data->hour, gps_data->minute, gps_data->second);
    cJSON_AddStringToObject(root, "timestamp", timestamp);
    
    // Add location data
    cJSON_AddNumberToObject(root, "latitude", gps_data->latitude);
    cJSON_AddNumberToObject(root, "longitude", gps_data->longitude);
    cJSON_AddNumberToObject(root, "accuracy", 10.0); // GPS typically has ~10m accuracy
    
    // Add GPS-specific data
    cJSON_AddStringToObject(root, "source", "gps");
    cJSON_AddNumberToObject(root, "satellites", gps_data->satellite_count);
    cJSON_AddNumberToObject(root, "speed_kmh", gps_data->speed_kmh);
    cJSON_AddNumberToObject(root, "heading", gps_data->heading);
    
    char *json_string = cJSON_Print(root);
    cJSON_Delete(root);
    
    return json_string;
}

int parse_google_geolocation_response(const char *json, double *lat, double *lon, double *accuracy_m) {
    if (!json || !lat || !lon) {
        return -1;
    }
    
    cJSON *root = cJSON_Parse(json);
    if (!root) {
        printf("JSON_WRITER: Failed to parse Google API response\n");
        return -1;
    }
    
    // Check for error in response
    cJSON *error = cJSON_GetObjectItem(root, "error");
    if (error) {
        cJSON *message = cJSON_GetObjectItem(error, "message");
        if (message && cJSON_IsString(message)) {
            printf("JSON_WRITER: Google API Error: %s\n", message->valuestring);
        }
        cJSON_Delete(root);
        return -1;
    }
    
    // Parse location data
    cJSON *location = cJSON_GetObjectItem(root, "location");
    if (!location) {
        printf("JSON_WRITER: No location data in Google API response\n");
        cJSON_Delete(root);
        return -1;
    }
    
    cJSON *lat_json = cJSON_GetObjectItem(location, "lat");
    cJSON *lng_json = cJSON_GetObjectItem(location, "lng");
    
    if (!lat_json || !lng_json || !cJSON_IsNumber(lat_json) || !cJSON_IsNumber(lng_json)) {
        printf("JSON_WRITER: Invalid latitude/longitude in Google API response\n");
        cJSON_Delete(root);
        return -1;
    }
    
    *lat = lat_json->valuedouble;
    *lon = lng_json->valuedouble;
    
    // Parse accuracy (optional)
    if (accuracy_m) {
        cJSON *accuracy_json = cJSON_GetObjectItem(root, "accuracy");
        if (accuracy_json && cJSON_IsNumber(accuracy_json)) {
            *accuracy_m = accuracy_json->valuedouble;
        } else {
            *accuracy_m = 0.0; // Default if not provided
        }
    }
    
    cJSON_Delete(root);
    return 0;
}

char* create_websocket_lbs_message(const char *imei, const LBSData *lbs_data) {
    if (!imei || !lbs_data || !lbs_data->location || !lbs_data->location->is_resolved) {
        return NULL;
    }
    
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return NULL;
    }
    
    // Add message type and device info
    cJSON_AddStringToObject(root, "type", "location");
    cJSON_AddStringToObject(root, "imei", imei);
    
    // Add timestamp
    char timestamp[32];
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d",
             lbs_data->year, lbs_data->month, lbs_data->day,
             lbs_data->hour, lbs_data->minute, lbs_data->second);
    cJSON_AddStringToObject(root, "timestamp", timestamp);
    
    // Add location data
    cJSON_AddNumberToObject(root, "latitude", lbs_data->location->lat);
    cJSON_AddNumberToObject(root, "longitude", lbs_data->location->lon);
    cJSON_AddNumberToObject(root, "accuracy", lbs_data->location->accuracy_m);
    
    // Add source information
    cJSON_AddStringToObject(root, "source", "lbs");
    cJSON_AddNumberToObject(root, "cell_count", lbs_data->unique_lbs_count);
    cJSON_AddNumberToObject(root, "wifi_count", lbs_data->unique_wifi_count);
    
    // Add address if available
    if (lbs_data->location->address[0] != '\0') {
        cJSON_AddStringToObject(root, "address", lbs_data->location->address);
    }
    
    char *json_string = cJSON_Print(root);
    cJSON_Delete(root);
    
    return json_string;
}
