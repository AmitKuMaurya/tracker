#include "json_writer.h"
#include "offline_data.h"
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
    
    // Add WiFi data
    cJSON_AddNumberToObject(json, "wifi_count", lbs_data->wifi_count);
    
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
