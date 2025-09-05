#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "lbs_latlong.h"

typedef struct {
    char *data;
    size_t size;
} MemoryBuffer;

static size_t write_memory_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    MemoryBuffer *mem = (MemoryBuffer *)userp;

    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) {
        return 0;
    }
    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = '\0';
    return realsize;
}

static int parse_latlon_from_response(const char *json, double *lat, double *lon, double *accuracy_m, char *address, size_t address_len) {
    if (!json) return -1;
    // Very small JSON parser for expected keys to avoid adding a dependency
    if (!strstr(json, "\"status\":\"ok\"") &&
        !strstr(json, "\"status\": \"ok\"")) {
        return -1;
    }

    const char *lat_pos = strstr(json, "\"lat\"");
    const char *lon_pos = strstr(json, "\"lon\"");
    const char *acc_pos = strstr(json, "\"accuracy\"");
    const char *addr_pos = strstr(json, "\"address\"");
    if (!lat_pos || !lon_pos) return -1;

    // Move to ':' after key
    lat_pos = strchr(lat_pos, ':');
    lon_pos = strchr(lon_pos, ':');
    if (!lat_pos || !lon_pos) return -1;
    lat_pos++; lon_pos++;

    // sscanf tolerant parse
    if (sscanf(lat_pos, " %lf", lat) != 1) return -1;
    if (sscanf(lon_pos, " %lf", lon) != 1) return -1;

    if (accuracy_m && acc_pos) {
        acc_pos = strchr(acc_pos, ':');
        if (acc_pos) {
            acc_pos++;
            double acc_tmp = 0.0;
            if (sscanf(acc_pos, " %lf", &acc_tmp) == 1) {
                *accuracy_m = acc_tmp;
            }
        }
    }

    if (address && address_len > 0 && addr_pos) {
        addr_pos = strchr(addr_pos, ':');
        if (addr_pos) {
            addr_pos++;
            // Expect a JSON string; copy until closing quote while handling optional whitespace
            while (*addr_pos == ' ' || *addr_pos == '\t') addr_pos++;
            if (*addr_pos == '"') {
                addr_pos++;
                size_t i = 0;
                while (*addr_pos && *addr_pos != '"' && i + 1 < address_len) {
                    // naive unescape for common cases
                    if (*addr_pos == '\\' && addr_pos[1] != '\0') {
                        addr_pos++;
                    }
                    address[i++] = *addr_pos++;
                }
                address[i] = '\0';
            }
        }
    }
    return 0;
}

int lbs_query_unwired(LBSData *data) {
    if (!data || data->unique_lbs_count <= 0) {
        return -1;
    }

    // Allocate and initialize LocationData structure (calloc zeros all bytes)
    data->location = calloc(1, sizeof(LocationData));
    if (!data->location) {
        return -1;
    }
    
    // calloc already initializes all bytes to 0, so we only need to set non-zero defaults
    data->location->is_resolved = 0;  // This is the only non-zero default we need

    CURL *curl = NULL;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        free(data->location);
        data->location = NULL;
        curl_global_cleanup();
        return -1;
    }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    const char *url = "https://us1.unwiredlabs.com/v2/process.php";

    int result = -1;
    for (int i = 0; i < data->unique_lbs_count; i++) {
        MemoryBuffer response = {0};
        char postfields[512];

        unsigned int lac = data->unique_cells[i].lac;
        unsigned int cid = data->unique_cells[i].cell_id;

        // Build JSON payload per spec
        snprintf(postfields, sizeof(postfields),
            "{\n"
            "    \"token\": \"%s\",\n"
            "    \"radio\": \"lte\",\n"
            "    \"mcc\": %d,\n"
            "    \"mnc\": %d,\n"
            "    \"cells\": [{\n"
            "        \"lac\": %u,\n"
            "        \"cid\": %u,\n"
            "        \"psc\": 0\n"
            "    }],\n"
            "    \"address\": 1\n"
            "}",
            "pk.3aee9ebc2a0e02047c8414b566af0f88", data->mcc, data->mnc, lac, cid);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_memory_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

        res = curl_easy_perform(curl);
        if (res == CURLE_OK && response.size > 0) {
            double lat = 0.0, lon = 0.0, acc = 0.0;
            char address[256] = {0};
            if (parse_latlon_from_response(response.data, &lat, &lon, &acc, address, sizeof(address)) == 0) {
                data->location->lat = lat;
                data->location->lon = lon;
                data->location->accuracy_m = acc;
                if (address[0] != '\0') {
                    strncpy(data->location->address, address, sizeof(data->location->address) - 1);
                    data->location->address[sizeof(data->location->address) - 1] = '\0';
                } else {
                    data->location->address[0] = '\0';
                }
                data->location->is_resolved = 1;
                result = 0; // success
                free(response.data);
                break; // stop after first valid response
            }
        }

        if (response.data) free(response.data);
        // If failed or invalid, continue to next unique cell
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return result;
}


