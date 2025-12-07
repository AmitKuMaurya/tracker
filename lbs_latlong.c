#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>
#include "lbs_latlong.h"
#include "json_writer.h"

// Maximum length for API key and URL
#define MAX_API_KEY_LEN 256
#define MAX_URL_LEN 512

// Static variables to store API key and URL loaded from .env
static char google_api_key[MAX_API_KEY_LEN] = {0};
static char google_geolocation_url[MAX_URL_LEN] = {0};
static int env_loaded = 0;

/**
 * @brief Load environment variables from .env file
 * 
 * This function reads the .env file and extracts GOOGLE_API_KEY and GOOGLE_GEOLOCATION_URL.
 * It first checks environment variables, then falls back to .env file.
 * 
 * @return 0 on success, -1 on error
 */
static int load_env_variables(void) {
    if (env_loaded) {
        return 0; // Already loaded
    }
    
    // First, try to get from environment variables (highest priority)
    const char *api_key_env = getenv("GOOGLE_API_KEY");
    const char *url_env = getenv("GOOGLE_GEOLOCATION_URL");
    
    if (api_key_env && api_key_env[0] != '\0') {
        strncpy(google_api_key, api_key_env, MAX_API_KEY_LEN - 1);
        google_api_key[MAX_API_KEY_LEN - 1] = '\0';
    }
    
    if (url_env && url_env[0] != '\0') {
        strncpy(google_geolocation_url, url_env, MAX_URL_LEN - 1);
        google_geolocation_url[MAX_URL_LEN - 1] = '\0';
    }
    
    // If both are set from environment, we're done
    if (google_api_key[0] != '\0' && google_geolocation_url[0] != '\0') {
        env_loaded = 1;
        printf("LBS_GOOGLE: Environment variables loaded successfully\n");
        return 0;
    }
    else{
        printf("LBS_GOOGLE: Environment variables not loaded\n");
        return -1;
    }
    

}

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


int lbs_query_google(LBSData *data) {
    if (!data) {
        return -1;
    }
    
    // Load environment variables from .env file if not already loaded
    if (load_env_variables() != 0) {
        fprintf(stderr, "LBS_GOOGLE: ERROR: Failed to load API key from .env file\n");
        return -1;
    }
    
    // Check if we have any data to work with
    if (data->unique_lbs_count <= 0 && data->unique_wifi_count <= 0) {
        printf("LBS_GOOGLE: No cell towers or WiFi access points available\n");
        return -1;
    }

    // Allocate and initialize LocationData structure
    data->location = calloc(1, sizeof(LocationData));
    if (!data->location) {
        printf("LBS_GOOGLE: Failed to allocate memory for location data\n");
        return -1;
    }
    
    data->location->is_resolved = 0;

    // Build JSON payload for Google API using json_writer
    char *json_payload = create_google_geolocation_payload(data);
    if (!json_payload) {
        printf("LBS_GOOGLE: Failed to build JSON payload\n");
        free(data->location);
        data->location = NULL;
        return -1;
    }
    
    printf("LBS_GOOGLE: Sending request with %d cell towers and %d WiFi APs\n", 
           data->unique_lbs_count, data->unique_wifi_count);
    printf("LBS_GOOGLE: Payload: %s\n", json_payload);

    CURL *curl = NULL;
    CURLcode res;
    int result = -1;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    
    if (!curl) {
        printf("LBS_GOOGLE: Failed to initialize CURL\n");
        free(json_payload);
        free(data->location);
        data->location = NULL;
        curl_global_cleanup();
        return -1;
    }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    
    MemoryBuffer response = {0};

    // Configure CURL for Google Geolocation API
    curl_easy_setopt(curl, CURLOPT_URL, google_geolocation_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(json_payload));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_memory_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    
    // Perform the request
    res = curl_easy_perform(curl);
    
    if (res == CURLE_OK && response.size > 0) {
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        
        printf("LBS_GOOGLE: HTTP response code: %ld\n", response_code);
        printf("LBS_GOOGLE: Response: %s\n", response.data);
        
        if (response_code == 200) {
            double lat = 0.0, lon = 0.0, accuracy = 0.0;
            
            // Use json_writer function to parse Google API response
            if (parse_google_geolocation_response(response.data, &lat, &lon, &accuracy) == 0) {
                data->location->lat = lat;
                data->location->lon = lon;
                data->location->accuracy_m = accuracy;
                data->location->is_resolved = 1;
                
                printf("LBS_GOOGLE: Successfully resolved location: %.6f, %.6f (accuracy: %.1fm)\n", 
                       lat, lon, accuracy);
                
                result = 0; // Success
            } else {
                printf("LBS_GOOGLE: Failed to parse response\n");
            }
        } else {
            printf("LBS_GOOGLE: HTTP error: %ld\n", response_code);
        }
    } else {
        printf("LBS_GOOGLE: CURL error: %s\n", curl_easy_strerror(res));
    }

    // Cleanup
    if (response.data) {
        free(response.data);
    }
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    
    free(json_payload);
    
    if (result != 0) {
        // If we failed, clean up the location structure
        printf("LBS_GOOGLE: Cleaning up location data due to failure\n");
    }
    
    return result;
}


