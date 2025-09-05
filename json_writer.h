#ifndef JSON_WRITER_H
#define JSON_WRITER_H

#include <stdio.h>
#include <cjson/cJSON.h>

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

#endif // JSON_WRITER_H
