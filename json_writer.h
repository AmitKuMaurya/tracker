#ifndef JSON_WRITER_H
#define JSON_WRITER_H

#include <stdio.h>

typedef struct {
    FILE *file;
    int first_field;
} JsonWriter;

JsonWriter* json_writer_create(const char *filename);
void json_writer_destroy(JsonWriter *writer);
void json_writer_start_object(JsonWriter *writer);
void json_writer_end_object(JsonWriter *writer);
void json_writer_start_array(JsonWriter *writer, const char *name);
void json_writer_end_array(JsonWriter *writer);
void json_writer_add_string(JsonWriter *writer, const char *name, const char *value);
void json_writer_add_int(JsonWriter *writer, const char *name, int value);
void json_writer_add_uint(JsonWriter *writer, const char *name, unsigned int value);
void json_writer_add_hex(JsonWriter *writer, const char *name, unsigned char value);

#endif // JSON_WRITER_H
