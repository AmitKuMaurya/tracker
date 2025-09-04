#include "json_writer.h"
#include <stdlib.h>
#include <string.h>

JsonWriter* json_writer_create(const char *filename) {
    JsonWriter *writer = malloc(sizeof(JsonWriter));
    if (!writer) return NULL;
    
    writer->file = fopen(filename, "a");
    if (!writer->file) {
        free(writer);
        return NULL;
    }
    
    writer->first_field = 1;
    return writer;
}

void json_writer_destroy(JsonWriter *writer) {
    if (writer) {
        if (writer->file) {
            fclose(writer->file);
        }
        free(writer);
    }
}

void json_writer_start_object(JsonWriter *writer) {
    if (!writer || !writer->file) return;
    fprintf(writer->file, "{\n");
    writer->first_field = 1;
}

void json_writer_end_object(JsonWriter *writer) {
    if (!writer || !writer->file) return;
    fprintf(writer->file, "\n}");
}

void json_writer_start_array(JsonWriter *writer, const char *name) {
    if (!writer || !writer->file) return;
    
    if (!writer->first_field) {
        fprintf(writer->file, ",\n");
    }
    fprintf(writer->file, "  \"%s\": [\n", name);
    writer->first_field = 1;
}

void json_writer_end_array(JsonWriter *writer) {
    if (!writer || !writer->file) return;
    fprintf(writer->file, "\n  ]");
    writer->first_field = 0;
}

void json_writer_add_string(JsonWriter *writer, const char *name, const char *value) {
    if (!writer || !writer->file) return;
    
    if (!writer->first_field) {
        fprintf(writer->file, ",\n");
    }
    fprintf(writer->file, "  \"%s\": \"%s\"", name, value);
    writer->first_field = 0;
}

void json_writer_add_int(JsonWriter *writer, const char *name, int value) {
    if (!writer || !writer->file) return;
    
    if (!writer->first_field) {
        fprintf(writer->file, ",\n");
    }
    fprintf(writer->file, "  \"%s\": %d", name, value);
    writer->first_field = 0;
}

void json_writer_add_uint(JsonWriter *writer, const char *name, unsigned int value) {
    if (!writer || !writer->file) return;
    
    if (!writer->first_field) {
        fprintf(writer->file, ",\n");
    }
    fprintf(writer->file, "  \"%s\": %u", name, value);
    writer->first_field = 0;
}

void json_writer_add_hex(JsonWriter *writer, const char *name, unsigned char value) {
    if (!writer || !writer->file) return;
    
    if (!writer->first_field) {
        fprintf(writer->file, ",\n");
    }
    fprintf(writer->file, "  \"%s\": \"0x%02X\"", name, value);
    writer->first_field = 0;
}
