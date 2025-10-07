#include "database.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Global database connection
static DBConnection db_conn = {0};

// Database connection string
static const char* DB_CONNECTION_STRING = "postgresql://postgres:postgres@107.21.29.223:5432/tracker";

int db_init(void) {
    printf("DATABASE: Initializing PostgreSQL connection\n");
    
    // Initialize the connection structure
    strncpy(db_conn.connection_string, DB_CONNECTION_STRING, sizeof(db_conn.connection_string) - 1);
    db_conn.connection_string[sizeof(db_conn.connection_string) - 1] = '\0';
    db_conn.conn = NULL;
    db_conn.is_connected = false;
    
    // Attempt to connect
    return db_connect();
}

int db_connect(void) {
    // Don't connect if already connected
    if (db_conn.is_connected && db_conn.conn && PQstatus(db_conn.conn) == CONNECTION_OK) {
        printf("DATABASE: Already connected\n");
        return 0;
    }
    
    printf("DATABASE: Connecting to PostgreSQL database\n");
    
    // Clean up any existing connection
    if (db_conn.conn) {
        PQfinish(db_conn.conn);
        db_conn.conn = NULL;
    }
    
    // Attempt connection
    db_conn.conn = PQconnectdb(db_conn.connection_string);
    
    // Check if connection object was created
    if (db_conn.conn == NULL) {
        fprintf(stderr, "DATABASE ERROR: Failed to create connection object\n");
        db_conn.is_connected = false;
        return -1;
    }
    
    // Check connection status
    if (PQstatus(db_conn.conn) != CONNECTION_OK) {
        fprintf(stderr, "DATABASE ERROR: Connection failed: %s\n", PQerrorMessage(db_conn.conn));
        PQfinish(db_conn.conn);
        db_conn.conn = NULL;
        db_conn.is_connected = false;
        return -1;
    }
    
    db_conn.is_connected = true;
    printf("DATABASE: Successfully connected to PostgreSQL\n");
    return 0;
}

void db_disconnect(void) {
    if (db_conn.conn) {
        PQfinish(db_conn.conn);
        db_conn.conn = NULL;
    }
    db_conn.is_connected = false;
    printf("DATABASE: Disconnected\n");
}

void db_cleanup(void) {
    db_disconnect();
}

//PGresult *res = PQexec(conn, `SELECT "imei_id" FROM devices WHERE "device_id"= ""`);

char* db_get_imei_id(const char* device_id) {
    // Ensure we have a valid connection
    if (!db_conn.is_connected || db_conn.conn == NULL || PQstatus(db_conn.conn) != CONNECTION_OK) {
        fprintf(stderr, "DATABASE ERROR: No database connection\n");
        return "imei_not_found"; // Return string literal
    }
    
    // Validate input
    if (device_id == NULL || strlen(device_id) == 0) {
        fprintf(stderr, "DATABASE ERROR: Invalid device_id\n");
        return "imei_not_found"; // Return string literal
    }
    
    // Prepare SQL query with parameter
    const char* query = "SELECT \"imei_id\" FROM devices WHERE \"device_id\" = $1";
    
    // Prepare parameter values
    const char* param_values[1] = { device_id };
    int param_lengths[1] = { strlen(device_id) };
    int param_formats[1] = { 0 }; // 0 = text format
    
    printf("DATABASE: Executing query: SELECT \"imei_id\" FROM devices WHERE \"device_id\" = '%s'\n", device_id);
    
    // Execute the query
    PGresult* result = PQexecParams(db_conn.conn, 
                                   query, 
                                   1,        // number of parameters
                                   NULL,     // parameter types (NULL = inferred)
                                   param_values,
                                   param_lengths,
                                   param_formats,
                                   0);       // result format (0 = text)

    // Check if query execution failed
    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        fprintf(stderr, "DATABASE ERROR: Query execution failed: %s\n", PQerrorMessage(db_conn.conn));
        PQclear(result);
        return "imei_not_found"; // Return string literal
    }
    
    // Check if any rows were returned
    if (PQntuples(result) == 0) {
        printf("DATABASE: No matching record found for device_id: %s\n", device_id);
        PQclear(result);
        return "imei_not_found"; // Return string literal
    }
    
    // Get the IMEI value from the first row, first column
    const char* fetched_imei = PQgetvalue(result, 0, 0);
    char* imei_id = NULL;
    
    if (fetched_imei != NULL && strlen(fetched_imei) > 0) {
        // IMEI found - allocate memory and copy the value
        imei_id = malloc(16); // IMEI is 15 digits + null terminator
        if (imei_id != NULL) {
            strncpy(imei_id, fetched_imei, 15);
            imei_id[15] = '\0'; // Ensure null termination
            printf("DATABASE: Fetched imei_id: %s for device_id: %s\n", imei_id, device_id);
        } else {
            fprintf(stderr, "DATABASE ERROR: Memory allocation failed\n");
            PQclear(result);
            return "imei_not_found";
        }
    } else {
        // IMEI is NULL or empty in database
        printf("DATABASE: IMEI is NULL or empty for device_id: %s\n", device_id);
        PQclear(result);
        return "imei_not_found"; // Return string literal
    }
    
    PQclear(result);
    return imei_id;
}

char* db_get_device_id(const char* imei_id) {
    // Ensure we have a valid connection
    if (!db_conn.is_connected || db_conn.conn == NULL || PQstatus(db_conn.conn) != CONNECTION_OK) {
        fprintf(stderr, "DATABASE ERROR: No database connection\n");
        return "device_id_not_found"; // Return string literal
    }
    
    // Validate input
    if (imei_id == NULL || strlen(imei_id) == 0) {
        fprintf(stderr, "DATABASE ERROR: Invalid imei_id\n");
        return "device_id_not_found"; // Return string literal
    }
    
    // Prepare SQL query with parameter
    const char* query = "SELECT \"device_id\" FROM devices WHERE \"imei_id\" = $1";
    const char* params[] = {imei_id};
    int param_lengths[] = {strlen(imei_id)};
    int param_formats[] = {0}; // 0 = text
    
    printf("DATABASE: Executing query: SELECT \"device_id\" FROM devices WHERE \"imei_id\" = '%s'\n", imei_id);
    
    PGresult *result = PQexecParams(db_conn.conn, query, 1, NULL, params, param_lengths, param_formats, 0);
    
    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        fprintf(stderr, "DATABASE ERROR: Query failed: %s\n", PQerrorMessage(db_conn.conn));
        PQclear(result);
        return "device_id_not_found";
    }
    
    int num_rows = PQntuples(result);
    if (num_rows == 0) {
        printf("DATABASE: No device_id found for imei_id: %s\n", imei_id);
        PQclear(result);
        return "device_id_not_found";
    }
    
    char *device_id_str = PQgetvalue(result, 0, 0);
    if (device_id_str && strlen(device_id_str) > 0) {
        // Allocate memory for the device_id and copy it
        char *device_id = malloc(strlen(device_id_str) + 1);
        if (device_id) {
            strcpy(device_id, device_id_str);
            printf("DATABASE: Fetched device_id: %s for imei_id: %s\n", device_id, imei_id);
        } else {
            printf("DATABASE: Memory allocation failed for device_id\n");
            PQclear(result);
            return "device_id_not_found";
        }
        
        PQclear(result);
        return device_id;
    } else {
        // Device ID is NULL or empty in database
        printf("DATABASE: Device ID is NULL or empty for imei_id: %s\n", imei_id);
        PQclear(result);
        return "device_id_not_found"; // Return string literal
    }
    
    PQclear(result);
    return "device_id_not_found";
}


