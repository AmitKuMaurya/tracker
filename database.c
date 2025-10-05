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