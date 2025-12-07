#ifndef DATABASE_H
#define DATABASE_H

#include <libpq-fe.h>
#include <stdbool.h>

// Database connection structure
typedef struct {
    PGconn *conn;
    bool is_connected;
    char connection_string[256];
} DBConnection;

// Database initialization and cleanup
int db_init(void);
void db_cleanup(void);

// Connection management
int db_connect(void);
void db_disconnect(void);
char* db_get_imei_id(const char* device_id);
char* db_get_device_id(const char* imei_id);
int db_push_device_location(
    const char *imei_id,
    const char *latitude,
    const char *longitude,
    const char *accuracy,
    const char *source
);

#endif // DATABASE_H