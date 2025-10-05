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

#endif // DATABASE_H