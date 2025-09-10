#ifndef CONN_H
#define CONN_H

#include <time.h>

#define BUF_SIZE 4096
#define TIMEOUT_SECONDS 60  // 1 minute timeout

// Event type identifiers
#define EVENT_TYPE_SOCKET 1
#define EVENT_TYPE_TIMER  2

// Event data structure to distinguish between socket and timer events
typedef struct EventData {
    struct Conn *conn;
    int event_type;  // EVENT_TYPE_SOCKET or EVENT_TYPE_TIMER
} EventData;

typedef struct Conn {
    int fd;
    char inbuf[BUF_SIZE];
    int inbuf_used;
    char login_id[32];
    int has_login_id;
    int timer_fd;              /**< Timer file descriptor for this connection */
    time_t last_activity;      /**< Timestamp of last activity */
    EventData *socket_event_data;  /**< Socket event data for cleanup */
    EventData *timer_event_data;   /**< Timer event data for cleanup */
} Conn;

#endif // CONN_H

