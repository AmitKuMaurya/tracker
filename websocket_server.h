#ifndef WEBSOCKET_SERVER_H
#define WEBSOCKET_SERVER_H
#include <openssl/sha.h>   // for SHA1
#include <openssl/bio.h>   // for Base64
#include <openssl/evp.h>   // for Base64
#include <pthread.h>
#include "login_map.h"
#include <unistd.h>
#include <stdbool.h>
#define WS_PORT 8082
#define WS_MAX_EVENTS 1000
#define WS_BUF_SIZE 4096

// WebSocket opcodes
#define WS_OP_CONTINUATION 0x0
#define WS_OP_TEXT 0x1
#define WS_OP_BINARY 0x2
#define WS_OP_CLOSE 0x8
#define WS_OP_PING 0x9
#define WS_OP_PONG 0xA

// WebSocket connection states
typedef enum {
    WS_STATE_HANDSHAKE,
    WS_STATE_OPEN,
    WS_STATE_CLOSING,
    WS_STATE_CLOSED
} WSState;

// WebSocket connection structure
typedef struct {
    int fd;
    char imei[32];
    int has_imei;
    WSState state;
    char *write_buf;
    size_t write_buf_len;
    size_t write_buf_used;
} WSConnection;

// WebSocket server structure
typedef struct {
    int server_fd;
    int epoll_fd;
    pthread_t thread_id;
    int running;
} WSServer;

// Function declarations
int websocket_server_init(void);
void websocket_server_start(void);
void websocket_server_stop(void);
int websocket_send_to_imei(const char *imei, const char *data, size_t len);
int websocket_broadcast(const char *data, size_t len);

#endif // WEBSOCKET_SERVER_H