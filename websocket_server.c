#define _GNU_SOURCE
#include "websocket_server.h"
#include "database.h"
#include "hashmap.h"

static WSServer g_ws_server = {0};

// Static function prototypes
static void *websocket_server_thread(void *arg);
static int make_socket_non_blocking(int fd);
static void handle_accept_ws(int server_fd);
static int handle_websocket_handshake(WSConnection *conn);
static int handle_websocket_frame(WSConnection *conn);
static int contains_case_insensitive(const char *haystack, const char *needle);
static int parse_websocket_frame(const char *buf, size_t len, 
                                int *opcode, int *fin, 
                                char *payload, size_t *payload_len);
static int create_websocket_frame(char *buf, size_t buf_len, 
                                 const char *payload, size_t payload_len, 
                                 int opcode);
static int base64_encode(const unsigned char *input, size_t input_len, 
                        char *output, size_t output_len);
static void remove_websocket_connection(WSConnection *conn);
static void cleanup_ws_connection_callback(const char *imei, WSConnection *conn, void *ctx);
void ws_connection_cleanup(WSConnection *ws_conn);
bool device_online_status(const char *imei);

int websocket_server_init(void) {
    memset(&g_ws_server, 0, sizeof(g_ws_server));

    // Create server socket
    g_ws_server.server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_ws_server.server_fd == -1) {
        perror("WebSocket socket");
        return -1;
    }

    int opt = 1;
    setsockopt(g_ws_server.server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(WS_PORT);

    if (bind(g_ws_server.server_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("WebSocket bind");
        close(g_ws_server.server_fd);
        return -1;
    }

    if (listen(g_ws_server.server_fd, SOMAXCONN) == -1) {
        perror("WebSocket listen");
        close(g_ws_server.server_fd);
        return -1;
    }

    if (make_socket_non_blocking(g_ws_server.server_fd) == -1) {
        perror("WebSocket make non-blocking (server)");
        close(g_ws_server.server_fd);
        return -1;
    }

    // Create epoll instance
    g_ws_server.epoll_fd = epoll_create1(0);
    if (g_ws_server.epoll_fd == -1) {
        perror("WebSocket epoll_create1");
        close(g_ws_server.server_fd);
        return -1;
    }

    // Add server socket to epoll
    struct epoll_event event;
    event.events = EPOLLIN | EPOLLET;
    event.data.fd = g_ws_server.server_fd;
    if (epoll_ctl(g_ws_server.epoll_fd, EPOLL_CTL_ADD, g_ws_server.server_fd, &event) == -1) {
        perror("WebSocket epoll_ctl: server");
        close(g_ws_server.epoll_fd);
        close(g_ws_server.server_fd);
        return -1;
    }

    printf("WebSocket server initialized on port %d (epfd=%d)\n", WS_PORT, g_ws_server.epoll_fd);
    return 0;
}

void websocket_server_start(void) {
    if (g_ws_server.running) {
        return;
    }
    
    g_ws_server.running = 1;
    if (pthread_create(&g_ws_server.thread_id, NULL, websocket_server_thread, NULL) != 0) {
        perror("WebSocket pthread_create");
        g_ws_server.running = 0;
    }
    
    printf("WebSocket server thread started\n");
}

void websocket_server_stop(void) {
    if (!g_ws_server.running) {
        return;
    }

    printf("Stopping WebSocket server...\n");

    // Stop main loop
    g_ws_server.running = 0;
    pthread_join(g_ws_server.thread_id, NULL);

    // Clean up any remaining WebSocket connections tracked in the hash map
    hash_map_for_each_ws_connection(cleanup_ws_connection_callback, NULL);

    // Close sockets
    close(g_ws_server.epoll_fd);
    close(g_ws_server.server_fd);

    printf("WebSocket server stopped and all connections freed.\n");
}

static void cleanup_ws_connection_callback(const char *imei, WSConnection *conn, void *ctx) {
    (void)imei;
    (void)ctx;

    if (conn) {
        remove_websocket_connection(conn);
    }
}


static void *websocket_server_thread(void *arg) {
    (void)arg;
    struct epoll_event events[WS_MAX_EVENTS];
    
    printf("WebSocket server thread running\n");
    
    while (g_ws_server.running) {
        int n = epoll_wait(g_ws_server.epoll_fd, events, WS_MAX_EVENTS, 100);
        if (n == -1) {
            if (errno == EINTR) continue;
            perror("WebSocket epoll_wait");
            break;
        }
        
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == g_ws_server.server_fd) {
                // New connection
                handle_accept_ws(g_ws_server.server_fd);
            } else {
                // Client connection
                EventData_W *event_data = (EventData_W *)events[i].data.ptr;
                if (!event_data) {
                    fprintf(stderr, "WebSocket: Invalid event data (NULL pointer)\n");
                    continue;
                }
                
                WSConnection *conn = event_data->ws_conn;
                if (!conn) {
                    fprintf(stderr, "WebSocket: Event with NULL connection pointer\n");
                    continue;
                }
                
                // Check for errors/hangup first
                if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                    printf("WebSocket: Error or hangup on fd=%d\n", conn->fd);
                    remove_websocket_connection(conn);
                    continue;
                }
                
                // Handle readable events
                if (events[i].events & EPOLLIN) {
                    if (conn->state == WS_STATE_HANDSHAKE) {
                        int handshake_result = handle_websocket_handshake(conn);
                        if (handshake_result == 0) {
                            conn->state = WS_STATE_OPEN;
                            printf("WebSocket: Handshake complete for fd=%d\n", conn->fd);

                            //After successful handshake, sending device validation success
                            printf("WebSocket: Sending device validation for device_id %s\n", conn->device_id);
                            char * device_validation_msg = device_validation_json(conn->device_id, 1);
                            if (device_validation_msg) {
                                websocket_send_to_device_id(conn->device_id, device_validation_msg, strlen(device_validation_msg));
                                free(device_validation_msg);
                            }

                            // After successful handshake, send device online status
                            printf("WebSocket: Sending online status for device_id %s\n", conn->device_id);
                            int is_online = device_online_status(conn->imei) ? 1 : 0;
                            char *device_status_msg = device_online_status_json(is_online, NULL, conn->device_id[0] ? conn->device_id : NULL);
                            if (device_status_msg) {
                                websocket_send_to_imei_id(conn->imei, device_status_msg, strlen(device_status_msg));
                                free(device_status_msg);
                            }
                        } else if (handshake_result == -2){
                            // Handshake failed due to invalid device_id
                            printf("WebSocket: Invalid device_id for fd=%d\n", conn->fd);
                            // Sending device validation failure
                            char * device_validation_msg = device_validation_json(conn->device_id, 0);
                            if (device_validation_msg) {
                                websocket_send_to_device_id(conn->device_id, device_validation_msg, strlen(device_validation_msg));
                                free(device_validation_msg);
                            }
                            remove_websocket_connection(conn);
                        }
                        else {
                            printf("WebSocket: Handshake failed for fd=%d\n", conn->fd);
                            remove_websocket_connection(conn);
                        }
                    } else if (conn->state == WS_STATE_OPEN) {
                        if (handle_websocket_frame(conn) != 0) {
                            printf("WebSocket: Frame handling failed for fd=%d\n", conn->fd);
                            remove_websocket_connection(conn);
                        }
                    }
                }
            }
        }
    }
    
    return NULL;
}

static void handle_accept_ws(int server_fd) {
    while (1) {
        struct sockaddr_in in_addr;
        socklen_t in_len = sizeof(in_addr);
        int infd = accept(server_fd, (struct sockaddr *)&in_addr, &in_len);
        
        if (infd == -1) {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;
            perror("WebSocket accept");
            break;
        }

        make_socket_non_blocking(infd);

        // ✅ Dynamically allocate WSConnection
        WSConnection *ws_conn = calloc(1, sizeof(WSConnection));
        if (!ws_conn) {
            fprintf(stderr, "WebSocket: calloc failed\n");
            close(infd);
            continue;
        }
        
        // Initialize connection
        ws_conn->fd = infd;
        ws_conn->state = WS_STATE_HANDSHAKE;
        ws_conn->has_imei = 0;
        ws_conn->imei[0] = '\0';
        ws_conn->has_device_id = 0;
        ws_conn->device_id[0] = '\0';
        ws_conn->write_buf = NULL;
        ws_conn->write_buf_len = 0;
        ws_conn->write_buf_used = 0;
        ws_conn->cleanup_in_progress = 0;
        ws_conn->epfd = g_ws_server.epoll_fd;  // ✅ Store epoll fd

        // ✅ Create EventData for epoll
        EventData_W *event_data = malloc(sizeof(EventData_W));
        if (!event_data) {
            fprintf(stderr, "WebSocket: Failed to allocate event data\n");
            free(ws_conn);
            close(infd);
            continue;
        }
        event_data->ws_conn = ws_conn;
        event_data->event_type = EVENT_TYPE_SOCKET_W;
        ws_conn->socket_event_data = event_data;
        
        // Add to epoll
        struct epoll_event event;
        event.data.ptr = event_data;  // ✅ Use ptr, not fd
        event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
        if (epoll_ctl(g_ws_server.epoll_fd, EPOLL_CTL_ADD, infd, &event) == -1) {
            perror("WebSocket epoll_ctl: client");
            free(event_data);
            free(ws_conn);
            close(infd);
            continue;
        }
        
        printf("WebSocket: New connection accepted fd=%d (epfd=%d)\n", infd, g_ws_server.epoll_fd);
    }
}

static int handle_websocket_handshake(WSConnection *conn) {
    char buf[WS_BUF_SIZE];
    ssize_t len = recv(conn->fd, buf, sizeof(buf) - 1, 0);
    if (len <= 0) {
        if (len == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 1; // Try again later
        }
        return -1;
    }

    buf[len] = '\0';
    printf("WebSocket: Received handshake request from fd=%d\n", conn->fd);

    if (strncmp(buf, "GET ", 4) != 0) {
        printf("WebSocket: Not a GET request\n");
        return -1;
    }

    // Extract device_id from URL
    char original_buf[WS_BUF_SIZE];
    strncpy(original_buf, buf, sizeof(original_buf) - 1);
    original_buf[sizeof(original_buf) - 1] = '\0';

    char *request_line_end = strstr(buf, "\r\n");
    if (request_line_end) *request_line_end = '\0';
    char *space1 = strchr(buf, ' ');
    char *space2 = space1 ? strchr(space1 + 1, ' ') : NULL;
    if (!space1 || !space2) {
        printf("WebSocket: Malformed request line\n");
        return -1;
    }
    *space2 = '\0';
    const char *url = space1 + 1;
    const char *device_id_q = strstr(url, "device_id=");
    char normalized_device_id[32] = {0};
    if (device_id_q) {
        device_id_q += 10;
        const char *amp = strchr(device_id_q, '&');
        size_t device_id_len = amp ? (size_t)(amp - device_id_q) : strlen(device_id_q);
        if (device_id_len >= sizeof(normalized_device_id)) device_id_len = sizeof(normalized_device_id) - 1;
        char device_id_tmp[32];
        strncpy(device_id_tmp, device_id_q, device_id_len);
        device_id_tmp[device_id_len] = '\0';
        size_t tmp_len = strlen(device_id_tmp);
        const size_t KEEP = 9;
        const char *last = (tmp_len > KEEP) ? device_id_tmp + (tmp_len - KEEP) : device_id_tmp;
        snprintf(normalized_device_id, sizeof normalized_device_id, "%s", last);
        printf("WebSocket: Extracted device_id=%s\n", normalized_device_id);
    }

    // Parse headers
    int upgrade_found = 0;
    int connection_found = 0;
    char client_key[256] = {0};

    char *headers = strstr(original_buf, "\r\n");
    if (!headers) return -1;
    headers += 2;

    char *line = strtok(headers, "\r\n");
    while (line) {
        if (strncasecmp(line, "Upgrade:", 8) == 0) {
            if (contains_case_insensitive(line, "websocket")) upgrade_found = 1;
        } else if (strncasecmp(line, "Connection:", 11) == 0) {
            if (contains_case_insensitive(line, "upgrade")) connection_found = 1;
        } else if (strncasecmp(line, "Sec-WebSocket-Key:", 18) == 0) {
            const char *value = line + 18;
            while (*value == ' ') value++;
            strncpy(client_key, value, sizeof(client_key) - 1);
            client_key[sizeof(client_key) - 1] = '\0';
        }
        line = strtok(NULL, "\r\n");
    }

    if (!upgrade_found || !connection_found || client_key[0] == '\0') {
        printf("WebSocket: Missing required headers\n");
        return -1;
    }

    // Create Sec-WebSocket-Accept
    char combined_key[256];
    snprintf(combined_key, sizeof(combined_key), "%s%s", client_key, WS_MAGIC_STRING);
    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)combined_key, strlen(combined_key), sha1_hash);
    char accept_key[256];
    base64_encode(sha1_hash, SHA_DIGEST_LENGTH, accept_key, sizeof(accept_key));

    // Send handshake response
    char response[512];
    int resp_len = snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "\r\n",
        accept_key);
    ssize_t sent = send(conn->fd, response, resp_len, 0);
    if (sent != resp_len) {
        printf("WebSocket: Failed to send complete response\n");
        return -1;
    }

    // Store device_id on connection
    if (normalized_device_id[0] != '\0') {
        strncpy(conn->device_id, normalized_device_id, sizeof(conn->device_id) - 1);
        conn->device_id[sizeof(conn->device_id) - 1] = '\0';
        conn->has_device_id = 1;
    }

    // Get IMEI from database
    const char* imei_id = db_get_imei_id(normalized_device_id);
    if (imei_id) {
        // char * device_validation_msg = device_validation_json(normalized_device_id, 1);
        // if (device_validation_msg) {
        //     websocket_send_to_device_id(normalized_device_id, device_validation_msg, strlen(device_validation_msg));
        //     free(device_validation_msg);
        // }
        strncpy(conn->imei, imei_id, sizeof(conn->imei) - 1);
        conn->imei[sizeof(conn->imei) - 1] = '\0';
        conn->has_imei = 1;
        
        // ✅ Register WebSocket connection in hashmap
        hash_map_set_ws_connection(imei_id, conn, conn->fd);
        
        printf("WebSocket: Mapped device_id %s to IMEI %s\n", normalized_device_id, imei_id);
        
        // Send online status
        // int is_online = device_online_status(imei_id) ? 1 : 0;
        // char *device_status_msg = device_online_status_json(is_online, NULL, normalized_device_id[0] ? normalized_device_id : NULL);
        // if (device_status_msg) {
        //     websocket_send_to_imei_id(imei_id, device_status_msg, strlen(device_status_msg));
        //     free(device_status_msg);
        // }
    } else {
        char * device_validation_msg = device_validation_json(normalized_device_id, 0); 
        if (device_validation_msg) {
            websocket_send_to_device_id(normalized_device_id, device_validation_msg, strlen(device_validation_msg));
            free(device_validation_msg);
        }
        printf("WebSocket: No IMEI mapping found for device_id so invalid device_id %s\n", normalized_device_id);
        return -2; // Indicate invalid device_id
    }

    return 0;
}

static int contains_case_insensitive(const char *haystack, const char *needle) {
    if (!haystack || !needle || !*needle) return 0;
    size_t nlen = strlen(needle);
    for (const char *p = haystack; *p; p++) {
        size_t i = 0;
        while (i < nlen && p[i] && tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == nlen) return 1;
    }
    return 0;
}
 
static int handle_websocket_frame(WSConnection *conn) {
    char buf[WS_BUF_SIZE];
    ssize_t len = recv(conn->fd, buf, sizeof(buf), 0);
    
    if (len <= 0) {
        return -1;
    }
    
    int opcode, fin;
    char payload[WS_BUF_SIZE];
    size_t payload_len;
    
    if (parse_websocket_frame(buf, len, &opcode, &fin, payload, &payload_len) != 0) {
        return -1;
    }
    
    switch (opcode) {
        case WS_OP_TEXT:
        case WS_OP_BINARY:
            printf("WebSocket: Received %zd bytes from fd=%d\n", payload_len, conn->fd);
            break;
            
        case WS_OP_CLOSE:
            printf("WebSocket: Close frame received from fd=%d\n", conn->fd);
            remove_websocket_connection(conn);
            break;
            
        case WS_OP_PING:
            {
                char pong_frame[WS_BUF_SIZE];
                int frame_len = create_websocket_frame(pong_frame, sizeof(pong_frame), 
                                                     payload, payload_len, WS_OP_PONG);
                if (frame_len > 0) {
                    send(conn->fd, pong_frame, frame_len, 0);
                }
            }
            break;
            
        case WS_OP_PONG:
            break;
            
        default:
            printf("WebSocket: Unknown opcode %d from fd=%d\n", opcode, conn->fd);
            break;
    }
    
    return 0;
}

// ✅ This is ONLY called by hashmap when cleaning up the entry
// It should NOT free the WSConnection - that's done by remove_websocket_connection
void ws_connection_cleanup(WSConnection *ws_conn) {
    if (!ws_conn) return;
    if (ws_conn->cleanup_in_progress) return;
    printf("HASHMAP CALLBACK: ws_connection_cleanup for fd=%d\n", ws_conn->fd);
    ws_conn->cleanup_in_progress = 1;
    // ✅ If the connection is still alive (not cleaned up by epoll thread),
    // we need to clean it up now
    if (ws_conn->fd != -1) {
        // Remove from epoll
        if (ws_conn->epfd != -1) {
            epoll_ctl(ws_conn->epfd, EPOLL_CTL_DEL, ws_conn->fd, NULL);
        }
        
        // Close socket
        close(ws_conn->fd);
        ws_conn->fd = -1;
    }
    
    // Free write buffer if still allocated
    if (ws_conn->write_buf) {
        free(ws_conn->write_buf);
        ws_conn->write_buf = NULL;
    }
    
    // Free event data if still allocated
    if (ws_conn->socket_event_data) {
        free(ws_conn->socket_event_data);
        ws_conn->socket_event_data = NULL;
    }
    
    
    printf("HASHMAP CALLBACK: ws_connection_cleanup completed\n");
}

static void remove_websocket_connection(WSConnection *conn) {
    if (!conn) return;
    
    // ✅ Prevent double cleanup
    if (conn->fd == -1) {
        printf("WebSocket: Connection already cleaned up\n");
        return;
    }
    
    int fd_backup = conn->fd; // For logging
    
    printf("WebSocket: Removing connection fd=%d\n", fd_backup);
    
    // ✅ Mark as cleaned FIRST to prevent race conditions
    conn->cleanup_in_progress = 1;
    
    // ✅ STEP 1: Notify hashmap
    if (conn->has_imei && conn->imei[0] != '\0') {
        fd_map_remove_ws(conn->fd);
        hash_map_remove_ws_connection(conn->imei);
    }
    
    // ✅ STEP 2: Clean up resources
    if (conn->epfd != -1 && conn->fd != -1) {
        epoll_ctl(conn->epfd, EPOLL_CTL_DEL, conn->fd, NULL);
    }
    
    if (conn->fd != -1) {
        close(conn->fd);
        conn->fd = -1; // ✅ Mark as closed
    }
    
    if (conn->write_buf) {
        free(conn->write_buf);
        conn->write_buf = NULL;
    }
    
    if (conn->socket_event_data) {
        free(conn->socket_event_data);
        conn->socket_event_data = NULL;
    }
    
    // ✅ STEP 3: Free the structure
    free(conn);
    
    printf("WebSocket: Connection cleanup completed for fd=%d\n", fd_backup);
}

int websocket_send_to_imei_id(const char *imei_id, const char *data, size_t len) {
    if (!imei_id || !data || len == 0) {
        return -1;
    }
    
    // ✅ Get WS connection from hashmap
    WSConnection *ws_conn = (WSConnection *)hash_map_get_ws_connection(imei_id);
    if (!ws_conn) {
        printf("WebSocket: No connection found for IMEI %s\n", imei_id);
        return -1;
    }
    
    if (ws_conn->state != WS_STATE_OPEN || ws_conn->cleanup_in_progress) {
        printf("WebSocket: Connection not ready for IMEI %s\n", imei_id);
        return -1;
    }
    
    char frame[WS_BUF_SIZE];
    int frame_len = create_websocket_frame(frame, sizeof(frame), data, len, WS_OP_TEXT);
    
    if (frame_len > 0) {
        ssize_t sent = send(ws_conn->fd, frame, frame_len, 0);
        if (sent == frame_len) {
            printf("WebSocket: Sent %zd bytes to IMEI %s (fd=%d)\n", len, imei_id, ws_conn->fd);
            return 1;
        } else {
            printf("WebSocket: Failed to send data to fd=%d\n", ws_conn->fd);
        }
    }
    
    return 0;
}

int websocket_send_to_device_id(const char *device_id, const char *data, size_t len) {
    if (!device_id || !data || len == 0) {
        return -1;
    }
    
    // Convert device_id to IMEI
    const char *imei = hash_map_get_imei_by_device_id(device_id);
    if (!imei) {
        printf("WebSocket: No IMEI found for device_id %s\n", device_id);
        return -1;
    }
    
    return websocket_send_to_imei_id(imei, data, len);
}

int websocket_broadcast(const char *data, size_t len) {
    if (!data || len == 0) {
        return -1;
    }
    
    // TODO: Implement broadcast using hashmap iteration
    printf("WebSocket: Broadcast not yet implemented with dynamic allocation\n");
    return 0;
}

static int parse_websocket_frame(const char *buf, size_t len, 
                                int *opcode, int *fin, 
                                char *payload, size_t *payload_len) {
    if (len < 2) return -1;
    
    unsigned char byte1 = buf[0];
    unsigned char byte2 = buf[1];
    
    *fin = (byte1 & 0x80) != 0;
    *opcode = byte1 & 0x0F;
    int masked = (byte2 & 0x80) != 0;
    size_t payload_length = byte2 & 0x7F;
    
    size_t header_size = 2;
    
    if (payload_length == 126) {
        if (len < 4) return -1;
        payload_length = (buf[2] << 8) | buf[3];
        header_size += 2;
    } else if (payload_length == 127) {
        if (len < 10) return -1;
        payload_length = (buf[2] << 24) | (buf[3] << 16) | (buf[4] << 8) | buf[5];
        header_size += 8;
    }
    
    if (masked) {
        header_size += 4;
    }
    
    if (len < header_size + payload_length) {
        return -1;
    }
    
    if (masked) {
        const unsigned char *masking_key = (const unsigned char *)buf + header_size - 4;
        for (size_t i = 0; i < payload_length; i++) {
            payload[i] = buf[header_size + i] ^ masking_key[i % 4];
        }
    } else {
        memcpy(payload, buf + header_size, payload_length);
    }
    
    *payload_len = payload_length;
    return 0;
}

static int create_websocket_frame(char *buf, size_t buf_len, 
                                 const char *payload, size_t payload_len, 
                                 int opcode) {
    if (buf_len < payload_len + 10) return -1;
    
    int header_size = 2;
    buf[0] = 0x80 | opcode;
    
    if (payload_len <= 125) {
        buf[1] = payload_len;
    } else if (payload_len <= 65535) {
        buf[1] = 126;
        buf[2] = (payload_len >> 8) & 0xFF;
        buf[3] = payload_len & 0xFF;
        header_size += 2;
    } else {
        buf[1] = 127;
        buf[2] = 0;
        buf[3] = 0;
        buf[4] = 0;
        buf[5] = 0;
        buf[6] = (payload_len >> 24) & 0xFF;
        buf[7] = (payload_len >> 16) & 0xFF;
        buf[8] = (payload_len >> 8) & 0xFF;
        buf[9] = payload_len & 0xFF;
        header_size += 8;
    }
    
    memcpy(buf + header_size, payload, payload_len);
    return header_size + payload_len;
}

static int base64_encode(const unsigned char *input, size_t input_len, char *output, size_t output_len) {
    BIO *b64, *bmem;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    if (!b64) return -1;

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    if (!bmem) {
        BIO_free(b64);
        return -1;
    }

    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, input_len);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    long length = BIO_get_mem_data(bmem, NULL);
    if (length < 0 || (size_t)length + 1 > output_len) {
        BIO_free_all(b64);
        return -1;
    }

    char *data;
    BIO_get_mem_data(bmem, &data);
    memcpy(output, data, length);
    output[length] = '\0';
    BIO_free_all(b64);
    return (int)length;
}

static int make_socket_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

bool device_online_status(const char *imei) {
    if (!imei) return false;
    return hash_map_is_device_online(imei);
}
