
#define _GNU_SOURCE
#include "websocket_server.h"
#include "database.h"
#include "hashmap.h"


static WSServer g_ws_server = {0};

// WebSocket connection management
#define MAX_WS_CONNECTIONS 1000
static WSConnection g_ws_connections[MAX_WS_CONNECTIONS];
static pthread_mutex_t g_ws_connections_mutex = PTHREAD_MUTEX_INITIALIZER;

// Static function prototypes
static void *websocket_server_thread(void *arg);
static int make_socket_non_blocking(int fd);
static int accept_websocket_connection(int server_fd);
static int handle_websocket_handshake(int fd);
static int handle_websocket_frame(int fd);
static int contains_case_insensitive(const char *haystack, const char *needle);
static int parse_websocket_frame(const char *buf, size_t len, 
                                int *opcode, int *fin, 
                                char *payload, size_t *payload_len);
static int create_websocket_frame(char *buf, size_t buf_len, 
                                 const char *payload, size_t payload_len, 
                                 int opcode);
static int base64_encode(const unsigned char *input, size_t input_len, 
                        char *output, size_t output_len);
static void remove_websocket_connection(int fd);
static void cleanup_websocket_connection(int fd);
bool device_online_status(const char *imei);

int websocket_server_init(void) {
    memset(&g_ws_server, 0, sizeof(g_ws_server));
    memset(g_ws_connections, 0, sizeof(g_ws_connections));
    
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
    
    // Make server socket non-blocking
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
    
    // Initialize all connection slots as available
    for (int i = 0; i < MAX_WS_CONNECTIONS; i++) {
        g_ws_connections[i].fd = -1;
    }
    
    printf("WebSocket server initialized on port %d\n", WS_PORT);
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
    
    g_ws_server.running = 0;
    pthread_join(g_ws_server.thread_id, NULL);
    
    close(g_ws_server.epoll_fd);
    close(g_ws_server.server_fd);
    
    printf("WebSocket server stopped\n");
}

static void *websocket_server_thread(void *arg) {
    (void)arg;  // Mark parameter as unused
    struct epoll_event events[WS_MAX_EVENTS];
    
    printf("WebSocket server thread running\n");
    
    while (g_ws_server.running) {
        int n = epoll_wait(g_ws_server.epoll_fd, events, WS_MAX_EVENTS, 100);
        if (n == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("WebSocket epoll_wait");
            // On fatal epoll_wait error, break loop so server can stop/cleanup
            break;
        }
        
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == g_ws_server.server_fd) {
                // New connection
                while (accept_websocket_connection(g_ws_server.server_fd) == 0) {
                    // Continue accepting until no more connections
                }
            } else {
                // Client connection
                int fd = events[i].data.fd;
                
                pthread_mutex_lock(&g_ws_connections_mutex);
                WSConnection *conn = NULL;
                for (int j = 0; j < MAX_WS_CONNECTIONS; j++) {
                    if (g_ws_connections[j].fd == fd) {
                        conn = &g_ws_connections[j];
                        break;
                    }
                }
                pthread_mutex_unlock(&g_ws_connections_mutex);
                
                if (!conn) {
                    printf("WebSocket: Unknown connection fd=%d\n", fd);
                    close(fd);
                    continue;
                }
                
                if (events[i].events & EPOLLIN) {
                    // Data available to read
                    if (conn->state == WS_STATE_HANDSHAKE) {
                        if (handle_websocket_handshake(fd) == 0) {
                            conn->state = WS_STATE_OPEN;
                            printf("WebSocket: Handshake complete for fd=%d\n", fd);
                            // Check online status and send appropriate message
                        } else {
                            printf("WebSocket: Handshake failed for fd=%d\n", fd);
                            remove_websocket_connection(fd);
                        }
                    } else if (conn->state == WS_STATE_OPEN) {
                        if (handle_websocket_frame(fd) != 0) {
                            printf("WebSocket: Frame handling failed for fd=%d\n", fd);
                            remove_websocket_connection(fd);
                        }
                    }
                }
                
                if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                    printf("WebSocket: Error or hangup on fd=%d\n", fd);
                    remove_websocket_connection(fd);
                }
            }
        }
    }
    
    return NULL;
}

static int accept_websocket_connection(int server_fd) {
    struct sockaddr_in in_addr;
    socklen_t in_len = sizeof(in_addr);
    int fd = accept(server_fd, (struct sockaddr *)&in_addr, &in_len);
    
    if (fd == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("WebSocket accept");
        }
        return -1;
    }
    
    if (make_socket_non_blocking(fd) == -1) {
        close(fd);
        return -1;
    }
    
    // Find free connection slot
    pthread_mutex_lock(&g_ws_connections_mutex);
    int slot = -1;
    for (int i = 0; i < MAX_WS_CONNECTIONS; i++) {
        if (g_ws_connections[i].fd == -1) {
            slot = i;
            break;
        }
    }
    
    if (slot == -1) {
        pthread_mutex_unlock(&g_ws_connections_mutex);
        printf("WebSocket: Max connections reached\n");
        close(fd);
        return -1;
    }
    
    // Initialize connection
    g_ws_connections[slot].fd = fd;
    g_ws_connections[slot].state = WS_STATE_HANDSHAKE;
    g_ws_connections[slot].cleanup_in_progress = 0;
    g_ws_connections[slot].has_imei = 0;
    g_ws_connections[slot].imei[0] = '\0';
    g_ws_connections[slot].has_device_id = 0;
    g_ws_connections[slot].device_id[0] = '\0';
    g_ws_connections[slot].write_buf = NULL;
    g_ws_connections[slot].write_buf_len = 0;
    g_ws_connections[slot].write_buf_used = 0;
    
    pthread_mutex_unlock(&g_ws_connections_mutex);
    
    // Add to epoll
    struct epoll_event event;
    event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
    event.data.fd = fd;
    if (epoll_ctl(g_ws_server.epoll_fd, EPOLL_CTL_ADD, fd, &event) == -1) {
        perror("WebSocket epoll_ctl: client");
        cleanup_websocket_connection(fd);
        return -1;
    }
    
    printf("WebSocket: New connection accepted fd=%d\n", fd);
    return 0;
}

static int handle_websocket_handshake(int fd) {
    char buf[WS_BUF_SIZE];
    ssize_t len = recv(fd, buf, sizeof(buf) - 1, MSG_DONTWAIT);
    if (len <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 1;
        printf("WebSocket: recv failed in handshake: %s\n", strerror(errno));
        return -1;
    }

    buf[len] = '\0';
    printf("WebSocket: Received handshake request:\n%s\n", buf);

    if (strncmp(buf, "GET ", 4) != 0) {
        printf("WebSocket: Not a GET request\n");
        return -1;
    }

    // Keep an untouched copy for later parsing
    char original_buf[WS_BUF_SIZE];
    strncpy(original_buf, buf, sizeof(original_buf) - 1);
    original_buf[sizeof(original_buf) - 1] = '\0';

    // Extract device ID from the request line
    char *request_line_end = strstr(buf, "\r\n");
    if (request_line_end) *request_line_end = '\0';
    char *space1 = strchr(buf, ' ');
    char *space2 = space1 ? strchr(space1 + 1, ' ') : NULL;
    if (!space1 || !space2) {
        printf("WebSocket: Malformed request line\n");
        return -1;
    }
    *space2 = '\0';
    const char *url = space1 + 1; // "/ws?device_id=..."
    const char *device_id_q = strstr(url, "device_id=");
    char normalized_device_id[32] = {0};
    if (device_id_q) {
        device_id_q += 10;// Move past "device_id="
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

    // Now parse headers (use original_buf since buf was modified)
    int upgrade_found = 0;
    int connection_found = 0;
    char client_key[256] = {0};

    char *headers = strstr(original_buf, "\r\n");
    if (!headers) return -1;
    headers += 2; // Move past request line CRLF

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
        printf("WebSocket: Missing required headers (Upgrade/Connection/Key)\n");
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
    ssize_t sent = send(fd, response, resp_len, 0);
    if (sent != resp_len) {
        printf("WebSocket: Failed to send complete response: %zd/%d bytes\n", sent, resp_len);
        return -1;
    }

    // Store device ID on the connection if available
    if (normalized_device_id[0] != '\0') {
        pthread_mutex_lock(&g_ws_connections_mutex);
        for (int i = 0; i < MAX_WS_CONNECTIONS; i++) {
            if (g_ws_connections[i].fd == fd) {
                strncpy(g_ws_connections[i].device_id, normalized_device_id, sizeof(g_ws_connections[i].device_id) - 1);
                g_ws_connections[i].device_id[sizeof(g_ws_connections[i].device_id) - 1] = '\0';
                g_ws_connections[i].has_device_id = 1;
                break;
            }
        }
        pthread_mutex_unlock(&g_ws_connections_mutex);
    }
    printf("WebSocket: Handshake response sent, device_id=%s\n", normalized_device_id[0] ? normalized_device_id : "none");
    const char* imei_id = db_get_imei_id(normalized_device_id);
    if (imei_id) {
        pthread_mutex_lock(&g_ws_connections_mutex);
        for (int i = 0; i < MAX_WS_CONNECTIONS; i++) {
            if (g_ws_connections[i].fd == fd) {
                strncpy(g_ws_connections[i].imei, imei_id, sizeof(g_ws_connections[i].imei) - 1);
                g_ws_connections[i].imei[sizeof(g_ws_connections[i].imei) - 1] = '\0';
                g_ws_connections[i].has_imei = 1;
                
                // Register WebSocket connection in hashmap for fast lookups
                hash_map_set_ws_connection(imei_id, (struct WSConnection*)&g_ws_connections[i]);
                
                // Set up fast FD-to-IMEI mapping for O(1) lookups
                fd_map_set_ws(fd, imei_id);
                break;
            }
        }
        pthread_mutex_unlock(&g_ws_connections_mutex);
        printf("WebSocket: Mapped device_id %s to IMEI %s\n", normalized_device_id, imei_id);
    } else {
        printf("WebSocket: No IMEI mapping found for device_id %s\n", normalized_device_id);
    }

    // Check if device is online and send status message
    int is_online = (imei_id && device_online_status(imei_id)) ? 1 : 0;
    {
        char *device_status_msg = device_online_status_json(is_online);
        if (device_status_msg) {
            websocket_send_to_imei_id(imei_id, device_status_msg, strlen(device_status_msg));
            free(device_status_msg);
        }
        printf("WebSocket: IMEI %s is %s\n", imei_id ? imei_id : "unknown", is_online ? "online" : "offline");
    }

    return 0;
}

// Simple case-insensitive substring check to avoid non-standard strcasestr
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
 
static int handle_websocket_frame(int fd) {
    char buf[WS_BUF_SIZE];
    ssize_t len = recv(fd, buf, sizeof(buf), 0);
    
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
            // Handle incoming data if needed
            printf("WebSocket: Received %zd bytes from fd=%d\n", payload_len, fd);
            break;
            
        case WS_OP_CLOSE:
            printf("WebSocket: Close frame received from fd=%d\n", fd);
            remove_websocket_connection(fd);
            break;
            
        case WS_OP_PING:
            // Respond with pong
            {
                char pong_frame[WS_BUF_SIZE];
                int frame_len = create_websocket_frame(pong_frame, sizeof(pong_frame), 
                                                     payload, payload_len, WS_OP_PONG);
                if (frame_len > 0) {
                    send(fd, pong_frame, frame_len, 0);
                }
            }
            break;
            
        case WS_OP_PONG:
            // No action needed
            break;
            
        default:
            printf("WebSocket: Unknown opcode %d from fd=%d\n", opcode, fd);
            break;
    }
    
    return 0;
}

int websocket_send_to_imei_id(const char *imei_id, const char *data, size_t len) {
    if (!imei_id || !data || len == 0) {
        return -1;
    }
    
    pthread_mutex_lock(&g_ws_connections_mutex);
    
    int count = 0;
    for (int i = 0; i < MAX_WS_CONNECTIONS; i++) {
        if (g_ws_connections[i].fd != -1 && 
            g_ws_connections[i].has_imei &&
            strcmp(g_ws_connections[i].imei, imei_id) == 0) {
            char* device_id = g_ws_connections[i].has_device_id ? g_ws_connections[i].device_id : "unknown";
            printf("WebSocket: Sending data to device_id=%s (IMEI=%s) on fd=%d\n", 
                   device_id, imei_id, g_ws_connections[i].fd);
            if(!g_ws_connections[i].has_device_id) {
                printf("WebSocket: Warning - Connection fd=%d has no associated device ID\n", g_ws_connections[i].fd);
            }
            char frame[WS_BUF_SIZE];
            int frame_len = create_websocket_frame(frame, sizeof(frame), data, len, WS_OP_TEXT);
            
            if (frame_len > 0) {
                ssize_t sent = send(g_ws_connections[i].fd, frame, frame_len, 0);
                if (sent == frame_len) {
                    count++;
                } else {
                    printf("WebSocket: Failed to send data to fd=%d\n", g_ws_connections[i].fd);
                }
            }
        }
    }
    
    pthread_mutex_unlock(&g_ws_connections_mutex);
    
    return count;
}

int websocket_send_to_device_id(const char *device_id, const char *data, size_t len) {
    if (!device_id || !data || len == 0) {
        return -1;
    }
    
    // Convert device_id to IMEI for internal lookup
    const char *imei = hash_map_get_imei_by_device_id(device_id);
    if (!imei) {
        printf("WebSocket: No IMEI found for device_id %s\n", device_id);
        return -1;
    }
    
    // Use existing IMEI-based function
    return websocket_send_to_imei_id(imei, data, len);
}

int websocket_broadcast(const char *data, size_t len) {
    if (!data || len == 0) {
        return -1;
    }
    
    pthread_mutex_lock(&g_ws_connections_mutex);
    
    int count = 0;
    for (int i = 0; i < MAX_WS_CONNECTIONS; i++) {
        if (g_ws_connections[i].fd != -1 && g_ws_connections[i].state == WS_STATE_OPEN) {
            char frame[WS_BUF_SIZE];
            int frame_len = create_websocket_frame(frame, sizeof(frame), data, len, WS_OP_TEXT);
            
            if (frame_len > 0) {
                ssize_t sent = send(g_ws_connections[i].fd, frame, frame_len, 0);
                if (sent == frame_len) {
                    count++;
                }
            }
        }
    }
    
    pthread_mutex_unlock(&g_ws_connections_mutex);
    
    return count;
}

static int parse_websocket_frame(const char *buf, size_t len, 
                                int *opcode, int *fin, 
                                char *payload, size_t *payload_len) {
    if (len < 2) {
        return -1;
    }
    
    unsigned char byte1 = buf[0];
    unsigned char byte2 = buf[1];
    
    *fin = (byte1 & 0x80) != 0;
    *opcode = byte1 & 0x0F;
    int masked = (byte2 & 0x80) != 0;
    size_t payload_length = byte2 & 0x7F;
    
    size_t header_size = 2;
    
    if (payload_length == 126) {
        if (len < 4) {
            return -1;
        }
        payload_length = (buf[2] << 8) | buf[3];
        header_size += 2;
    } else if (payload_length == 127) {
        if (len < 10) {
            return -1;
        }
        // For simplicity, we assume payload length fits in 32 bits
        payload_length = (buf[2] << 24) | (buf[3] << 16) | (buf[4] << 8) | buf[5];
        header_size += 8;
    }
    
    if (masked) {
        header_size += 4; // Masking key
    }
    
    if (len < header_size + payload_length) {
        return -1;
    }
    
    // Extract payload
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
    if (buf_len < payload_len + 10) {
        return -1;
    }
    
    int header_size = 2;
    buf[0] = 0x80 | opcode; // FIN bit set + opcode
    
    if (payload_len <= 125) {
        buf[1] = payload_len;
    } else if (payload_len <= 65535) {
        buf[1] = 126;
        buf[2] = (payload_len >> 8) & 0xFF;
        buf[3] = payload_len & 0xFF;
        header_size += 2;
    } else {
        buf[1] = 127;
        // For simplicity, assume payload length fits in 32 bits
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

    // Get the encoded length
    long length = BIO_get_mem_data(bmem, NULL);
    if (length < 0 || (size_t)length + 1 > output_len) {
        BIO_free_all(b64);
        return -1;
    }

    // Get the encoded data
    char *data;
    BIO_get_mem_data(bmem, &data);
    memcpy(output, data, length);
    output[length] = '\0';
    BIO_free_all(b64);
    return (int)length;
}

static void remove_websocket_connection(int fd) {
    pthread_mutex_lock(&g_ws_connections_mutex);
    // Mark cleanup_in_progress under lock and capture any data needed
    int do_cleanup = 1;
    for (int i = 0; i < MAX_WS_CONNECTIONS; i++) {
        if (g_ws_connections[i].fd == fd) {
            if (g_ws_connections[i].cleanup_in_progress) {
                do_cleanup = 0;
            } else {
                g_ws_connections[i].cleanup_in_progress = 1;
            }
            break;
        }
    }
    pthread_mutex_unlock(&g_ws_connections_mutex);

    if (do_cleanup) {
        cleanup_websocket_connection(fd);
    }
}

static void cleanup_websocket_connection(int fd) {
    // First, capture data we need while holding the mutex, but do not call out while holding it
    char imei_copy[32] = {0};
    int had_imei = 0;
    int index = -1;

    pthread_mutex_lock(&g_ws_connections_mutex);
    for (int i = 0; i < MAX_WS_CONNECTIONS; i++) {
        if (g_ws_connections[i].fd == fd) {
            index = i;
            if (g_ws_connections[i].has_imei) {
                strncpy(imei_copy, g_ws_connections[i].imei, sizeof(imei_copy) - 1);
                imei_copy[sizeof(imei_copy) - 1] = '\0';
                had_imei = 1;
            }
            break;
        }
    }
    pthread_mutex_unlock(&g_ws_connections_mutex);

    // Perform hashmap operations outside the mutex to avoid deadlocks
    if (had_imei) {
        hash_map_remove_ws_connection(imei_copy);
        fd_map_remove_ws(fd);
    }

    // Proceed with epoll and fd cleanup
    epoll_ctl(g_ws_server.epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    close(fd);

    // Now free buffers and reset the slot under the mutex again
    pthread_mutex_lock(&g_ws_connections_mutex);
    if (index != -1 && g_ws_connections[index].fd == fd) {
        if (g_ws_connections[index].write_buf) {
            free(g_ws_connections[index].write_buf);
        }
        memset(&g_ws_connections[index], 0, sizeof(WSConnection));
        g_ws_connections[index].fd = -1;
    }
    pthread_mutex_unlock(&g_ws_connections_mutex);
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
    
    // Check if there's a TCP connection in the hashmap
    return hash_map_is_device_online(imei);
}

