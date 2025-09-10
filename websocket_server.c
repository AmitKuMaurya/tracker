#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include "websocket_server.h"
#include "login_map.h"

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
static void extract_imei_from_handshake(int fd, const char *buffer);

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
                
                if (events[i].events & (EPOLLERR | EPOLLHUP)) {
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
    g_ws_connections[slot].has_imei = 0;
    g_ws_connections[slot].imei[0] = '\0';
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

int handle_websocket_handshake(int fd) {
    char buffer[2048];
    int bytes = recv(fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes <= 0) {
        return -1;
    }
    buffer[bytes] = '\0';


    // Look for Sec-WebSocket-Key
    char *key_header = strstr(buffer, "Sec-WebSocket-Key:");
    if (!key_header) {
        return -1;
    }

    key_header += strlen("Sec-WebSocket-Key:");
    while (*key_header == ' ') key_header++; // skip spaces

    char client_key[128];
    printf("client_key: %s\n", key_header);
    sscanf(key_header, "%127s", client_key);

    // Append GUID
    const char *guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char combined[256];
    snprintf(combined, sizeof(combined), "%s%s", client_key, guid);
    printf("combined: %s\n", combined);
    // SHA1 hash
    unsigned char sha1_result[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)combined, strlen(combined), sha1_result);
    printf("sha1_result: %s\n", sha1_result);
    // Base64 encode
    char accept_key[256];
    if (base64_encode(sha1_result, SHA_DIGEST_LENGTH, accept_key, sizeof(accept_key)) < 0) {
        return -1;
    }
    printf("accept_key: %s\n", accept_key);
    // Build response
    char response[512];
    snprintf(response, sizeof(response),
             "HTTP/1.1 101 Switching Protocols\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Accept: %s\r\n\r\n",
             accept_key);

    // Send response
    send(fd, response, strlen(response), 0);

    // Extract IMEI from the handshake buffer after successful handshake
    extract_imei_from_handshake(fd, buffer);

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

int websocket_send_to_imei(const char *imei, const char *data, size_t len) {
    if (!imei || !data || len == 0) {
        return -1;
    }
    
    pthread_mutex_lock(&g_ws_connections_mutex);
    
    int count = 0;
    for (int i = 0; i < MAX_WS_CONNECTIONS; i++) {
        if (g_ws_connections[i].fd != -1 && 
            g_ws_connections[i].has_imei &&
            strcmp(g_ws_connections[i].imei, imei) == 0) {
            
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
    cleanup_websocket_connection(fd);
    pthread_mutex_unlock(&g_ws_connections_mutex);
}

static void cleanup_websocket_connection(int fd) {
    for (int i = 0; i < MAX_WS_CONNECTIONS; i++) {
        if (g_ws_connections[i].fd == fd) {
            printf("WebSocket: Cleaning up connection fd=%d, IMEI=%s\n", 
                   fd, g_ws_connections[i].has_imei ? g_ws_connections[i].imei : "unknown");
            
            epoll_ctl(g_ws_server.epoll_fd, EPOLL_CTL_DEL, fd, NULL);
            close(fd);
            
            if (g_ws_connections[i].write_buf) {
                free(g_ws_connections[i].write_buf);
            }
            
            memset(&g_ws_connections[i], 0, sizeof(WSConnection));
            g_ws_connections[i].fd = -1;
            break;
        }
    }
}

static int make_socket_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void extract_imei_from_handshake(int fd, const char *buffer) {
    // Extract IMEI from query parameters
    char *request_line = strstr(buffer, "GET ");
    if (request_line) {
        char *url_start = request_line + 4; // Skip "GET "
        char *url_end = strstr(url_start, " HTTP/");
        if (url_end) {
            // Create a copy of the URL to avoid modifying the original buffer
            size_t url_len = url_end - url_start;
            char url_copy[512];
            if (url_len < sizeof(url_copy)) {
                strncpy(url_copy, url_start, url_len);
                url_copy[url_len] = '\0';
                
                // Look for imei parameter
                char *imei_param = strstr(url_copy, "imei=");
                if (imei_param) {
                    imei_param += 5; // Skip "imei="
                    char *imei_end = strchr(imei_param, '&');
                    if (imei_end) {
                        *imei_end = '\0';
                    }
                    
                    // Find the connection and store IMEI
                    pthread_mutex_lock(&g_ws_connections_mutex);
                    for (int i = 0; i < MAX_WS_CONNECTIONS; i++) {
                        if (g_ws_connections[i].fd == fd) {
                            strncpy(g_ws_connections[i].imei, imei_param, sizeof(g_ws_connections[i].imei) - 1);
                            g_ws_connections[i].imei[sizeof(g_ws_connections[i].imei) - 1] = '\0';
                            g_ws_connections[i].has_imei = 1;
                            printf("WebSocket: IMEI %s registered for fd=%d\n", g_ws_connections[i].imei, fd);
                            break;
                        }
                    }
                    pthread_mutex_unlock(&g_ws_connections_mutex);
                }
            }
        }
    }
}