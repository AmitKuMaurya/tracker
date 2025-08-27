#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <ctype.h>

#define PORT 8081
#define MAX_EVENTS 10000   // maximum events epoll can wait for
#define BUF_SIZE 1024      // buffer for reading data
#define SOCKET_BUF 4096    // 4 KB per socket buffer

// Global variable to store parsed data pointer
unsigned char *parsed_data = NULL;
int parsed_data_size = 0;
bool parse_data(char *data) {
    int len = strlen(data);

    // Free previous data if exists
    if (parsed_data != NULL) {
        free(parsed_data);
        parsed_data = NULL;
    }

    // Allocate worst-case size: half of input length (if all chars are hex)
    int max_bytes = len / 2 + 1;
    parsed_data = (unsigned char *)malloc(max_bytes);
    if (!parsed_data) {
        perror("malloc failed");
        return false;
    }

    int bytes_written = 0;
    int have_high_nibble = 0; // 0 = expecting high nibble, 1 = have high nibble stored
    unsigned int high_nibble = 0;

    for (int i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)data[i];
        if (isspace(ch)) {
            continue; // skip whitespace
        }

        if (!isxdigit(ch)) {
            printf("Error: Invalid non-hex character '%c' at input index %d\n", ch, i);
            free(parsed_data);
            parsed_data = NULL;
            parsed_data_size = 0;
            return false;
        }

        unsigned int val;
        if (ch >= '0' && ch <= '9') {
            val = (unsigned int)(ch - '0');
        } else if (ch >= 'a' && ch <= 'f') {
            val = 10u + (unsigned int)(ch - 'a');
        } else if (ch >= 'A' && ch <= 'F') {
            val = 10u + (unsigned int)(ch - 'A');
        } else {
            // Shouldn't happen due to isxdigit check
            val = 0u;
        }

        if (!have_high_nibble) {
            high_nibble = val;
            have_high_nibble = 1;
        } else {
            unsigned int byte_val = (high_nibble << 4) | val;
            parsed_data[bytes_written++] = (unsigned char)byte_val;
            have_high_nibble = 0;
            high_nibble = 0;
        }
    }

    if (have_high_nibble) {
        printf("Error: Number of hex digits must be even.\n");
        free(parsed_data);
        parsed_data = NULL;
        parsed_data_size = 0;
        return false;
    }

    parsed_data_size = bytes_written;
    return true;
}

int main() {
    int server_fd, client_fd, epoll_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[BUF_SIZE];

    // 1. Create server socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    // Allow immediate reuse of port
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // 2. Bind to address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(1);
    }

    // 3. Listen
    if (listen(server_fd, 1000) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(1);
    }

    printf("Server listening on port %d...\n", PORT);

    // 4. Create epoll instance
    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1 failed");
        exit(1);
    }

    // Register server socket
    struct epoll_event event, events[MAX_EVENTS];
    event.events = EPOLLIN;
    event.data.fd = server_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event) < 0) {
        perror("epoll_ctl failed (server_fd)");
        close(server_fd);
        exit(1);
    }

    // 5. Event loop
    while (1) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (n < 0) {
            perror("epoll_wait failed");
            break;
        }

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            if (fd == server_fd) {
                // New client connection
                client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
                if (client_fd < 0) {
                    perror("Accept failed");
                    continue;
                }

                // Reduce socket buffer size to 4 KB
                int bufsize = SOCKET_BUF;
                if (setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)) < 0) {
                    perror("setsockopt(SO_RCVBUF) failed");
                }
                if (setsockopt(client_fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0) {
                    perror("setsockopt(SO_SNDBUF) failed");
                }

                char client_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
                printf("New client connected from %s:%d (fd=%d)\n",
                       client_ip, ntohs(client_addr.sin_port), client_fd);

                // Add client to epoll
                event.events = EPOLLIN;
                event.data.fd = client_fd;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event);

            } else {
                // Data from existing client
                int bytes_received = recv(fd, buffer, sizeof(buffer) - 1, 0);
                if (bytes_received <= 0) {
                    printf("Client on socket %d disconnected.\n", fd);
                    close(fd);
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
                } else {
                    buffer[bytes_received] = '\0';
                    if (!parse_data(buffer)) {
                        printf("Error: Failed to parse data from fd=%d\n", fd);
                        continue;
                    }
                    printf("Parsed %d bytes: ", parsed_data_size);
                    for (int i = 0; i < parsed_data_size; i++) {
                        printf("%02X ", parsed_data[i]);
                    }
                    printf("\n");

                    // Echo back to client
                    send(fd, buffer, bytes_received, 0);
                }
            }
        }
    }

    // Cleanup global variables
    if (parsed_data != NULL) {
        free(parsed_data);
        parsed_data = NULL;
    }

    close(server_fd);
    close(epoll_fd);
    return 0;
}
