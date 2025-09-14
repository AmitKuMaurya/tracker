#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <time.h>
#include <stdint.h>
#include "conn.h"
#include "login_map.h"
#include "data_processing.h"
#include "websocket_server.h"

#define PORT 8081
#define MAX_EVENTS 10000   // maximum epoll events
#define BUF_SIZE 4096      // buffer size per connection
// Utility: make socket non-blocking
int make_socket_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Create and configure timer for connection timeout
int create_connection_timer(int epfd, Conn *c) {
    if (!c) {
        fprintf(stderr, "Invalid connection for timer creation\n");
        return -1;
    }
    
    // Create timer file descriptor
    c->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (c->timer_fd == -1) {
        perror("timerfd_create");
        return -1;
    }
    
    // Configure timer to expire in TIMEOUT_SECONDS
    struct itimerspec timer_spec = {0};
    timer_spec.it_value.tv_sec = TIMEOUT_SECONDS;
    timer_spec.it_value.tv_nsec = 0;
    timer_spec.it_interval.tv_sec = 0;  // One-shot timer
    timer_spec.it_interval.tv_nsec = 0;
    
    if (timerfd_settime(c->timer_fd, 0, &timer_spec, NULL) == -1) {
        perror("timerfd_settime");
        close(c->timer_fd);
        c->timer_fd = -1;
        return -1;
    }
    
    // Create event data for timer
    EventData *timer_event_data = malloc(sizeof(EventData));
    if (!timer_event_data) {
        fprintf(stderr, "Failed to allocate timer event data\n");
        close(c->timer_fd);
        c->timer_fd = -1;
        return -1;
    }
    timer_event_data->conn = c;
    timer_event_data->event_type = EVENT_TYPE_TIMER;
    
    // Store pointer for cleanup
    c->timer_event_data = timer_event_data;
    
    // Add timer to epoll
    struct epoll_event timer_event;
    timer_event.data.ptr = timer_event_data;
    timer_event.events = EPOLLIN | EPOLLET;
    
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, c->timer_fd, &timer_event) == -1) {
        perror("epoll_ctl: add timer");
        close(c->timer_fd);
        c->timer_fd = -1;
        return -1;
    }
    
    // Update last activity timestamp
    c->last_activity = time(NULL);
    
    printf("TIMER: Created timeout timer for connection fd=%d (timer_fd=%d)\n", c->fd, c->timer_fd);
    return 0;
}

// Reset connection timer (called on activity)
int reset_connection_timer(Conn *c) {
    if (!c || c->timer_fd == -1) {
        return -1;
    }
    
    // Configure timer to expire in TIMEOUT_SECONDS from now
    struct itimerspec timer_spec = {0};
    timer_spec.it_value.tv_sec = TIMEOUT_SECONDS;
    timer_spec.it_value.tv_nsec = 0;
    timer_spec.it_interval.tv_sec = 0;  // One-shot timer
    timer_spec.it_interval.tv_nsec = 0;
    
    if (timerfd_settime(c->timer_fd, 0, &timer_spec, NULL) == -1) {
        perror("timerfd_settime reset");
        return -1;
    }
    
    // Update last activity timestamp
    c->last_activity = time(NULL);
    
    printf("TIMER: Reset timeout timer for connection imei=%s\n", c->login_id);
    return 0;
}

// Handle timer expiration (timeout)
void handle_connection_timeout(int epfd, Conn *c) {
    if (!c) {
        return;
    }
    
    printf("TIMER: Connection timeout - closing fd=%d (login_id: %s)\n", 
           c->fd, c->has_login_id ? c->login_id : "unknown");
    
    // Remove from login map
    login_map_remove_for_conn(c);
    
    // Remove timer from epoll and close it
    if (c->timer_fd != -1) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, c->timer_fd, NULL);
        close(c->timer_fd);
        c->timer_fd = -1;
    }
    
    // Remove socket from epoll and close it
    if (c->fd != -1) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
        close(c->fd);
        c->fd = -1;
    }
    
    // Free connection structure
    free(c);
    
    printf("TIMER: Connection cleanup completed\n");
}

// Clean up connection resources
void cleanup_connection(int epfd, Conn *c) {
    if (!c) {
        return;
    }
    
    printf("CLEANUP: Cleaning up connection fd=%d\n", c->fd);
    
    // Remove from login map
    login_map_remove_for_conn(c);
    
    // Clean up timer and its event data
    if (c->timer_fd != -1) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, c->timer_fd, NULL);
        close(c->timer_fd);
        c->timer_fd = -1;
    }
    if (c->timer_event_data) {
        free(c->timer_event_data);
        c->timer_event_data = NULL;
    }
    
    // Clean up socket and its event data
    if (c->fd != -1) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
        close(c->fd);
        c->fd = -1;
    }
    if (c->socket_event_data) {
        free(c->socket_event_data);
        c->socket_event_data = NULL;
    }
    
    // Free connection memory
    free(c);
}


// Read data from socket
void handle_read(int epfd, Conn *c) {
    if (!c || c->fd == -1) {
        return;
    }
    
    while (1) {
        ssize_t count = recv(c->fd, c->inbuf + c->inbuf_used,
                             BUF_SIZE - c->inbuf_used, 0);
        if (count == -1) {
            if (errno != EAGAIN) {
                perror("recv");
                cleanup_connection(epfd, c);
                return;  // Connection cleaned up, don't use c anymore
            }
            break;
        } else if (count == 0) {
            // Client closed connection
            printf("CLIENT: Connection closed by client fd=%d\n", c->fd);
            cleanup_connection(epfd, c);
            return;  // Connection cleaned up, don't use c anymore
        } else {
            // Data received - reset the timeout timer
            reset_connection_timer(c);
            
            c->inbuf_used += count;
            if (c->inbuf_used >= BUF_SIZE) {
                fprintf(stderr, "BUFFER: Buffer overflow, dropping data for fd=%d\n", c->fd);
                c->inbuf_used = 0;
            }
            
            printf("DATA: Received %zd bytes from fd=%d\n", count, c->fd);
            process_input_buffer(c);
        }
    }
}

// Accept new connection
void handle_accept(int server_fd, int epfd) {
    while (1) {
        struct sockaddr_in in_addr;
        socklen_t in_len = sizeof(in_addr);
        int infd = accept(server_fd, (struct sockaddr *)&in_addr, &in_len);
        if (infd == -1) {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;
            perror("accept");
            break;
        }

        make_socket_non_blocking(infd);

        Conn *c = calloc(1, sizeof(Conn));
        if (!c) {
            fprintf(stderr, "calloc failed\n");
            close(infd);
            continue;
        }
        
        // Initialize connection structure
        c->fd = infd;
        c->timer_fd = -1;  // Will be set by create_connection_timer
        c->last_activity = time(NULL);
        c->has_login_id = 0;
        c->inbuf_used = 0;
        c->socket_event_data = NULL;
        c->timer_event_data = NULL;

        // Add socket to epoll with event data
        EventData *socket_event_data = malloc(sizeof(EventData));
        if (!socket_event_data) {
            fprintf(stderr, "Failed to allocate socket event data\n");
            free(c);
            close(infd);
            continue;
        }
        socket_event_data->conn = c;
        socket_event_data->event_type = EVENT_TYPE_SOCKET;
        
        // Store pointer for cleanup
        c->socket_event_data = socket_event_data;
        
        struct epoll_event event;
        event.data.ptr = socket_event_data;
        event.events = EPOLLIN | EPOLLET;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, infd, &event) == -1) {
            perror("epoll_ctl: add socket");
            free(socket_event_data);
            free(c);
            close(infd);
            continue;
        }
        
        // Create and start timeout timer
        if (create_connection_timer(epfd, c) == -1) {
            fprintf(stderr, "Failed to create timer for connection fd=%d\n", infd);
            epoll_ctl(epfd, EPOLL_CTL_DEL, infd, NULL);
            free(c);
            close(infd);
            continue;
        }

        printf("ACCEPT: New connection fd=%d with timer_fd=%d\n", infd, c->timer_fd);
    }
}

// Handle timer expiration events
void handle_timer_event(int epfd, Conn *c) {
    if (!c || c->timer_fd == -1) {
        return;
    }
    
    // Read timer data to reset the timer event (required)
    uint64_t timer_data;
    ssize_t bytes_read = read(c->timer_fd, &timer_data, sizeof(timer_data));
    if (bytes_read != sizeof(timer_data)) {
        if (bytes_read == -1 && errno != EAGAIN) {
            perror("read timer");
        }
    }
    
    printf("TIMER: Timer expired for connection fd=%d (timer_fd=%d)\n", c->fd, c->timer_fd);
    
    // Handle connection timeout
    handle_connection_timeout(epfd, c);
}

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, SOMAXCONN) == -1) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on 0.0.0.0:%d\n", PORT);

    // Initialize and start WebSocket server
    if (websocket_server_init() == 0) {
        websocket_server_start();
        printf("WebSocket server started on port %d\n", WS_PORT);
    } else {
        printf("Failed to initialize WebSocket server\n");
    }

    make_socket_non_blocking(server_fd);

    int epfd = epoll_create1(0);
    if (epfd == -1) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }

    struct epoll_event event;
    event.data.fd = server_fd;
    event.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, server_fd, &event) == -1) {
        perror("epoll_ctl: listen_sock");
        exit(EXIT_FAILURE);
    }

    struct epoll_event *events = calloc(MAX_EVENTS, sizeof(event));

    while (1) {
        int n = epoll_wait(epfd, events, MAX_EVENTS, -1);
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == server_fd) {
                // Server socket - new connection
                handle_accept(server_fd, epfd);
            } else {
                // Client connection or timer event
                EventData *event_data = (EventData *)events[i].data.ptr;
                if (!event_data || !event_data->conn) {
                    fprintf(stderr, "EPOLL: Invalid event data\n");
                    continue;
                }
                
                Conn *c = event_data->conn;
                
                if (event_data->event_type == EVENT_TYPE_SOCKET) {
                    // Socket event - data received or connection closed
                    handle_read(epfd, c);
                } else if (event_data->event_type == EVENT_TYPE_TIMER) {
                    // Timer event - connection timeout
                    handle_timer_event(epfd, c);
                    // Note: event_data will be freed in cleanup_connection
                } else {
                    fprintf(stderr, "EPOLL: Unknown event type: %d\n", event_data->event_type);
                }
            }
        }
    }

    free(events);
    close(server_fd);
    return 0;
}






