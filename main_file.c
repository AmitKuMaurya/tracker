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
#include "hashmap.h"
#include "data_processing.h"
#include "websocket_server.h"
#include "database.h"

#define PORT 8081
#define MAX_EVENTS 1000
#define BUF_SIZE 4096

// Event type for cleanup timer
#define EVENT_TYPE_CLEANUP 3

// Static global for cleanup timer fd (needed for reading in event loop)
static int g_cleanup_timer_fd = -1;

int make_socket_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int create_connection_timer( Conn *c) {
    if (!c) {
        fprintf(stderr, "Invalid connection for timer creation\n");
        return -1;
    }
    
    c->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC); // here we create timer_fd which we will use to get notification when times out.
    if (c->timer_fd == -1) {
        perror("timerfd_create");
        return -1;
    }
    
    struct itimerspec timer_spec = {0};
    timer_spec.it_value.tv_sec = TIMEOUT_SECONDS;
    timer_spec.it_value.tv_nsec = 0;
    timer_spec.it_interval.tv_sec = 0;
    timer_spec.it_interval.tv_nsec = 0;

    if (timerfd_settime(c->timer_fd, 0, &timer_spec, NULL) == -1) { // this is like start button we giving setting of timer here and start timer
        perror("timerfd_settime");
        close(c->timer_fd);
        c->timer_fd = -1;
        return -1;
    }
    
    EventData *timer_event_data = malloc(sizeof(EventData));  // here is event data pointer which we will get when time up and epoll notify us.
    if (!timer_event_data) {
        fprintf(stderr, "Failed to allocate timer event data\n");
        close(c->timer_fd);
        c->timer_fd = -1;
        return -1;
    }
    timer_event_data->conn = c;
    timer_event_data->event_type = EVENT_TYPE_TIMER;
    c->timer_event_data = timer_event_data;
    
    struct epoll_event timer_event;
    timer_event.data.ptr = timer_event_data;
    timer_event.events = EPOLLIN | EPOLLET;

    if (epoll_ctl(c->epfd, EPOLL_CTL_ADD, c->timer_fd, &timer_event) == -1) {
        perror("epoll_ctl: add timer");
        close(c->timer_fd);
        free(timer_event_data);
        c->timer_fd = -1;
        c->timer_event_data = NULL;
        return -1;
    }
    
    c->last_activity = time(NULL);
    printf("TIMER: Created timeout timer for connection fd=%d (timer_fd=%d)\n", c->fd, c->timer_fd);
    return 0;
}

int reset_connection_timer(Conn *c) { // in this function we just again set the timer again when we get data from client so that timer restarts again from 0
    if (!c || c->timer_fd == -1) {
        return -1;
    }
    
    struct itimerspec timer_spec = {0};
    timer_spec.it_value.tv_sec = TIMEOUT_SECONDS;
    timer_spec.it_value.tv_nsec = 0;
    timer_spec.it_interval.tv_sec = 0;
    timer_spec.it_interval.tv_nsec = 0;
    
    if (timerfd_settime(c->timer_fd, 0, &timer_spec, NULL) == -1) {
        perror("timerfd_settime reset");
        return -1;
    }
    
    c->last_activity = time(NULL);
    printf("TIMER: Reset timeout timer for connection imei=%s\n", c->imei_id);
    return 0;
}

void handle_connection_timeout( Conn *c) {
    if (!c) return;
    
    printf("TIMER: Connection timeout - closing fd=%d (imei_id: %s)\n", 
           c->fd, c->has_imei_id ? c->imei_id : "unknown");
    
    hash_map_remove_tcp_connection_by_fd(c->fd);
    printf("TIMER: Connection cleanup completed\n");
}

void cleanup_connection( Conn *c) {
    if (!c) return;
    
    printf("CLEANUP: Cleaning up connection fd=%d\n", c->fd);

    hash_map_remove_tcp_connection_by_fd(c->fd);
}

void handle_read( Conn *c) {
    if (!c || c->fd == -1) return;
    
    while (1) {
        ssize_t count = recv(c->fd, c->inbuf + c->inbuf_used,
                             BUF_SIZE - c->inbuf_used, 0);
        if (count == -1) {
            if (errno != EAGAIN) {
                perror("recv");
                cleanup_connection(c);
                return;
            }
            break;
        } else if (count == 0) {
            printf("CLIENT: Connection closed by client fd=%d\n", c->fd);
            cleanup_connection(c);
            return;
        } else {
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
        
        c->fd = infd;
        c->timer_fd = -1;
        c->last_activity = time(NULL);
        c->has_imei_id = 0;
        c->inbuf_used = 0;
        c->socket_event_data = NULL;
        c->timer_event_data = NULL;
        c->epfd = epfd;  // Store epoll fd in connection

        EventData *socket_event_data = malloc(sizeof(EventData));
        if (!socket_event_data) {
            fprintf(stderr, "Failed to allocate socket event data\n");
            free(c);
            close(infd);
            continue;
        }
        socket_event_data->conn = c;
        socket_event_data->event_type = EVENT_TYPE_SOCKET;
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
        
        if (create_connection_timer(c) == -1) {
            fprintf(stderr, "Failed to create timer for connection fd=%d\n", infd);
            epoll_ctl(epfd, EPOLL_CTL_DEL, infd, NULL);
            free(socket_event_data);
            free(c);
            close(infd);
            continue;
        }

        printf("ACCEPT: New connection fd=%d with timer_fd=%d\n", infd, c->timer_fd);
    }
}

void handle_timer_event(Conn *c) {// hthis function is useless we can directly call handle_connection_timeout in main epoll loop we can update it later
    if (!c || c->timer_fd == -1) return;
    
    uint64_t timer_data;
    ssize_t bytes_read = read(c->timer_fd, &timer_data, sizeof(timer_data));
    if (bytes_read != sizeof(timer_data)) {
        if (bytes_read == -1 && errno != EAGAIN) {
            perror("read timer");
        }
    }
    
    printf("TIMER: Timer expired for connection fd=%d (timer_fd=%d)\n", c->fd, c->timer_fd);
    handle_connection_timeout(c);
}

void tcp_connection_cleanup(Conn *conn) {
    if (conn) {
        printf("TCP cleanup callback for fd=%d\n", conn->fd);
        // ✅ DOES ALL THE CLEANUP:
        if (conn->timer_fd != -1) {
            epoll_ctl(conn->epfd, EPOLL_CTL_DEL, conn->timer_fd, NULL);
            close(conn->timer_fd);
            conn->timer_fd = -1;
        }
        if (conn->fd != -1) {
            epoll_ctl(conn->epfd, EPOLL_CTL_DEL, conn->fd, NULL);
            close(conn->fd);
            conn->fd = -1;
        }
        free(conn->timer_event_data);
        free(conn->socket_event_data);
        free(conn);
    }
}

int main() {
    if(db_init() != 0) {
        fprintf(stderr, "Failed to initialize database connection\n");
    } else {
        printf("Database initialized successfully\n");
    }
    
    if(hash_map_init() != 0) {
        fprintf(stderr, "Failed to initialize hashmap\n");
        exit(EXIT_FAILURE);
    } else {
        printf("Hashmap initialized successfully\n");
    }
    hash_map_set_cleanup_callbacks(tcp_connection_cleanup, NULL);
    
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
        close(epfd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // ✅ Create cleanup timer with proper EventData structure
    g_cleanup_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (g_cleanup_timer_fd == -1) {
        perror("timerfd_create cleanup");
        exit(EXIT_FAILURE);
    }
    
    struct itimerspec cleanup_spec = {0};
    cleanup_spec.it_value.tv_sec = 30;      // First trigger after 30 seconds
    cleanup_spec.it_interval.tv_sec = 30;   // Repeat every 30 seconds
    if (timerfd_settime(g_cleanup_timer_fd, 0, &cleanup_spec, NULL) == -1) {
        perror("timerfd_settime cleanup");
        exit(EXIT_FAILURE);
    }

    // ✅ Use EventData with EVENT_TYPE_CLEANUP
    EventData *cleanup_event_data = malloc(sizeof(EventData));
    if (!cleanup_event_data) {
        fprintf(stderr, "Failed to allocate cleanup event data\n");
        exit(EXIT_FAILURE);
    }
    cleanup_event_data->conn = NULL;  // No connection for cleanup timer
    cleanup_event_data->event_type = EVENT_TYPE_CLEANUP;

    struct epoll_event cleanup_event;
    cleanup_event.data.ptr = cleanup_event_data;  // ✅ Use ptr, not fd
    cleanup_event.events = EPOLLIN;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, g_cleanup_timer_fd, &cleanup_event) == -1) {
        perror("epoll_ctl: cleanup timer");
        free(cleanup_event_data);
        exit(EXIT_FAILURE);
    }

    printf("Cleanup timer initialized (30 second intervals)\n");

    struct epoll_event *events = calloc(MAX_EVENTS, sizeof(struct epoll_event));
    if (!events) {
        perror("calloc events");
        exit(EXIT_FAILURE);
    }

    while (1) {
        int n = epoll_wait(epfd, events, MAX_EVENTS, -1);
        if (n == -1) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }
        
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == server_fd) {
                // Server socket - new connection
                handle_accept(server_fd, epfd);
            } else {
                // ✅ All other events use EventData
                EventData *event_data = (EventData *)events[i].data.ptr;
                if (!event_data) {
                    fprintf(stderr, "EPOLL: Invalid event data (NULL pointer)\n");
                    continue;
                }
                
                // ✅ Handle cleanup timer
                if (event_data->event_type == EVENT_TYPE_CLEANUP) {
                    uint64_t expirations;
                    ssize_t bytes_read = read(g_cleanup_timer_fd, &expirations, sizeof(expirations));
                    if (bytes_read == sizeof(expirations)) {
                        printf("CLEANUP: Running scheduled removal cleanup (triggered %llu time(s))\n", 
                               (unsigned long long)expirations);
                        hash_map_cleanup_scheduled_removals();
                        hash_map_print_stats();  // Optional: print stats after cleanup
                    }
                    continue;
                }
                
                // ✅ Handle connection events (require conn to be non-NULL)
                Conn *c = event_data->conn;
                if (!c) {
                    fprintf(stderr, "EPOLL: Connection event with NULL conn pointer\n");
                    continue;
                }
                
                if (event_data->event_type == EVENT_TYPE_SOCKET) {
                    if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                        cleanup_connection(c);
                        continue;
                    }
                    handle_read(c);
                } else if (event_data->event_type == EVENT_TYPE_TIMER) {
                    handle_timer_event(c);
                } else {
                    fprintf(stderr, "EPOLL: Unknown event type: %d\n", event_data->event_type);
                }
            }
        }
    }

    // Cleanup on exit
    epoll_ctl(epfd, EPOLL_CTL_DEL, g_cleanup_timer_fd, NULL);
    free(events);
    close(g_cleanup_timer_fd);
    close(epfd);
    close(server_fd);
    hash_map_cleanup();
    free(cleanup_event_data);
    websocket_server_stop(); // Stop WebSocket server
    hash_map_cleanup();
    db_cleanup(); // Clean up database
    return 0;
}