#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <math.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include "conn.h"
#include "login_map.h"
#include "offline_data.h"

#define PORT 12345
#define MAX_EVENTS 10000   // maximum epoll events
#define BUF_SIZE 4096      // buffer size per connection

// Mapping implementation is moved to login_map.c; only APIs are used here

// Connection state


// Forward declaration
void command_action(Conn *c, const char *cmd, int len);
void login_command(Conn *c, const unsigned char *cmd, int len);
void gps_command(Conn *c, const unsigned char *cmd, int len);
// Utility: make socket non-blocking
int make_socket_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Process input and extract complete frames
void process_input(Conn *c) {
    int i = 0;
    while (i <= c->inbuf_used - 4) {
        // look for header
        if ((unsigned char)c->inbuf[i] == 0x78 &&
            (unsigned char)c->inbuf[i+1] == 0x78) {

            // search for terminator
            int j;
            for (j = i + 2; j <= c->inbuf_used - 2; j++) {
                if ((unsigned char)c->inbuf[j] == 0x0D &&
                    (unsigned char)c->inbuf[j+1] == 0x0A) {

                    int frame_len = (j + 2) - i;
                    // copy frame
                    char *frame = malloc(frame_len);
                    if (!frame) {
                        fprintf(stderr, "malloc failed\n");
                        return;
                    }
                    memcpy(frame, c->inbuf + i, frame_len);

                    // send to handler
                    command_action(c, frame, frame_len);

                    free(frame);

                    // move index after this frame
                    i = j + 2;
                    break;
                }
            }
            if (j > c->inbuf_used - 2) {
                // no complete frame found yet, discard all
                c->inbuf_used = 0;
                return;
            }
        } else {
            i++;
        }
    }

    // after processing, discard all data
    c->inbuf_used = 0;
}

// Read data from socket
void handle_read(Conn *c) {
    while (1) {
        ssize_t count = recv(c->fd, c->inbuf + c->inbuf_used,
                             BUF_SIZE - c->inbuf_used, 0);
        if (count == -1) {
            if (errno != EAGAIN) {
                perror("recv");
                close(c->fd);
                login_map_remove_for_conn(c);
                c->fd = -1;
            }
            break;
        } else if (count == 0) {
            // client closed
            close(c->fd);
            login_map_remove_for_conn(c);
            c->fd = -1;
            break;
        } else {
            c->inbuf_used += count;
            if (c->inbuf_used >= BUF_SIZE) {
                fprintf(stderr, "buffer overflow, dropping data\n");
                c->inbuf_used = 0;
            }
            process_input(c);
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
        c->fd = infd;

        struct epoll_event event;
        event.data.ptr = c;
        event.events = EPOLLIN | EPOLLET;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, infd, &event) == -1) {
            perror("epoll_ctl: add");
            free(c);
            close(infd);
            continue;
        }

        printf("Accepted connection: fd=%d\n", infd);
    }
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
                handle_accept(server_fd, epfd);
            } else {
                Conn *c = (Conn *)events[i].data.ptr;
                if (c->fd != -1) handle_read(c);
            }
        }
    }

    free(events);
    close(server_fd);
    return 0;
}

// Example command handler
void command_action(Conn *c, const char *cmd, int len) {
    printf("command_action: got frame of %d bytes: ", len);
    for (int i = 0; i < len; i++)
        printf("%02X ", (unsigned char)cmd[i]);
    printf("\n");
    if (len > 4) {
        unsigned char proto = (unsigned char)cmd[3];
        if (proto == 0x01) {
            printf("login command received\n");
            login_command(c, (const unsigned char *)cmd, len);
        } else if (proto == 0x08) {
            printf("heartbeat command received\n");
        } else if (proto == 0x10) {
            printf("GPS online command received\n");
            gps_command(c, (const unsigned char *)cmd, len);
        }
        else if(proto == 0x18) {
            printf("LBS offline command received\n");
            lbs_command(c, (const unsigned char *)cmd, len);
        }
    }
}

void login_command(Conn *c, const unsigned char *cmd, int len) {
    // Expect format: 78 78, len, 01, IMEI(8 bytes BCD), ver(1), 0D 0A
    if (len < 2 + 1 + 1 + 8 + 1 + 2) return;
    const unsigned char *imei_bcd = cmd + 4; // 8 bytes starting at index 4
    char imei[16]; // 15 digits + null
    int digit_index = 0;
    for (int i = 0; i < 8 && digit_index < 15; i++) {
        unsigned char byte = imei_bcd[i];
        unsigned char high = (byte >> 4) & 0x0F;
        unsigned char low = byte & 0x0F;
        imei[digit_index++] = (char)('0' + high);
        if (digit_index < 15) imei[digit_index++] = (char)('0' + low);
    }
    imei[15] = '\0';

    strncpy(c->login_id, imei, sizeof(c->login_id) - 1);
    c->login_id[sizeof(c->login_id) - 1] = '\0';
    c->has_login_id = 1;
    printf("Mapped fd %d -> login_id %s\n", c->fd, c->login_id);

    // register in global map (login_id -> conn)
    login_map_set(c->login_id, c);
    // reply success: 7878 01 01 0D0A
    unsigned char response[] = {0x78, 0x78, 0x01, 0x01, 0x0D, 0x0A};
    send(c->fd, response, sizeof(response), 0);
}

void gps_command(Conn *c, const unsigned char *cmd, int len) {
    // Minimum length check: 78 78 + len(1) + proto(1) + datetime(6) + gps_info(1) + lat_long(8) + speed(1) + status_heading(2) + terminator(2)
    if (len < 24) {
        printf("GPS command too short: %d bytes\n", len);
        return;
    }
    
    // Extract status and heading bytes (position depends on protocol version)
    // For basic 0x10 protocol, status/heading is at position: 2(header) + 1(len) + 1(proto) + 6(datetime) + 1(gps_info) + 8(lat_long) + 1(speed) = 20
    int status_pos = 20;
    if (status_pos + 1 >= len) {
        printf("Invalid GPS command length for status extraction\n");
        return;
    }
    
    unsigned char status_byte1 = cmd[status_pos];
    unsigned char status_byte2 = cmd[status_pos + 1];
    
    // Check if GPS is positioned (bit 4 of first status byte)
    // According to protocol: bit 4 (0-indexed from left) indicates GPS positioning status
    // 0 = GPS not positioned, 1 = GPS positioned
    int is_positioned = (status_byte1 & 0x08) != 0; // Mask with 00001000 (bit 3 from right)
    
    if (!is_positioned) {
        printf("GPS not positioned, skipping data processing\n");
        
        // Still need to reply to the device as required by protocol
        unsigned char response[] = {0x78, 0x78, 0x00, 0x10, 
                                   cmd[4], cmd[5], cmd[6], cmd[7], cmd[8], cmd[9], // Copy datetime
                                   0x0D, 0x0A};
        send(c->fd, response, sizeof(response), 0);
        return;
    }
    
    printf("GPS is positioned, processing data...\n");
    
    // Parse datetime (BCD encoded)
    // Position: 4-9 (after 78 78 len proto)
    int year = (cmd[4] >> 4) * 10 + (cmd[4] & 0x0F) + 2000;
    int month = (cmd[5] >> 4) * 10 + (cmd[5] & 0x0F);
    int day = (cmd[6] >> 4) * 10 + (cmd[6] & 0x0F);
    int hour = (cmd[7] >> 4) * 10 + (cmd[7] & 0x0F);
    int minute = (cmd[8] >> 4) * 10 + (cmd[8] & 0x0F);
    int second = (cmd[9] >> 4) * 10 + (cmd[9] & 0x0F);
    
    printf("DateTime: %04d-%02d-%02d %02d:%02d:%02d (GMT+0)\n", 
           year, month, day, hour, minute, second);
    
    // Parse latitude and longitude (positions 11-18)
    // GPS info byte at position 10 contains length and satellite count
    unsigned char gps_info = cmd[10];
    int gps_data_length = (gps_info >> 4) & 0x0F;
    int satellite_count = gps_info & 0x0F;
    printf("GPS data length: %d, Satellites: %d\n", gps_data_length, satellite_count);
    
    // Extract latitude (4 bytes) and longitude (4 bytes)
    uint32_t latitude_raw = (cmd[11] << 24) | (cmd[12] << 16) | (cmd[13] << 8) | cmd[14];
    uint32_t longitude_raw = (cmd[15] << 24) | (cmd[16] << 16) | (cmd[17] << 8) | cmd[18];
    
    // Convert to degrees (divide by 30000 to get minutes, then convert to degrees)
    double latitude_minutes = latitude_raw / 30000.0;
    double longitude_minutes = longitude_raw / 30000.0;
    
    double latitude_degrees = floor(latitude_minutes / 60.0);
    double latitude_decimal = latitude_degrees + (latitude_minutes - (latitude_degrees * 60.0)) / 60.0;
    
    double longitude_degrees = floor(longitude_minutes / 60.0);
    double longitude_decimal = longitude_degrees + (longitude_minutes - (longitude_degrees * 60.0)) / 60.0;
    
    // Check direction from status byte
    int is_north = (status_byte1 & 0x04) != 0; // Bit 5: 0=South, 1=North
    int is_west = (status_byte1 & 0x02) != 0;   // Bit 6: 0=East, 1=West
    
    if (!is_north) {
        latitude_decimal = -latitude_decimal; // South latitude is negative
    }
    if (is_west) {
        longitude_decimal = -longitude_decimal; // West longitude is negative
    }
    
    printf("Latitude: %.6f %s\n", latitude_decimal, is_north ? "N" : "S");
    printf("Longitude: %.6f %s\n", longitude_decimal, is_west ? "W" : "E");
    
    // Parse speed (1 byte)
    unsigned char speed_kmh = cmd[19];
    printf("Speed: %d km/h\n", speed_kmh);
    
    // Parse heading (from status bytes)
    // Heading is stored in the last 10 bits of the two status bytes
    int heading = ((status_byte1 & 0x03) << 8) | status_byte2;
    printf("Heading: %d degrees\n", heading);
    
    
    // Reply to device as required by protocol
    unsigned char response[] = {0x78, 0x78, 0x00, 0x10, 
                               cmd[4], cmd[5], cmd[6], cmd[7], cmd[8], cmd[9], // Copy datetime
                               0x0D, 0x0A};
    send(c->fd, response, sizeof(response), 0);
    
    printf("GPS data processed and reply sent\n");
}





