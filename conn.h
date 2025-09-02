#ifndef CONN_H
#define CONN_H

#define BUF_SIZE 4096

typedef struct Conn {
    int fd;
    char inbuf[BUF_SIZE];
    int inbuf_used;
    char login_id[32];
    int has_login_id;
} Conn;

#endif // CONN_H

