#include <string.h>
#include <stdio.h>
#include "conn.h"
#include "login_map.h"

#define LOGIN_MAP_CAPACITY 1024
typedef struct {
    int in_use;
    char login_id[32];
    Conn *conn;
} LoginMapEntry;

static LoginMapEntry g_login_map[LOGIN_MAP_CAPACITY];

static int login_map_find_index(const char *login_id) {
    for (int i = 0; i < LOGIN_MAP_CAPACITY; i++) {
        if (g_login_map[i].in_use && strncmp(g_login_map[i].login_id, login_id, sizeof(g_login_map[i].login_id)) == 0) {
            return i;
        }
    }
    return -1;
}

void login_map_set(const char *login_id, Conn *c) {
    int idx = login_map_find_index(login_id);
    if (idx >= 0) {
        g_login_map[idx].conn = c;
        return;
    }
    for (int i = 0; i < LOGIN_MAP_CAPACITY; i++) {
        if (!g_login_map[i].in_use) {
            g_login_map[i].in_use = 1;
            strncpy(g_login_map[i].login_id, login_id, sizeof(g_login_map[i].login_id) - 1);
            g_login_map[i].login_id[sizeof(g_login_map[i].login_id) - 1] = '\0';
            g_login_map[i].conn = c;
            return;
        }
    }
    fprintf(stderr, "login map full, cannot register %s\n", login_id);
}

void login_map_remove_for_conn(Conn *c) {
    for (int i = 0; i < LOGIN_MAP_CAPACITY; i++) {
        if (g_login_map[i].in_use && g_login_map[i].conn == c) {
            g_login_map[i].in_use = 0;
            g_login_map[i].login_id[0] = '\0';
            g_login_map[i].conn = NULL;
        }
    }
}

Conn * login_map_get(const char *login_id) {
    int idx = login_map_find_index(login_id);
    if (idx >= 0) return g_login_map[idx].conn;
    return NULL;
}

const char * login_map_get_login_id_by_fd(int fd) {
    for (int i = 0; i < LOGIN_MAP_CAPACITY; i++) {
        if (g_login_map[i].in_use && g_login_map[i].conn && g_login_map[i].conn->fd == fd) {
            return g_login_map[i].login_id;
        }
    }
    return NULL;
}