#ifndef LOGIN_MAP_H
#define LOGIN_MAP_H

#include "conn.h"

void login_map_set(const char *login_id, Conn *c);
void login_map_remove_for_conn(Conn *c);
Conn * login_map_get(const char *login_id);
const char * login_map_get_login_id_by_fd(int fd);

#endif // LOGIN_MAP_H

