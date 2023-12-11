#ifndef ADBCAT_SERVER_H
#define ADBCAT_SERVER_H

#include <event2/listener.h>
#include "hashtable.h"
#include "adbcat.h"

static HashTable active_connections = HT_INITIALIZER

typedef struct adb_server_connection_t {
    struct bufferevent *bev;
} adb_server_connection_t;

static unsigned char server_session_key[SESSION_KEY_SIZE] = {0};

typedef struct gateway_message_t {
    int from;
    size_t size;
    size_t sent;
} gateway_message_t;

int start_server(
        struct event_base *base,
        int adb_server_port,
        struct sockaddr *gateway_addr,
        socklen_t gateway_addr_len
);

#endif //ADBCAT_SERVER_H
