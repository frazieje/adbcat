#ifndef ADBCAT_SERVER_H
#define ADBCAT_SERVER_H

#include <event2/listener.h>
#include "hashtable.h"
#include "adbcat.h"

static HashTable active_connections = HT_INITIALIZER

typedef struct adb_server_connection_t {
    struct bufferevent *adb_bev;
    struct bufferevent *gw_bev;
    uint32_t from;
} adb_server_connection_t;

enum gateway_message_type { gw_msg_forward, gw_msg_close };

typedef struct gateway_message_t {
    enum gateway_message_type type; //
    uint32_t from;
    uint64_t length;
} gateway_message_t;

typedef struct gateway_context_t {
    struct sockaddr *adbserver_addr;
    socklen_t adbserver_addr_len;
    unsigned char session_key[SESSION_KEY_SIZE];
    gateway_message_t *current_message;
    uint64_t current_message_sent;
} gateway_context_t;

int start_server(
        struct event_base *base,
        int adb_server_port,
        struct sockaddr *gateway_addr,
        socklen_t gateway_addr_len
);

#endif //ADBCAT_SERVER_H
