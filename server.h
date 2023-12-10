#ifndef ADBCAT_SERVER_H
#define ADBCAT_SERVER_H

#include <event2/listener.h>
#include "hashtable.h"

static HashTable active_connections = HT_INITIALIZER

int start_server(
        struct event_base *base,
        int adb_server_port,
        struct sockaddr *gateway_addr,
        socklen_t gateway_addr_len
);

#endif //ADBCAT_SERVER_H
