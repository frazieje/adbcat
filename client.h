#ifndef ADBCAT_CLIENT_H
#define ADBCAT_CLIENT_H

#include <event2/listener.h>
#include "adbcat.h"

typedef struct gateway_connect_t {
    struct sockaddr *gateway_addr;
    socklen_t gateway_addr_len;
    char session_key[SESSION_KEY_SIZE];
} gateway_connect_t;

int start_client(
        struct event_base *base,
        int local_port,
        struct sockaddr *gateway_addr,
        socklen_t gateway_addr_len,
        unsigned char *session_key
);

#endif //ADBCAT_CLIENT_H
