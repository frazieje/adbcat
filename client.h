#ifndef ADBCAT_CLIENT_H
#define ADBCAT_CLIENT_H

#include <event2/listener.h>
#include "adbcat.h"

typedef struct gateway_addr_t {
    struct sockaddr_in6 *gateway_addr;
    int gateway_addr_len;
    char session_key[SESSION_KEY_SIZE];
} gateway_addr_t;

int start_client(struct event_base *base, int l_port, char *g_host, int g_port, unsigned char *session_key);

#endif //ADBCAT_CLIENT_H
