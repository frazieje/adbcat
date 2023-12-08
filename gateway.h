#ifndef ADBCAT_GATEWAY_H
#define ADBCAT_GATEWAY_H

#include <event2/listener.h>
#include "adbcat.h"
#include "hashtable.h"

enum gateway_connection_mode { gateway_client, gateway_server, unknown };

typedef struct gateway_connection_t {
    struct bufferevent *bev;
    struct sockaddr *address;
    int socklen;
    int fd;
    unsigned char session_key[SESSION_KEY_SIZE];
    enum gateway_connection_mode type;
    struct gateway_connection_t *prev;
    struct gateway_connection_t *next;
//    SSL *ssl;
} gateway_connection_t;

#define ADDRESS_STRING_SIZE (NI_MAXHOST + NI_MAXSERV + 1)

HashTable gateway_clients = HT_INITIALIZER
HashTable gateway_servers = HT_INITIALIZER

int start_gateway(struct event_base *base, int l_port);

#endif //ADBCAT_GATEWAY_H
