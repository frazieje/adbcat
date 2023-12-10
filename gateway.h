#ifndef ADBCAT_GATEWAY_H
#define ADBCAT_GATEWAY_H

#include <event2/listener.h>
#include "adbcat.h"
#include "hashtable.h"
#include "utils.h"

enum gateway_connection_mode { gateway_client, gateway_server, unknown };

typedef struct gateway_connection_t {
    struct bufferevent *bev;
    char addr_str[ADDRESS_STRING_SIZE];
    unsigned char session_key[SESSION_KEY_SIZE];
    enum gateway_connection_mode type;
    struct gateway_connection_t *prev;
    struct gateway_connection_t *next;
//    SSL *ssl;
} gateway_connection_t;

typedef struct gateway_connection_ref_t {
    gateway_connection_t *value;
} gateway_connection_ref_t;

static HashTable gateway_clients = HT_INITIALIZER
static HashTable gateway_servers = HT_INITIALIZER

int start_gateway(struct event_base *base, int l_port);

#endif //ADBCAT_GATEWAY_H
