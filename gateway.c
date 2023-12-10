#include <gateway.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <event2/bufferevent.h>
#include <hashtable.h>
#include <event2/buffer.h>
#include <utils.h>

#define LL_ADD(item, list) { \
    item->prev = NULL; \
    item->next = list; \
    list = item; \
    if (list->next != NULL) list->next->prev = item; \
}

#define LL_REMOVE(item, list) { \
    if (item->prev != NULL) item->prev->next = item->next; \
    if (item->next != NULL) item->next->prev = item->prev; \
    if (list == item) list = item->next; \
    item->prev = item->next = NULL; \
}

static void remove_server(gateway_connection_t *server) {
    if (server == NULL) {
        return;
    }
    ht_erase(&gateway_servers, server->session_key);
}

static void add_server(gateway_connection_t *server) {
    if (server == NULL) {
        return;
    }
    gateway_connection_ref_t *existing_clients_ref = ht_lookup( &gateway_clients,server->session_key);
    gateway_connection_t *existing_clients = NULL;
    if (existing_clients_ref != NULL) {
        existing_clients = existing_clients_ref->value;
    }
    if (existing_clients != NULL) {
        server->next = existing_clients;
    }

    gateway_connection_ref_t ref = { .value = server };
    ht_insert(&gateway_servers, server->session_key, &ref);
}

static void remove_client(gateway_connection_t *client) {
    if (client == NULL) {
        return;
    }
    gateway_connection_ref_t *existing_clients_ref = ht_lookup( &gateway_clients,client->session_key);
    gateway_connection_t *existing_clients = NULL;
    if (existing_clients_ref != NULL) {
        existing_clients = existing_clients_ref->value;
    }
    if (existing_clients != NULL) {
        gateway_connection_t *curr = existing_clients;
        gateway_connection_t *dupe = NULL;
        while (curr != NULL) {
            if (curr->bev == client->bev) {
                dupe = curr;
                break;
            }
            curr = curr->next;
        }
        if (dupe != NULL) {
            LL_REMOVE(dupe, existing_clients)
            if (existing_clients != NULL) {
                gateway_connection_ref_t ref = { .value = existing_clients };
                ht_insert(&gateway_clients, existing_clients->session_key, &ref);
            } else {
                ht_erase(&gateway_clients, client->session_key);
            }
        }
    }
}

static void add_client(gateway_connection_t *client) {
    if (client == NULL) {
        return;
    }
    gateway_connection_ref_t *existing_clients_ref = ht_lookup( &gateway_clients,client->session_key);
    gateway_connection_t *existing_clients = NULL;
    if (existing_clients_ref != NULL) {
        existing_clients = existing_clients_ref->value;
    }
    if (existing_clients != NULL) {
        gateway_connection_t *curr = existing_clients;
        gateway_connection_t *dupe = NULL;
        while (curr != NULL) {
            if (curr->bev == client->bev) {
                dupe = curr;
                break;
            }
            curr = curr->next;
        }
        if (dupe == NULL) {
            printf("adding new client to ll%s\n", client->addr_str);
            LL_ADD(client, existing_clients)
        }
    } else {
        printf("adding new client to ht%s\n", client->addr_str);
        gateway_connection_ref_t ref = { .value = client };
        ht_insert(&gateway_clients, client->session_key, &ref);
    }
}

static void closeClient(gateway_connection_t *conn) {
    printf("closing client %s\n", conn->addr_str);
    if (conn->type == gateway_client) {
        remove_client(conn);
    } else if (conn->type == gateway_server) {
        remove_server(conn);
    }
    bufferevent_free(conn->bev);
    evutil_closesocket(bufferevent_getfd(conn->bev));
    free(conn);
}

static gateway_connection_t *get_peer_connection(gateway_connection_t *conn) {
    if (memcmp(conn->session_key, EMPTY_SESSION, SESSION_KEY_SIZE) == 0) {
        return NULL;
    }
    gateway_connection_ref_t *result = NULL;
    switch (conn->type) {
        case gateway_client:
            result = (gateway_connection_ref_t *)ht_lookup(&gateway_servers, conn->session_key);
            break;
        case gateway_server:
            result = (gateway_connection_ref_t *)ht_lookup(&gateway_clients, conn->session_key);
            break;
        case unknown:
            result = NULL;
    }
    if (result != NULL) {
        return result->value;
    } else {
        return NULL;
    }
}

static void printConnection(gateway_connection_t *conn) {
    char session_key_str[SESSION_KEY_SIZE * 2 + 1];
    get_session_key_str(conn->session_key, session_key_str);
    if (conn->type == gateway_server) {
        printf("%s server %s\n", session_key_str, conn->addr_str);
    } else {
        printf("%s client %s\n", session_key_str, conn->addr_str);
    }
}

static void printConnections() {
    int count = 0;
    printf("\nACTIVE CONNECTIONS\n");
    if (gateway_servers.size == 0 && gateway_clients.size == 0) {
        printf("--no active connections\n");
        return;
    }
    size_t chain;
    HTNode* node;
    HTNode* next;
    for (chain = 0; chain < gateway_servers.capacity; ++chain) {
        for (node = gateway_servers.nodes[chain]; node;) {
            next = node->next;
            gateway_connection_t *curr_server = ((gateway_connection_ref_t *)node->value)->value;
            count++;
            printConnection(curr_server);
            node = next;
        }
    }
    for (chain = 0; chain < gateway_clients.capacity; ++chain) {
        for (node = gateway_clients.nodes[chain]; node;) {
            next = node->next;
            gateway_connection_t *curr_client = ((gateway_connection_ref_t *)node->value)->value;
            while (curr_client != NULL) {
                count++;
                printConnection(curr_client);
                curr_client = curr_client->next;
            }
            node = next;
        }
    }
    printf("Total: %d\n\n", count);
}

static void drained_writecb(struct bufferevent *bev, void *ctx);

static void eventcb(struct bufferevent *bev, short events, void *ctx);

static void readcb(struct bufferevent *bev, void *ctx) {
    gateway_connection_t *conn = (gateway_connection_t *)ctx;

    if (conn == NULL)  {
        return;
    }

    printf("read bytes from %s\n", conn->addr_str);

    struct evbuffer *input = bufferevent_get_input(bev);
    struct evbuffer *output = bufferevent_get_output(bev);

    char data[4096];
    int nbytes;
    size_t input_length;
    printf("1\n");
    if (memcmp(conn->session_key, EMPTY_SESSION, SESSION_KEY_SIZE) == 0) {
        printf("%s has no session key\n", conn->addr_str);
        if (conn->type == unknown) {
            printf("%s has no session type\n", conn->addr_str);
            //session is not yet set, try to read start line
            int min_length = MAGIC_BYTES_SIZE + SESSION_TYPE_SIZE;
            input_length = evbuffer_get_length(input);
            if (input_length < min_length) {
                printf("short read from new client %s, aborting for now\n", conn->addr_str);
                return;
            }
            nbytes = evbuffer_remove(input, data, min_length); //remove maximum size of first line
            printf("removed %d from buffer of length %lu\n", nbytes, input_length);
            int magicBytes = memcmp(data, MAGIC_BYTES, MAGIC_BYTES_SIZE);
            if (magicBytes != 0) {
                printf("new client %s handshake failed 0x143\n", conn->addr_str);
                closeClient(conn);
                return;
            }
            if (memcmp(&data[MAGIC_BYTES_SIZE], SESSION_TYPE_CLIENT, SESSION_TYPE_SIZE) == 0) {
                printf("%s indicated a client session type\n", conn->addr_str);
                conn->type = gateway_client;
            } else if (memcmp(&data[MAGIC_BYTES_SIZE], SESSION_TYPE_SERVER, SESSION_TYPE_SIZE) == 0) {
                printf("%s indicated a server session type\n", conn->addr_str);
                conn->type = gateway_server;
            } else {
                printf("new client %s handshake failed 0x322\n", conn->addr_str);
                closeClient(conn);
                return;
            }
        }
        if (conn->type == gateway_client) {
            input_length = evbuffer_get_length(input);
            if (input_length < SESSION_KEY_SIZE) {
                printf("short read from client session %s, aborting for now\n", conn->addr_str);
                return;
            }
            evbuffer_remove(input, conn->session_key, SESSION_KEY_SIZE);
        } else if (conn->type == gateway_server) {
            printf("sending session key response to new server %s\n", conn->addr_str);
            gen_session_key(conn->session_key, SESSION_KEY_SIZE);
            unsigned char response[3 + SESSION_KEY_SIZE];
            memcpy(response, "OK ", 3);
            memcpy(&response[3], conn->session_key, SESSION_KEY_SIZE);
            evbuffer_add(output, response, 3 + SESSION_KEY_SIZE);
        } else {
            memcpy(conn->session_key, EMPTY_SESSION, SESSION_KEY_SIZE);
            return;
        }
    }

    if (conn->type == gateway_client) {
        add_client(conn);
    } else if (conn->type == gateway_server) {
        printf("inserting new server %s\n", conn->addr_str);
        add_server(conn);
    } else {
        return;
    }

    printf("2\n");
    char session_key_str[(SESSION_KEY_SIZE * 2) + 1];
    get_session_key_str(conn->session_key, session_key_str);
    printf("%s has session key %s\n", conn->addr_str, session_key_str);
    input_length = evbuffer_get_length(input);
    printf("read %lu from %s ...\n", input_length, conn->addr_str);
    if (input_length > 0) {
        printf("3\n");
        gateway_connection_t *peer = get_peer_connection(conn);
        printf("4\n");
        if (peer != NULL) {
            printf("peer %s found for %s, forwarding\n", peer->addr_str, conn->addr_str);
            struct evbuffer *peer_output = bufferevent_get_output(peer->bev);
            // TODO: prepend all client sends
//            if (conn->server == 0) {
//                evbuffer_add(peer_output, )
//            }
            evbuffer_add_buffer(peer_output, input);
            if (evbuffer_get_length(peer_output) >= MAX_OUTPUT_BUFFER_SIZE) {
                printf("peer %s buffer full, disable %s until drained\n", peer->addr_str, conn->addr_str);
                bufferevent_setcb(peer->bev, readcb, drained_writecb,
                                  eventcb, peer);
                bufferevent_setwatermark(peer->bev, EV_WRITE, MAX_OUTPUT_BUFFER_SIZE/2,
                                         MAX_OUTPUT_BUFFER_SIZE);
                bufferevent_disable(bev, EV_READ);
            }
        } else {
            printf("peer not found for client %s", conn->addr_str);
            if (input_length <= MAX_INPUT_BUFFER_SIZE) {
                printf(", aborting for now \n");
                return;
            }
            if (conn->type == gateway_client || conn->type == unknown) {
                //for clients (and unknowns), we're going to disconnect them if their peer has gone MIA
                printf(", draining and disconnecting\n");
                closeClient(conn);
            } else {
                //for servers, we're going to just drain the buffer
                printf(", draining\n");
            }
            evbuffer_drain(input, input_length);
        }
    } else {
        printf("no bytes to handle for %s\n", conn->addr_str);
    }
}

static void eventcb(struct bufferevent *bev, short events, void *ctx) {
    if (events & BEV_EVENT_ERROR)
        perror("Error from bufferevent");
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        gateway_connection_t *conn = (gateway_connection_t *) ctx;
        if (ctx != NULL) {
            printf("error callback for %s\n", conn->addr_str);
            if (conn->type == server) {
                printf("server ");
            } else if (conn->type == client) {
                printf("client ");
            } else {
                printf("");
            }
            printf("%s disconnected\n", conn->addr_str);
            closeClient(conn);
            printConnections();
        } else {
            bufferevent_free(bev);
        }
    }
}

static void drained_writecb(struct bufferevent *bev, void *ctx) {
    gateway_connection_t *conn = (gateway_connection_t *)ctx;
    printf("conn %s buffer drained\n", conn->addr_str);
    /* this conn was choking the other side until output buffer drained.
     * Now it seems drained. */
    bufferevent_setcb(bev, readcb, NULL, eventcb, ctx);
    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);

    gateway_connection_t *peer = get_peer_connection(conn);
    if (peer != NULL) {
        printf("re-enabling peer %s for %s\n", peer->addr_str, conn->addr_str);
        bufferevent_enable(peer->bev, EV_READ);
    }
}

static void accept_conn_cb(
        struct evconnlistener *listener,
        evutil_socket_t fd,
        struct sockaddr *address,
        int socklen,
        void *ctx
) {
    struct event_base *base = evconnlistener_get_base(listener);
    struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);

    gateway_connection_t *conn = malloc(sizeof(gateway_connection_t));
    conn->bev = bev;
    conn->type = unknown;
    memcpy(conn->session_key, EMPTY_SESSION, SESSION_KEY_SIZE);
    address_to_str(address, socklen, conn->addr_str, ADDRESS_STRING_SIZE);
    conn->next = NULL;
    conn->prev = NULL;
    printf("Got new connection from %s\n", conn->addr_str);
    bufferevent_setcb(bev, readcb, NULL, eventcb, conn);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
}

static void accept_error_cb(struct evconnlistener *listener, void *ctx)
{
    struct event_base *base = evconnlistener_get_base(listener);
    int err = EVUTIL_SOCKET_ERROR();
    fprintf(stderr, "Got an error %d (%s) on the listener. "
                    "Shutting down.\n", err, evutil_socket_error_to_string(err));

    event_base_loopexit(base, NULL);
}

int start_gateway(struct event_base *base, int l_port) {

    struct evconnlistener *listener;
    struct sockaddr_in6 sin;

    ht_setup(&gateway_clients,
             sizeof(unsigned char[SESSION_KEY_SIZE]),
             sizeof(gateway_connection_ref_t), 0);

    ht_setup(&gateway_servers,
             sizeof(unsigned char[SESSION_KEY_SIZE]),
             sizeof(gateway_connection_ref_t), 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin6_family = AF_INET6;
    /* Listen on the given port, on :: */
    sin.sin6_port = htons(l_port);
    listener = evconnlistener_new_bind(base, accept_conn_cb, NULL,
                                       LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 8192,
                                       (struct sockaddr *) &sin, sizeof(sin));
    if (!listener) {
        perror("Couldn't create listener");
        return 1;
    }

    char addr_str[ADDRESS_STRING_SIZE];
    address_to_str((struct sockaddr *)&sin, sizeof(sin), addr_str, ADDRESS_STRING_SIZE);

    printf("Listening on %s\n", addr_str);
    evconnlistener_set_error_cb(listener, accept_error_cb);

    return event_base_dispatch(base);
}