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

static void add_server() {

}



static void remove_client(gateway_connection_t *client) {
    if (client == NULL) {
        return;
    }
    gateway_connection_t *existing_clients = HT_LOOKUP_AS(gateway_connection_t *, &gateway_clients,
                                                          client->session_key);
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
            LL_ADD(client, existing_clients)
        }
    }
}

static void add_client(gateway_connection_t *client) {
    if (client == NULL) {
        return;
    }
    gateway_connection_t *existing_clients = HT_LOOKUP_AS(gateway_connection_t *, &gateway_clients,
                                                          client->session_key);
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
            LL_ADD(client, existing_clients)
        }
    } else {
        ht_insert(&gateway_clients, client->session_key, &client);
    }
}

static void closeClient(gateway_connection_t *conn) {
    char addr_str[ADDRESS_STRING_SIZE];
    address_to_str(conn->address, conn->socklen, addr_str, ADDRESS_STRING_SIZE);
    printf("closing client %s\n", addr_str);
    if (conn->type == gateway_client) {
        gateway_connection_t *server = HT_LOOKUP_AS(gateway_connection_t *, &connections, conn->session_key);
        if (server != NULL) {
            remove_client_from_server(conn, server);
        }
    } else if (conn->type == gateway_server) {
        ht_erase(&connections, conn->session_key);
    }
    evutil_closesocket(conn->fd);
    free(conn);
}

static gateway_connection_t *get_peer_connection(gateway_connection_t *conn) {
    if (memcmp(conn->session_key, EMPTY_SESSION, SESSION_KEY_SIZE) == 0) {
        return NULL;
    }
    switch (conn->type) {
        case gateway_client:
            return HT_LOOKUP_AS(gateway_connection_t *, &connections, conn->session_key);
        case gateway_server:
            return conn->next;
        case unknown:
            return NULL;
    }
}

void printConnections() {
    gateway_connection_t *curr = connections;
    int count = 0;
    printf("\nACTIVE CONNECTIONS\n");
    if (curr == NULL) {
        printf("--no active connections\n");
        return;
    }
    while (curr != NULL) {
        char session_key_str[SESSION_KEY_SIZE * 2 + 1];
        get_session_key_str(curr->session_key, session_key_str);
        if (curr->server > 0) {
            printf("%s server %s:%s\n", session_key_str, curr->host, curr->port);
        } else {
            printf("%s client %s:%s\n", session_key_str, curr->host, curr->port);
        }
        curr = curr->next;
        count++;
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

    char addr_str[ADDRESS_STRING_SIZE];
    address_to_str(conn->address, conn->socklen, addr_str, ADDRESS_STRING_SIZE);

    printf("read bytes from %s\n", addr_str);

    struct evbuffer *input = bufferevent_get_input(bev);
    struct evbuffer *output = bufferevent_get_output(bev);

    char data[4096];
    int nbytes;
    size_t input_length;
    printf("1\n");
    if (memcmp(conn->session_key, EMPTY_SESSION, SESSION_KEY_SIZE) == 0) {
        printf("%s has no session key\n", addr_str);
        if (conn->type == unknown) {
            printf("%s has no session type\n", addr_str);
            //session is not yet set, try to read start line
            int min_length = MAGIC_BYTES_SIZE + SESSION_TYPE_SIZE;
            input_length = evbuffer_get_length(input);
            if (input_length < min_length) {
                printf("short read from new client %s, aborting for now\n", addr_str);
                return;
            }
            nbytes = evbuffer_remove(input, data, min_length); //remove maximum size of first line
            printf("removed %d from buffer of length %lu\n", nbytes, input_length);
            int magicBytes = memcmp(data, MAGIC_BYTES, MAGIC_BYTES_SIZE);
            if (magicBytes != 0) {
                printf("new client %s handshake failed 0x143\n", addr_str);
                closeClient(conn);
                return;
            }
            if (memcmp(&data[MAGIC_BYTES_SIZE], SESSION_TYPE_CLIENT, SESSION_TYPE_SIZE) == 0) {
                printf("%s indicated a client session type\n", addr_str);
                conn->type = gateway_client;
            } else if (memcmp(&data[MAGIC_BYTES_SIZE], SESSION_TYPE_SERVER, SESSION_TYPE_SIZE) == 0) {
                printf("%s indicated a server session type\n", addr_str);
                conn->type = gateway_server;
            } else {
                printf("new client %s handshake failed 0x322\n", addr_str);
                closeClient(conn);
                return;
            }
        }
        if (conn->type == gateway_client) {
            input_length = evbuffer_get_length(input);
            if (input_length < SESSION_KEY_SIZE) {
                printf("short read from client session %s, aborting for now\n", addr_str);
                return;
            }
            evbuffer_remove(input, conn->session_key, SESSION_KEY_SIZE);
        } else if (conn->type == gateway_server) {
            printf("sending session key response to new server %s\n", addr_str);
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

        gateway_connection_t *existing_clients = HT_LOOKUP_AS(gateway_connection_t *, &gateway_clients,
                                                    conn->session_key);


        if (server != NULL) {
            char server_addr_str[ADDRESS_STRING_SIZE];
            address_to_str(server->address, server->socklen, server_addr_str, ADDRESS_STRING_SIZE);
            printf("found server %s in table for %s", server_addr_str, addr_str);
            add_client_to_server(conn, server);
        } else {
            printf("new client %s no server found\n", addr_str);
        }
    } else if (conn->type == gateway_server) {
        printf("inserting new server %s", addr_str);
        ht_insert(&connections, conn->session_key, &conn);
    } else {
        return;
    }

    printf("2\n");
    char session_key_str[(SESSION_KEY_SIZE * 2) + 1];
    get_session_key_str(conn->session_key, session_key_str);
    printf("%s has session key %s\n", addr_str, session_key_str);
    input_length = evbuffer_get_length(input);
    printf("read %lu from %s ...\n", input_length, addr_str);
    if (input_length > 0) {
        printf("3\n");
        gateway_connection_t *peer = get_peer_connection(conn);
        printf("4\n");
        if (peer != NULL) {
            char peer_addr_str[ADDRESS_STRING_SIZE];
            address_to_str(peer->address, peer->socklen, peer_addr_str, ADDRESS_STRING_SIZE);
            printf("peer %s found for %s, forwarding\n", peer_addr_str, addr_str);
            struct evbuffer *peer_output = bufferevent_get_output(peer->bev);
            // TODO: prepend all client sends
//            if (conn->server == 0) {
//                evbuffer_add(peer_output, )
//            }
            evbuffer_add_buffer(peer_output, input);
            if (evbuffer_get_length(peer_output) >= MAX_OUTPUT_BUFFER_SIZE) {
                printf("peer %s buffer full, disable %s until drained\n", peer_addr_str, addr_str);
                bufferevent_setcb(peer->bev, readcb, drained_writecb,
                                  eventcb, peer);
                bufferevent_setwatermark(peer->bev, EV_WRITE, MAX_OUTPUT_BUFFER_SIZE/2,
                                         MAX_OUTPUT_BUFFER_SIZE);
                bufferevent_disable(bev, EV_READ);
            }
        } else {
            printf("peer not found for client %s", addr_str);
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
        printf("no bytes to handle for %s\n", addr_str);
    }
}

static void eventcb(struct bufferevent *bev, short events, void *ctx) {
    if (events & BEV_EVENT_ERROR)
        perror("Error from bufferevent");
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        gateway_connection_t *conn = (gateway_connection_t *) ctx;
        if (ctx != NULL) {
            char addr_str[ADDRESS_STRING_SIZE];
            address_to_str(conn->address, conn->socklen, addr_str, ADDRESS_STRING_SIZE);
            printf("error callback for %s\n", addr_str);
            if (conn->type == server) {
                printf("server ");
            } else if (conn->type == client) {
                printf("client ");
            } else {
                printf("");
            }
            printf("%s disconnected\n", addr_str);
            closeClient(conn);
            printConnections();
        }
        bufferevent_free(bev);
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
    conn->address = address;
    conn->socklen = socklen;
    conn->fd = fd;
    conn->next = NULL;
    conn->prev = NULL;
    char addr_str[ADDRESS_STRING_SIZE];
    address_to_str(conn->address, conn->socklen, addr_str, ADDRESS_STRING_SIZE);
    printf("Got new connection from %s\n", addr_str);
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
             sizeof(gateway_connection_t *), 0);

    ht_setup(&gateway_servers,
             sizeof(unsigned char[SESSION_KEY_SIZE]),
             sizeof(gateway_connection_t *), 0);

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