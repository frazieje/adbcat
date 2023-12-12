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

static void readcb(struct bufferevent *bev, void *ctx);

static void drained_writecb(struct bufferevent *bev, void *ctx);

static void eventcb(struct bufferevent *bev, short events, void *ctx);

static void close_on_finished_writecb(struct bufferevent *bev, void *ctx) {
    struct evbuffer *b = bufferevent_get_output(bev);
    gateway_connection_t *conn = (gateway_connection_t *)ctx;
    if (evbuffer_get_length(b) == 0) {
        printf("writing finished, closing client %s now\n", conn->addr_str);
        bufferevent_free(bev);
        free(conn);
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

static void closeClientOnFinished(gateway_connection_t *conn) {
    printf("closing client %s on finished\n", conn->addr_str);
    if (conn->type == gateway_client) {
        remove_client(conn);
    } else if (conn->type == gateway_server) {
        remove_server(conn);
    }
    if (evbuffer_get_length(
            bufferevent_get_output(conn->bev)) > 0) {
        printf("closing client %s on finished write\n", conn->addr_str);
        bufferevent_setcb(conn->bev,
                          NULL, close_on_finished_writecb,
                          eventcb, conn);
        bufferevent_disable(conn->bev, EV_READ);
    } else {
        printf("closing client %s now\n", conn->addr_str);
        bufferevent_free(conn->bev);
        free(conn);
    }
}

static gateway_connection_t *get_server_connection(unsigned char *session_key) {
    if (memcmp(session_key, EMPTY_SESSION, SESSION_KEY_SIZE) == 0) {
        return NULL;
    }
    gateway_connection_ref_t *result = (gateway_connection_ref_t *)ht_lookup(&gateway_servers, session_key);
    if (result != NULL) {
        return result->value;
    } else {
        return NULL;
    }
}

static gateway_connection_t *get_client_connection(unsigned char *session_key, uint32_t from) {
    if (memcmp(session_key, EMPTY_SESSION, SESSION_KEY_SIZE) == 0) {
        return NULL;
    }
    gateway_connection_ref_t *existing_clients_ref = ht_lookup( &gateway_clients,session_key);
    gateway_connection_t *existing_clients = NULL;
    if (existing_clients_ref != NULL) {
        existing_clients = existing_clients_ref->value;
    }
    if (existing_clients != NULL) {
        gateway_connection_t *curr = existing_clients;
        gateway_connection_t *dupe = NULL;
        while (curr != NULL) {
            if (from == bufferevent_getfd(curr->bev)) {
                return curr;
            }
            curr = curr->next;
        }
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

static void readcb(struct bufferevent *bev, void *ctx) {
    gateway_connection_t *conn = (gateway_connection_t *)ctx;

    if (conn == NULL)  {
        return;
    }

    printf("read bytes from %s\n", conn->addr_str);

    struct evbuffer *input = bufferevent_get_input(bev);
    struct evbuffer *output = bufferevent_get_output(bev);

    int min_length = MAGIC_BYTES_SIZE + SESSION_TYPE_SIZE;
    char data[min_length];
    int nbytes;
    size_t input_length;
    printf("1\n");
    if (memcmp(conn->session_key, EMPTY_SESSION, SESSION_KEY_SIZE) == 0) {
        printf("%s has no session key\n", conn->addr_str);
        if (conn->type == unknown) {
            printf("%s has no session type\n", conn->addr_str);
            //session is not yet set, try to read start line
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
            unsigned char response[SESSION_OK_RESPONSE_SIZE + SESSION_KEY_SIZE];
            memcpy(response, SESSION_OK_RESPONSE, SESSION_OK_RESPONSE_SIZE);
            memcpy(&response[SESSION_OK_RESPONSE_SIZE], conn->session_key, SESSION_KEY_SIZE);
            evbuffer_add(output, response, SESSION_OK_RESPONSE_SIZE + SESSION_KEY_SIZE);
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

    while ((input_length = evbuffer_get_length(input)) > 0) {
        printf("%lu left in buffer from %s...\n", input_length, conn->addr_str);
        gateway_connection_t *peer = NULL;
        if (conn->type == gateway_server) {
            printf("3 server\n");
            gateway_message_t *message = conn->current_message;
            if (message == NULL) {
                printf("read new server message from %s\n", conn->addr_str);
                int min_msg_length = SERVER_MSG_TYPE_SIZE + SERVER_MSG_FROM_SIZE + SERVER_FWD_LENGTH_SIZE;
                if (input_length < min_msg_length) {
                    printf("not enough data to read server message from %s, aborting for now\n", conn->addr_str);
                    return;
                }
                char msg_type[SERVER_MSG_TYPE_SIZE + 1];
                evbuffer_remove(input, msg_type, SERVER_MSG_TYPE_SIZE);
                msg_type[SERVER_MSG_TYPE_SIZE] = '\0';
                if (strcmp(msg_type, SERVER_CLOSE_MSG) == 0) {
                    printf("message from server %s is a close message\n", conn->addr_str);
                    uint32_t from;
                    evbuffer_remove(input, &from, SERVER_MSG_FROM_SIZE);
                    peer = get_client_connection(conn->session_key, from);
                    printf("process close message from server %s for client %d\n", conn->addr_str, from);
                    if (peer != NULL) {
                        printf("client %d has active connection %s, closing\n", from, peer->addr_str);
                        closeClientOnFinished(peer);
                    } else {
                        printf("no active connection found for client %d on server %s\n", from, conn->addr_str);
                    }
                } else if (strcmp(msg_type, SERVER_FWD_MSG) == 0) {
                    gateway_message_t *new_message = malloc(sizeof(gateway_message_t));
                    memset(new_message, 0, sizeof(gateway_message_t));
                    new_message->type = gw_msg_forward;
                    evbuffer_remove(input, &new_message->from, SERVER_MSG_FROM_SIZE);
                    evbuffer_remove(input, &new_message->length, SERVER_FWD_LENGTH_SIZE);
                    printf("message from server %s is a fward message for client %d, with length %lu\n", conn->addr_str, new_message->from,
                           new_message->length);
                    conn->current_message = new_message;
                    conn->current_message_sent = 0;
                } else {
                    printf("message is unrecognized, error\n");
                    closeClient(conn);
                    return;
                }
                continue;
            }
            uint64_t remaining = message->length - conn->current_message_sent;
            printf("message from client %d with %lu remaining...\n", message->from, remaining);
            peer = get_client_connection(conn->session_key, conn->current_message->from);
            if (peer != NULL) {
                struct evbuffer *peer_output = bufferevent_get_output(peer->bev);
                char remaining_data[remaining];
                int msg_nbytes = evbuffer_remove(input, remaining_data, remaining);
                evbuffer_add(peer_output, remaining_data, msg_nbytes);
                conn->current_message_sent += msg_nbytes;
                printf("wrote %d bytes to server %d\n", msg_nbytes, message->from);
                if (evbuffer_get_length(peer_output) >= MAX_OUTPUT_BUFFER_SIZE) {
                    printf("peer %s buffer full, disable %s until drained\n", peer->addr_str, conn->addr_str);
                    bufferevent_setcb(peer->bev, readcb, drained_writecb,
                                      eventcb, peer);
                    bufferevent_setwatermark(peer->bev, EV_WRITE, MAX_OUTPUT_BUFFER_SIZE / 2,
                                             MAX_OUTPUT_BUFFER_SIZE);
                    bufferevent_disable(bev, EV_READ);
                }
            } else {
                printf("peer not found for client %s\n", conn->addr_str);
                if (input_length <= MAX_INPUT_BUFFER_SIZE) {
                    printf(", aborting for now \n");
                    return;
                }
                //for servers, we're going to just drain the buffer
                printf(", draining\n");
                evbuffer_drain(input, input_length);
            }
            if (message->length == conn->current_message_sent) {
                printf("message finished from %d\n", message->from);
                conn->current_message_sent = 0;
                conn->current_message = NULL;
                free(conn->current_message);
            }
        } else {
            peer = get_server_connection(conn->session_key);
            printf("4 client\n");
            if (peer != NULL) {
                printf("server peer %s found for %s, forwarding with preamble\n", peer->addr_str, conn->addr_str);
                struct evbuffer *peer_output = bufferevent_get_output(peer->bev);
                uint32_t bevfd = bufferevent_getfd(conn->bev);
                int server_fwd_preamble_size = SERVER_MSG_TYPE_SIZE + SERVER_MSG_FROM_SIZE + SERVER_FWD_LENGTH_SIZE;
                unsigned char preamble[server_fwd_preamble_size];
                memcpy(preamble, SERVER_FWD_MSG, SERVER_MSG_TYPE_SIZE);
                memcpy(&preamble[SERVER_MSG_TYPE_SIZE], &bevfd, SERVER_MSG_FROM_SIZE);
                memcpy(&preamble[SERVER_MSG_TYPE_SIZE + SERVER_MSG_FROM_SIZE], &input_length,
                       SERVER_FWD_LENGTH_SIZE);
                evbuffer_add(peer_output, preamble, server_fwd_preamble_size);
                evbuffer_add_buffer(peer_output, input);
                size_t total_bytes_sent = server_fwd_preamble_size + input_length;
                printf("forwarded %lu bytes from client %s to server peer %s with from %d, forwarding with preamble\n", total_bytes_sent, peer->addr_str, conn->addr_str, bevfd);
                if (evbuffer_get_length(peer_output) >= MAX_OUTPUT_BUFFER_SIZE) {
                    printf("peer %s buffer full, disable %s until drained\n", peer->addr_str, conn->addr_str);
                    bufferevent_setcb(peer->bev, readcb, drained_writecb,
                                      eventcb, peer);
                    bufferevent_setwatermark(peer->bev, EV_WRITE, MAX_OUTPUT_BUFFER_SIZE / 2,
                                             MAX_OUTPUT_BUFFER_SIZE);
                    bufferevent_disable(bev, EV_READ);
                }
            } else {
                printf("peer not found for client %s\n", conn->addr_str);
                if (input_length <= MAX_INPUT_BUFFER_SIZE) {
                    printf(", aborting for now \n");
                    return;
                }
                //for clients, we're going to disconnect them if their peer has gone MIA
                printf(", draining and disconnecting\n");
                closeClient(conn);
                evbuffer_drain(input, input_length);
            }
        }
    }

    printf("no bytes left to handle for %s\n", conn->addr_str);
}

static void eventcb(struct bufferevent *bev, short events, void *ctx) {
    if (events & BEV_EVENT_ERROR)
        perror("Error from bufferevent");
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        gateway_connection_t *conn = (gateway_connection_t *) ctx;
        if (ctx != NULL) {
            printf("error callback for %s\n", conn->addr_str);
            if (conn->type == gateway_server) {
                printf("server ");
            } else if (conn->type == gateway_client) {
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

    if (conn->type == gateway_server) {
        size_t chain;
        HTNode* node;
        HTNode* next;
        for (chain = 0; chain < gateway_clients.capacity; ++chain) {
            for (node = gateway_clients.nodes[chain]; node;) {
                next = node->next;
                struct gateway_connection_t *curr_conn = (gateway_connection_t *)node->value;
                printf("re-enabling client %s for server %s\n", curr_conn->addr_str, conn->addr_str);
                bufferevent_enable(curr_conn->bev, EV_READ);
                node = next;
            }
        }
    } else {
        gateway_connection_t *peer = get_server_connection(conn->session_key);
        if (peer != NULL) {
            printf("re-enabling server %s for client %s\n", peer->addr_str, conn->addr_str);
            bufferevent_enable(peer->bev, EV_READ);
        }
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
    conn->current_message = NULL;
    conn->current_message_sent = 0;
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

int start_gateway(struct event_base *base, int local_port) {
    printf("Running in gateway mode\n");
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
    sin.sin6_port = htons(local_port);
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