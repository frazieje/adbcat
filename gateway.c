#include "gateway.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <netinet/in.h>
#include "adbcat.h"
#include "hashtable.h"
#include "utils.h"
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

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

enum gateway_connection_mode { gateway_client, gateway_server, unknown };

typedef struct gateway_connection_t {
    struct bufferevent *bev;
    char addr_str[ADDRESS_STRING_SIZE];
    unsigned char session_key[SESSION_KEY_SIZE];
    enum gateway_connection_mode type;
    gateway_message_t *current_message;
    uint64_t current_message_sent;
    struct gateway_connection_t *prev;
    struct gateway_connection_t *next;
} gateway_connection_t;

typedef struct gateway_connection_ref_t {
    gateway_connection_t *value;
} gateway_connection_ref_t;

typedef struct gateway_settings_t {
    SSL_CTX *ssl_ctx;
    int cleartext_enabled;
    int verbose_enabled;
} gateway_settings_t;

static gateway_settings_t gw_settings;

static HashTable gateway_clients = HT_INITIALIZER
static HashTable gateway_servers = HT_INITIALIZER

static void gateway_log(char *str, ...) {
    if (gw_settings.verbose_enabled) {
        va_list valist;
        va_start(valist, str);
        vfprintf(stdout, str, valist);
        va_end(valist);
    }
}

static int remove_server(gateway_connection_t *server) {
    if (server == NULL) {
        return 0;
    }
    ht_erase(&gateway_servers, server->session_key);
    return 1;
}

static int add_server(gateway_connection_t *server) {
    if (server == NULL) {
        return 0;
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
    return 1;
}

static int remove_client(gateway_connection_t *client) {
    if (client == NULL) {
        return 0;
    }
    gateway_connection_ref_t *existing_clients_ref = ht_lookup(&gateway_clients, client->session_key);
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
            return 1;
        }
    }
    return 0;
}

static int add_client(gateway_connection_t *client) {
    if (client == NULL) {
        return 0;
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
            gateway_log("adding new client to ll%s\n", client->addr_str);
            LL_ADD(client, existing_clients)
            gateway_connection_ref_t ref = { .value = existing_clients };
            ht_insert(&gateway_clients, client->session_key, &ref);
            return 1;
        }
    } else {
        gateway_log("adding new client to ht%s\n", client->addr_str);
        gateway_connection_ref_t ref = { .value = client };
        ht_insert(&gateway_clients, client->session_key, &ref);
        return 1;
    }
    return 0;
}

static void readcb(struct bufferevent *bev, void *ctx);

static void drained_writecb(struct bufferevent *bev, void *ctx);

static void eventcb(struct bufferevent *bev, short events, void *ctx);

static void close_on_finished_writecb(struct bufferevent *bev, void *ctx) {
    struct evbuffer *b = bufferevent_get_output(bev);
    gateway_connection_t *conn = ctx;
    if (evbuffer_get_length(b) == 0) {
        gateway_log("writing finished, closing client %s now\n", conn->addr_str);
        bufferevent_free(bev);
        free(conn);
    }
}

static int closeClient(gateway_connection_t *conn) {
    gateway_log("closing client %s\n", conn->addr_str);
    int result = 0;
    if (conn->type == gateway_client) {
        result = remove_client(conn);
    } else if (conn->type == gateway_server) {
        result = remove_server(conn);
    }
    bufferevent_free(conn->bev);
    evutil_closesocket(bufferevent_getfd(conn->bev));
    free(conn);
    return result;
}

static void closeClientOnFinished(gateway_connection_t *conn) {
    gateway_log("closing client %s on finished\n", conn->addr_str);
    if (conn->type == gateway_client) {
        remove_client(conn);
    } else if (conn->type == gateway_server) {
        remove_server(conn);
    }
    if (evbuffer_get_length(
            bufferevent_get_output(conn->bev)) > 0) {
        gateway_log("closing client %s on finished write\n", conn->addr_str);
        bufferevent_setcb(conn->bev,
                          NULL, close_on_finished_writecb,
                          eventcb, conn);
        bufferevent_disable(conn->bev, EV_READ);
    } else {
        gateway_log("closing client %s now\n", conn->addr_str);
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
    gateway_connection_t *conn = ctx;

    if (conn == NULL)  {
        return;
    }

    gateway_log("read bytes from %s\n", conn->addr_str);

    struct evbuffer *input = bufferevent_get_input(bev);
    struct evbuffer *output = bufferevent_get_output(bev);

    int min_length = MAGIC_BYTES_SIZE + SESSION_TYPE_SIZE;
    char data[min_length];
    int nbytes;
    size_t input_length;
    if (memcmp(conn->session_key, EMPTY_SESSION, SESSION_KEY_SIZE) == 0) {
        if (conn->type == unknown) {
            gateway_log("%s has no session type\n", conn->addr_str);
            //session is not yet set, try to read start line
            input_length = evbuffer_get_length(input);
            if (input_length < min_length) {
                gateway_log("short read from new client %s, aborting for now\n", conn->addr_str);
                return;
            }
            nbytes = evbuffer_remove(input, data, min_length); //remove maximum size of first line
            gateway_log("removed %d from buffer of length %lu\n", nbytes, input_length);
            int magicBytes = memcmp(data, MAGIC_BYTES, MAGIC_BYTES_SIZE);
            if (magicBytes != 0) {
                fprintf(stderr, "new client %s handshake failed 0x143\n", conn->addr_str);
                closeClient(conn);
                return;
            }
            if (memcmp(&data[MAGIC_BYTES_SIZE], SESSION_TYPE_CLIENT, SESSION_TYPE_SIZE) == 0) {
                gateway_log("%s indicated a client session type\n", conn->addr_str);
                conn->type = gateway_client;
            } else if (memcmp(&data[MAGIC_BYTES_SIZE], SESSION_TYPE_SERVER, SESSION_TYPE_SIZE) == 0) {
                gateway_log("%s indicated a server session type\n", conn->addr_str);
                conn->type = gateway_server;
            } else {
                fprintf(stderr, "new client %s handshake failed 0x322\n", conn->addr_str);
                closeClient(conn);
                return;
            }
        }
        if (conn->type == gateway_client) {
            input_length = evbuffer_get_length(input);
            if (input_length < SESSION_KEY_SIZE) {
                gateway_log("short read from client session %s, aborting for now\n", conn->addr_str);
                return;
            }
            evbuffer_remove(input, conn->session_key, SESSION_KEY_SIZE);
        } else if (conn->type == gateway_server) {
            gateway_log("sending session key response to new server %s\n", conn->addr_str);
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

    int new_result = 0;

    if (conn->type == gateway_client) {
        new_result = add_client(conn);
    } else if (conn->type == gateway_server) {
        new_result = add_server(conn);
    } else {
        return;
    }

    if (new_result)
        printConnections();

    char session_key_str[(SESSION_KEY_SIZE * 2) + 1];
    get_session_key_str(conn->session_key, session_key_str);
    gateway_log("%s has session key %s\n", conn->addr_str, session_key_str);

    while ((input_length = evbuffer_get_length(input)) > 0) {
        gateway_log("%lu left in buffer from %s...\n", input_length, conn->addr_str);
        gateway_connection_t *peer = NULL;
        if (conn->type == gateway_server) {
            gateway_message_t *message = conn->current_message;
            if (message == NULL) {
                gateway_log("read new server message from %s\n", conn->addr_str);
                int min_msg_length = SERVER_MSG_TYPE_SIZE + SERVER_MSG_FROM_SIZE + SERVER_FWD_LENGTH_SIZE;
                if (input_length < min_msg_length) {
                    gateway_log("not enough data to read server message from %s, aborting for now\n", conn->addr_str);
                    return;
                }
                char msg_type[SERVER_MSG_TYPE_SIZE + 1];
                evbuffer_remove(input, msg_type, SERVER_MSG_TYPE_SIZE);
                msg_type[SERVER_MSG_TYPE_SIZE] = '\0';
                if (strcmp(msg_type, SERVER_CLOSE_MSG) == 0) {
                    gateway_log("message from server %s is a close message\n", conn->addr_str);
                    uint32_t from;
                    evbuffer_remove(input, &from, SERVER_MSG_FROM_SIZE);
                    evbuffer_drain(input, SERVER_FWD_LENGTH_SIZE);
                    peer = get_client_connection(conn->session_key, from);
                    gateway_log("process close message from server %s for client %d\n", conn->addr_str, from);
                    if (peer != NULL) {
                        gateway_log("client %d has active connection %s, closing\n", from, peer->addr_str);
                        closeClientOnFinished(peer);
                    } else {
                        gateway_log("no active connection found for client %d on server %s\n", from, conn->addr_str);
                    }
                } else if (strcmp(msg_type, SERVER_FWD_MSG) == 0) {
                    gateway_message_t *new_message = malloc(sizeof(gateway_message_t));
                    memset(new_message, 0, sizeof(gateway_message_t));
                    new_message->type = gw_msg_forward;
                    evbuffer_remove(input, &new_message->from, SERVER_MSG_FROM_SIZE);
                    evbuffer_remove(input, &new_message->length, SERVER_FWD_LENGTH_SIZE);
                    gateway_log("message from server %s is a fward message for client %d, with length %lu\n", conn->addr_str, new_message->from,
                           new_message->length);
                    conn->current_message = new_message;
                    conn->current_message_sent = 0;
                } else {
                    gateway_log("message is unrecognized, error\n");
                    closeClient(conn);
                    return;
                }
                continue;
            }
            uint64_t remaining = message->length - conn->current_message_sent;
            gateway_log("message from server %s to client %d with %lu remaining...\n", conn->addr_str, message->from, remaining);
            peer = get_client_connection(conn->session_key, conn->current_message->from);
            if (peer != NULL) {
                gateway_log("client peer %s found for %s, forwarding\n", peer->addr_str, conn->addr_str);
                struct evbuffer *peer_output = bufferevent_get_output(peer->bev);
                char remaining_data[remaining];
                int msg_nbytes = evbuffer_remove(input, remaining_data, remaining);
                evbuffer_add(peer_output, remaining_data, msg_nbytes);
                conn->current_message_sent += msg_nbytes;
                gateway_log("wrote %d bytes to client %d\n", msg_nbytes, message->from);
                if (evbuffer_get_length(peer_output) >= MAX_OUTPUT_BUFFER_SIZE) {
                    gateway_log("peer %s buffer full, disable %s until drained\n", peer->addr_str, conn->addr_str);
                    bufferevent_setcb(peer->bev, readcb, drained_writecb,
                                      eventcb, peer);
                    bufferevent_setwatermark(peer->bev, EV_WRITE, MAX_OUTPUT_BUFFER_SIZE / 2,
                                             MAX_OUTPUT_BUFFER_SIZE);
                    bufferevent_disable(bev, EV_READ);
                }
            } else {
                gateway_log("peer not found for client %s", conn->addr_str);
                if (input_length <= MAX_INPUT_BUFFER_SIZE) {
                    gateway_log(", aborting for now \n");
                    return;
                }
                //for servers, we're going to just drain the buffer
                gateway_log(", draining\n");
                evbuffer_drain(input, input_length);
            }
            if (message->length == conn->current_message_sent) {
                gateway_log("message finished from %d\n", message->from);
                conn->current_message_sent = 0;
                conn->current_message = NULL;
                free(conn->current_message);
            }
        } else {
            peer = get_server_connection(conn->session_key);
            if (peer != NULL) {
                gateway_log("server peer %s found for %s, forwarding with preamble\n", peer->addr_str, conn->addr_str);
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
                gateway_log("forwarded %lu bytes from client %s to server peer %s with from %d and length %lu, forwarding with preamble\n", total_bytes_sent, conn->addr_str, peer->addr_str, bevfd, input_length);
                if (evbuffer_get_length(peer_output) >= MAX_OUTPUT_BUFFER_SIZE) {
                    gateway_log("peer %s buffer full, disable %s until drained\n", peer->addr_str, conn->addr_str);
                    bufferevent_setcb(peer->bev, readcb, drained_writecb,
                                      eventcb, peer);
                    bufferevent_setwatermark(peer->bev, EV_WRITE, MAX_OUTPUT_BUFFER_SIZE / 2,
                                             MAX_OUTPUT_BUFFER_SIZE);
                    bufferevent_disable(bev, EV_READ);
                }
            } else {
                gateway_log("peer not found for client %s\n", conn->addr_str);
                if (input_length <= MAX_INPUT_BUFFER_SIZE) {
                    gateway_log(", aborting for now \n");
                    return;
                }
                //for clients, we're going to disconnect them if their peer has gone MIA
                gateway_log(", draining and disconnecting\n");
                closeClient(conn);
                evbuffer_drain(input, input_length);
            }
        }
    }

    gateway_log("no bytes left to handle for %s\n", conn->addr_str);
}

static void eventcb(struct bufferevent *bev, short events, void *ctx) {
    if (events & BEV_EVENT_ERROR) {
        if (errno)
            perror("Error from bufferevent");
    }
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        gateway_connection_t *conn = ctx;
        if (ctx != NULL) {
            gateway_log("error callback for %s\n", conn->addr_str);
            if (bufferevent_openssl_get_ssl(bev)) {
                unsigned long openssl_error = bufferevent_get_openssl_error(bev);
                if (openssl_error) {
                    gateway_log("%s connection error: %s\n", conn->addr_str, ERR_error_string(openssl_error, NULL));
                }
            }
            if (conn->type == gateway_server) {
                gateway_log("server %s disconnected\n", conn->addr_str);
            } else if (conn->type == gateway_client) {
                gateway_log("client %s disconnected\n", conn->addr_str);
                gateway_connection_t *server_peer = get_server_connection(conn->session_key);
                if (server_peer != NULL) {
                    gateway_log("found server %s for client %s, sending close message to server\n", server_peer->addr_str, conn->addr_str);
                    uint32_t bevfd = bufferevent_getfd(conn->bev);
                    unsigned char length[SERVER_FWD_LENGTH_SIZE] = {0};
                    int server_close_size = SERVER_MSG_TYPE_SIZE + SERVER_MSG_FROM_SIZE + SERVER_FWD_LENGTH_SIZE;
                    unsigned char server_close[server_close_size];
                    memcpy(server_close, SERVER_CLOSE_MSG, SERVER_MSG_TYPE_SIZE);
                    memcpy(&server_close[SERVER_MSG_TYPE_SIZE], &bevfd, SERVER_MSG_FROM_SIZE);
                    memcpy(&server_close[SERVER_MSG_TYPE_SIZE + SERVER_MSG_FROM_SIZE], length,
                           SERVER_FWD_LENGTH_SIZE);
                    struct evbuffer *dst = bufferevent_get_output(server_peer->bev);
                    int success = evbuffer_add(dst, server_close, server_close_size);
                    if (success == 0) {
                        gateway_log("wrote %d bytes to server %s close client %s\n", server_close_size, server_peer->addr_str, conn->addr_str);
                    }
                } else {
                    gateway_log("client %s disconnected, no server found. not sending close msg\n", conn->addr_str);
                }
            }
            if (closeClient(conn)) {
                printConnections();
            }
        } else {
            bufferevent_free(bev);
        }
    }
}

static void drained_writecb(struct bufferevent *bev, void *ctx) {
    gateway_connection_t *conn = ctx;
    gateway_log("conn %s buffer drained\n", conn->addr_str);
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
                gateway_connection_t *curr_conn = node->value;
                gateway_log("re-enabling client %s for server %s\n", curr_conn->addr_str, conn->addr_str);
                bufferevent_enable(curr_conn->bev, EV_READ);
                node = next;
            }
        }
    } else {
        gateway_connection_t *peer = get_server_connection(conn->session_key);
        if (peer != NULL) {
            gateway_log("re-enabling server %s for client %s\n", peer->addr_str, conn->addr_str);
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
    struct bufferevent *bev;

    SSL_CTX *ssl_ctx = gw_settings.ssl_ctx;

    if (ssl_ctx != NULL) {
        SSL *ssl = SSL_new(ssl_ctx);

        gateway_log("Created TLS object for connection\n");

        if (ssl == NULL) {
            perror("Failed to create new TLS structure");
            return;
        }

        bev = bufferevent_openssl_socket_new(
            base, fd, ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

        if (!bev) {
            perror("Failed to create TLS-enabled bufferevent");
            return;
        }
    } else {
        bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
        if (!bev) {
            perror("Failed to create bufferevent");
            return;
        }
    }

    gateway_connection_t *conn = malloc(sizeof(gateway_connection_t));

    conn->bev = bev;
    conn->type = unknown;
    memcpy(conn->session_key, EMPTY_SESSION, SESSION_KEY_SIZE);
    address_to_str(address, socklen, conn->addr_str, ADDRESS_STRING_SIZE);
    conn->next = NULL;
    conn->prev = NULL;
    conn->current_message = NULL;
    conn->current_message_sent = 0;

    gateway_log("Got new connection from %s\n", conn->addr_str);

    bufferevent_setcb(bev, readcb, NULL, eventcb, conn);
    bufferevent_enable(bev, EV_READ | EV_WRITE);

    fflush(stdout);
}

static void accept_error_cb(struct evconnlistener *listener, void *ctx)
{
    struct event_base *base = evconnlistener_get_base(listener);
    int err = EVUTIL_SOCKET_ERROR();
    fprintf(stderr, "Got an error %d (%s) on the listener. "
                    "Shutting down.\n", err, evutil_socket_error_to_string(err));

    event_base_loopexit(base, NULL);
}

static int configure_ssl_ctx(gateway_config_t *config, SSL_CTX *ssl_ctx) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);

    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_2);
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_1);

    char cert_path[config->cert_path_len + 1];
    char key_path[config->key_path_len + 1];

    memcpy(cert_path, config->cert_path, config->cert_path_len);
    cert_path[config->cert_path_len] = '\0';
    memcpy(key_path, config->key_path, config->key_path_len);
    key_path[config->key_path_len] = '\0';

    if (config->enable_verbose) {
        char current_wd[MAX_FILE_PATH];
        getcwd(current_wd, sizeof(current_wd));
        printf("Loading cert from path: %s\n", cert_path);
        printf("Loading key from path: %s\n", key_path);
        printf("Current working directory: %s\n", current_wd);
    }

    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_path) != 1) {
        SSL_CTX_free(ssl_ctx);
        return 1;
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_path, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ssl_ctx);
        return 2;
    }
    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        SSL_CTX_free(ssl_ctx);
        return 3;
    }

    return 0;
}

int start_gateway(gateway_config_t *config) {
    printf("Running in gateway mode\n");
    struct evconnlistener *listener;
    struct sockaddr_in6 sin;
    struct event_base *base;
    SSL_CTX *ssl_ctx = NULL;

    if (!config->enable_cleartext) {
        ssl_ctx = SSL_CTX_new(TLS_server_method());
        if (!ssl_ctx) {
            fprintf(stderr, "Could not create TLS context\n");
            return 1;
        }

        int result = configure_ssl_ctx(config, ssl_ctx);
        if (result > 0) {
            fprintf(stderr, "Could not configure TLS context: ");
            switch (result) {
                case 1:
                    printf("Problem loading TLS certificate file\n");
                    break;
                case 2:
                    printf("Problem loading TLS key file\n");
                    break;
                case 3:
                    printf("Private key check failed\n");
                    break;
                default:
                    printf("Unknown error\n");
                    break;
            }
            return result;
        }
    }

    base = event_base_new();
    if (!base) {
        fprintf(stderr, "Couldn't open event base\n");
        return 1;
    }

    ht_setup(&gateway_clients,
             sizeof(unsigned char[SESSION_KEY_SIZE]),
             sizeof(gateway_connection_ref_t), 0);

    ht_setup(&gateway_servers,
             sizeof(unsigned char[SESSION_KEY_SIZE]),
             sizeof(gateway_connection_ref_t), 0);


    gw_settings.ssl_ctx = ssl_ctx;
    gw_settings.cleartext_enabled = config->enable_cleartext;
    gw_settings.verbose_enabled = config->enable_verbose;

    memset(&sin, 0, sizeof(sin));
    sin.sin6_family = AF_INET6;
    /* Listen on the given port, on :: */
    sin.sin6_port = htons(config->port);
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

    fflush(stdout);

    return event_base_dispatch(base);
}