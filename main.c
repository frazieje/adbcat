#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <adbcat.h>
#include <utils.h>
#include <unistd.h>
#include <gateway.h>
#include <client.h>
#include <server.h>

//#define LL_ADD(item, list) { \
//    item->prev = NULL; \
//    item->next = list; \
//    list = item; \
//    if (list->next != NULL) list->next->prev = item; \
//}
//
//#define LL_REMOVE(item, list) { \
//    if (item->prev != NULL) item->prev->next = item->next; \
//    if (item->next != NULL) item->next->prev = item->prev; \
//    if (list == item) list = item->next; \
//    item->prev = item->next = NULL; \
//}

//typedef struct client_connection_t {
//    /* The actual connection, encapsulated in a bufferevent. */
//    struct bufferevent *bev;
//    evutil_socket_t fd;
//    char host[NI_MAXHOST];
//    char port[NI_MAXSERV];
//    struct client_connection_t *prev;
//    struct client_connection_t *next;
//    unsigned char session_key[SESSION_KEY_SIZE];
//    int server;
//    /* Optional openssl context */
////    SSL *ssl;
//} client_connection_t;
//
//client_connection_t *connections;
//
//client_connection_t * get_connection_by_bev(struct bufferevent *bev) {
//    client_connection_t *curr = connections;
//    while (curr != NULL) {
//        if (curr->bev == bev) {
//            return curr;
//        } else {
//            curr = curr->next;
//        }
//    }
//    return NULL;
//}

//void closeClient(client_connection_t *conn) {
//    printf("closing client %s:%s\n", conn->host, conn->port);
//    client_connection_t *lconn = get_connection_by_bev(conn->bev);
//    if (lconn != NULL) {
//        printf("found client in ll, removing\n");
//        LL_REMOVE(lconn, connections)
//    }
//    evutil_closesocket(conn->fd);
//    free(conn);
//}
//
//client_connection_t * get_peer_connection(client_connection_t *conn) {
//    client_connection_t *curr = connections;
//    while (curr != NULL) {
//        if (curr->bev != conn->bev) {
//            if (memcmp(curr->session_key, conn->session_key, SESSION_KEY_SIZE) == 0) {
//                return curr;
//            }
//        }
//        curr = curr->next;
//    }
//    return NULL;
//}
//
//int countConnections(client_connection_t *list) {
//    int count = 0;
//    client_connection_t *curr = list;
//    while (curr != NULL) {
//        count++;
//        curr = curr->next;
//    }
//    return count;
//}
//
//void get_session_key_str(unsigned char *session_key, char *target) {
//    for (int i = 0; i < SESSION_KEY_SIZE; i++) {
//        sprintf(&target[i*2], "%02x", (unsigned int)session_key[i]);
//    }
//    target[SESSION_KEY_SIZE * 2] = '\0';
//}
//
//void printConnections() {
//    client_connection_t *curr = connections;
//    int count = 0;
//    printf("\nACTIVE CONNECTIONS\n");
//    if (curr == NULL) {
//        printf("--no active connections\n");
//        return;
//    }
//    while (curr != NULL) {
//        char session_key_str[SESSION_KEY_SIZE * 2 + 1];
//        get_session_key_str(curr->session_key, session_key_str);
//        if (curr->server > 0) {
//            printf("%s server %s:%s\n", session_key_str, curr->host, curr->port);
//        } else {
//            printf("%s client %s:%s\n", session_key_str, curr->host, curr->port);
//        }
//        curr = curr->next;
//        count++;
//    }
//    printf("Total: %d\n\n", count);
//}
//
//static void drained_writecb(struct bufferevent *bev, void *ctx);
//static void eventcb(struct bufferevent *bev, short events, void *ctx);
//
//static void readcb(struct bufferevent *bev, void *ctx)
//{
//    client_connection_t *conn = (client_connection_t *)ctx;
//
//    if (conn == NULL)  {
//        return;
//    }
//
//    printf("read bytes from %s:%s\n", conn->host, conn->port);
//
//    struct evbuffer *input = bufferevent_get_input(bev);
//    struct evbuffer *output = bufferevent_get_output(bev);
//
//    char data[4096];
//    int nbytes;
//    size_t input_length;
//    printf("1\n");
//    if (memcmp(conn->session_key, EMPTY_SESSION, SESSION_KEY_SIZE) == 0) {
//        printf("%s:%s has no session key\n", conn->host, conn->port);
//        if (conn->server < 0) {
//            printf("%s:%s has no session type\n", conn->host, conn->port);
//            //session is not yet set, try to read start line
//            int min_length = MAGIC_BYTES_SIZE + SESSION_TYPE_SIZE;
//            input_length = evbuffer_get_length(input);
//            if (input_length < min_length) {
//                printf("short read from new client %s:%s, aborting for now\n", conn->host, conn->port);
//                return;
//            }
//            nbytes = evbuffer_remove(input, data, min_length); //remove maximum size of first line
//            printf("removed %d from buffer of length %lu\n", nbytes, input_length);
//            int magicBytes = memcmp(data, MAGIC_BYTES, MAGIC_BYTES_SIZE);
//            if (magicBytes != 0) {
//                printf("new client %s:%s handshake failed 0x143\n", conn->host, conn->port);
//                closeClient(conn);
//                return;
//            }
//            if (memcmp(&data[MAGIC_BYTES_SIZE], SESSION_TYPE_CLIENT, SESSION_TYPE_SIZE) == 0) {
//                printf("%s:%s indicated a client session type\n", conn->host, conn->port);
//                conn->server = 0;
//            } else if (memcmp(&data[MAGIC_BYTES_SIZE], SESSION_TYPE_SERVER, SESSION_TYPE_SIZE) == 0) {
//                printf("%s:%s indicated a server session type\n", conn->host, conn->port);
//                conn->server = 1;
//            } else {
//                printf("new client %s:%s handshake failed 0x322\n", conn->host, conn->port);
//                closeClient(conn);
//                return;
//            }
//        }
//        if (conn->server == 0) {
//            input_length = evbuffer_get_length(input);
//            if (input_length < SESSION_KEY_SIZE) {
//                printf("short read from client session %s:%s, aborting for now\n", conn->host, conn->port);
//                return;
//            }
//            evbuffer_remove(input, conn->session_key, SESSION_KEY_SIZE);
//            LL_ADD(conn, connections)
//        } else if (conn->server > 0) {
//            printf("sending session key response to new server %s:%s\n", conn->host, conn->port);
//            gen_session_key(conn->session_key, SESSION_KEY_SIZE);
//            LL_ADD(conn, connections)
//            unsigned char response[3 + SESSION_KEY_SIZE];
//            memcpy(response, "OK ", 3);
//            memcpy(&response[3], conn->session_key, SESSION_KEY_SIZE);
//            evbuffer_add(output, response, 3 + SESSION_KEY_SIZE);
//        }
//    }
//    printf("2\n");
//    char session_key_str[(SESSION_KEY_SIZE * 2) + 1];
//    get_session_key_str(conn->session_key, session_key_str);
//    printf("%s:%s has session key %s\n", conn->host, conn->port, session_key_str);
//    input_length = evbuffer_get_length(input);
//    printf("read %lu from %s:%s ...\n", input_length, conn->host, conn->port);
//    if (input_length > 0) {
//        printf("3\n");
//        client_connection_t *peer = get_peer_connection(conn);
//        printf("4\n");
//        if (peer != NULL) {
//            printf("peer %s:%s found for %s:%s, forwarding\n", peer->host, peer->port, conn->host, conn->port);
//            struct evbuffer *peer_output = bufferevent_get_output(peer->bev);
//            // TODO: prepend all client sends
////            if (conn->server == 0) {
////                evbuffer_add(peer_output, )
////            }
//            evbuffer_add_buffer(peer_output, input);
//            if (evbuffer_get_length(peer_output) >= MAX_OUTPUT_BUFFER_SIZE) {
//                printf("peer %s:%s buffer full, disable %s:%s until drained\n", peer->host, peer->port, conn->host, conn->port);
//                bufferevent_setcb(peer->bev, readcb, drained_writecb,
//                                  eventcb, peer);
//                bufferevent_setwatermark(peer->bev, EV_WRITE, MAX_OUTPUT_BUFFER_SIZE/2,
//                                         MAX_OUTPUT_BUFFER_SIZE);
//                bufferevent_disable(bev, EV_READ);
//            }
//        } else {
//            printf("peer not found for client %s:%s ", conn->host, conn->port);
//            if (input_length <= MAX_INPUT_BUFFER_SIZE) {
//                printf(", aborting for now \n");
//                return;
//            }
//            if (conn->server <= 0) {
//                //for clients (and unknowns), we're going to disconnect them if their peer has gone MIA
//                printf(", draining and disconnecting\n");
//                closeClient(conn);
//            } else {
//                //for servers, we're going to just drain the buffer
//                printf(", draining\n");
//            }
//            evbuffer_drain(input, input_length);
//        }
//    } else {
//        printf("no bytes to handle for %s:%s\n", conn->host, conn->port);
//    }
//}
//
//static void eventcb(struct bufferevent *bev, short events, void *ctx)
//{
//    if (events & BEV_EVENT_ERROR)
//        perror("Error from bufferevent");
//    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
//        client_connection_t *conn = (client_connection_t *)ctx;
//        if (ctx != NULL) {
//            printf("error callback for %s:%s\n", conn->host, conn->port);
//            if (conn->server > 0) {
//                printf("server ");
//            } else if (conn->server == 0) {
//                printf("client ");
//            } else {
//                printf("");
//            }
//            printf("%s:%s disconnected\n", conn->host, conn->port);
//            closeClient(conn);
//            printConnections();
//        }
//        bufferevent_free(bev);
//    }
//}
//
//static void
//drained_writecb(struct bufferevent *bev, void *ctx)
//{
//    client_connection_t *conn = (client_connection_t *)ctx;
//    printf("conn %s:%s buffer drained\n", conn->host, conn->port);
//    /* this conn was choking the other side until output buffer drained.
//     * Now it seems drained. */
//    bufferevent_setcb(bev, readcb, NULL, eventcb, ctx);
//    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
//
//    client_connection_t *peer = get_peer_connection(conn);
//
//    if (peer) {
//        printf("re-enabling peer %s:%s for %s:%s full, wait until drained\n", peer->host, peer->port, conn->host, conn->port);
//        bufferevent_enable(peer->bev, EV_READ);
//    }
//}
//
//static void accept_conn_cb(
//        struct evconnlistener *listener,
//        evutil_socket_t fd,
//        struct sockaddr *address,
//        int socklen,
//        void *ctx
//) {
//    /* Setup a bufferevent */
//    struct event_base *base = evconnlistener_get_base(listener);
//    struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
//    client_connection_t *conn = malloc(sizeof(client_connection_t));
//    conn->bev = bev;
//    conn->server = -1;
//    memcpy(conn->session_key, EMPTY_SESSION, SESSION_KEY_SIZE);
//    getnameinfo(address, socklen, conn->host, NI_MAXHOST, conn->port, NI_MAXSERV,
//                NI_NUMERICHOST | NI_NUMERICSERV);
//    conn->fd = fd;
//    conn->next = NULL;
//    conn->prev = NULL;
//    printf("Got new connection from %s:%s\n", conn->host, conn->port);
//    bufferevent_setcb(bev, readcb, NULL, eventcb, conn);
//    bufferevent_enable(bev, EV_READ|EV_WRITE);
//}
//
//static void accept_error_cb(struct evconnlistener *listener, void *ctx)
//{
//    struct event_base *base = evconnlistener_get_base(listener);
//    int err = EVUTIL_SOCKET_ERROR();
//    fprintf(stderr, "Got an error %d (%s) on the listener. "
//                    "Shutting down.\n", err, evutil_socket_error_to_string(err));
//
//    event_base_loopexit(base, NULL);
//}

int main(int argc, char **argv) {

    struct event_base *base;
    long g_port = DEFAULT_GATEWAY_PORT; // gateway port
    long l_port = DEFAULT_LOCAL_LISTEN_PORT; // local listen port
    enum adbcat_type type;
    char usage_str[] = "Usage: %s [-h gateway host] [-u gateway port] [-p local port] [session key | 'gateway']\n";

    char g_host[NI_MAXHOST] = DEFAULT_GATEWAY_HOST; // gateway host

    unsigned char session_key[SESSION_KEY_SIZE];

    int opt;
    opterr = 0;
    while ((opt = getopt(argc, argv, "h:p:u:")) != -1) {
        switch (opt) {
            case 'h':
                if (strlen(optarg) > NI_MAXHOST) {
                    fprintf(stderr, "gateway hostname too long\n");
                    exit(EXIT_FAILURE);
                }
                strcpy(g_host, optarg);
                break;
            case 'p':
                l_port = strtol(optarg, NULL, 10);
                break;
            case 'u':
                g_port = strtol(optarg, NULL, 10);
                break;
            default: /* '?' */
                break;
        }
    }

    int remaining = argc - optind;

    if (remaining == 1) {
        if (strcmp("gateway", argv[optind]) == 0) {
            if (l_port != DEFAULT_LOCAL_LISTEN_PORT) {
                g_port = l_port;
            } else {
                l_port = g_port;
            }
            type = gateway;
        } else if (strlen(argv[optind]) == SESSION_KEY_SIZE * 2) {
            type = client;
            const char *pos = argv[optind];
            for (int i = 0; i < SESSION_KEY_SIZE; i++) {
                sscanf(pos, "%2hhx", &session_key[i]); // NOLINT(*-err34-c)
                pos += 2;
            }
        } else {
            fprintf(stderr, "Malformed session key argument");
            exit(EXIT_FAILURE);
        }
    } else if (remaining != 0) {
        fprintf(stderr, usage_str, argv[0]);
        exit(EXIT_FAILURE);
    } else {
        type = server;
    }

    if (type == client) {
        if (l_port <= 0 || l_port > 65535) {
            fprintf(stderr, "Invalid port\n");
            return 1;
        }
    }

    if (g_port <= 0 || g_port > 65535) {
        fprintf(stderr, "Invalid remote port\n");
        return 1;
    }

    base = event_base_new();
    if (!base) {
        fprintf(stderr, "Couldn't open event base\n");
        return 1;
    }

    switch(type) {
        case gateway:
            return start_gateway(base, (int)l_port);
        case client:
            return start_client(base, (int)l_port, g_host, (int)g_port, session_key);
        case server:
            return start_server(base, g_host, (int)g_port);
        default:
            return EXIT_FAILURE;
    }


    /* Clear the sockaddr before using it, in case there are extra
     * platform-specific fields that can mess us up. */
//    memset(&sin, 0, sizeof(sin));
//    sin.sin6_family = AF_INET6;
//    /* Listen on the given port, on :: */
//    sin.sin6_port = htons(port);
//    listener = evconnlistener_new_bind(base, accept_conn_cb, NULL,
//                                       LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, 8192,
//                                       (struct sockaddr*)&sin, sizeof(sin));
//    if (!listener) {
//        perror("Couldn't create listener");
//        return 1;
//    }
//
//    char l_host_s[NI_MAXHOST];
//    char l_port[NI_MAXSERV];
//    getnameinfo((struct sockaddr*)&sin, sizeof(sin), l_host_s, NI_MAXHOST,
//                l_port, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
//
//    printf("Listening on %s port %s\n", l_host_s, l_port);
//    evconnlistener_set_error_cb(listener, accept_error_cb);
//
//    return event_base_dispatch(base);
}
