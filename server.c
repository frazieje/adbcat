#include <server.h>
#include <unistd.h>
#include <string.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <stdlib.h>
#include "adbcat.h"
#include "utils.h"

static void gateway_readcb(struct bufferevent *bev, void *ctx);

static void gateway_eventcb(struct bufferevent *bev, short what, void *ctx);

static void adb_readcb(struct bufferevent *bev, void *ctx);

static void adb_eventcb(struct bufferevent *bev, short what, void *ctx);

static void closeClient(adb_server_connection_t *cxn) {
    bufferevent_free(cxn->adb_bev);
    evutil_closesocket(bufferevent_getfd(cxn->adb_bev));
    ht_erase(&active_connections, &cxn->from);
}

static void closeGateway(struct bufferevent *bev) {
    printf("closing gateway connection\n");
    struct event_base *base = bufferevent_get_base(bev);
    bufferevent_free(bev);
    evutil_closesocket(bufferevent_getfd(bev));
    printf("closing any local connections to the adb server\n");
    size_t chain;
    HTNode* node;
    HTNode* next;
    int count = 0;
    for (chain = 0; chain < active_connections.capacity; ++chain) {
        for (node = active_connections.nodes[chain]; node;) {
            next = node->next;
            adb_server_connection_t *curr_conn = (adb_server_connection_t *)node->value;
            count++;
            closeClient(curr_conn);
            node = next;
        }
    }
    printf("closed %d adb server connections\n", count);
    event_base_loopexit(base, NULL);
}

static void adb_drained_writecb(struct bufferevent *bev, void *ctx) {
    printf("adb_drained_writecb\n");
    adb_server_connection_t *cxn = (adb_server_connection_t *)ctx;
    bufferevent_setcb(bev, adb_readcb, NULL, adb_eventcb, cxn);
    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
    if (cxn->gw_bev)
        bufferevent_enable(cxn->gw_bev, EV_READ);
}

static void gateway_drained_writecb(struct bufferevent *bev, void *ctx) {
    printf("gateway_drained_writecb\n");
    size_t chain;
    HTNode* node;
    HTNode* next;
    bufferevent_setcb(bev, gateway_readcb, NULL, gateway_eventcb, ctx);
    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
    for (chain = 0; chain < active_connections.capacity; ++chain) {
        for (node = active_connections.nodes[chain]; node;) {
            next = node->next;
            adb_server_connection_t *curr_conn = (adb_server_connection_t *)node->value;
            bufferevent_enable(curr_conn->adb_bev, EV_READ);
            node = next;
        }
    }
}

static void adb_eventcb(struct bufferevent *bev, short what, void *ctx) {
    printf("adb_eventcb\n");
    if (ctx == NULL) {
        printf("adb_eventcb cxn is null\n");
    } else {
        printf("adb_eventcb cxn is not null\n");
    }
    if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        if (what & BEV_EVENT_ERROR) {
            if (errno)
                perror("connection error");
        }
        printf("adb_eventcb eof or error\n");

        adb_server_connection_t *cxn = (adb_server_connection_t *)ctx;

        unsigned char length[SERVER_FWD_LENGTH_SIZE] = {0};
        int server_close_size = SERVER_MSG_TYPE_SIZE + SERVER_MSG_FROM_SIZE + SERVER_FWD_LENGTH_SIZE;
        unsigned char server_close[server_close_size];
        memcpy(server_close, SERVER_CLOSE_MSG, SERVER_MSG_TYPE_SIZE);
        memcpy(&server_close[SERVER_MSG_TYPE_SIZE], &cxn->from, SERVER_MSG_FROM_SIZE);
        memcpy(&server_close[SERVER_MSG_TYPE_SIZE + SERVER_MSG_FROM_SIZE], length,
               SERVER_FWD_LENGTH_SIZE);
        struct evbuffer *dst = bufferevent_get_output(cxn->gw_bev);
        int success = evbuffer_add(dst, server_close, server_close_size);
        if (success == 0) {
            printf("wrote %d bytes to close client %d\n", server_close_size, cxn->from);
        }
        closeClient(cxn);
    }
}

static void adb_readcb(struct bufferevent *bev, void *ctx) {
    printf("adb_readcb\n");
    struct evbuffer *src, *dst;
    size_t len;

    adb_server_connection_t *cxn = (adb_server_connection_t *)ctx;
    dst = bufferevent_get_output(cxn->gw_bev);
    src = bufferevent_get_input(bev);
    len = evbuffer_get_length(src);

    printf("reading %lu bytes from client adb cxn (from %d)\n", len, cxn->from);

    if (len > 0) {
        int server_fwd_preamble_size = SERVER_MSG_TYPE_SIZE + SERVER_MSG_FROM_SIZE + SERVER_FWD_LENGTH_SIZE;
        unsigned char preamble[server_fwd_preamble_size];
        memcpy(preamble, SERVER_FWD_MSG, SERVER_MSG_TYPE_SIZE);
        memcpy(&preamble[SERVER_MSG_TYPE_SIZE], &cxn->from, SERVER_MSG_FROM_SIZE);
        memcpy(&preamble[SERVER_MSG_TYPE_SIZE + SERVER_MSG_FROM_SIZE], &len, SERVER_FWD_LENGTH_SIZE);
        int success = evbuffer_add(dst, preamble, server_fwd_preamble_size);
        if (success == 0) {
            success = evbuffer_add_buffer(dst, src);
            if (success == 0) {
                printf("wrote %lu total bites with %d preamble and %lu payload bytes\n", server_fwd_preamble_size + len, server_fwd_preamble_size, len);
            }
        }
        if (evbuffer_get_length(dst) >= MAX_OUTPUT_BUFFER_SIZE) {
            void *curr_gw_ctx;
            bufferevent_getcb(cxn->gw_bev, NULL, NULL, NULL, &curr_gw_ctx);
            bufferevent_setcb(cxn->gw_bev, gateway_readcb, gateway_drained_writecb,
                              gateway_eventcb, curr_gw_ctx);
            bufferevent_setwatermark(cxn->gw_bev, EV_WRITE, MAX_OUTPUT_BUFFER_SIZE/2,
                                     MAX_OUTPUT_BUFFER_SIZE);
            bufferevent_disable(bev, EV_READ);
        }
    }

}

static void gateway_readcb(struct bufferevent *bev, void *ctx) {
    struct evbuffer *src, *dst;
    size_t len;
    src = bufferevent_get_input(bev);
    len = evbuffer_get_length(src);

    gateway_context_t *gw_ctx = (gateway_context_t *)ctx;

    if (memcmp(gw_ctx->session_key, EMPTY_SESSION, SESSION_KEY_SIZE) == 0) {
        int min_length = SESSION_OK_RESPONSE_SIZE + SESSION_KEY_SIZE;
        char data[min_length];
        if (len < min_length) {
            printf("short read from gateway, aborting for now\n");
            return;
        }
        evbuffer_remove(src, data, min_length);
        if (memcmp(data, SESSION_OK_RESPONSE, SESSION_OK_RESPONSE_SIZE) != 0) {
            printf("gateway handshake failed 0x143\n");
            closeGateway(bev);
            return;
        }
        memcpy(gw_ctx->session_key, &data[SESSION_OK_RESPONSE_SIZE], SESSION_KEY_SIZE);
        char session_key_str[SESSION_KEY_SIZE * 2 + 1];
        get_session_key_str(gw_ctx->session_key, session_key_str);
        printf("local adb server shared via adbcat at %s\n", session_key_str);
    }
    printf("read %lu from gateway...\n", len);
    while ((len = evbuffer_get_length(src)) > 0) {
        printf("%lu left in buffer...\n", len);
        gateway_message_t *message = gw_ctx->current_message;
        if (message == NULL) {
            // read the next message
            printf("read new message\n");
            size_t min_msg_size = SERVER_MSG_TYPE_SIZE + SERVER_MSG_FROM_SIZE + SERVER_MSG_FROM_SIZE;
            if (len < min_msg_size) {
                printf("not enough bytes in buffer to read message, aborting for \n");
                return;
            }
            char msg_type[SERVER_MSG_TYPE_SIZE + 1];
            evbuffer_remove(src, msg_type, SERVER_MSG_TYPE_SIZE);
            msg_type[SERVER_MSG_TYPE_SIZE] = '\0';
            if (strcmp(msg_type, SERVER_CLOSE_MSG) == 0) {
                printf("message is a close message\n");
                uint32_t from;
                evbuffer_remove(src, &from, SERVER_MSG_FROM_SIZE);
                adb_server_connection_t *cxn = ht_lookup(&active_connections, &from);
                printf("process close message for client %d\n", from);
                if (cxn != NULL) {
                    printf("client %d has active connection with adb server, closing\n", from);
                    closeClient(cxn);
                } else {
                    printf("no active connection found for client %d\n", from);
                }
            } else if (strcmp(msg_type, SERVER_FWD_MSG) == 0) {
                gateway_message_t *new_message = malloc(sizeof(gateway_message_t));
                memset(new_message, 0, sizeof(gateway_message_t));
                new_message->type = gw_msg_forward;
                evbuffer_remove(src, &new_message->from, SERVER_MSG_FROM_SIZE);
                evbuffer_remove(src, &new_message->length, SERVER_FWD_LENGTH_SIZE);
                printf("message is a fward message from %d, with length %lu\n", new_message->from, new_message->length);
                gw_ctx->current_message = new_message;
                gw_ctx->current_message_sent = 0;
            } else {
                printf("message is unrecognized, error\n");
                closeGateway(bev);
                return;
            }
            continue;
        }
        //we're already working on a fwd message
        uint64_t remaining = message->length - gw_ctx->current_message_sent;
        printf("message from client %d with %lu remaining...\n", message->from, remaining);
        adb_server_connection_t *cxn = ht_lookup(&active_connections, &message->from);

        if (cxn == NULL) {
            printf("no connection open for %d, opening\n", message->from);
            struct event_base *base = bufferevent_get_base(bev);
            struct bufferevent *adb_server_bev = bufferevent_socket_new(base, -1,
                                                                        BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
            if (bufferevent_socket_connect(adb_server_bev,
                                           (struct sockaddr *)gw_ctx->adbserver_addr, gw_ctx->adbserver_addr_len)<0) {
                perror("bufferevent_socket_connect");
                bufferevent_free(adb_server_bev);
                return;
            }
            adb_server_connection_t newCxn = { .adb_bev = adb_server_bev, .gw_bev = bev, .from = message->from };
            int insret = ht_insert(&active_connections, &message->from, &newCxn);
            adb_server_connection_t *newCxnP = ht_lookup(&active_connections, &message->from);
            printf("newCxnP has from %d, insret = %d\n", newCxnP->from, insret);
            cxn = newCxnP;
            bufferevent_setcb(adb_server_bev, adb_readcb, NULL, adb_eventcb, newCxnP);
            bufferevent_enable(adb_server_bev, EV_READ|EV_WRITE);
        }
        dst = bufferevent_get_output(cxn->adb_bev);
        char data[remaining];
        int nbytes = evbuffer_remove(src, data, remaining);
        evbuffer_add(dst, data, nbytes);
        gw_ctx->current_message_sent += nbytes;
        printf("wrote %d bytes to client %d\n", nbytes, message->from);
        if (evbuffer_get_length(dst) >= MAX_OUTPUT_BUFFER_SIZE) {
            bufferevent_setcb(cxn->adb_bev, adb_readcb, adb_drained_writecb,
                              adb_eventcb, cxn);
            bufferevent_setwatermark(cxn->adb_bev, EV_WRITE, MAX_OUTPUT_BUFFER_SIZE/2,
                                     MAX_OUTPUT_BUFFER_SIZE);
            bufferevent_disable(bev, EV_READ);
        }
        if (message->length == gw_ctx->current_message_sent) {
            printf("message finished from %d\n", message->from);
            gw_ctx->current_message_sent = 0;
            gw_ctx->current_message = NULL;
            free(gw_ctx->current_message);
        }
    }
    printf("processed all bytes in buffer\n");
}

static void gateway_eventcb(struct bufferevent *bev, short what, void *ctx) {
    printf("gateway_eventcb\n");
    if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        if (what & BEV_EVENT_ERROR) {
            if (errno)
                perror("connection error");
        }
        printf("gateway_eventcb eof or error\n");
        /* Flush all pending data */
        gateway_readcb(bev, ctx);
        closeGateway(bev);
    }
}

int start_server(
        struct event_base *base,
        int adb_server_port,
        struct sockaddr *gateway_addr,
        socklen_t gateway_addr_len
) {
    printf("Running in server mode\n");
    struct sockaddr_in6 adb_server;
    int sock;
    int ret;
    struct addrinfo hints;
    struct addrinfo *res_list, *res;

    ht_setup(&active_connections,
             sizeof(uint32_t),
             sizeof(adb_server_connection_t), 0);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    char adb_port_str[32];
    sprintf(adb_port_str, "%d", adb_server_port);
    ret = getaddrinfo("localhost", adb_port_str, &hints, &res_list);
    if (ret != 0) {
        fprintf(stderr, "Error in getaddrinfo: %s\n", gai_strerror(ret));
        return 1;
    }

    // try to connect to the provided adb server to make sure it's available
    for (res = res_list; res != NULL; res = res->ai_next) {
        sock = socket(res->ai_family, res->ai_socktype,
                      res->ai_protocol);
        if (sock == -1)
            continue;

        if (connect(sock, res->ai_addr, res->ai_addrlen) != -1) {
            close(sock);
            break;
        } else {
            close(sock);
        }
    }

    if (res == NULL) {
        fprintf(stderr, "Could not connect to adb server at localhost:%s\n", adb_port_str);
        return 1;
    }

    memset(&adb_server, 0, sizeof(adb_server));

    struct bufferevent *gateway_bev = bufferevent_socket_new(base, -1,
                                         BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

    if (bufferevent_socket_connect(gateway_bev,
                                   (struct sockaddr *)gateway_addr, gateway_addr_len)<0) {
        perror("bufferevent_socket_connect");
        bufferevent_free(gateway_bev);
        return 1;
    }

    if (gateway_bev == NULL) {
        perror("Failed to create socket-based bufferevent");
        return 1;
    }

    struct evbuffer *gateway_out = bufferevent_get_output(gateway_bev);
    printf("gateway_bev is %p\n", gateway_bev);

    size_t server_preamble_size = MAGIC_BYTES_SIZE + SESSION_TYPE_SIZE;
    char preamble[server_preamble_size];
    memcpy(preamble, MAGIC_BYTES, MAGIC_BYTES_SIZE);
    memcpy(&preamble[MAGIC_BYTES_SIZE], SESSION_TYPE_SERVER, SESSION_TYPE_SIZE);

    evbuffer_prepend(gateway_out, preamble, server_preamble_size);

    gateway_context_t gw_ctx;
    memset(&gw_ctx, 0, sizeof(gateway_context_t));
    memcpy(gw_ctx.session_key, EMPTY_SESSION, SESSION_KEY_SIZE);
    gw_ctx.adbserver_addr = res->ai_addr;
    gw_ctx.adbserver_addr_len = res->ai_addrlen;
    gw_ctx.current_message = NULL;
    gw_ctx.current_message_sent = 0;
    bufferevent_setcb(gateway_bev, gateway_readcb, NULL, gateway_eventcb, &gw_ctx);
    bufferevent_enable(gateway_bev, EV_READ|EV_WRITE);

    return event_base_dispatch(base);
}
