#include "server.h"
#include <unistd.h>
#include <string.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "adbcat.h"
#include "gateway.h"
#include "utils.h"
#include "hashtable.h"

static HashTable active_connections = HT_INITIALIZER

typedef struct adb_server_connection_t {
    struct bufferevent *adb_bev;
    struct bufferevent *gw_bev;
    uint32_t from;
} adb_server_connection_t;

typedef struct gateway_context_t {
    struct sockaddr *adbserver_addr;
    socklen_t adbserver_addr_len;
    unsigned char session_key[SESSION_KEY_SIZE];
    gateway_message_t *current_message;
    uint64_t current_message_sent;
} gateway_context_t;

typedef struct server_settings_t {
    struct sockaddr *gateway_addr;
    socklen_t gateway_addr_len;
    SSL_CTX *ssl_ctx;
    int cleartext_enabled;
    int verbose_enabled;
} server_settings_t;

static server_settings_t server_settings;

static void gateway_readcb(struct bufferevent *bev, void *ctx);

static void gateway_eventcb(struct bufferevent *bev, short what, void *ctx);

static void adb_readcb(struct bufferevent *bev, void *ctx);

static void adb_eventcb(struct bufferevent *bev, short what, void *ctx);

static void server_log(char *str, ...) {
    if (server_settings.verbose_enabled) {
        va_list valist;
        va_start(valist, str);
        vfprintf(stdout, str, valist);
        va_end(valist);
        fflush(stdout);
    }
}

static void closeClient(adb_server_connection_t *cxn) {
    bufferevent_free(cxn->adb_bev);
    evutil_closesocket(bufferevent_getfd(cxn->adb_bev));
    ht_erase(&active_connections, &cxn->from);
}

static void closeGateway(struct bufferevent *bev) {
    server_log("closing gateway connection\n");
    struct event_base *base = bufferevent_get_base(bev);
    bufferevent_free(bev);
    evutil_closesocket(bufferevent_getfd(bev));
    server_log("closing any local connections to the adb server\n");
    size_t chain;
    HTNode* node;
    HTNode* next;
    int count = 0;
    for (chain = 0; chain < active_connections.capacity; ++chain) {
        for (node = active_connections.nodes[chain]; node;) {
            next = node->next;
            adb_server_connection_t *curr_conn = node->value;
            count++;
            closeClient(curr_conn);
            node = next;
        }
    }
    server_log("closed %d adb server connections\n", count);
    event_base_loopexit(base, NULL);
}

static void adb_drained_writecb(struct bufferevent *bev, void *ctx) {
    server_log("adb_drained_writecb\n");
    adb_server_connection_t *cxn = (adb_server_connection_t *)ctx;
    bufferevent_setcb(bev, adb_readcb, NULL, adb_eventcb, cxn);
    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
    if (cxn->gw_bev)
        bufferevent_enable(cxn->gw_bev, EV_READ);
}

static void gateway_drained_writecb(struct bufferevent *bev, void *ctx) {
    server_log("gateway_drained_writecb\n");
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
    if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        if (what & BEV_EVENT_ERROR) {
            if (errno)
                perror("connection error");
        }
        server_log("adb_eventcb eof or error\n");

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
            server_log("wrote %d bytes to close client %d\n", server_close_size, cxn->from);
        }
        closeClient(cxn);
    }
}

static void adb_readcb(struct bufferevent *bev, void *ctx) {
    struct evbuffer *src, *dst;
    size_t len;

    adb_server_connection_t *cxn = (adb_server_connection_t *)ctx;
    dst = bufferevent_get_output(cxn->gw_bev);
    src = bufferevent_get_input(bev);
    len = evbuffer_get_length(src);

    server_log("adb_readcb reading %lu bytes from client adb cxn (from %d)\n", len, cxn->from);

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
                server_log("adb_readcb wrote %lu total bites with %d preamble and %lu payload bytes\n", server_fwd_preamble_size + len, server_fwd_preamble_size, len);
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

    gateway_context_t *gw_ctx = ctx;

    if (memcmp(gw_ctx->session_key, EMPTY_SESSION, SESSION_KEY_SIZE) == 0) {
        int min_length = SESSION_OK_RESPONSE_SIZE + SESSION_KEY_SIZE;
        char data[min_length];
        if (len < min_length) {
            server_log("gateway_readcb short read from gateway, aborting for now\n");
            return;
        }
        evbuffer_remove(src, data, min_length);
        if (memcmp(data, SESSION_OK_RESPONSE, SESSION_OK_RESPONSE_SIZE) != 0) {
            server_log("gateway_readcb handshake failed 0x143\n");
            closeGateway(bev);
            return;
        }
        memcpy(gw_ctx->session_key, &data[SESSION_OK_RESPONSE_SIZE], SESSION_KEY_SIZE);
        char session_key_str[SESSION_KEY_SIZE * 2 + 1];
        get_session_key_str(gw_ctx->session_key, session_key_str);
        printf("local adb server shared via adbcat at %s\n", session_key_str);
    }
    server_log("read %lu from gateway...\n", len);
    while ((len = evbuffer_get_length(src)) > 0) {
        server_log("%lu left in buffer...\n", len);
        gateway_message_t *message = gw_ctx->current_message;
        if (message == NULL) {
            // read the next message
            server_log("read new message\n");
            size_t min_msg_size = SERVER_MSG_TYPE_SIZE + SERVER_MSG_FROM_SIZE + SERVER_MSG_FROM_SIZE;
            if (len < min_msg_size) {
                server_log("not enough bytes in buffer to read message, aborting for \n");
                return;
            }
            char msg_type[SERVER_MSG_TYPE_SIZE + 1];
            evbuffer_remove(src, msg_type, SERVER_MSG_TYPE_SIZE);
            msg_type[SERVER_MSG_TYPE_SIZE] = '\0';
            if (strcmp(msg_type, SERVER_CLOSE_MSG) == 0) {
                server_log("message is a close message\n");
                uint32_t from;
                evbuffer_remove(src, &from, SERVER_MSG_FROM_SIZE);
                adb_server_connection_t *cxn = ht_lookup(&active_connections, &from);
                server_log("process close message for client %d\n", from);
                if (cxn != NULL) {
                    server_log("client %d has active connection with adb server, closing\n", from);
                    closeClient(cxn);
                } else {
                    server_log("no active connection found for client %d\n", from);
                }
            } else if (strcmp(msg_type, SERVER_FWD_MSG) == 0) {
                gateway_message_t *new_message = malloc(sizeof(gateway_message_t));
                memset(new_message, 0, sizeof(gateway_message_t));
                new_message->type = gw_msg_forward;
                evbuffer_remove(src, &new_message->from, SERVER_MSG_FROM_SIZE);
                evbuffer_remove(src, &new_message->length, SERVER_FWD_LENGTH_SIZE);
                server_log("message is a fward message from %d, with length %lu\n", new_message->from, new_message->length);
                gw_ctx->current_message = new_message;
                gw_ctx->current_message_sent = 0;
            } else {
                server_log("message is unrecognized, error\n");
                closeGateway(bev);
                return;
            }
            continue;
        }
        //we're already working on a fwd message
        uint64_t remaining = message->length - gw_ctx->current_message_sent;
        server_log("message from client %d with %lu remaining...\n", message->from, remaining);
        adb_server_connection_t *cxn = ht_lookup(&active_connections, &message->from);

        if (cxn == NULL) {
            server_log("no connection open for %d, opening\n", message->from);
            struct event_base *base = bufferevent_get_base(bev);
            struct bufferevent *adb_server_bev = bufferevent_socket_new(base, -1,
                                                                        BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
            if (bufferevent_socket_connect(adb_server_bev,
                                           (struct sockaddr *)gw_ctx->adbserver_addr, gw_ctx->adbserver_addr_len)<0) {
                server_log("bufferevent_socket_connect");
                bufferevent_free(adb_server_bev);
                return;
            }
            adb_server_connection_t newCxn = { .adb_bev = adb_server_bev, .gw_bev = bev, .from = message->from };
            int insert = ht_insert(&active_connections, &message->from, &newCxn);
            adb_server_connection_t *newCxnP = ht_lookup(&active_connections, &message->from);
            server_log("newCxnP has from %d, insert = %d\n", newCxnP->from, insert);
            cxn = newCxnP;
            bufferevent_setcb(adb_server_bev, adb_readcb, NULL, adb_eventcb, newCxnP);
            bufferevent_enable(adb_server_bev, EV_READ|EV_WRITE);
        }
        dst = bufferevent_get_output(cxn->adb_bev);
        char data[remaining];
        int nbytes = evbuffer_remove(src, data, remaining);
        evbuffer_add(dst, data, nbytes);
        gw_ctx->current_message_sent += nbytes;
        server_log("wrote %d bytes to client %d\n", nbytes, message->from);
        if (evbuffer_get_length(dst) >= MAX_OUTPUT_BUFFER_SIZE) {
            bufferevent_setcb(cxn->adb_bev, adb_readcb, adb_drained_writecb,
                              adb_eventcb, cxn);
            bufferevent_setwatermark(cxn->adb_bev, EV_WRITE, MAX_OUTPUT_BUFFER_SIZE/2,
                                     MAX_OUTPUT_BUFFER_SIZE);
            bufferevent_disable(bev, EV_READ);
        }
        if (message->length == gw_ctx->current_message_sent) {
            server_log("message finished from %d\n", message->from);
            gw_ctx->current_message_sent = 0;
            gw_ctx->current_message = NULL;
            free(gw_ctx->current_message);
        }
    }
    server_log("processed all bytes in buffer\n");
}

static void gateway_eventcb(struct bufferevent *bev, short what, void *ctx) {
    if (what & BEV_EVENT_CONNECTED) {
        struct evbuffer *gateway_out = bufferevent_get_output(bev);

        size_t server_preamble_size = MAGIC_BYTES_SIZE + SESSION_TYPE_SIZE;
        char preamble[server_preamble_size];
        memcpy(preamble, MAGIC_BYTES, MAGIC_BYTES_SIZE);
        memcpy(&preamble[MAGIC_BYTES_SIZE], SESSION_TYPE_SERVER, SESSION_TYPE_SIZE);

        evbuffer_prepend(gateway_out, preamble, server_preamble_size);
    }
    if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        if (what & BEV_EVENT_ERROR) {
            if (bufferevent_openssl_get_ssl(bev)) {
                unsigned long openssl_error = bufferevent_get_openssl_error(bev);
                if (openssl_error) {
                    server_log("gateway connection error: %s\n", ERR_error_string(openssl_error, NULL));
                }
            }
            if (errno)
                perror("gateway connection error");
        }
        /* Flush all pending data */
        gateway_readcb(bev, ctx);
        closeGateway(bev);
    }
}

static int configure_ssl_ctx(SSL_CTX *ssl_ctx) {

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);

    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_2);
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_1);

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_set_default_verify_paths(ssl_ctx) != 1) {
        SSL_CTX_free(ssl_ctx);
        return 1;
    }

    return 0;
}

int start_server(
        int adb_server_port,
        struct sockaddr *gateway_addr,
        socklen_t gateway_addr_len,
        int enable_cleartext,
        int enable_verbose
) {
    printf("Running in server mode\n");
    struct sockaddr_in6 adb_server;
    int sock;
    int ret;
    struct addrinfo hints;
    struct addrinfo *res_list, *res;
    struct event_base *base;
    struct bufferevent *gateway_bev;

    server_settings.gateway_addr = gateway_addr;
    server_settings.gateway_addr_len = gateway_addr_len;
    server_settings.cleartext_enabled = enable_cleartext;
    server_settings.verbose_enabled = enable_verbose;

    if (!enable_cleartext) {
        server_settings.ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!server_settings.ssl_ctx)
            return 1;

        if (configure_ssl_ctx(server_settings.ssl_ctx) > 0) {
            return 1;
        }
    }

    base = event_base_new();
    if (!base) {
        fprintf(stderr, "Couldn't open event base\n");
        return 1;
    }

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

    if (server_settings.ssl_ctx != NULL) {
        SSL *ssl = SSL_new(server_settings.ssl_ctx);

        gateway_bev = bufferevent_openssl_socket_new(base, -1, ssl, BUFFEREVENT_SSL_CONNECTING, // client handshake
            BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
        if (!gateway_bev)
            SSL_free(ssl);
    } else {
        gateway_bev = bufferevent_socket_new(base, -1,
        BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    }

    if (bufferevent_socket_connect(gateway_bev,
                                   (struct sockaddr *)gateway_addr, gateway_addr_len) < 0) {
        perror("bufferevent_socket_connect");
        bufferevent_free(gateway_bev);
        if (server_settings.ssl_ctx != NULL)
            SSL_CTX_free(server_settings.ssl_ctx);
        return 1;
    }

    if (gateway_bev == NULL) {
        perror("Failed to create socket-based bufferevent");
        if (server_settings.ssl_ctx != NULL)
            SSL_CTX_free(server_settings.ssl_ctx);
        return 1;
    }

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
