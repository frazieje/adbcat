#include <client.h>
#include <string.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "adbcat.h"
#include "utils.h"

typedef struct client_settings_t {
    struct sockaddr *gateway_addr;
    socklen_t gateway_addr_len;
    unsigned char session_key[SESSION_KEY_SIZE];
    SSL_CTX *ssl_ctx;
    int cleartext_enabled;
    int verbose_enabled;
} client_settings_t;

typedef struct client_connection_t {
    struct client_connection_t *peer;
    struct bufferevent *bev;
    unsigned char session_key[SESSION_KEY_SIZE];
} client_connection_t;

static client_settings_t client_settings;

static void client_log(char *str, ...) {
    if (client_settings.verbose_enabled) {
        va_list valist;
        va_start(valist, str);
        vfprintf(stdout, str, valist);
        va_end(valist);
    }
}

static void drained_writecb(struct bufferevent *bev, void *ctx);

static void eventcb(struct bufferevent *bev, short what, void *ctx);

static void readcb(struct bufferevent *bev, void *ctx) {
    client_connection_t *connection = ctx;
    struct bufferevent *peer = connection->peer->bev;
    struct evbuffer *src, *dst;
    size_t len;
    src = bufferevent_get_input(bev);
    len = evbuffer_get_length(src);
    if (!peer) {
        if (len <= MAX_INPUT_BUFFER_SIZE) {
            client_log(", aborting for now \n");
            return;
        }
        evbuffer_drain(src, len);
    }

    dst = bufferevent_get_output(peer);
    evbuffer_add_buffer(dst, src);

    if (evbuffer_get_length(dst) >= MAX_OUTPUT_BUFFER_SIZE) {
        bufferevent_setcb(peer, readcb, drained_writecb,
                          eventcb, connection->peer);
        bufferevent_setwatermark(peer, EV_WRITE, MAX_OUTPUT_BUFFER_SIZE / 2,
                                 MAX_OUTPUT_BUFFER_SIZE);
        bufferevent_disable(bev, EV_READ);
    }
}

static void drained_writecb(struct bufferevent *bev, void *ctx) {
    client_connection_t *connection = ctx;
    struct bufferevent *peer = connection->peer->bev;
    bufferevent_setcb(bev, readcb, NULL, eventcb, connection);
    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
    if (peer)
        bufferevent_enable(peer, EV_READ);
}

static void close_on_finished_writecb(struct bufferevent *bev, void *ctx) {
    struct evbuffer *b = bufferevent_get_output(bev);
    client_connection_t *connection = ctx;
    if (evbuffer_get_length(b) == 0) {
        bufferevent_free(bev);
        free(connection);
    }
}

static void eventcb(struct bufferevent *bev, short what, void *ctx) {
    client_connection_t *connection = ctx;
    struct bufferevent *peer = connection->peer->bev;

    if (what & BEV_EVENT_CONNECTED) {
        if (memcmp(connection->session_key, EMPTY_SESSION, SESSION_KEY_SIZE) != 0) {
            struct evbuffer *gateway_out = bufferevent_get_output(bev);

            size_t client_preamble_size = MAGIC_BYTES_SIZE + SESSION_TYPE_SIZE + SESSION_KEY_SIZE;
            char preamble[client_preamble_size];
            memcpy(preamble, MAGIC_BYTES, MAGIC_BYTES_SIZE);
            memcpy(&preamble[MAGIC_BYTES_SIZE], SESSION_TYPE_CLIENT, SESSION_TYPE_SIZE);
            memcpy(&preamble[MAGIC_BYTES_SIZE + SESSION_TYPE_SIZE], connection->session_key, SESSION_KEY_SIZE);

            evbuffer_prepend(gateway_out, preamble, client_preamble_size);
        }
    }

    if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        if (what & BEV_EVENT_ERROR) {
            if (bufferevent_openssl_get_ssl(bev)) {
                unsigned long openssl_error = bufferevent_get_openssl_error(bev);
                if (openssl_error) {
                    client_log("gateway connection error: %s\n", ERR_error_string(openssl_error, NULL));
                }
            }
            if (errno)
                perror("connection error");
        }
        if (peer) {
            /* Flush all pending data */
            readcb(bev, ctx);
            if (evbuffer_get_length(
                bufferevent_get_output(peer))) {
                bufferevent_setcb(peer,
                                  NULL, close_on_finished_writecb,
                                  eventcb, connection->peer);
                bufferevent_disable(peer, EV_READ);
            } else {
                bufferevent_free(peer);
                free(connection->peer);
            }
        }
        bufferevent_free(bev);
        free(connection);
    }
}


static void accept_conn_cb(
    struct evconnlistener *listener,
    evutil_socket_t fd,
    struct sockaddr *a,
    int slen,
    void *p
) {

    struct bufferevent *gateway_bev, *client_bev;
    struct event_base *base = evconnlistener_get_base(listener);
    SSL_CTX *ssl_ctx = client_settings.ssl_ctx;

    client_bev = bufferevent_socket_new(base, fd,
                                        BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

    if (ssl_ctx != NULL) {
        SSL *ssl = SSL_new(ssl_ctx);

        if (ssl == NULL) {
            perror("Failed to create new TLS structure");
            return;
        }

        gateway_bev = bufferevent_openssl_socket_new(
            base, -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

        if (!gateway_bev) {
            perror("Failed to create TLS-enabled bufferevent");
            return;
        }
    } else {
        gateway_bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
        if (!gateway_bev) {
            perror("Failed to create bufferevent");
            return;
        }
    }

    if (bufferevent_socket_connect(gateway_bev, client_settings.gateway_addr,
                                   (int) client_settings.gateway_addr_len) < 0) {
        perror("bufferevent_socket_connect");
        bufferevent_free(gateway_bev);
        bufferevent_free(client_bev);
        return;
    }

    client_connection_t *adb_connection = malloc(sizeof(struct client_connection_t));
    client_connection_t *gateway_connection = malloc(sizeof(struct client_connection_t));

    adb_connection->peer = gateway_connection;
    gateway_connection->peer = adb_connection;
    adb_connection->bev = client_bev;
    gateway_connection->bev = gateway_bev;
    memset(adb_connection->session_key, 0, SESSION_KEY_SIZE);
    memcpy(gateway_connection->session_key, client_settings.session_key, SESSION_KEY_SIZE);

    bufferevent_setcb(client_bev, readcb, NULL, eventcb, adb_connection);
    bufferevent_setcb(gateway_bev, readcb, NULL, eventcb, gateway_connection);

    bufferevent_enable(client_bev, EV_READ | EV_WRITE);
    bufferevent_enable(gateway_bev, EV_READ | EV_WRITE);
}

static void accept_error_cb(struct evconnlistener *listener, void *ctx) {
    struct event_base *base = evconnlistener_get_base(listener);
    int err = EVUTIL_SOCKET_ERROR();
    fprintf(stderr, "Got an error %d (%s) on the listener. "
            "Shutting down.\n", err, evutil_socket_error_to_string(err));

    event_base_loopexit(base, NULL);
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

int start_client(
    int port,
    struct sockaddr *gateway_addr,
    socklen_t gateway_addr_len,
    unsigned char *session_key,
    int enable_cleartext,
    int enable_verbose
) {
    printf("Running in client mode\n");
    struct evconnlistener *listener;
    struct sockaddr_in6 sin;
    struct event_base *base;
    SSL_CTX *ssl_ctx = NULL;

    if (!enable_cleartext) {
        ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx)
            return 1;

        if (configure_ssl_ctx(ssl_ctx) > 0) {
            return 1;
        }
    }

    base = event_base_new();
    if (!base) {
        fprintf(stderr, "Couldn't open event base\n");
        return 1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin6_family = AF_INET6;
    /* Listen on the given port, on :: */
    sin.sin6_port = htons(port);

    client_settings.gateway_addr = gateway_addr;
    client_settings.gateway_addr_len = gateway_addr_len;
    client_settings.ssl_ctx = ssl_ctx;
    client_settings.cleartext_enabled = enable_cleartext;
    client_settings.verbose_enabled = enable_verbose;

    memcpy(client_settings.session_key, session_key, SESSION_KEY_SIZE);

    listener = evconnlistener_new_bind(base, accept_conn_cb, NULL,
                                       LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 8192,
                                       (struct sockaddr *) &sin, sizeof(sin));
    if (!listener) {
        perror("Couldn't create listener");
        return 1;
    }

    char addr_str[ADDRESS_STRING_SIZE];
    address_to_str((struct sockaddr *) &sin, sizeof(sin), addr_str, ADDRESS_STRING_SIZE);

    printf("Listening on %s\n", addr_str);
    evconnlistener_set_error_cb(listener, accept_error_cb);

    return event_base_dispatch(base);
}
