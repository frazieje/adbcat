#include <client.h>
#include <string.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include "adbcat.h"
#include "utils.h"

static void drained_writecb(struct bufferevent *bev, void *ctx);

static void eventcb(struct bufferevent *bev, short events, void *ctx);

static void readcb(struct bufferevent *bev, void *ctx) {
    struct bufferevent *peer = ctx;
    struct evbuffer *src, *dst;
    size_t len;
    src = bufferevent_get_input(bev);
    len = evbuffer_get_length(src);
    if (!peer) {
        if (len <= MAX_INPUT_BUFFER_SIZE) {
            printf(", aborting for now \n");
            return;
        }
        evbuffer_drain(src, len);
    }

    dst = bufferevent_get_output(peer);
    evbuffer_add_buffer(dst, src);

    if (evbuffer_get_length(dst) >= MAX_OUTPUT_BUFFER_SIZE) {
        bufferevent_setcb(peer, readcb, drained_writecb,
                          eventcb, bev);
        bufferevent_setwatermark(peer, EV_WRITE, MAX_OUTPUT_BUFFER_SIZE/2,
                                 MAX_OUTPUT_BUFFER_SIZE);
        bufferevent_disable(bev, EV_READ);
    }
}

static void drained_writecb(struct bufferevent *bev, void *ctx) {
    struct bufferevent *peer = ctx;
    bufferevent_setcb(bev, readcb, NULL, eventcb, peer);
    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
    if (peer)
        bufferevent_enable(peer, EV_READ);
}

static void close_on_finished_writecb(struct bufferevent *bev, void *ctx) {
    struct evbuffer *b = bufferevent_get_output(bev);

    if (evbuffer_get_length(b) == 0) {
        bufferevent_free(bev);
    }
}

static void eventcb(struct bufferevent *bev, short what, void *ctx) {
    struct bufferevent *peer = ctx;

    if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        if (what & BEV_EVENT_ERROR) {
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
                                  eventcb, NULL);
                bufferevent_disable(peer, EV_READ);
            } else {
                bufferevent_free(peer);
            }
        }
        bufferevent_free(bev);
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

    client_bev = bufferevent_socket_new(base, fd,
                                  BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

    gateway_bev = bufferevent_socket_new(base, -1,
                                   BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

    gateway_connect_t *gateway_connect = (gateway_connect_t *)p;

    if (bufferevent_socket_connect(gateway_bev,
                                   (struct sockaddr *)gateway_connect->gateway_addr, gateway_connect->gateway_addr_len)<0) {
        perror("bufferevent_socket_connect");
        bufferevent_free(gateway_bev);
        bufferevent_free(client_bev);
        return;
    }

    bufferevent_setcb(client_bev, readcb, NULL, eventcb, gateway_bev);
    bufferevent_setcb(gateway_bev, readcb, NULL, eventcb, client_bev);

    struct evbuffer *gateway_out = bufferevent_get_output(gateway_bev);

    size_t client_preamble_size = MAGIC_BYTES_SIZE + SESSION_TYPE_SIZE + SESSION_KEY_SIZE;
    char preamble[client_preamble_size];
    memcpy(preamble, MAGIC_BYTES, MAGIC_BYTES_SIZE);
    memcpy(&preamble[MAGIC_BYTES_SIZE], SESSION_TYPE_CLIENT, SESSION_TYPE_SIZE);
    memcpy(&preamble[MAGIC_BYTES_SIZE + SESSION_TYPE_SIZE], gateway_connect->session_key, SESSION_KEY_SIZE);

    evbuffer_prepend(gateway_out, preamble, client_preamble_size);

    bufferevent_enable(client_bev, EV_READ|EV_WRITE);
    bufferevent_enable(gateway_bev, EV_READ|EV_WRITE);
}

static void accept_error_cb(struct evconnlistener *listener, void *ctx)
{
    struct event_base *base = evconnlistener_get_base(listener);
    int err = EVUTIL_SOCKET_ERROR();
    fprintf(stderr, "Got an error %d (%s) on the listener. "
                    "Shutting down.\n", err, evutil_socket_error_to_string(err));

    event_base_loopexit(base, NULL);
}

int start_client(
        struct event_base *base,
        int local_port,
        struct sockaddr *gateway_addr,
        socklen_t gateway_addr_len,
        unsigned char *session_key
) {
    printf("Running in client mode\n");
    struct evconnlistener *listener;
    struct sockaddr_in6 sin;

    memset(&sin, 0, sizeof(sin));
    sin.sin6_family = AF_INET6;
    /* Listen on the given port, on :: */
    sin.sin6_port = htons(local_port);

    gateway_connect_t gateway_connect = { .gateway_addr = gateway_addr, .gateway_addr_len = gateway_addr_len };
    memcpy(gateway_connect.session_key, session_key, SESSION_KEY_SIZE);

    listener = evconnlistener_new_bind(base, accept_conn_cb, &gateway_connect,
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