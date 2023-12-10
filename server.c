#include <server.h>
#include <unistd.h>
#include <string.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include "adbcat.h"

static void gateway_readcb(struct bufferevent *bev, void *ctx) {
    struct evbuffer *src, *dst;
    size_t len;
    src = bufferevent_get_input(bev);
    len = evbuffer_get_length(src);

    if (ctx == NULL) {
        printf("session not yet set")

    }

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

int start_server(
        struct event_base *base,
        int adb_server_port,
        struct sockaddr *gateway_addr,
        socklen_t gateway_addr_len
) {

    struct sockaddr_in6 adb_server;
    int sock;
    int ret;

    memset(&adb_server, 0, sizeof(adb_server));
    adb_server.sin6_addr = in6addr_loopback;
    adb_server.sin6_family = AF_INET6;
    adb_server.sin6_port = htons(adb_server_port);

    sock = socket(adb_server.sin6_family, SOCK_STREAM, IPPROTO_TCP);

    if (sock == -1) {
        perror("could not create socket");
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&adb_server, sizeof(adb_server)) != -1) {
        close(sock);
    } else {
        close(sock);
        perror("could not connect to adb server");
        return 1;
    }

    errno = 0;
    sock = socket(adb_server.sin6_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) {
        perror("Failed to create socket");
        return 1;
    }

    ret = connect(sock, (struct sockaddr*)gateway_addr, gateway_addr_len);
    if (ret != 0) {
        perror("Failed to connect to host");
        return 1;
    }
    ret = evutil_make_socket_nonblocking(sock);
    if (ret != 0) {
        perror("Failed to set socket to non-blocking mode");
        return 1;
    }

    struct bufferevent *gateway_bev = bufferevent_socket_new(base, sock, 0);

    if (gateway_bev == NULL) {
        perror("Failed to create socket-based bufferevent");
        return 1;
    }

    struct evbuffer *gateway_out = bufferevent_get_output(gateway_bev);

    size_t server_preamble_size = MAGIC_BYTES_SIZE + SESSION_TYPE_SIZE;
    char preamble[server_preamble_size];
    memcpy(preamble, MAGIC_BYTES, MAGIC_BYTES_SIZE);
    memcpy(&preamble[MAGIC_BYTES_SIZE], SESSION_TYPE_SERVER, SESSION_TYPE_SIZE);

    evbuffer_prepend(gateway_out, preamble, server_preamble_size);

    bufferevent_setcb(gateway_bev, gateway_readcb, NULL, gateway_eventcb, NULL);
    bufferevent_enable(gateway_bev, EV_READ|EV_WRITE);

    return event_base_dispatch(base);
}
