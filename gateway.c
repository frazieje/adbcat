#include <gateway.h>
#include <string.h>
#include <netinet/in.h>

int start_gateway(struct event_base *base) {
    memset(&sin, 0, sizeof(sin));
    sin.sin6_family = AF_INET6;
    /* Listen on the given port, on :: */
    sin.sin6_port = htons(port);
    listener = evconnlistener_new_bind(base, accept_conn_cb, NULL,
                                       LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, 8192,
                                       (struct sockaddr*)&sin, sizeof(sin));
    if (!listener) {
        perror("Couldn't create listener");
        return 1;
    }

    char l_host_s[NI_MAXHOST];
    char l_port[NI_MAXSERV];
    getnameinfo((struct sockaddr*)&sin, sizeof(sin), l_host_s, NI_MAXHOST,
                l_port, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);

    printf("Listening on %s port %s\n", l_host_s, l_port);
    evconnlistener_set_error_cb(listener, accept_error_cb);

    return event_base_dispatch(base);
}