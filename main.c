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

int main(int argc, char **argv) {

    struct addrinfo hints;
    struct addrinfo *res_list, *res;
    struct event_base *base;
    char g_port[NI_MAXSERV + 1] = DEFAULT_GATEWAY_PORT;
    char l_port[NI_MAXSERV + 1] = DEFAULT_LOCAL_LISTEN_PORT;
    enum adbcat_type type;
    char usage_str[] = "Usage: %s [-h gateway host] [-u gateway port] [-p local port] [session key | 'gateway']\n";

    char g_host[NI_MAXHOST + 1] = DEFAULT_GATEWAY_HOST; // gateway host

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
                if (strlen(optarg) > NI_MAXSERV) {
                    fprintf(stderr, "gateway port too long\n");
                    exit(EXIT_FAILURE);
                }
                strcpy(l_port, optarg);
                break;
            case 'u':
                if (strlen(optarg) > NI_MAXSERV) {
                    fprintf(stderr, "gateway port too long\n");
                    exit(EXIT_FAILURE);
                }
                strcpy(g_port, optarg);
                break;
            default: /* '?' */
                break;
        }
    }

    int remaining = argc - optind;

    if (remaining == 1) {
        if (strcmp("gateway", argv[optind]) == 0) {
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
        if (strcmp(l_port, DEFAULT_LOCAL_LISTEN_PORT) == 0) {
            strcpy(l_port, DEFAULT_ADB_SERVER_PORT);
        }
    }

    long l_port_i = strtol(l_port, NULL, 10);
    long g_port_i = strtol(g_port, NULL, 10);

    if (l_port_i <= 0 || l_port_i > 65535) {
        fprintf(stderr, "Invalid local port\n");
        return 1;
    }

    if (g_port_i <= 0 || g_port_i > 65535) {
        fprintf(stderr, "Invalid gateway port\n");
        return 1;
    }

    base = event_base_new();
    if (!base) {
        fprintf(stderr, "Couldn't open event base\n");
        return 1;
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    int ret = getaddrinfo(g_host, g_port, &hints, &res_list);
    if (ret != 0) {
        fprintf(stderr, "Error in getaddrinfo: %s\n", gai_strerror(ret));
        return 1;
    }

    if (type != gateway) {
        int sock;

        // try to connect to the provided gateway to make sure it's available
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
            fprintf(stderr, "Could not connect to gateway at %s:%s\n", g_host, g_port);
            return 1;
        }
    } else {
        if (strcmp(l_port, DEFAULT_LOCAL_LISTEN_PORT) == 0) {
            l_port_i = g_port_i;
        }
    }

    switch(type) {
        case gateway:
            return start_gateway(base, (int)l_port_i);
        case client:
            return start_client(
                base,
                (int)l_port_i,
                res->ai_addr,
                res->ai_addrlen,
                session_key
            );
        case server:
            return start_server(base, (int)l_port_i, res->ai_addr, res->ai_addrlen);
        default:
            return EXIT_FAILURE;
    }
}
