#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include "adbcat.h"
#include "utils.h"
#include "gateway.h"
#include "client.h"
#include "server.h"

int main(int argc, char **argv) {
    printf("Starting adbcat v0.2\n");
    struct addrinfo hints;
    struct addrinfo *res_list, *res;
    struct event_base *base;
    char g_port[NI_MAXSERV + 1] = DEFAULT_GATEWAY_PORT;
    char l_port[NI_MAXSERV + 1] = DEFAULT_LOCAL_LISTEN_PORT;
    enum adbcat_type type;
    int enable_cleartext = 0;
    int enable_verbose = 0;
    char usage_str[] = "Usage: %s [-h gateway host] [-u gateway port] [-t gateway cert path (PEM)] [-k gateway key path (PEM)] [-p local port] [session key | 'gateway']\n";

    char g_host[NI_MAXHOST + 1] = DEFAULT_GATEWAY_HOST; // gateway host
    char g_cert_chain[MAX_FILE_PATH] = DEFAULT_GATEWAY_CERT;
    char g_key[MAX_FILE_PATH] = DEFAULT_GATEWAY_KEY;

    unsigned char session_key[SESSION_KEY_SIZE];

    int opt;
    opterr = 0;
    while ((opt = getopt(argc, argv, "h:p:u:t:k:vc")) != -1) {
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
                    fprintf(stderr, "local port too long\n");
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
            case 't':
                if (strlen(optarg) > MAX_FILE_PATH - 1) {
                    fprintf(stderr, "gateway cert path too long\n");
                    exit(EXIT_FAILURE);
                }
                strcpy(g_cert_chain, optarg);
                break;
            case 'k':
                if (strlen(optarg) > MAX_FILE_PATH - 1) {
                    fprintf(stderr, "gateway key path too long\n");
                    exit(EXIT_FAILURE);
                }
                strcpy(g_key, optarg);
                break;
            case 'v':
                enable_verbose = 1;
                break;
            case 'c':
                enable_cleartext = 1;
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
            gateway_config_t config = {
            .port = (int)l_port_i,
            .cert_path = g_cert_chain,
            .key_path = g_key,
            .enable_cleartext = enable_cleartext,
            .enable_verbose = enable_verbose
        };
            return start_gateway(&config);
        case client:
            return start_client(
                (int)l_port_i,
                res->ai_addr,
                res->ai_addrlen,
                session_key,
                enable_cleartext,
                enable_verbose
            );
        case server:
            return start_server((int)l_port_i, res->ai_addr, res->ai_addrlen, enable_cleartext, enable_verbose);
        default:
            return EXIT_FAILURE;
    }
}
