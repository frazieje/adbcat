#ifndef ADBCAT_GATEWAY_H
#define ADBCAT_GATEWAY_H
#include <stdint.h>

enum gateway_message_type { gw_msg_forward, gw_msg_close };

typedef struct gateway_message_t {
    enum gateway_message_type type; //
    uint32_t from;
    uint64_t length;
} gateway_message_t;

typedef struct gateway_config_t {
    int port;
    char *cert_path;
    int cert_path_len;
    char *key_path;
    int key_path_len;
    int enable_cleartext;
    int enable_verbose;
} gateway_config_t;

/**
 * Start the gateway. The gateway accepts connections from adbcat servers and clients, and relays data between
 * connections with matching session keys.
 *
 * @param config the gateway config
 */
/*
 * @param base the libevent event_base to listen on
 * @param local_port the local port to listen on
 * @param cert_path path to TLS certificate PEM file
 * @param cert_path_len length of the path to TLS certificate PEM file
 * @param key_path path to TLS key PEM file
 * @param key_path_len length of the path to TLS key PEM file
 * @param enable_cleartext enable cleartext communication. Disabled by default
 */
int start_gateway(gateway_config_t *config);

#endif //ADBCAT_GATEWAY_H
