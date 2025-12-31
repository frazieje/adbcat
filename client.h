#ifndef ADBCAT_CLIENT_H
#define ADBCAT_CLIENT_H

#include <event2/listener.h>

int start_client(
        int port,
        struct sockaddr *gateway_addr,
        socklen_t gateway_addr_len,
        unsigned char *session_key,
        int enable_cleartext,
        int enable_verbose
);

#endif //ADBCAT_CLIENT_H
