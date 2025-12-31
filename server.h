#ifndef ADBCAT_SERVER_H
#define ADBCAT_SERVER_H

#include <event2/listener.h>

int start_server(
        int adb_server_port,
        struct sockaddr *gateway_addr,
        socklen_t gateway_addr_len,
        int enable_cleartext,
        int enable_verbose
);

#endif //ADBCAT_SERVER_H
