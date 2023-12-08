#ifndef ADBCAT_SERVER_H
#define ADBCAT_SERVER_H

#include <event2/listener.h>

int start_server(struct event_base *base, char *g_host, int g_port);

#endif //ADBCAT_SERVER_H
