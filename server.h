#ifndef ADBCAT_SERVER_H
#define ADBCAT_SERVER_H

#include <event2/listener.h>

int start_server(struct event_base *base);

#endif //ADBCAT_SERVER_H
