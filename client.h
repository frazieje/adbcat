#ifndef ADBCAT_CLIENT_H
#define ADBCAT_CLIENT_H

#include <event2/listener.h>

int start_client(struct event_base *base, unsigned char *session_key);

#endif //ADBCAT_CLIENT_H
