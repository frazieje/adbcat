#ifndef ADBCAT_UTILS_H
#define ADBCAT_UTILS_H

#include <netinet/in.h>

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

void gen_session_key(unsigned char *target, int length);

void get_session_key_str(unsigned char *session_key, char *target);

void address_to_str(struct sockaddr *sin, int socklen, char *dest, size_t max_length);

#endif //ADBCAT_UTILS_H
