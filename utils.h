#ifndef ADBCAT_UTILS_H
#define ADBCAT_UTILS_H

#include <netinet/in.h>

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define ADDRESS_STRING_SIZE (NI_MAXHOST + NI_MAXSERV + 1)

void gen_session_key(unsigned char *target, int length);

void get_session_key_str(char *target, const unsigned char *session_key);

void address_to_str(struct sockaddr *sin, int socklen, char *dest, size_t max_length);

#endif //ADBCAT_UTILS_H
