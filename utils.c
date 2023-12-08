#ifdef __linux__
#include <bsd/stdlib.h>
#endif
#ifdef _WIN32
#define _CRT_RAND_S
#endif
#include <stdlib.h>
#include <utils.h>
#include <adbcat.h>
#include <string.h>
#include <netdb.h>

void gen_session_key(unsigned char *target, int length) {
    int i;
    for (i = 0; i < length; i++)
    {
#ifdef __unix__
        target[i] = arc4random();
#endif
#ifdef _WIN32
        int rand;
        rand_s(&rand);
        target[i] = rand;
#endif
    }
}

void get_session_key_str(unsigned char *session_key, char *target) {
    for (int i = 0; i < SESSION_KEY_SIZE; i++) {
        sprintf(&target[i*2], "%02x", (unsigned int)session_key[i]);
    }
    target[SESSION_KEY_SIZE * 2] = '\0';
}


void address_to_str(struct sockaddr *sin, int socklen, char *dest, size_t max_length) {
    char host[NI_MAXHOST + 1];
    char port[NI_MAXSERV + 1];
    char result[NI_MAXHOST + NI_MAXHOST + 1];
    getnameinfo(sin, socklen, host, NI_MAXHOST, port, NI_MAXSERV,
                NI_NUMERICHOST | NI_NUMERICSERV);
    sprintf(result, "%s:%s", host, port);

    memcpy(dest, result, MIN(strlen(result) + 1, max_length));
}