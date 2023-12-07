#ifdef __linux__
#include <bsd/stdlib.h>
#endif
#ifdef _WIN32
#define _CRT_RAND_S
#endif
#include <stdlib.h>
#include <utils.h>

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