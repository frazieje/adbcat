#ifndef ADBCAT_ADBCAT_H
#define ADBCAT_ADBCAT_H

#define SESSION_KEY_SIZE 16
#define MAGIC_BYTES_SIZE 8
#define SESSION_TYPE_SIZE 6
#define SESSION_TYPE_SERVER "SERVER"
#define SESSION_TYPE_CLIENT "CLIENT"

#define MAX_INPUT_BUFFER_SIZE (512*1024)
#define MAX_OUTPUT_BUFFER_SIZE (512*1024)

unsigned char MAGIC_BYTES[] = { 15, 7, 20, 1, 3, 2, 4, 1};
unsigned char EMPTY_SESSION[SESSION_KEY_SIZE];

enum adbcat_type { gateway, client, server };

#endif //ADBCAT_ADBCAT_H
