#ifndef SOCKET_HELPER_H
#define SOCKET_HELPER_H

#include <arpa/inet.h>

typedef enum {
    TCP = SOCK_STREAM,
    UDP = SOCK_DGRAM,
} SockType;

typedef enum {
    IPv4 = AF_INET,
    IPv6 = AF_INET6,
} SockFamily;

typedef struct {
    int sock; // fd
    SockFamily fam; // v4 or v6
    union {
        struct sockaddr_in sas4;
        struct sockaddr_in6 sas6;
    } sas; // actual socket struct
} SockFactoryRes;

SockFactoryRes* CreateSocket(SockFamily fam, SockType sockType, const char* address, int port);

#endif //SOCKET_HELPER_H
