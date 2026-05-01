#ifndef SOCKET_HELPER_H
#define SOCKET_HELPER_H

#include <android/log.h>
#include <android/sensor.h>
#include <android/looper.h>
#include <errno.h>
#include <jni.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <sys/utsname.h>
#include <linux/fcntl.h>
#include <time.h>
#include <sys/un.h>
#include "atomic_cat.h"

typedef enum {
    TCP = SOCK_STREAM,
    UDP = SOCK_DGRAM
} SockType;

typedef enum {
    IPv4 = AF_INET,
    IPv6 = AF_INET6,
    Unix = AF_UNIX
} SockFamily;

typedef struct {
    int sock;
    SockFamily fam;
    union {
        struct sockaddr_in sas4;
        struct sockaddr_in6 sas6;
        struct sockaddr_un sasUn;
    } sas;
} SockFactoryRes;


#define RANDOM_EPHEMERAL_PORT 0 // client behavior
#define ARBITRARY_PORT 8080 // server behavior


SockFactoryRes CreateSocket(SockFamily fam, SockType sockType, const char* address, int port, const char* sunPath);

#endif //SOCKET_HELPER_H
