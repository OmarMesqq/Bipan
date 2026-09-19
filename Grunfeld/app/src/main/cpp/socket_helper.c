#include "socket_helper.h"

#include <string.h>
#include <unistd.h>
#include <stdlib.h>

SockFactoryRes* CreateSocket(SockFamily fam, SockType sockType, const char* address, int port) {
    int sock = socket((int)fam, (int)sockType, 0);
    if (sock == -1) {
        return NULL;
    }

    SockFactoryRes* res = malloc(sizeof(SockFactoryRes));
    if (res == NULL) {
        close(sock);
        return NULL;
    }

    // Common elements
    res->sock = sock;
    res->fam = fam;

    if (fam == IPv4) {
        struct sockaddr_in sas4 = {
                .sin_family = (__kernel_sa_family_t) fam,
                .sin_port = htons(port)
        };
        inet_pton((int)fam, address, &sas4.sin_addr);

        res->sas.sas4 = sas4;
        return res;
    } else if (fam == IPv6) {
        struct sockaddr_in6 sas6 = {
                .sin6_family = (unsigned short int) fam,
                .sin6_port = htons(port)
        };
        inet_pton((int)fam, address, &sas6.sin6_addr);

        res->sas.sas6 = sas6;
        return res;
    } else {
        return NULL;
    }
}
