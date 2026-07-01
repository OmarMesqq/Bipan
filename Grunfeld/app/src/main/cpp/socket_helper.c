#include "socket_helper.h"

#include <string.h>
#include <unistd.h>
#include <stdlib.h>

SockFactoryRes* CreateSocket(SockFamily fam, SockType sockType, const char* address, int port, const char* sunPath, SockProto proto) {
    int sock = socket((int)fam, (int)sockType, (int)proto);
    if (sock == -1) {
        return NULL;
    }

    // Allocate memory on the heap
    SockFactoryRes* res = malloc(sizeof(SockFactoryRes));
    if (res == NULL) {
        close(sock); // Clean up the socket descriptor if malloc fails
        return NULL;
    }

    // Initialize the common elements
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
    } else if (fam == Unix) {
        struct sockaddr_un sasUn = {
                .sun_family = AF_UNIX
        };
        strncpy(sasUn.sun_path, sunPath, sizeof(sasUn.sun_path)-1);

        res->sas.sasUn = sasUn;
        return res;
    } else {
        struct sockaddr_nl sasNetlink;
        memset(&sasNetlink, 0, sizeof(sasNetlink));
        sasNetlink.nl_family = Netlink;
        sasNetlink.nl_pid = (__u32) getpid();
        sasNetlink.nl_groups = 0;

        res->sas.sasNetlink = sasNetlink;
        return res;
    }
}
