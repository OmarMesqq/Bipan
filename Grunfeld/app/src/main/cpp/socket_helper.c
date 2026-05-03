#include "socket_helper.h"

#include <string.h>
#include <unistd.h>
#include "shared.h"

SockFactoryRes CreateSocket(SockFamily fam, SockType sockType, const char* address, int port, const char* sunPath, SockProto proto) {
    int sock = socket(fam, sockType, proto);
    if (sock == -1) {
        longjmp(jump_buffer, 1);
    }

    if (fam == IPv4) {
        struct sockaddr_in sas4 = {
                .sin_family = fam,
                .sin_port = htons(port)
        };
        inet_pton(fam, address, &sas4.sin_addr);
        SockFactoryRes res = {
                .sock = sock,
                .fam = fam,
                .sas.sas4 = sas4
        };
        return res;
    } else if (fam == IPv6) {
        struct sockaddr_in6 sas6 = {
                .sin6_family = fam,
                .sin6_port = htons(port)
        };
        inet_pton(fam, address, &sas6.sin6_addr);
        SockFactoryRes res = {
                .sock = sock,
                .fam = fam,
                .sas.sas6 = sas6
        };
        return res;
    } else if (fam == Unix) {
        struct sockaddr_un sasUn = {
                .sun_family = AF_UNIX
        };
        strncpy(sasUn.sun_path, sunPath, sizeof(sasUn.sun_path)-1);
        SockFactoryRes res = {
                .sock = sock,
                .fam = fam,
                .sas.sasUn = sasUn
        };
        return res;
    } else {
        struct sockaddr_nl sasNetlink;
        memset(&sasNetlink, 0, sizeof(sasNetlink));
        sasNetlink.nl_family = Netlink;
        sasNetlink.nl_pid = getpid();
        sasNetlink.nl_groups = 0;

        SockFactoryRes res = {
                .sock = sock,
                .fam = fam,
                .sas.sasNetlink = sasNetlink
        };
        return res;
    }
}