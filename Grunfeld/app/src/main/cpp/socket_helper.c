#include "socket_helper.h"

SockFactoryRes CreateSocket(SockFamily fam, SockType sockType, const char* address, int port, const char* sunPath) {
    int sock = socket(fam, sockType, 0);

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
    } else {
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
    }
}