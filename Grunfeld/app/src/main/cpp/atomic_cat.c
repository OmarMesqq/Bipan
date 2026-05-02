#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <string.h>
#include <time.h>

#include "atomic_cat.h"

// Force the compiler to remove padding
struct __attribute__((packed)) log_header {
    uint8_t id;          // Offset 0
    uint16_t tid;        // Offset 1
    uint32_t tv_sec;     // Offset 3
    uint32_t tv_nsec;    // Offset 7
}; // Total size: 11 bytes

static const char* LOGCAT_SOCK_PATH = "/dev/socket/logdw";

void write_to_logcat_async(android_LogPriority prio, const char* tag, const char* msg) {
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    // Note: The leading '\0' makes it an abstract socket namespace address but logdw is usually a filesystem node.
    strncpy(addr.sun_path, LOGCAT_SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return;
    }

    // Prepare Header
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);

    struct log_header header;
    header.id = 0; // 0 = LOG_ID_MAIN
    header.tid = (uint16_t)gettid();
    header.tv_sec = (uint32_t)now.tv_sec;
    header.tv_nsec = (uint32_t)now.tv_nsec;

    uint8_t priority = (uint8_t) prio;

    // Use 5 vectors for the atomic write
    struct iovec vec[5];
    vec[0].iov_base = &header;
    vec[0].iov_len = sizeof(header);
    vec[1].iov_base = &priority;
    vec[1].iov_len = 1;
    vec[2].iov_base = (void*)tag;
    vec[2].iov_len = strlen(tag) + 1;
    vec[3].iov_base = (void*)msg;
    vec[3].iov_len = strlen(msg) + 1;

    writev(fd, vec, 4);

    close(fd);
}