#include "atomic_cat.h"

// Android log priorities
#define ASYNC_LOG_INFO 4

void write_to_logcat_async(const char* tag, const char* msg) {
    // 1. Open the log daemon socket
    // We use SOCK_DGRAM and SOCK_CLOEXEC for safety
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/dev/socket/logdw", sizeof(addr.sun_path) - 1);

    // 2. Connect to the log daemon
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return;
    }

    // 3. Prepare the structured packet
    // Logcat expects: [Log ID (1 byte)] [Priority (1 byte)] [Tag\0] [Message\0]
    char log_id = 0; // 0 = Main Log
    char priority = ASYNC_LOG_INFO;

    struct iovec vec[4];
    vec[0].iov_base = &log_id;
    vec[0].iov_len = 1;
    vec[1].iov_base = &priority;
    vec[1].iov_len = 1;
    vec[2].iov_base = (void*)tag;
    vec[2].iov_len = strlen(tag) + 1; // Include null terminator
    vec[3].iov_base = (void*)msg;
    vec[3].iov_len = strlen(msg) + 1; // Include null terminator

    // 4. Use writev for an atomic, async-safe write
    writev(fd, vec, 4);

    close(fd);
}