#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <android/log.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/**
 * Credits to:
 * https://cs.android.com/android/platform/superproject/+/android-latest-release:bionic/libc/async_safe/async_safe_log.cpp
 */

#define LOGCAT_SOCKET_PATH "/dev/socket/logdw"

// Force the compiler to remove padding
struct __attribute__((packed)) log_header {
  uint8_t id;        // Offset 0
  uint16_t tid;      // Offset 1
  uint32_t tv_sec;   // Offset 3
  uint32_t tv_nsec;  // Offset 7
};  // Total size: 11 bytes

static inline void write_to_logcat_raw(android_LogPriority prio, const char* tag, const char* msg) {
  int fd = (int)arm64_raw_syscall(__NR_socket, AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, 0, 0, 0);
  if (fd < 0) {
    return;
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, LOGCAT_SOCKET_PATH, sizeof(addr.sun_path) - 1);

  if (arm64_raw_syscall(__NR_connect, fd, (long)&addr, sizeof(addr), 0, 0, 0) < 0) {
    arm64_raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
    return;
  }

  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);

  struct log_header header;
  header.id = 0;  // MAIN
  header.tid = (uint16_t)gettid();
  header.tv_sec = (uint32_t)now.tv_sec;
  header.tv_nsec = (uint32_t)now.tv_nsec;

  uint8_t priority = (uint8_t)prio;

  struct iovec vec[4];
  vec[0].iov_base = &header;
  vec[0].iov_len = sizeof(header);
  vec[1].iov_base = &priority;
  vec[1].iov_len = 1;
  vec[2].iov_base = (void*)tag;
  vec[2].iov_len = strlen(tag) + 1;
  vec[3].iov_base = (void*)msg;
  vec[3].iov_len = strlen(msg) + 1;

  // Atomic write to socket
  arm64_raw_syscall(__NR_writev, fd, (long)vec, 4, 0, 0, 0);
  arm64_raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
}

// 3. The Public Formatted Function
inline void write_to_logcat_async(android_LogPriority prio, const char* tag, const char* fmt, ...) {
  char buffer[1024];  // Local stack buffer, no malloc

  va_list args;
  va_start(args, fmt);
  // Format the string into our local buffer
  vsnprintf(buffer, sizeof(buffer), fmt, args);
  va_end(args);

  write_to_logcat_raw(prio, tag, buffer);
}

#endif