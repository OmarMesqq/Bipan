#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "utils.hpp"

#define LOGCAT_SOCKET_PATH "/dev/socket/logdw"

// Force the compiler to remove padding
struct __attribute__((packed)) log_header {
  uint8_t id;        // Offset 0
  uint16_t tid;      // Offset 1
  uint32_t tv_sec;   // Offset 3
  uint32_t tv_nsec;  // Offset 7
};  // Total size: 11 bytes

static int g_log_fd = -1;

/**
 * Doing unbuffered I/O and socket creation/destruction for every log
 * is a bad idea.
 *
 * TODO: buffer messages with prio < FATAL, otherwise write directly to logcat
 */
static inline void write_to_logcat_raw(android_LogPriority prio, const char* tag, const char* msg) {
  if (g_log_fd < 0) {
    int fd = (int)arm64_raw_syscall(__NR_socket, AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, 0, 0, 0);
    if (fd < 0) {
      return;
    }

    struct sockaddr_un addr;
    local_memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    local_strncpy(addr.sun_path, LOGCAT_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (arm64_raw_syscall(__NR_connect, fd, (long)&addr, sizeof(addr), 0, 0, 0) < 0) {
      arm64_raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
      return;
    }
    g_log_fd = fd;  // Store for reuse
  }

  struct timespec now;
  arm64_raw_syscall(__NR_clock_gettime, CLOCK_REALTIME, (long)&now, 0, 0, 0, 0);

  uint16_t tid = (uint16_t)arm64_raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);

  struct log_header header;
  header.id = 0;  // MAIN
  header.tid = tid;
  header.tv_sec = (uint32_t)now.tv_sec;
  header.tv_nsec = (uint32_t)now.tv_nsec;

  uint8_t priority = (uint8_t)prio;

  struct iovec vec[4];
  vec[0].iov_base = &header;
  vec[0].iov_len = sizeof(header);

  vec[1].iov_base = &priority;
  vec[1].iov_len = 1;

  vec[2].iov_base = (void*)tag;
  vec[2].iov_len = local_strlen(tag) + 1;

  vec[3].iov_base = (void*)msg;
  vec[3].iov_len = local_strlen(msg) + 1;

  // Atomic write to socket
  arm64_raw_syscall(__NR_writev, g_log_fd, (long)vec, 4, 0, 0, 0);
}

/**
 * Writes a message to Android Logcat in an AS-safe way
 *
 * Credits to https://cs.android.com/android/platform/superproject/+/android-latest-release:bionic/libc/async_safe/async_safe_log.cpp
 */
inline void write_to_logcat_async(android_LogPriority prio, const char* tag, const char* fmt, ...) {
  char buffer[1024];  // Local stack buffer, no heap

  /**
   * Welp, this is from libc. Probably not AS-safe :/
   * Formats the string into our local buffer
   */
  va_list args;
  va_start(args, fmt);
  vsnprintf(buffer, sizeof(buffer), fmt, args);
  va_end(args);

  write_to_logcat_raw(prio, tag, buffer);
}

#endif