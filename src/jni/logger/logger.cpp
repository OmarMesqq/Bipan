#include "logger/logger.hpp"

#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <syscall.h>
#include <time.h>

#include <cstdio>

#include "as_safe_string.hpp"
#include "common_utils.hpp"

#define LOGCAT_SOCKET_PATH "/dev/socket/logdw"

static constexpr const char* TAG = "BipanLogger";

/**
 * Credits to the amazing AOSP team:
 * https://cs.android.com/android/platform/superproject/+/android-latest-release:bionic/libc/async_safe/async_safe_log.cpp
 */

// Force the compiler to remove padding
struct __attribute__((packed)) log_header {
  uint8_t id;        // Offset 0
  uint16_t tid;      // Offset 1
  uint32_t tv_sec;   // Offset 3
  uint32_t tv_nsec;  // Offset 7
};  // Total size: 11 bytes

static thread_local int g_log_fd = -1;

static inline void write_to_logcat_raw(android_LogPriority prio, const char* tag, const char* msg);

bool initializeLogger() {
  if (g_log_fd != -1) {
    return true;
  }

  int fd = (int)raw_syscall(__NR_socket, AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, 0, 0, 0);
  if (fd < 0) {
    return false;
  }

  struct sockaddr_un addr;
  local_memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  local_strncpy(addr.sun_path, LOGCAT_SOCKET_PATH, sizeof(addr.sun_path) - 1);

  if (raw_syscall(__NR_connect, fd, (long)&addr, sizeof(addr), 0, 0, 0) < 0) {
    raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
    return false;
  }

  g_log_fd = fd;
  return true;
}

bool destroyLogger() {
  int fd = g_log_fd;
  g_log_fd = -1;

  if (fd == -1) {
    return true;
  }

  int ret = (int)raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
  if (ret != 0) {
    return false;
  }
  return true;
}

int getLogcatFd() {
  return g_log_fd;
}

/**
 * Writes a message to Android's `logcat` in an AS-safe way
 */
void write_to_logcat_async(android_LogPriority prio, const char* tag, const char* fmt, ...) {
  if (g_log_fd == -1) {
    return;
  }

  if (!tag || !fmt) {
    write_to_logcat_raw(ANDROID_LOG_ERROR, TAG, "Got bad input for logging");
    return;
  }

  char buffer[1024] = {0};

  // Skip AS-unsafe vsnprintf if no formatting in passed string
  if (!local_strstr(fmt, "\%")) {
    write_to_logcat_raw(prio, tag, fmt);
    return;
  }

  /**
   * TODO:
   * Welp, this is from libc. Probably not AS-safe :/
   * Formats the string into our local buffer
   */
  va_list args;
  va_start(args, fmt);
  vsnprintf(buffer, sizeof(buffer), fmt, args);
  va_end(args);

  write_to_logcat_raw(prio, tag, buffer);
}

static inline void write_to_logcat_raw(android_LogPriority prio, const char* tag, const char* msg) {
  if (g_log_fd == -1) {
    return;
  }

  struct timespec now;
  raw_syscall(__NR_clock_gettime, CLOCK_REALTIME, (long)&now, 0, 0, 0, 0);

  uint16_t tid = (uint16_t)raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);

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
  raw_syscall(__NR_writev, g_log_fd, (long)vec, 4, 0, 0, 0);
}
