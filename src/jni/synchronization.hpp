#ifndef SYNCHRONIZATION_HPP
#define SYNCHRONIZATION_HPP

#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "logger.hpp"
#include "shared.hpp"
#include "utils.hpp"

/**
 * The Broker calls this to "teleport" an FD to the Target.
 */
inline void send_fd(int socket, int fd) {
  struct msghdr msg = {};
  char buf[CMSG_SPACE(sizeof(int))] = {0};
  char dummy = '!';
  struct iovec io = {.iov_base = &dummy, .iov_len = 1};

  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  *((int*)CMSG_DATA(cmsg)) = fd;

  if (sendmsg(socket, &msg, 0) < 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "send_fd failed! Socket: %d | FD: %d | Err: %s", socket, fd, strerror(errno));
  }
}

/**
 * The Target calls this in the SIGSYS handler to "catch" the FD.
 */
__attribute__((always_inline)) inline int recv_fd(int socket) {
  struct msghdr msg;
  my_memset(&msg, 0, sizeof(msg));  // Freestanding initialization

  struct cmsghdr* cmsg;
  char buf[CMSG_SPACE(sizeof(int))];
  my_memset(buf, 0, sizeof(buf));

  char dummy[1];
  struct iovec io = {.iov_base = dummy, .iov_len = sizeof(dummy)};

  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);

  // Use raw syscall instead of libc recvmsg!
  if (arm64_raw_syscall(__NR_recvmsg, socket, (long)&msg, 0, 0, 0, 0) <= 0) {
    return -1;
  }

  cmsg = CMSG_FIRSTHDR(&msg);
  if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) {
    return -1;
  }

  // The kernel has now placed a NEW FD into our table! Extract it.
  return *((int*)CMSG_DATA(cmsg));
}

/**
 * Puts the thread to sleep IF the value at *addr equals 'expected'
 */
__attribute__((always_inline)) inline void futex_wait(volatile int* addr, int expected) {
  arm64_raw_syscall(__NR_futex, (long)addr, FUTEX_WAIT, expected, 0, 0, 0);
}

/**
 * Wakes up exactly 1 thread that is sleeping on *addr
 */
__attribute__((always_inline)) inline void futex_wake(volatile int* addr) {
  arm64_raw_syscall(__NR_futex, (long)addr, FUTEX_WAKE, 1, 0, 0, 0);
}

static volatile int ipc_lock_state = 0;

// Async-signal-safe lock
inline void lock_ipc() {
  // Writes 1 and returns the old value.
  // If it returns 1, it was already locked, so we sleep on the futex.
  while (__sync_lock_test_and_set(&ipc_lock_state, 1)) {
    futex_wait(&ipc_lock_state, 1);
  }
}

// Async-signal-safe unlock
inline void unlock_ipc() {
  __sync_lock_release(&ipc_lock_state);  // sets back to 0 atomically
  futex_wake(&ipc_lock_state);           // wakes up the next waiting thread
}

#define IN_USE 0
#define FREE_TO_GO 1

static volatile int lock = FREE_TO_GO;
inline void* atomic_compare(void* arg) {
  volatile int* addr = &lock;
  int expected = 0;
  int desired = 1;
  asm goto(
      "cas %w0, %w1, [%2]\n\t"
      "cbz %w0, %l[first]"
      : "+r"(expected)
      : "r"(desired), "r"(addr)
      : "memory"
      : first);
  return NULL;
first:
  return NULL;
}

#endif
