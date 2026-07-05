#ifndef SYNCHRONIZATION_HPP
#define SYNCHRONIZATION_HPP

#include <linux/futex.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/**
 * The app calls this to send an fd to the companion
 */
__attribute__((always_inline)) inline ssize_t send_fd(int socket, int fd) {
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

  ssize_t ret = sendmsg(socket, &msg, 0);
  return ret;
}

/**
 * Called by the companion to capture the sockfd of its end of the socketpair
 */
inline int recv_fd(int socket) {
  struct msghdr msg;
  local_memset(&msg, 0, sizeof(msg));

  struct cmsghdr* cmsg;
  char buf[CMSG_SPACE(sizeof(int))];
  local_memset(buf, 0, sizeof(buf));

  char dummy[1];
  struct iovec io = {.iov_base = dummy, .iov_len = sizeof(dummy)};

  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);

  if (arm64_raw_syscall(__NR_recvmsg, socket, (long)&msg, 0, 0, 0, 0) <= 0) {
    return -1;
  }

  cmsg = CMSG_FIRSTHDR(&msg);
  if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) {
    return -1;
  }

  // The kernel has now placed a new fd into our table: extract it
  return *((int*)CMSG_DATA(cmsg));
}

/**
 * Puts the calling thread to sleep if `*addr` = `expected`
 */
__attribute__((always_inline)) inline void futex_wait(volatile int* addr, int expected) {
  arm64_raw_syscall(__NR_futex, (long)addr, FUTEX_WAIT, expected, 0, 0, 0);
}

/**
 * Puts the calling thread to sleep if `*addr` = `expected` with wake up timeout of `timeout_ms`
 */
__attribute__((always_inline)) inline int futex_wait_timeout(volatile int* addr, int expected, long timeout_ms) {
  struct timespec ts;
  ts.tv_sec = timeout_ms / 1000;
  ts.tv_nsec = (timeout_ms % 1000) * 1000000L;

  return (int)arm64_raw_syscall(
      __NR_futex,
      (long)addr,
      FUTEX_WAIT,
      expected,
      (long)&ts,
      0,
      0);
}

/**
 * Wakes up exactly 1 thread that is sleeping (waiting) on  `*addr`
 */
__attribute__((always_inline)) inline void futex_wake(volatile int* addr) {
  arm64_raw_syscall(__NR_futex, (long)addr, FUTEX_WAKE, 1, 0, 0, 0);
}

static volatile int ipc_lock_state = 0;

// AS-safe lock
inline void lock_ipc() {
  // Atomically writes 1 and returns the old value
  // if it returns 1, the IPC was already locked, so we sleep on the futex
  while (__sync_lock_test_and_set(&ipc_lock_state, 1)) {
    futex_wait(&ipc_lock_state, 1);
  }
}

// AS-safe unlock
inline void unlock_ipc() {
  __sync_lock_release(&ipc_lock_state);  // sets back to 0 atomically
  futex_wake(&ipc_lock_state);           // wake up the "next" waiting thread
}

#endif
