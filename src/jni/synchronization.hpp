#ifndef SYNCHRONIZATION_HPP
#define SYNCHRONIZATION_HPP

#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <linux/futex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "shared.hpp"

/**
 * The Broker calls this to "teleport" an FD to the Target.
 */
void send_fd(int socket, int fd) {
  struct msghdr msg = {0};
  struct cmsghdr* cmsg;
  char buf[CMSG_SPACE(sizeof(int))];  // Space for the FD payload
  memset(buf, 0, sizeof(buf));

  // Linux requires at least 1 byte of real data to send control messages
  struct iovec io = {
    .iov_base = (void*)"!",     // cast as C++ is annoying with type safety
    .iov_len = 1
    };

  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);

  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;  // This is the "Magic" flag for FDs
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));

  *((int*)CMSG_DATA(cmsg)) = fd;

  if (sendmsg(socket, &msg, 0) < 0) {
    LOGE("send_fd failed: %s (errno: %d) | FD to send: %d | Socket: %d\n",
            strerror(errno), errno, fd, socket);
  }
}

/**
 * The Target calls this in the SIGSYS handler to "catch" the FD.
 */
int recv_fd(int socket) {
  struct msghdr msg = {0};
  struct cmsghdr* cmsg;
  char buf[CMSG_SPACE(sizeof(int))];
  char dummy[1];
  struct iovec io = {.iov_base = dummy, .iov_len = sizeof(dummy)};

  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);

  if (recvmsg(socket, &msg, 0) <= 0) {
    return -1;
  }

  cmsg = CMSG_FIRSTHDR(&msg);
  if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) {
    return -1;
  }

  // The kernel has now placed a NEW FD into our table!
  return *((int*)CMSG_DATA(cmsg));
}

// Puts the thread to sleep IF the value at *addr equals 'expected'
static inline void futex_wait(volatile int* addr, int expected) {
  syscall(__NR_futex, (int*)addr, FUTEX_WAIT, expected, NULL, NULL, 0);
}

// Wakes up exactly 1 thread that is sleeping on *addr
static inline void futex_wake(volatile int* addr) {
  syscall(__NR_futex, (int*)addr, FUTEX_WAKE, 1, NULL, NULL, 0);
}

#endif
