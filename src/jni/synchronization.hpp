#ifndef SYNCHRONIZATION_HPP
#define SYNCHRONIZATION_HPP

#include <linux/futex.h>
#include <sys/syscall.h>
#include <time.h>
#include <utils.hpp> // TODO: didnt want to include this...

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

#endif
