#ifndef IPC_LOCK_HPP
#define IPC_LOCK_HPP

#include <linux/futex.h>

#include "synchronization.hpp"

static volatile int ipc_lock_state = 0;

// AS-safe lock
__attribute__((always_inline)) inline void lock_ipc() {
  // Atomically writes 1 and returns the old value
  // if it returns 1, the IPC was already locked, so we sleep on the futex
  while (__sync_lock_test_and_set(&ipc_lock_state, 1)) {
    futex_wait(&ipc_lock_state, 1);
  }
}

// AS-safe unlock
__attribute__((always_inline)) inline void unlock_ipc() {
  __sync_lock_release(&ipc_lock_state);  // sets back to 0 atomically
  futex_wake(&ipc_lock_state);           // wake up the "next" waiting thread
}

#endif