#ifndef BIPAN_SHARED_H
#define BIPAN_SHARED_H

#include <android/log.h>

#include <atomic>

#define TAG "Bipan"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

enum BROKER_STATUS {
  IDLE = 0,
  APP_LOADING_DATA = 1,
  REQUEST_SYSCALL = 2,
  BROKER_ANSWERED = 3
};

// Shared memory structure
struct SharedIPC {
  std::atomic<BROKER_STATUS> state;

  std::atomic<bool> isTarget;
  std::atomic<uintptr_t> pc;
  std::atomic<uintptr_t> lr;

  // Syscall data
  int syscall_no;
  long arg0, arg1, arg2, arg3, arg4, arg5;
  long return_value;

  // bridge for marshalling ptr data across the boundary
  char buffer[8192];
};

/**
 * Pointer to our shared memory region
 * Thanks to C++17, I can mark this as
 * inline and (hopefully) all TUs
 * get the same address
 */
inline SharedIPC* ipc_mem = nullptr;

#endif