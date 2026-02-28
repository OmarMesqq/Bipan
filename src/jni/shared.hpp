#ifndef BIPAN_SHARED_H
#define BIPAN_SHARED_H

#include <android/log.h>

#include <string>

#define TAG "Bipan"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/**
 * MAGIC NUMBER:
 * 
 * So far, most syscalls I've intercepted only use 5 arguments +
 * NR number. Apparently, you can do an "if" check in the seccomp
 * filter as to allow/trap the offenders exclusively
 * based on an arbitrary value.
 */
#define SECCOMP_BYPASS 0xBADB01

// #define BROKER_ARCH

#ifdef BROKER_ARCH
enum BROKER_STATUS {
  IDLE = 0,
  REQUEST_SYSCALL = 1,
  BROKER_ANSWERED = 2
};

typedef struct {
  volatile int status;

  int nr;  // syscall number

  // arguments
  long arg0;
  char path[256];  // arg1 is a string pointer, so this takes its contents
  long arg2, arg3, arg4, arg5;

  long ret;  // return value provided by kernel
} SharedIPC;

/**
 * The declarations below are initialized once in Bipan's Zygote injection:
 * `bipan.cpp`
 */

/**
 * IPC memory map between main process
 * and the Broker.
 *
 * This allows the former to send syscall arguments
 * and get its results back.
 */
extern SharedIPC* ipc_mem;

/**
 * Socket pair for which allows the Broker
 * to pass and "transform" FDs in its address space to
 * valid ones in the main process.
 */
extern int sv[2];
#endif

// For traversing /proc/<PID>/maps
extern char safe_proc_pid_path[64];

inline bool starts_with(const char* str, const char* prefix) {
  return strncmp(str, prefix, strlen(prefix)) == 0;
}

#endif
