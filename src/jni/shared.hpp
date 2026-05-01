#ifndef BIPAN_SHARED_H
#define BIPAN_SHARED_H

#include <android/log.h>

#include <string>

#define TAG "Bipan"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Globals populated in entrypoint

// Used in signal handler for checking if app is reading virtual filesystem
extern char safe_proc_pid_path[64];
// Used in hooks module to apply PC-relative seccomp in the JNI tripwires
extern uintptr_t g_bipan_lib_start;
extern uintptr_t g_bipan_lib_end;

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

inline bool starts_with(const char* str, const char* prefix) {
  return strncmp(str, prefix, strlen(prefix)) == 0;
}

inline void write_to_char_buf(char* dest, const char* src, size_t len) {
  for (size_t i = 0; i < len; i++) {
    dest[i] = src[i];
  }
}

inline size_t local_strlen(const char* s) {
  size_t len = 0;
  while (s[len]) len++;
  return len;
}

inline const char* local_strstr(const char* haystack, const char* needle) {
  if (!*needle) return haystack;
  for (; *haystack; haystack++) {
    if (*haystack == *needle) {
      const char *h = haystack, *n = needle;
      while (*h && *n && *h == *n) {
        h++;
        n++;
      }
      if (!*n) return haystack;
    }
  }
  return nullptr;
}

inline const char* local_strchr(const char* s, int c) {
  while (*s) {
    if (*s == (char)c) return s;
    s++;
  }
  return nullptr;
}

inline int local_atoi(const char* s) {
  if (!s) return 0;

  int res = 0;
  int sign = 1;

  // 1. Skip leading whitespace
  while (*s == ' ' || *s == '\t' || *s == '\n' ||
         *s == '\r' || *s == '\f' || *s == '\v') {
    s++;
  }

  // 2. Handle optional sign
  if (*s == '-') {
    sign = -1;
    s++;
  } else if (*s == '+') {
    s++;
  }

  // 3. Process digits and stop at the first non-digit
  while (*s >= '0' && *s <= '9') {
    res = res * 10 + (*s - '0');
    s++;
  }

  return res * sign;
}

#endif
