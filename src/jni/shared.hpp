#ifndef BIPAN_SHARED_H
#define BIPAN_SHARED_H

#include <android/log.h>

#define TAG "Bipan"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

enum BROKER_STATUS {
  IDLE = 0,
  REQUEST_SYSCALL = 1,
  BROKER_ANSWERED = 2
};

typedef struct {
  volatile int status;

  int nr; // syscall number

  // arguments
  long arg0;
  char path[256];  // arg1 is a string pointer, so this takes its contents
  long arg2, arg3, arg4, arg5;
  
  long ret;     // return value provided by kernel
} SharedIPC;

extern SharedIPC* ipc_mem;


#endif
