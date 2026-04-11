#include <android/log.h>
#include <errno.h>
#include <jni.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syscall.h>

#define TAG "Grunfeld"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static void get_uname();
static void sigsys_log_handler(int sig, siginfo_t* info, void* void_context);
static void install_sigsys_handler();


JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
  LOGD("Native C bridge initialized. Dumping system info...");

  LOGD("Getting uname BEFORE sigsys handler installation");
  get_uname();

  LOGD("Getting uname AFTER sigsys handler installation");
  install_sigsys_handler();
  get_uname();

  return JNI_VERSION_1_6;
}

static void get_uname() {
  struct utsname buffer = {0};
  long ret;
  asm volatile(
      "mov x0, %[buf] \n\t"   // place `buffer`'s address in x0
      "mov x8, #160   \n\t"   // 160 is the syscall number for uname
      "svc #0         \n\t"   // Supervisor Call
      "mov %[res], x0 \n\t"   // Store return value in ret
      : [res] "=r"(ret)       // Output operand
      : [buf] "r"(&buffer)    // Input operand
      : "x0", "x8", "memory"  // Clobbered registers
  );

  if (ret < 0) {
    if (ret == -EPERM || errno == EPERM) {
      LOGE("uname failed due to Permission Denied (EPERM)");
    } else {
      LOGE("uname failed due to unknown reason (status code: %ld)", ret);
    }
  } else {
    if (ret == 0) {
      LOGD("uname was SUCCESSFUL (status code: %ld)", ret);
    } else {
      LOGD("uname was SUCCESSFUL but returned non-zero (status code: %ld)", ret);
    }

    LOGD("System Name: %s\n", buffer.sysname);
    LOGD("Node Name:   %s\n", buffer.nodename);
    LOGD("Release:     %s\n", buffer.release);
    LOGD("Version:     %s\n", buffer.version);
    LOGD("Machine:     %s\n", buffer.machine);
    LOGD("Domain Name:     %s\n", buffer.domainname);
  }
}

static void install_sigsys_handler() {
  struct sigaction sa = {0};
  sa.sa_sigaction = sigsys_log_handler;
  sa.sa_flags = SA_SIGINFO;

  long sigactionRet = syscall(__NR_rt_sigaction, SIGSYS, (long)&sa, 0, 8);
  if (sigactionRet != 0) {
    LOGE("Failed to set SIGSYS handler (errno: %d)", errno);
    return;
  }
  LOGD("Installed SIGSYS handler successfully. Return value: %ld", sigactionRet);
}

static void sigsys_log_handler(int sig, siginfo_t* info, void* void_context) {
  LOGE("Should never reach here...");
  _exit(-1);
}
