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

#define TAG "Grunfeld"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static void get_uname();
static void sigsys_log_handler(int sig, siginfo_t* info, void* void_context);
static void install_sigsys_handler();
static void scan_memory_maps();
static void demo_fork_execve();

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
  LOGD("Native C bridge initialized. Dumping system info...");

  // uname + signal handler testing
  LOGD("Getting uname BEFORE sigsys handler installation");
  get_uname();
  LOGD("Getting uname AFTER sigsys handler installation");
  install_sigsys_handler();
  get_uname();

  // execve/execveat testing
  demo_fork_execve();

  // /proc/self/maps hiding
  scan_memory_maps();

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

static void demo_fork_execve() {
  pid_t pid = fork();
  if (pid == 0) {
    sleep(1);
    LOGD("Child: becoming '/sytem/bin/echo'...\n");
    sleep(1);

    char* args[] = {"/system/bin/echo", "Hello", NULL};
    char* env[] = {NULL};

    if (execve("/system/bin/echo", args, env) == -1) {
      if (errno == EPERM) {  // Sandbox worked?
        LOGE("Child: received permission denied (EPERM)");
        _exit(13);
      }
    }
    LOGE("Child: 'execve' failed due to UNKNOWN reason");
    _exit(1);
  } else {
    int status;
    LOGD("Parent: Waiting for child (PID %d) to finish...", pid);

    if (waitpid(pid, &status, 0) == -1) {
      LOGE("Parent: waitpid failed: %s", strerror(errno));
    } else {
      if (WIFSIGNALED(status)) {  // The process was terminated by a signal
        int sig = WTERMSIG(status);
        LOGE("Parent: Child terminated by SIGNAL %d (%s)", sig, strsignal(sig));
      } else if (WIFEXITED(status)) {  // The process exited normally by itself
        int exit_code = WEXITSTATUS(status);
        if (exit_code == 0) {
          LOGD("Parent: Child exited normally (status code %d)", exit_code);
        } else {
          LOGE("Parent: Child exited with FAILURE (status code %d)", exit_code);
        }
      } else {
        LOGE("Parent: Child failed by UNKNOWN cause (status code: %d)", status);
      }
    }
  }
}

static void scan_memory_maps() {
  FILE* fp;
  char line[1024];

  fp = fopen("/proc/self/maps", "r");
  if (fp == NULL) {
    LOGE("Error opening /proc/self/maps");
    return;
  }

  LOGD("----------- Memory mappings below: ---------------------");

  while (fgets(line, sizeof(line), fp)) {
    long long start, end, offset;
    char perms[5];
    int dev_major, dev_minor;
    long inode;
    char path[1024] = {0};  // Initialize to handle anonymous mappings

    // Parse the line
    int fields = sscanf(line, "%llx-%llx %4s %llx %x:%x %ld %1023s",
                        &start, &end, perms, &offset, &dev_major, &dev_minor, &inode, path);

    if (fields < 2) {
      LOGW("scan_memory_maps: sscanf failed to read basic range info. Continuing next line...");
      continue;
    };

    // Skip legit system mappings
    if (strstr(path, "/dev/__properties__") ||
        strncmp(path, "/system", 7) == 0 ||
        strncmp(path, "/metadata", 9) == 0 ||
        strncmp(path, "/apex", 5) == 0 ||
        strncmp(path, "/vendor", 7) == 0) {
      continue;
    }

    LOGD("Range: %llx-%llx | Perms: %s | Path: %s", start, end, perms, path);
  }

  fclose(fp);
  return;
}

static void install_sigsys_handler() {
  struct sigaction sa = {0};
  sa.sa_sigaction = sigsys_log_handler;
  sa.sa_flags = SA_SIGINFO;
  int sigactionRet = sigaction(SIGSYS, &sa, NULL);
  if (sigactionRet != 0) {
    LOGE("failed to set SIGSYS handler (errno: %d)", errno);
    return;
  }
  LOGD("Installed SIGSYS handler successfuly. Return value: %d", sigactionRet);
}

static void sigsys_log_handler(int sig, siginfo_t* info, void* void_context) {
  ucontext_t* ctx = (ucontext_t*)void_context;
  uintptr_t pc = ctx->uc_mcontext.pc;
  uintptr_t lr = ctx->uc_mcontext.regs[30];
  int nr = info->si_syscall;  // syscalls go in x8 in aarch64

  long arg0 = ctx->uc_mcontext.regs[0];
  long arg1 = ctx->uc_mcontext.regs[1];
  long arg2 = ctx->uc_mcontext.regs[2];
  long arg3 = ctx->uc_mcontext.regs[3];
  long arg4 = ctx->uc_mcontext.regs[4];
  long arg5 = ctx->uc_mcontext.regs[5];
  long result = 0;

  switch (nr) {
    case 160: {
      LOGD("Running legit uname");
      break;
    }
    default: {
      LOGE("Got another syscall: %d", nr);
      break;
    }
  }
  result = syscall(nr,
                   ctx->uc_mcontext.regs[0],
                   ctx->uc_mcontext.regs[1],
                   ctx->uc_mcontext.regs[2],
                   ctx->uc_mcontext.regs[3],
                   ctx->uc_mcontext.regs[4],
                   ctx->uc_mcontext.regs[5]);

  ctx->uc_mcontext.regs[0] = result;
}