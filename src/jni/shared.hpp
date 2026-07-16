#ifndef BIPAN_SHARED_H
#define BIPAN_SHARED_H

#include <jni.h>

#include <string>
#include <unordered_set>

#define TAG "Bipan"
#define BIPAN_PANIC() arm64_raw_syscall(__NR_exit_group, -1, 0, 0, 0, 0, 0)
// #define DEBUG
// #define VERBOSE_LOGGING
// #define EXPERIMENTAL
// #define BROKER_EXTENDED_LOGGING

// Globals populated in entrypoint

// Used in hooks module
extern uintptr_t g_bipan_lib_start;
extern uintptr_t g_bipan_lib_end;
extern char g_package_name[256];
extern jclass g_bipan_java_class;
extern std::unordered_set<std::string> g_telephony_spoofing_allowlist;

enum CompanionCommand {
  CMD_FETCH_TARGETS = 1,
  CMD_START_BROKER = 2
};

enum BrokerStatus {
  IDLE = 0,
  REQUEST_SYSCALL = 1,
  BROKER_ANSWERED = 2
};

enum IpcAction {
  ACTION_EXECUTE_NATIVE = 1,
  ACTION_USE_RET = 2,
  ACTION_RECV_FD = 3,
  ACTION_EXIT_PROCESS = 4
};

#define MAX_STACK_TRACE 60

typedef struct {
  volatile int lock;
  volatile int status;

  uintptr_t caller_pc;
  uintptr_t caller_fp;
  uintptr_t stack_trace[MAX_STACK_TRACE];

  pid_t target_pid;

  int nr;  // syscall number
  long arg0, arg1, arg2, arg3, arg4, arg5;

  // Payloads to cross the process boundary
  char string_payload[256];     // Paths (/sbin/su, etc)
  int pipefd_payload[2];        // pipe2 1st arg
  uint8_t struct_payload[128];  // sockaddrs
  uint8_t out_buffer[512];      // Returned data (uname, readlinkat)

  int action;
  long ret;  // return value provided by kernel

  char package_name[256];

#ifdef DEBUG
  // process_vm_readv and process_vm_writev info
  uintptr_t vm_iov_addr[4];
  size_t vm_iov_len[4];
  int vm_iov_count;
#endif
} SharedIPC;

/**
 * IPC memory map between main process
 * and the Broker.
 *
 * This allows the former to send syscall arguments
 * and get its results back.
 */
extern SharedIPC* ipc_mem;

/**
 * Android log priority values, in increasing order of priority.
 */
typedef enum android_LogPriority {
  /** For internal use only.  */
  ANDROID_LOG_UNKNOWN = 0,
  /** The default priority, for internal use only.  */
  ANDROID_LOG_DEFAULT, /* only for SetMinPriority() */
  /** Verbose logging. Should typically be disabled for a release apk. */
  ANDROID_LOG_VERBOSE,
  /** Debug logging. Should typically be disabled for a release apk. */
  ANDROID_LOG_DEBUG,
  /** Informational logging. Should typically be disabled for a release apk. */
  ANDROID_LOG_INFO,
  /** Warning logging. For use with recoverable failures. */
  ANDROID_LOG_WARN,
  /** Error logging. For use with unrecoverable failures. */
  ANDROID_LOG_ERROR,
  /** Fatal logging. For use when aborting. */
  ANDROID_LOG_FATAL,
  /** For internal use only.  */
  ANDROID_LOG_SILENT, /* only for SetMinPriority(); must be last */
} android_LogPriority;

#endif
