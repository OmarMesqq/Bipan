#ifndef BIPAN_SHARED_H
#define BIPAN_SHARED_H

#include <string>

#define TAG "Bipan"

// Globals populated in entrypoint

// Used in signal handler for checking if app is reading virtual filesystem
extern char safe_proc_pid_path[64];
// Used in hooks module to apply PC-relative seccomp in the JNI tripwires
extern uintptr_t g_bipan_lib_start;
extern uintptr_t g_bipan_lib_end;

extern char package_name[256];

enum CompanionCommand {
  CMD_FETCH_TARGETS = 1,
  CMD_START_BROKER = 2
};

enum BROKER_STATUS {
  IDLE = 0,
  REQUEST_SYSCALL = 1,
  BROKER_ANSWERED = 2
};

enum IpcAction {
  ACTION_EXECUTE_NATIVE = 1,
  ACTION_USE_RET = 2,
  ACTION_RECV_FD = 3,
  ACTION_EXECUTE_AND_SCRUB_SOCK = 4
};

typedef struct {
  volatile int lock;
  volatile int status;

  uintptr_t caller_pc;
  pid_t target_pid;

  int nr;  // syscall number
  long arg0, arg1, arg2, arg3, arg4, arg5;

  // Payloads to cross the process boundary
  char string_payload[256];     // Paths (/sbin/su, etc)
  uint8_t struct_payload[128];  // sockaddrs
  uint8_t out_buffer[512];      // Returned data (uname, readlinkat)

  int action;
  long ret;  // return value provided by kernel
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
 * Socket pair for which allows the Broker
 * to pass and "transform" FDs in its address space to
 * valid ones in the main process.
 */
extern int sv[2];

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
