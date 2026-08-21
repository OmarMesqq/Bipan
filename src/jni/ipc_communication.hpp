#ifndef IPC_COMMUNICATION_HPP
#define IPC_COMMUNICATION_HPP

#include <linux/limits.h>
#include <sys/types.h>

#include <cstdint>

#include "feature_flags.hpp"

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
  ACTION_EXIT_PROCESS = 3
};

/**
 * For stack unwinding at Broker.
 * Yes, large value but 99% of time it won't unwind this much :)
 */
#define MAX_STACK_TRACE 150

#define IPC_PACKAGE_NAME_SIZE 128

typedef struct {
  volatile int lock;
  volatile int status;

  uintptr_t caller_pc;                     // Program counter at time of trap
  uintptr_t caller_fp;                     // Frame Pointer (x29)
  uintptr_t stack_trace[MAX_STACK_TRACE];  // Link Register (x30)

  pid_t target_pid;

  int nr;  // syscall number
  long arg0, arg1, arg2, arg3, arg4, arg5;
  char package_name[IPC_PACKAGE_NAME_SIZE];

  // Paths
  char string_payload[256];
  // Binary data structs (e.g. `sockaddr`s)
  uint8_t struct_payload[128];
  // Data returned by Broker for syscalls like `uname` and `readlinkat`
  uint8_t out_buffer[PATH_MAX];

  int action;
  long ret;  // return value provided by kernel
} SharedIPC;

#endif