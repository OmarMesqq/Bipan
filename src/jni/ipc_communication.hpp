#ifndef IPC_COMMUNICATION_HPP
#define IPC_COMMUNICATION_HPP

#include <linux/limits.h>
#include <sys/types.h>

#include <cstdint>

#include "compile_time_flags.hpp"

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
#define MAX_STACK_TRACE 300

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
  char string_payload[256];      // Paths (/sbin/su, etc)
  uint8_t struct_payload[128];   // sockaddrs
  uint8_t out_buffer[PATH_MAX];  // Returned data (uname, readlinkat)

  int action;
  long ret;  // return value provided by kernel

#ifdef TRAP_EXPERIMENTAL_SYSCALLS
  // pipe2 1st arg
  int pipefd_payload[2];

  // process_vm_readv and process_vm_writev info
  uintptr_t vm_iov_addr[4];
  size_t vm_iov_len[4];
  int vm_iov_count;
#endif
} SharedIPC;

#endif