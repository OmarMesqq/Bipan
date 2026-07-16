#ifndef SHARED_IPC_HPP
#define SHARED_IPC_HPP
#include <sys/types.h>

#include <cstdint>

#include "compile_time_flags.hpp"

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

#ifdef TRAP_EXPERIMENTAL_SYSCALLS
  // process_vm_readv and process_vm_writev info
  uintptr_t vm_iov_addr[4];
  size_t vm_iov_len[4];
  int vm_iov_count;
#endif
} SharedIPC;

#endif