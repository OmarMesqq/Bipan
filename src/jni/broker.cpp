#include "broker.hpp"

#include <dlfcn.h>
#include <sys/prctl.h>
#include <syscall.h>
#include <unistd.h>

#include <fstream>
#include <sstream>
#include <string>

#include "bipan_shared.hpp"

static inline long arm64_raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5);


void brokerProcessLoop() {
  prctl(PR_SET_NAME, "bipan_broker", 0, 0, 0);
  LOGW("Starting broker loop...");

  while (true) {
    // Spin until app sends a request
    while (
        (ipc_mem->state.load(std::memory_order_acquire) == IDLE) ||
        (ipc_mem->state.load(std::memory_order_acquire) == APP_LOADING_DATA)) {
      usleep(50);
    }

    BROKER_STATUS current_state = ipc_mem->state.load(std::memory_order_acquire);

    if (current_state == REQUEST_SYSCALL) {
      if (ipc_mem->syscall_no == __NR_uname) {
        ipc_mem->return_value = arm64_raw_syscall(
            __NR_uname,
            (long)ipc_mem->buffer,
            0, 0, 0, 0, 0);
      }
    }
    // Tell app we are done
    ipc_mem->state.store(BROKER_ANSWERED, std::memory_order_release);

    // Wait for app to unlock
    while (ipc_mem->state.load(std::memory_order_acquire) == BROKER_ANSWERED) {
      __asm__ volatile("yield" ::: "memory");
    }
  }
}


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wregister"
#pragma clang diagnostic ignored "-Wdeprecated-register"

/**
 * Executes a raw system call on ARM64.
 * Forces the compiler to map arguments to the correct x0-x5 and x8 registers.
 */
static inline long arm64_raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5) {
  std::string syscallName = "Unknown";
  switch (sysno) {
    case __NR_uname:
      syscallName = "uname";
      break;
    case __NR_execve:
      syscallName = "execve";
      break;
    case __NR_execveat:
      syscallName = "execveat";
      break;
  }
  LOGW("Broker: running legit syscall %s", syscallName.c_str());

  register long x8 __asm__("x8") = sysno;
  register long x0 __asm__("x0") = a0;
  register long x1 __asm__("x1") = a1;
  register long x2 __asm__("x2") = a2;
  register long x3 __asm__("x3") = a3;
  register long x4 __asm__("x4") = a4;
  register long x5 __asm__("x5") = a5;

  __asm__ volatile(
      "svc #0\n"
      : "+r"(x0)                                              // Output: x0 will contain the return value
      : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)  // Inputs
      : "memory", "cc"                                        // Clobbers: memory and condition codes might change
  );

  return x0;
}
#pragma clang diagnostic pop
