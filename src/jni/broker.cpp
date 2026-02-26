#include "broker.hpp"

#include <unistd.h>
#include <sys/prctl.h>

#include "shared.hpp"
#include "synchronization.hpp"

static inline long arm64_raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5);

void startBroker(int sock) {
  prctl(PR_SET_NAME, "BipanBroker", 0, 0, 0);

  while (true) {
    while (ipc_mem->status != REQUEST_SYSCALL) {
      futex_wait(&ipc_mem->status, ipc_mem->status);
    }
    __sync_synchronize();

    long ret = arm64_raw_syscall(
        ipc_mem->nr,
        ipc_mem->arg0,
        (long)ipc_mem->path,
        ipc_mem->arg2,
        ipc_mem->arg3,
        ipc_mem->arg4,
        ipc_mem->arg5);

    ipc_mem->ret = ret;
    if (ret >= 0) {
      send_fd(sock, (int)ret);  // Teleport it
      close((int)ret);          // Close broker's local copy to prevent -24
      ipc_mem->ret = 0;         // Signal success to target
    } else {
      ipc_mem->ret = ret;  // Signal error to target
    }

    __sync_synchronize();
    ipc_mem->status = BROKER_ANSWERED;
    futex_wake(&ipc_mem->status);
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