#include "filter.hpp"

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <syscall.h>
#include <unistd.h>

#include <cerrno>

#include "shared.hpp"

void applySeccomp(uintptr_t lib_start, uintptr_t lib_end) {
  // 1. Break 64-bit bounds into 32-bit chunks
  uint32_t start_hi = (uint32_t)(lib_start >> 32);
  uint32_t start_lo = (uint32_t)(lib_start & 0xFFFFFFFF);
  uint32_t end_lo = (uint32_t)(lib_end & 0xFFFFFFFF);

  // Note: This logic assumes your library does not cross a 4GB boundary
  // (i.e., start_hi == end_hi). For small Android libs, this is 99.99% true.
  if ((lib_start >> 32) != (lib_end >> 32)) {
    // If it ever hits this, the BPF logic needs more complex boundary crossing checks
    LOGE("Library crosses 4GB boundary, PC-relative seccomp may fail!");
  }

  struct sock_filter trapFilter[] = {
      // Load HIGH 32 bits of Instruction Pointer (Little Endian: offset + 4)
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer) + 4),
      // If High 32 bits DO NOT match, jump forward 4 instructions to normal syscall checks
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, start_hi, 0, 4),

      // Load LOW 32 bits of Instruction Pointer
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer)),
      // If Low 32 bits < start_lo, jump forward 2 instructions to normal syscall checks
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, start_lo, 0, 2),
      // If Low 32 bits >= end_lo, jump forward 1 instruction to normal syscall checks
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, end_lo, 1, 0),

      // If we survive the jumps, the IP is inside our library! Bypass allowed.
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

      // Load syscall number into accumulator
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

      // System info
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_uname, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

      // Binary execution
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

      // Filesystem
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_faccessat, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_newfstatat, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_readlinkat, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

      // Trap sigaction to protect Bipan's signal handler
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigaction, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

      // Networking
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bind, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_listen, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendto, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getsockname, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  // The seccomp "program"
  struct sock_fprog prog = {
      .len = 0,          // number of BPF instructions
      .filter = nullptr  // Pointer to array of BPF instructions
  };

  prog = {
      .len = (unsigned short)(sizeof(trapFilter) / sizeof(trapFilter[0])),
      .filter = trapFilter,
  };

  // Promise the kernel we won't ask for elevated privileges.
  // This is necessary as this function will be run in Zygote (non-root)
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    LOGE("applySeccomp: prctl failed: %d", errno);
    return;
  }

  /**
   * Apply seccomp across all threads - `SECCOMP_FILTER_FLAG_TSYNC` -
   * and ask the kernel to use our filter: `SECCOMP_SET_MODE_FILTER`
   */
  long seccompApplyRet = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog);
  if (seccompApplyRet == -1) {
    LOGE("applySeccomp: failed to apply seccomp (errno %d)", errno);
  }
}
