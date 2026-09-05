#include "filter.hpp"

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>

#include "as_safe_string.hpp"
#include "common_utils.hpp"
#include "feature_flags.hpp"
#include "globals.hpp"
#include "logger/logger.hpp"

void applySeccomp(uintptr_t lib_start, uintptr_t lib_end) {
#if defined(__LP64__)
  // Break 64-bit bounds into 32-bit chunks
  uint32_t start_hi = (uint32_t)(lib_start >> 32);
  uint32_t start_lo = (uint32_t)(lib_start & 0xFFFFFFFF);
  uint32_t end_lo = (uint32_t)(lib_end & 0xFFFFFFFF);

  // ASSUMPTION: The library does not cross a 4GB boundary (start_hi == end_hi)
  if ((lib_start >> 32) != (lib_end >> 32)) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Library crosses 4GB boundary, PC-relative seccomp will probably fail!");
    BIPAN_PANIC();
  }
#else
  // On 32-bit ARM, PC/uintptr_t is only 32 bits. The kernel still reports
  // seccomp_data.instruction_pointer as a 64-bit field but zero-extends the
  // real 32-bit PC into it — so the correct "high 32 bits" comparison value
  // is always zero, never a shifted lib_start (which is UB)
  uint32_t start_hi = 0;
  uint32_t start_lo = (uint32_t)lib_start;
  uint32_t end_lo = (uint32_t)lib_end;
#endif

  struct sock_filter trapFilter[] = {
      // Load high 32 bits of PC (Little Endian: offset + 4)
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer) + 4),
      // If high 32 bits do not match, jump forward 4 instructions to normal syscall checks
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, start_hi, 0, 4),

      // Load low 32 bits of PC
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer)),
      // If low 32 bits < start_lo, jump forward 2 instructions to normal syscall checks
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, start_lo, 0, 2),
      // If low 32 bits >= end_lo, jump forward 1 instruction to normal syscall checks
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, end_lo, 1, 0),

      // If no jumps happened, the PC is inside Bipan: allow it
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

      // Load syscall number (nr) into accumulator
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

      // System info
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_uname, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

      // Binary execution
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

      // `access` family
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_faccessat, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

      // `stat` family
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fstat, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
#if defined(__aarch64__)
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_newfstatat, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
#endif
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_statx, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_statfs, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

      // Filesystem
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_readlinkat, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_inotify_add_watch, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_inotify_rm_watch, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

      // Signal handling
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
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmmsg, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  // The seccomp "program"
  struct sock_fprog prog = {
      // number of BPF instructions
      .len = (unsigned short)(sizeof(trapFilter) / sizeof(trapFilter[0])),
      // Pointer to array of BPF instructions
      .filter = trapFilter,
  };

  // Promise the kernel we won't ask for elevated privileges
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] prctl(PR_SET_NO_NEW_PRIVS) failed (errno: %s)", strerror(errno));
    BIPAN_PANIC();
  }

  /**
   * Apply seccomp across all threads - `SECCOMP_FILTER_FLAG_TSYNC` -
   * using our filter: `SECCOMP_SET_MODE_FILTER`
   */
  long ret = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog);
  if (ret == -1) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to apply seccomp (errno: %s)", strerror(errno));
    BIPAN_PANIC();
  }
}
