#include "filter.hpp"

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <syscall.h>
#include <unistd.h>

#include <cerrno>

#include "shared.hpp"

/**
 * Berkeley Packet Filter to
 * trap some syscalls.
 * The kernel shall return `SIGSYS` to the program.
 * For this to properly work, Bipan must stay in memory
 * to install and maintain its signal handler during the app's
 * lifetime.
 */
static struct sock_filter trapFilter[] = {
    // --- MAGIC ARGUMENT BYPASS ---
    // Load the lower 32 bits of the 6th argument
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[5])),

    // Check if it matches our magic number
    // on match: execute next line
    // not match: skip the ALLOW
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_BYPASS, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    // Load syscall number into accumulator for standard rules
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

    // System info
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_uname, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

    // Binary execution
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

    // Touching the filesystem: getting FDs
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_faccessat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_newfstatat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

void applySeccompFilter() {
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
    LOGE("prctl(PR_SET_NO_NEW_PRIVS) failed: %d", errno);
    return;
  }

  // Apply the seccomp filter across all threads (`TSYNC`)
  // Another option is to use SECCOMP_SET_MODE_STRICT:
  // "The only system calls that the calling thread is permitted
  // to make are read(2), write(2), _exit(2)"
  long seccompApplyRet = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog);
  if (seccompApplyRet == -1) {
    LOGE("applySeccompFilter: failed to apply seccomp (errno %d)", errno);
  }
}
