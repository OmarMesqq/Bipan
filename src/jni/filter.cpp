#include "filter.hpp"

#include <dlfcn.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "bipan_shared.hpp"

/**
 * Berkeley Packet Filter program to
 * block the following syscalls:
 * - `execve`
 * - `execveat`
 * - `uname`
 *
 * The kernel shall return `EPERM` to the program, whilst
 * allowing other syscalls. Bipan can be ejected
 * from memory in this case.
 */
static struct sock_filter blockFilter[] = {
    // Load the syscall number into the accumulator
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

    // If it's `execve`, block it
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
    // If it's `execveat`, block it
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
    // If it's `uname`, block it
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_uname, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

    // Otherwise, allow it
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

/**
 * Berkeley Packet Filter program to
 * trap the following syscalls:
 * - `execve`
 * - `execveat`
 * - `uname`
 *
 * The kernel shall return `SIGSYS` to the program.
 * For this to properly work, Bipan must stay in memory
 * to install and maintain its signal handler during the app's
 * lifetime.
 */
static struct sock_filter trapFilter[] = {
    // Get the syscall's number
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

    // // If it's `execve`, trap it
    // BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
    // BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

    // // If it's `execveat`, trap it
    // BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
    // BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

    // If it's `uname`, trap it
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_uname, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

    // Otherwise, allow it
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

void applySeccompFilter(BIPAN_FILTER opt) {
  // The seccomp filter "program"
  struct sock_fprog prog = {
      .len = 0,          // number of BPF instructions
      .filter = nullptr  // Pointer to array of BPF instructions
  };

  switch (opt) {
    case BLOCK: {
      prog = {
          .len = (unsigned short)(sizeof(blockFilter) / sizeof(blockFilter[0])),
          .filter = blockFilter,
      };
      break;
    }
    case TRAP:
    case LOG: {
      prog = {
          .len = (unsigned short)(sizeof(trapFilter) / sizeof(trapFilter[0])),
          .filter = trapFilter,
      };
      break;
    }
    default: {
      LOGE("apply_seccomp_filter: unexepected filter option %u", opt);
      return;
    }
  }

  // Promise the kernel we won't ask for elevated privileges.
  // This is necessary as this function will be run in Zygote (non-root)
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    LOGE("prctl(PR_SET_NO_NEW_PRIVS) failed: %d", errno);
    return;
  }

  // Apply the seccomp filter
  // Another option is to use SECCOMP_SET_MODE_STRICT:
  // "The only system calls that the calling thread is permitted
  // to make are read(2), write(2), _exit(2)"
  long seccompApplyRet = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog);
  if (seccompApplyRet == -1) {
    LOGE("applySeccompFilter: failed to apply seccomp (errno %d)", errno);
  }
}
