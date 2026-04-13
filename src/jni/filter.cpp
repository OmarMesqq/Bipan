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
 * 
 * TODO:
 * - ioctl
 * - readlinkat /proc/self/fd/*
 *      cat /proc/13451/fd/88 | head -n 10
02000000-12000000 rw-p 00000000 00:00 0                                  [anon:dalvik-main space]
22000000-32000000 rw-p 00000000 00:00 0                                  [anon:dalvik-free list large object space]
42000000-44000000 r--s 00000000 00:05 21567                              /memfd:jit-zygote-cache (deleted)
44000000-46000000 r-xs 02000000 00:05 21567                              /memfd:jit-zygote-cache (deleted)
46000000-48000000 r--s 00000000 00:05 68815                              /memfd:jit-cache (deleted)
48000000-4a000000 r-xs 02000000 00:05 68815                              /memfd:jit-cache (deleted)
705a0000-70898000 rw-p 00000000 00:00 0                                  [anon:dalvik-/system/framework/boot.art]
70898000-708e8000 rw-p 00000000 00:00 0                                  [anon:dalvik-/system/framework/boot-core-libart.art]
708e8000-70914000 rw-p 00000000 00:00 0                                  [anon:dalvik-/system/framework/boot-okhttp.art]
70914000-70960000 rw-p 00000000 00:00 0                                  [anon:dalvik-/system/framework/boot-bouncycastle.art]
~ # ls -l /proc/13451/fd/88 
lrwx------. 1 u0_a38 u0_a38 64 Apr 13 02:12 /proc/13451/fd/88 -> '/memfd:F4ON5SYGiut0 (deleted)'*
 */
static struct sock_filter trapFilter[] = {
    // ---- Magic number bypass (`SECCOMP_BYPASS`) ----
    // load the lower 32 bits of the 6th argument
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[5])),
    // check if it matches our symbolic constant
    // on match: execute next line, allowing the syscall
    // not match: skip the allow, falling through traps
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_BYPASS, 0, 1),
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

    // Filesystem access: grants FDs to files in disk
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_faccessat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_newfstatat, 0, 1),
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

    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

void applySeccomp() {
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
