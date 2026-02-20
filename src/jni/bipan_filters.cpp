#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <syscall.h>
#include <unistd.h>
#include <cerrno>

#include "bipan_shared.hpp"
#include "bipan_filters.hpp"

/**
 * Block the following syscalls using seccomp:
 * - `execve`
 * - `execveat`
 * - `uname`
 * 
 * Returns `EPERM` to app
 */
void block_syscalls() {
    struct sock_filter filter[] = {
        // Load the syscall number into the accumulator
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        
        // Check for execve
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

        // Check for execveat
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

        // Check for uname
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_uname, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        
        // If it didn't match those, allow it
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    

    // Promise the kernel we won't ask for elevated privileges.
    // This is necessary as this function will be run in Zygote (non-root)
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        LOGE("prctl(PR_SET_NO_NEW_PRIVS) failed: %d", errno);
        return;
    }

    // Apply the seccomp filter
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
        LOGE("prctl(PR_SET_SECCOMP) failed: %d", errno);
    }
}