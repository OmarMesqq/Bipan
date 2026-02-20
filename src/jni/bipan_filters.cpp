#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <syscall.h>
#include <unistd.h>
#include <cerrno>
#include <signal.h>

#include "bipan_shared.hpp"
#include "bipan_filters.hpp"

static void sigsys_trap_handler(int sig, siginfo_t *info, void *void_context) {
    // Syscall the app called that triggered the trap
    int nr = info->si_syscall;

    LOGE("--- BIPAN SANDBOX TRAP ---");
    if (nr == __NR_execve || nr == __NR_execveat) {
        LOGE("Violation: Attempted to EXECUTE a binary (Syscall %d)", nr);
    } else if (nr == __NR_uname) {
        LOGE("Violation: Attempted to call uname (Syscall %d)", nr);
    } else {
        LOGE("Violation: Blocked syscall %d", nr);
    }
    
    _exit(1);
}

static void sigsys_log_handler(int sig, siginfo_t *info, void *void_context) {
    ucontext_t *ctx = (ucontext_t *)void_context;
    int nr = info->si_syscall;

    LOGE("--- BIPAN SANDBOX LOG (PASSIVE) ---");
    if (nr == __NR_execve) {
        // X0 contains the pointer to the filename string
        const char* path = (const char*)ctx->uc_mcontext.regs[0];
        LOGE("Violation: execve(\"%s\")", path ? path : "NULL");
    } 
    else if (nr == __NR_execveat) {
        // X1 contains the pointer to the filename string in execveat
        const char* path = (const char*)ctx->uc_mcontext.regs[1];
        LOGE("Violation: execveat(dfd, \"%s\")", path ? path : "NULL");
    }
    else if (nr == __NR_uname) {
        // X0 contains the pointer to the utsname struct
        LOGE("Violation: uname(%p)", (void*)ctx->uc_mcontext.regs[0]);
    }
    else {
        LOGE("Violation: Blocked syscall %d", nr);
    }

    // 1. Advance the Program Counter (PC) by 4 bytes.
    // On aarch64, 'svc #0' is exactly 4 bytes. Skipping it prevents the infinite loop.
    ctx->uc_mcontext.pc += 4;

    // 2. Set the return value in X0 to -EPERM (-1).
    // The app receives this as the result of the "failed" syscall.
    ctx->uc_mcontext.regs[0] = static_cast<unsigned long long>(-EPERM);
}

static struct sock_filter blockFilter[] = {
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

static struct sock_filter trapFilter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        
        // Trap execve
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

        // Trap execveat
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

        // Trap uname
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_uname, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

void applySeccompFilter(BIPAN_FILTER opt) {
    // The seccomp filter program
    struct sock_fprog prog = {
        .len = 0,   // number of BPF instructions
        .filter = nullptr // Pointer to array of BPF instructions
    };

    switch (opt) {
        case TRAP: {
            // Register the signal handler
            struct sigaction sa{};
            sa.sa_sigaction = sigsys_trap_handler;
            sa.sa_flags = SA_SIGINFO;
            if (sigaction(SIGSYS, &sa, nullptr) == -1) {
                LOGE("applySeccompFilter: Failed to set SIGSYS handler: %d", errno);
                return;
            }

            prog = {
                .len = (unsigned short)(sizeof(trapFilter) / sizeof(trapFilter[0])),
                .filter = trapFilter,
            };
            break;
        }
        case BLOCK: {
            prog = {
                .len = (unsigned short)(sizeof(blockFilter) / sizeof(blockFilter[0])),
                .filter = blockFilter,
            };
            break;
        }
        case LOG: {
            // Register the signal handler
            struct sigaction sa{};
            sa.sa_sigaction = sigsys_log_handler;
            sa.sa_flags = SA_SIGINFO;
            if (sigaction(SIGSYS, &sa, nullptr) == -1) {
                LOGE("applySeccompFilter: Failed to set SIGSYS handler: %d", errno);
                return;
            }

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
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
        LOGE("prctl(PR_SET_SECCOMP) failed: %d", errno);
    }
}
