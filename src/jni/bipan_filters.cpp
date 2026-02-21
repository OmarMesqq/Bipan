#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <syscall.h>
#include <unistd.h>
#include <cerrno>
#include <signal.h>
#include <dlfcn.h>
#include <cstring>
#include <sys/utsname.h>

#include "bipan_shared.hpp"
#include "bipan_filters.hpp"

static void sigsys_trap_handler(int sig, siginfo_t *info, void *void_context);
static void sigsys_log_handler(int sig, siginfo_t *info, void *void_context);
static void log_address_info(const char* label, uintptr_t addr);

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
    
    // If it's `execve`, trap it
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

    // If it's `execveat`, trap it
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

    // If it's `uname`, trap it
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_uname, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    
    // Otherwise, allow it
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

void applySeccompFilter(BIPAN_FILTER opt) {
    // The seccomp filter "program"
    struct sock_fprog prog = {
        .len = 0,   // number of BPF instructions
        .filter = nullptr // Pointer to array of BPF instructions
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
            // Register the signal handler before applying seccomp-bpf
            struct sigaction sa{};
            sa.sa_sigaction = opt == TRAP ? sigsys_trap_handler : sigsys_log_handler;
            sa.sa_flags = SA_SIGINFO;
            if (sigaction(SIGSYS, &sa, nullptr) == -1) {
                LOGE("applySeccompFilter: Failed to set SIGSYS handler for filter option %u: %d", opt, errno);
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
    long seccompApplyRet = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog);
    if (seccompApplyRet == -1) {
        LOGE("applySeccompFilter: failed to apply seccomp (errno %d)", errno);
    }
}

static void sigsys_trap_handler(int sig, siginfo_t *info, void *void_context) {
    int nr = info->si_syscall;

    LOGE("--- BIPAN SANDBOX TRAP ---");
    if (nr == __NR_execve || nr == __NR_execveat) {
        LOGE("Violation: Attempted to EXECUTE a binary (Syscall %d)", nr);
    } else if (nr == __NR_uname) {
        LOGE("Violation: Attempted to call uname (Syscall %d)", nr);
    } else {
        LOGE("Violation: Blocked syscall %d", nr);
    }
    
    // Aggressively exit the program upon violation
    _exit(1);
}

static void sigsys_log_handler(int sig, siginfo_t *info, void *void_context) {
    ucontext_t *ctx = (ucontext_t *)void_context;
    int nr = info->si_syscall;
    uintptr_t pc = ctx->uc_mcontext.pc;
    uintptr_t lr = ctx->uc_mcontext.regs[30];

    LOGE("--- BIPAN SANDBOX LOG START ---");
    if (nr == __NR_execve) {
        const char* path = (const char*)ctx->uc_mcontext.regs[0];
        LOGE("Violation: execve(\"%s\")", path ? path : "NULL");
    } 
    else if (nr == __NR_execveat) {
        const char* path = (const char*)ctx->uc_mcontext.regs[1];
        LOGE("Violation: execveat(dfd, \"%s\")", path ? path : "NULL");
    }
    else if (nr == __NR_uname) {
        struct utsname* buf = (struct utsname*)ctx->uc_mcontext.regs[0];
        if (!buf) {
            LOGE("sigsys_log_handler: utsname struct for uname is NULL!");
            _exit(1);
        }

        LOGE("Violation: uname. Spoofing values...");
        
        memset(buf, 0, sizeof(struct utsname));
        strncpy(buf->sysname, "Linux", 64);
        strncpy(buf->nodename, "localhost", 64);
        strncpy(buf->release, "6.6.56-android16-11-g8a3e2b1c4d5f", 64);
        strncpy(buf->version, "#1 SMP PREEMPT Fri Dec 05 12:00:00 UTC 2025", 64);
        strncpy(buf->machine, "aarch64", 64);
        strncpy(buf->domainname, "(none)", 64);
        
        LOGD("Spoofed 'uname' values.");
    }
    else {
        LOGE("Violation: syscall %d", nr);
    }

    /**
     * TODO: apparently this isn't necessary as, when using seccomp,
     * the kernel has "stepped over" the Supervisor Call by the time
     * our handler got SIGSYS. It automatically skipped the 4 bytes
     * of `svc #0` and now the PC is  `mov xY, x0` i.e.
     * put the syscall's result in the C/C++ variable that receives it.
     * As such, our only job is to mock the return value :)
     * 
     * You can check with:
     * uint32_t *instr_at_pc = (uint32_t *)pc;
     * uint32_t *instr_before_pc = (uint32_t *)(pc - 4);
     * LOGD("Instruction at PC: 0x%08x", *instr_at_pc);
     * LOGD("Instruction before PC: 0x%08x", *instr_before_pc);
     * DEPRECATED:
     * Increment the `pc` (Program Counter) by
     * 4 bytes as to skip the Supervisor Call
     * (`svc #0`) of aarch64.
     * This "pretends" the syscall happened to the target
     * program.
     */
    // ctx->uc_mcontext.pc += 4;

    /**
     * Mock the syscall's result.
     * Here I'm denying it by
     * placing `-EPERM` on x0 (return register in aarch64)
     * 
     * -EPERM is signed int (32 bits/4 bytes).
     * The innermost cast sign extends -EPERM to 64 bits,
     * thus keeping it negative. The outermost cast is simply
     * to shut up the compiler it lets me put the negative bit pattern
     * into an unsigned "box" (the register)
     * 
     * TODO: decide if return:
     * - `0`: fake success
     * - `static_cast<uint64_t>(static_cast<int64_t>(-EPERM))`: Permission denied
     */
    ctx->uc_mcontext.regs[0] = 0;

    log_address_info("PC (Actual Caller)", pc);
    log_address_info("LR (Return Address)", lr);

    LOGE("--- BIPAN SANDBOX LOG END ---");
}

static void log_address_info(const char* label, uintptr_t addr) {
    Dl_info dlinfo;
    if (dladdr((void*)addr, &dlinfo) && dlinfo.dli_fname) {
        LOGD("%s: %p | Library: %s | Symbol: %s", 
             label, 
             (void*)addr, 
             dlinfo.dli_fname, 
             dlinfo.dli_sname ? dlinfo.dli_sname : "N/A");
    } else {
        LOGE("%s: %p (Could not resolve)", label, (void*)addr);
    }
}
