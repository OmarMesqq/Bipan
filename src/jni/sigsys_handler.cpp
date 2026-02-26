#include "sigsys_handler.hpp"
#include "shared.hpp"
#include "synchronization.hpp"

#include <cstdint>
#include <dlfcn.h>
#include <signal.h>
#include <syscall.h>
#include <cstring>
#include <sys/utsname.h>
#include <cerrno>
#include <unistd.h>
#include <sys/prctl.h>

static volatile int ipc_lock_state = 0;
static inline long arm64_bypassed_syscall(long sysno, long a0, long a1, long a2, long a3, long a4);
static bool is_system_thread();
static void get_library_from_addr(const char* label, uintptr_t addr);

// Async-signal-safe lock
inline void lock_ipc() {
    // __sync_lock_test_and_set writes 1 and returns the old value.
    // If it returns 1, it was already locked, so we sleep on the futex.
    while (__sync_lock_test_and_set(&ipc_lock_state, 1)) {
        futex_wait(&ipc_lock_state, 1);
    }
}

// Async-signal-safe unlock
inline void unlock_ipc() {
    __sync_lock_release(&ipc_lock_state); // sets back to 0 securely
    futex_wake(&ipc_lock_state);          // wakes up the next waiting thread
}

static void log_address_info(const char* label, uintptr_t addr);
static void get_library_from_addr(char* label, uintptr_t addr);
static void sigsys_log_handler(int sig, siginfo_t *info, void *void_context);

void registerSigSysHandler() {
    struct sigaction sa{};
    sa.sa_sigaction = sigsys_log_handler;
    sa.sa_flags = SA_SIGINFO;
    // sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSYS, &sa, nullptr) == -1) {
        LOGE("applySeccompFilter: Failed to set SIGSYS handler (errno: %d)", errno);
        _exit(1);
    }
}

static void sigsys_log_handler(int sig, siginfo_t *info, void *void_context) {
    ucontext_t *ctx = (ucontext_t *)void_context;
    uintptr_t pc = ctx->uc_mcontext.pc;
    uintptr_t lr = ctx->uc_mcontext.regs[30];
    int nr = info->si_syscall;  // or ctx->uc_mcontext.regs[8];
    
    // Don't block legitimate system threads
    if (is_system_thread()) {
        long result = arm64_bypassed_syscall(
            nr, 
            ctx->uc_mcontext.regs[0], 
            ctx->uc_mcontext.regs[1], 
            ctx->uc_mcontext.regs[2], 
            ctx->uc_mcontext.regs[3], 
            ctx->uc_mcontext.regs[4]
        );
        ctx->uc_mcontext.regs[0] = result;
        return;
    }

    long arg0 = ctx->uc_mcontext.regs[0];
    long arg1 = ctx->uc_mcontext.regs[1];
    long arg2 = ctx->uc_mcontext.regs[2];
    long arg3 = ctx->uc_mcontext.regs[3];
    long arg4 = ctx->uc_mcontext.regs[4];
    long arg5 = ctx->uc_mcontext.regs[5];

    switch (nr) {
        case __NR_execve: {
            const char* path = (const char*)ctx->uc_mcontext.regs[0];

            LOGE("Violation: execve(\"%s\")", path);

            ctx->uc_mcontext.regs[0] = 0; // "success"
            break;
        }
        case __NR_execveat: {
            int dirfd = (int)ctx->uc_mcontext.regs[0];
            const char* path = (const char*)ctx->uc_mcontext.regs[1];

            LOGE("Violation: execveat(%d, \"%s\")", dirfd, path);

            ctx->uc_mcontext.regs[0] = 0; // "success"
            break;
        }
        case __NR_uname: {
            LOGE("Violation: uname");
            struct utsname* buf = (struct utsname*)ctx->uc_mcontext.regs[0];
            if (!buf) return;

            memset(buf, 0, sizeof(struct utsname));
            strncpy(buf->sysname, "Linux", 64);
            strncpy(buf->nodename, "localhost", 64);
            strncpy(buf->release, "6.6.56-android16-11-g8a3e2b1c4d5f", 64);
            strncpy(buf->version, "#1 SMP PREEMPT Fri Dec 05 12:00:00 UTC 2025", 64);
            strncpy(buf->machine, "aarch64", 64);
            strncpy(buf->domainname, "(none)", 64);
            
            ctx->uc_mcontext.regs[0] = 0; // "success"
            break;
        }
        case __NR_openat: {
            int dirfd = (int)ctx->uc_mcontext.regs[0];
            const char* pathname = (const char*)ctx->uc_mcontext.regs[1];
            int flags = (int)ctx->uc_mcontext.regs[2];
            mode_t mode = (mode_t)ctx->uc_mcontext.regs[3];

            // Reduce clutter: let app read its own paths
            bool is_app_data = (safe_path_user_0_len > 0 && strncmp(pathname, safe_path_user_0, safe_path_user_0_len) == 0) ||
                                   (safe_path_data_data_len > 0 && strncmp(pathname, safe_path_data_data, safe_path_data_data_len) == 0);

            // Binder devices MUST be opened by the native process context,
            // otherwise mmap() will fail with EINVAL due to TGID mismatches in the kernel.
            bool is_binder = (strncmp(pathname, "/dev/binder", 11) == 0) ||
                             (strncmp(pathname, "/dev/hwbinder", 13) == 0) ||
                             (strncmp(pathname, "/dev/vndbinder", 14) == 0);

            if (is_app_data || is_binder) {
                long native_fd = arm64_bypassed_syscall(__NR_openat, dirfd, (long)pathname, flags, mode, 0);
                ctx->uc_mcontext.regs[0] = native_fd;
                return;
            }

            LOGE("Violation: openat to file %s", pathname);

            lock_ipc();

            // Load syscall data in IPC memory
            ipc_mem->nr = nr;
            ipc_mem->arg0 = ctx->uc_mcontext.regs[0];                      // dirfd
            strncpy(ipc_mem->path, (char*)ctx->uc_mcontext.regs[1], 255);  // pathname
            ipc_mem->arg2 = ctx->uc_mcontext.regs[2];                      // flags
            ipc_mem->arg3 = ctx->uc_mcontext.regs[3];                      // mode
            ipc_mem->arg4 = 0;                                             // unused
            ipc_mem->arg5 = 0;                                             // unused

            /**
             * Make a request to broker,
             * suspend thread until status changes
             * flush memory cache
             */
            ipc_mem->status = REQUEST_SYSCALL;
            futex_wake(&ipc_mem->status);
            __sync_synchronize();
            while (ipc_mem->status != BROKER_ANSWERED) {
              futex_wait(&ipc_mem->status, REQUEST_SYSCALL);
            }
            __sync_synchronize();

            // Pass result to caller
            if (ipc_mem->ret == 0) {
                // Syscall succeeded
              ctx->uc_mcontext.regs[0] = recv_fd(sv[1]);
            } else {
              // Syscall failed
              ctx->uc_mcontext.regs[0] = ipc_mem->ret;
            }
            ipc_mem->status = IDLE;
            
            unlock_ipc();   // release lock
            break;
        }
        default: {
            LOGE("Violation: syscall number %d", nr);
            ctx->uc_mcontext.regs[0] = 0; // "success"
            break;
        }
    }

    get_library_from_addr("PC", pc);
    get_library_from_addr("LR", lr);
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

static void get_library_from_addr(const char* label, uintptr_t addr) {
  Dl_info dlinfo;
  if (dladdr((void*)addr, &dlinfo) && dlinfo.dli_fname) {
    const char* path = dlinfo.dli_fname;

    bool is_system = (strncmp(path, "/system/", 8) == 0);
    bool is_apex   = (strncmp(path, "/apex/", 6) == 0);

    if (!is_system && !is_apex) {
      LOGD("%s resolves to library %s", label, path);
    }
  } else {
    LOGE("Could not resolve library at %p", (void*)addr);
  }
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wregister"
static inline long arm64_bypassed_syscall(long sysno, long a0, long a1, long a2, long a3, long a4) {
    register long x8 __asm__("x8") = sysno;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = 0xBADB01; // The Magic Number!

    __asm__ volatile(
        "svc #0\n"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory", "cc"
    );

    return x0;
}
#pragma clang diagnostic pop

static bool is_system_thread() {
    char thread_name[16] = {0};
    if (prctl(PR_GET_NAME, thread_name, 0, 0, 0) != 0) {
        return false;
    }

    if (strncmp(thread_name, "RenderThread", 12) == 0 ||
        strncmp(thread_name, "hwuiTask", 8) == 0 ||
        strncmp(thread_name, "Binder:", 7) == 0 ||
        strncmp(thread_name, "Jit thread pool", 15) == 0 ||
        strncmp(thread_name, "Profile Saver", 13) == 0 ||
        strncmp(thread_name, "mali-", 5) == 0 ||      
        strncmp(thread_name, "kgsl-", 5) == 0 ||      
        strncmp(thread_name, "ReferenceQueueD", 15) == 0 ||
        strncmp(thread_name, "FinalizerDaemon", 15) == 0 ||
        strncmp(thread_name, "HeapTaskDaemon", 14) == 0) {
        return true;
    }
    return false;
}