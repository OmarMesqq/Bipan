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

static void log_address_info(const char* label, uintptr_t addr);
static void get_library_from_addr(uintptr_t addr);
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

            LOGE("Violation: openat");
            LOGE("dirfd: %d", dirfd);
            LOGE("pathname: %s", pathname);
            LOGE("flags: %d", flags);
            LOGE("mode: %u", mode);

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
            break;
        }
        default: {
            LOGE("Violation: syscall number %d", nr);
            ctx->uc_mcontext.regs[0] = 0; // "success"
            break;
        }
    }

    log_address_info("PC (Actual Caller)", pc);
    log_address_info("LR (Return Address)", lr);
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

static void get_library_from_addr(uintptr_t addr) {
  Dl_info dlinfo;
  if (dladdr((void*)addr, &dlinfo) && dlinfo.dli_fname) {
    LOGD("Address %p resolves to library %s",
         (void*)addr,
         dlinfo.dli_fname);
  } else {
    LOGE("Could not resolve library at %p ", (void*)addr);
  }
}