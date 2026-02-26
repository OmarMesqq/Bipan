#include "sigsys_handler.hpp"
#include "shared.hpp"

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
    if (sigaction(SIGSYS, &sa, nullptr) == -1) {
        LOGE("applySeccompFilter: Failed to set SIGSYS handler (errno: %d)", errno);
        _exit(1);
    }
}

static void sigsys_log_handler(int sig, siginfo_t *info, void *void_context) {
    ucontext_t *ctx = (ucontext_t *)void_context;
    int nr = info->si_syscall;
    uintptr_t pc = ctx->uc_mcontext.pc;
    uintptr_t lr = ctx->uc_mcontext.regs[30];

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

        LOGE("Violation: uname");
        
        memset(buf, 0, sizeof(struct utsname));
        strncpy(buf->sysname, "Linux", 64);
        strncpy(buf->nodename, "localhost", 64);
        strncpy(buf->release, "6.6.56-android16-11-g8a3e2b1c4d5f", 64);
        strncpy(buf->version, "#1 SMP PREEMPT Fri Dec 05 12:00:00 UTC 2025", 64);
        strncpy(buf->machine, "aarch64", 64);
        strncpy(buf->domainname, "(none)", 64);
    }
    else {
        LOGE("Violation: syscall number %d", nr);
    }

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