#include "sigsys_handler.hpp"

#include <dlfcn.h>
#include <linux/memfd.h>
#include <signal.h>
#include <sys/prctl.h>

#include <syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>

#include "assembly.hpp"
#include "blocker.hpp"
#include "shared.hpp"
#include "spoofer.hpp"
#include "synchronization.hpp"

static bool is_system_thread();
static void log_address_info(const char* label, uintptr_t addr);
static void get_library_from_addr(const char* label, uintptr_t addr);
static void sigsys_log_handler(int sig, siginfo_t* info, void* void_context);

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

static void sigsys_log_handler(int sig, siginfo_t* info, void* void_context) {
  ucontext_t* ctx = (ucontext_t*)void_context;
  uintptr_t pc = ctx->uc_mcontext.pc;
  uintptr_t lr = ctx->uc_mcontext.regs[30];
  int nr = info->si_syscall;  // syscalls go in x8 in aarch64

  // Don't block legitimate system threads
  if (is_system_thread()) {
    long result = arm64_bypassed_syscall(
        nr,
        ctx->uc_mcontext.regs[0],
        ctx->uc_mcontext.regs[1],
        ctx->uc_mcontext.regs[2],
        ctx->uc_mcontext.regs[3],
        ctx->uc_mcontext.regs[4]);
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
    case __NR_execve:
    case __NR_execveat: {
      const char* path = (const char*)ctx->uc_mcontext.regs[0];

      LOGE("Violation: execve/execvat (\"%s\")", path);

      ctx->uc_mcontext.regs[0] = -EACCES;
      break;
    }
    case __NR_uname: {
      LOGW("Spoofing uname");
      struct utsname* buf = (struct utsname*)ctx->uc_mcontext.regs[0];
      
      ctx->uc_mcontext.regs[0] = uname_spoofer(buf);
      break;
    }

    case __NR_faccessat:
    case __NR_newfstatat:
    case __NR_openat: {
      int dirfd = (int)ctx->uc_mcontext.regs[0];
      const char* pathname = (const char*)ctx->uc_mcontext.regs[1];
      int flags = (int)ctx->uc_mcontext.regs[2];
      mode_t mode = (mode_t)ctx->uc_mcontext.regs[3];

      bool reading_maps = (strcmp(pathname, "/proc/self/maps") == 0) ||
                          ((safe_proc_pid_path[0] != '\0') &&
                           starts_with(pathname, safe_proc_pid_path) &&
                           strstr(pathname, "/maps") != nullptr);

      if (reading_maps) {
        ctx->uc_mcontext.regs[0] = clean_proc_maps(dirfd, pathname, flags, mode);
        break;
      }
      
      // Filters senstive files and uses magic number under the hood
      ctx->uc_mcontext.regs[0] = filterPathname(
        nr,
        arg0,
        arg1,
        arg2,
        arg3,
        arg4
      );
      break;
    }
    default: {
      LOGE("Violation: syscall number %d", nr);
      ctx->uc_mcontext.regs[0] = 0;  // "success"
      break;
    }
  }
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
    bool is_apex = (strncmp(path, "/apex/", 6) == 0);

    if (!is_system && !is_apex) {
      LOGD("%s resolves to library %s", label, path);
    }
  } else {
    LOGE("Could not resolve library at %p", (void*)addr);
  }
}

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
