#include "sigsys_handler.hpp"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syscall.h>
#include <unistd.h>

#include <atomic>

#include "blocker.hpp"
#include "logger.hpp"
#include "shared.hpp"
#include "spoofer.hpp"
#include "synchronization.hpp"
#include "unwinder.hpp"
#include "utils.hpp"

struct SpoofedFD {
  int fd;
  char original_path[256];
};

// Fixed array to avoid heap
static SpoofedFD global_spoofed_fds[128];
static std::atomic<int> spoofed_fd_count{0};

// Atomic spinlock (AS safe)
static std::atomic_flag fds_lock = ATOMIC_FLAG_INIT;

struct kernel_sigaction {
  void (*sa_handler)(int, siginfo_t*, void*);
  unsigned long sa_flags;
  void (*sa_restorer)(void);
  uint64_t sa_mask;
};

static void sigsys_handler(int sig, siginfo_t* info, void* void_context);
static void sigill_handler(int sig, siginfo_t* info, void* void_context);
static void sigsegv_handler(int sig, siginfo_t* info, void* void_context);

void storeSpoofedFD(int fd, const char* original_path) {
  // Acquire spinlock
  while (fds_lock.test_and_set(std::memory_order_acquire));

  int idx = spoofed_fd_count.load();
  if (idx < 128) {
    global_spoofed_fds[idx].fd = fd;
    // Use local_strncpy or similar
    size_t i = 0;
    while (original_path[i] && i < 255) {
      global_spoofed_fds[idx].original_path[i] = original_path[i];
      i++;
    }
    global_spoofed_fds[idx].original_path[i] = '\0';
    spoofed_fd_count.store(idx + 1);
  }

  fds_lock.clear(std::memory_order_release);  // Release
}

// Store original handlers to forward ART signals
static struct kernel_sigaction old_sa_segv = {};

void registerSignalHandler() {
  struct kernel_sigaction sa_SYS = {};
  sa_SYS.sa_handler = sigsys_handler;
  sa_SYS.sa_flags = SA_SIGINFO;
  long ret = 0;

  // Register signal directly with kernel to bypass libsigchain.so
  ret = arm64_raw_syscall(__NR_rt_sigaction, SIGSYS, (long)&sa_SYS, 0, 8, 0, 0);
  if (ret != 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Failed to set SIGSYS handler. Aborting for safety!");
    _exit(1);
  }

  bool is_insta = local_strstr(package_name, "com.instagram.android");
  bool is_whatsapp = local_strstr(package_name, "com.whatsapp");
  if (is_insta) {
    struct kernel_sigaction sa_ILL = {};
    sa_ILL.sa_handler = sigill_handler;
    sa_ILL.sa_flags = SA_SIGINFO;
    arm64_raw_syscall(__NR_rt_sigaction, SIGILL, (long)&sa_ILL, 0, 8, 0, 0);
  } else if (is_whatsapp) {
    struct kernel_sigaction sa_SEGV = {.sa_handler = sigsegv_handler, .sa_flags = SA_SIGINFO};
    arm64_raw_syscall(__NR_rt_sigaction, SIGSEGV, (long)&sa_SEGV, (long)&old_sa_segv, 8, 0, 0);
  }
}

static thread_local bool in_sigsys_handler = false;
static void sigsys_handler(int sig, siginfo_t* info, void* void_context) {
  ucontext_t* ctx = (ucontext_t*)void_context;
  int nr = info->si_syscall;

  // 1. REENTRANCY GUARD
  if (in_sigsys_handler) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!!!] Recursed signal handler! Allowing syscall number %d", nr);
    ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr,
                                                 ctx->uc_mcontext.regs[0], ctx->uc_mcontext.regs[1],
                                                 ctx->uc_mcontext.regs[2], ctx->uc_mcontext.regs[3],
                                                 ctx->uc_mcontext.regs[4], ctx->uc_mcontext.regs[5]);
    return;
  }
  in_sigsys_handler = true;

  long arg0 = ctx->uc_mcontext.regs[0];
  long arg1 = ctx->uc_mcontext.regs[1];
  long arg2 = ctx->uc_mcontext.regs[2];
  long arg3 = ctx->uc_mcontext.regs[3];
  long arg4 = ctx->uc_mcontext.regs[4];
  long arg5 = ctx->uc_mcontext.regs[5];

  lock_ipc();

  // 2. Pack Registers
  ipc_mem->nr = nr;
  ipc_mem->arg0 = arg0;
  ipc_mem->arg1 = arg1;
  ipc_mem->arg2 = arg2;
  ipc_mem->arg3 = arg3;
  ipc_mem->arg4 = arg4;
  ipc_mem->arg5 = arg5;
  ipc_mem->caller_pc = ctx->uc_mcontext.pc;
  ipc_mem->target_pid = arm64_raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);

  // 3. Serialize Pointer Data (FREESTANDING ONLY)
  my_memset(ipc_mem->string_payload, 0, sizeof(ipc_mem->string_payload));
  my_memset(ipc_mem->struct_payload, 0, sizeof(ipc_mem->struct_payload));
  my_memset(ipc_mem->out_buffer, 0, sizeof(ipc_mem->out_buffer));

  if (nr == __NR_openat || nr == __NR_faccessat || nr == __NR_newfstatat || nr == __NR_readlinkat) {
    if (arg1 != 0) my_strncpy(ipc_mem->string_payload, (const char*)arg1, 255);
  } else if (nr == __NR_execve || nr == __NR_execveat) {
    if (arg0 != 0) my_strncpy(ipc_mem->string_payload, (const char*)arg0, 255);
  } else if (nr == __NR_bind || nr == __NR_sendto || nr == __NR_getsockname) {
    long sock_ptr = (nr == __NR_sendto) ? arg4 : arg1;
    if (sock_ptr != 0) {
      // Assuming max sockaddr is 128 bytes (sockaddr_storage)
      // We cast to char* for byte-by-byte copy
      my_strncpy((char*)ipc_mem->struct_payload, (const char*)sock_ptr, 127);
    }
  } else if (nr == __NR_sendmsg) {
    struct msghdr* msg = (struct msghdr*)arg1;
    if (msg && msg->msg_name) {
      my_strncpy((char*)ipc_mem->struct_payload, (const char*)msg->msg_name, 127);
    }
  }

  // 4. Wake Broker & Wait
  ipc_mem->status = REQUEST_SYSCALL;
  futex_wake(&ipc_mem->status);

  while (ipc_mem->status != BROKER_ANSWERED) {
    futex_wait(&ipc_mem->status, REQUEST_SYSCALL);
  }

  // 5. Deserialize Outputs and Handle FDs
  long result = ipc_mem->ret;

  if (nr == __NR_openat && result == 0) {
    // Broker returned 0 to indicate a successful FD teleport.
    result = recv_fd(sv[1]);
    if (result >= 0) {
      storeSpoofedFD(result, ipc_mem->string_payload);
    }
  } else if (nr == __NR_uname && result == 0) {
    // Copy spoofed utsname back to target pointer
    my_strncpy((char*)arg0, (char*)ipc_mem->out_buffer, sizeof(ipc_mem->out_buffer) - 1);
  } else if (nr == __NR_readlinkat && result > 0) {
    // Copy resolved symlink back to target buffer
    my_strncpy((char*)arg2, (char*)ipc_mem->out_buffer, (size_t)result);
  } else if (nr == __NR_getsockname && result == 0) {
    my_strncpy((char*)arg1, (char*)ipc_mem->struct_payload, 127);
  }

  // 6. Release Lock
  ipc_mem->status = IDLE;
  unlock_ipc();

  ctx->uc_mcontext.regs[0] = result;

  in_sigsys_handler = false;
}

static void sigill_handler(int sig, siginfo_t* info, void* void_context) {
  ucontext_t* ctx = (ucontext_t*)void_context;
  uintptr_t fault_pc = ctx->uc_mcontext.pc;
  uintptr_t return_address = 0;

  write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "SIGILL at %p. Attempting recovery...", (void*)fault_pc);

  is_trusted_system_caller("(SIGILL_RECOVERY)", &return_address, false);

  if (return_address != 0) {
    uintptr_t suicide_call_site = return_address - 4;

    write_to_logcat_async(ANDROID_LOG_WARN, TAG, "Patching suicide site %p. Redirecting to %p",
                          (void*)suicide_call_site, (void*)return_address);

    // Tell me lies...forever (NOP caller)
    patchInstruction(suicide_call_site, 0);

    // Set current CPU PC to return address. It's as if the crash never occurred!
    ctx->uc_mcontext.pc = return_address;

    ctx->uc_mcontext.regs[0] = 0;  // "Success"

    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Resurrection successful. App resuming...");
    return;
  }

  write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Recovery failed (No valid caller). Killing process.");
  _exit(-1);
}

static thread_local bool in_sigsegv_handler = false;
static void sigsegv_handler(int sig, siginfo_t* info, void* void_context) {
  if (in_sigsegv_handler) {
    arm64_raw_syscall(__NR_exit, -1, 0, 0, 0, 0, 0);
    return;
  }
  in_sigsegv_handler = true;

  ucontext_t* ctx = (ucontext_t*)void_context;
  uintptr_t fault_pc = ctx->uc_mcontext.pc;
  uintptr_t return_address = 0;

  // 1. Identify if this is a Meta library (libessential, libwa_log, etc)
  if (!is_trusted_system_caller("(SIGSEGV_CHECK)", nullptr, false)) {
    // 2. Try to find where we should go back to
    is_trusted_system_caller("(SIGSEGV_RECOVERY)", &return_address, false);

    // 3. THE FIX: If the return address is the same as the fault address,
    // or very close, the current instruction IS the problem.
    if (return_address == 0 || return_address == fault_pc) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Bipan: Loop detected at %p. Force-NOPing current PC.", (void*)fault_pc);

      // Lobotomize the instruction that actually triggered the SEGV
      patchInstruction(fault_pc, 0);

      // Force the CPU to the NEXT instruction (+4 bytes in ARM64)
      ctx->uc_mcontext.pc = fault_pc + 4;
      ctx->uc_mcontext.regs[0] = 0;  // Set return to 0 (Success)

      write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Bipan: Loop broken. Advanced to %p", (void*)ctx->uc_mcontext.pc);
    } else {
      // Standard recovery for function calls (suicide jumps)
      uintptr_t suicide_call_site = return_address - 4;
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "Bipan: Neutralizing call site %p", (void*)suicide_call_site);

      patchInstruction(suicide_call_site, 0);
      ctx->uc_mcontext.pc = return_address;
      ctx->uc_mcontext.regs[0] = 0;
    }

    in_sigsegv_handler = false;
    return;
  }

  // 4. FORWARDING (Java NPEs, ART logic)
  in_sigsegv_handler = false;
  if (old_sa_segv.sa_handler != nullptr &&
      old_sa_segv.sa_handler != (void*)SIG_DFL &&
      old_sa_segv.sa_handler != (void*)SIG_IGN) {
    old_sa_segv.sa_handler(sig, info, void_context);
    return;
  }

  _exit(-1);
}
