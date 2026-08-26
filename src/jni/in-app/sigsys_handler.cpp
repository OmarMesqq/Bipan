#include "sigsys_handler.hpp"

#include <arpa/inet.h>
#include <linux/memfd.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#include "as_safe_string.hpp"
#include "feature_flags.hpp"
#include "globals.hpp"
#include "in-app/ipc_lock.hpp"
#include "ipc_communication.hpp"
#include "logger/logger.hpp"

static void sigsys_handler(int sig, siginfo_t* info, void* void_context);
static inline void scrub_socket(struct sockaddr* s);
#ifdef IN_APP_ADDITIONAL_HANDLERS
#include <dlfcn.h>
#include <sys/mman.h>
#include <unwind.h>
typedef struct {
  void** frames;
  int count;
  int max;
} BacktraceState;
static _Unwind_Reason_Code unwind_callback(struct _Unwind_Context* context, void* arg);
static int capture_backtrace(void** out_frames, int max_frames);
static void print_backtrace();

static struct sigaction old_segv = {};
static struct sigaction old_abrt = {};
static struct sigaction old_quit = {};

static void bipan_additional_sig_handler(int sig, siginfo_t* info, void* void_context);
#endif

#ifdef IN_APP_PERF_ANALYSIS
#include <linux/prctl.h>
#include <time.h>
#define PERF_TAG "BipanPerf"
__attribute__((always_inline)) static inline long long ns_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}
#endif

#ifdef IN_APP_RAW_SIGNAL_REGISTRATION
struct kernel_sigaction {
  void (*sa_handler)(int, siginfo_t*, void*);
  unsigned long sa_flags;
  void (*sa_restorer)(void);
  uint64_t sa_mask;
};

void registerSignalHandler() {
  struct kernel_sigaction sa_SYS = {};
  sa_SYS.sa_handler = sigsys_handler;
  sa_SYS.sa_flags = SA_SIGINFO;
  long ret = 0;

  ret = arm64_raw_syscall(__NR_rt_sigaction, SIGSYS, (long)&sa_SYS, 0, 8, 0, 0);
  if (ret != 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] sigaction(SIGSYS) failed (errno: %s)", strerror((int)ret));
    BIPAN_PANIC();
  }

#ifdef IN_APP_ADDITIONAL_HANDLERS
  struct kernel_sigaction sa_SEGV = {};
  sa_SEGV.sa_handler = bipan_additional_sig_handler;
  sa_SEGV.sa_flags = SA_SIGINFO;

  ret = arm64_raw_syscall(__NR_rt_sigaction, SIGSEGV, (long)&sa_SEGV, 0, 8, 0, 0);
  if (ret != 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] sigaction(SIGSEGV) failed (errno: %s)", strerror((int)ret));
    BIPAN_PANIC();
  }
#endif
}
#else
#include <signal.h>
void registerSignalHandler() {
  struct sigaction act = {
      .sa_flags = SA_SIGINFO | SA_NODEFER,
      .sa_sigaction = &sigsys_handler};

  int ret = sigaction(SIGSYS, &act, nullptr);
  if (ret != 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] sigaction(SIGSYS) failed (errno: %s)", strerror(errno));
    BIPAN_PANIC();
  }
#ifdef IN_APP_ADDITIONAL_HANDLERS
  struct sigaction additionalAct = {
      .sa_flags = SA_SIGINFO,
      .sa_sigaction = &bipan_additional_sig_handler};

  ret = sigemptyset(&additionalAct.sa_mask);
  if (ret == -1) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] sigemptyset(additional signals) failed (errno: %s)", strerror(errno));
    BIPAN_PANIC();
  }

  ret = sigaction(SIGABRT, &additionalAct, &old_abrt);
  if (ret == -1) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] sigaction(SIGABRT) failed (errno: %s)", strerror(errno));
    BIPAN_PANIC();
  }
  ret = sigaction(SIGSEGV, &additionalAct, &old_segv);
  if (ret == -1) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] sigaction(SIGSEGV) failed (errno: %s)", strerror(errno));
    BIPAN_PANIC();
  }

  ret = sigaction(SIGQUIT, &additionalAct, &old_quit);
  if (ret == -1) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] sigaction(SIGQUIT) failed (errno: %s)", strerror(errno));
    BIPAN_PANIC();
  }
#endif
}
#endif

static thread_local bool in_sigsys_handler = false;
static void sigsys_handler(int sig, siginfo_t* info, void* void_context) {
  if (sig != SIGSYS) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Received signal %d != SIGSYS. Aborting!");
    BIPAN_PANIC();
  }

  if (in_sigsys_handler) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Recursed SIGSYS handler. We're probably cooked. Aborting!");
    BIPAN_PANIC();
  }
  in_sigsys_handler = true;

  ucontext_t* ctx = (ucontext_t*)void_context;
  int nr = info->si_syscall;

  if (ipc_mem == nullptr) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Caught syscall %d but IPC mem not ready!", nr);
    BIPAN_PANIC();
  }

  long arg0 = (long)ctx->uc_mcontext.regs[0];
  long arg1 = (long)ctx->uc_mcontext.regs[1];
  long arg2 = (long)ctx->uc_mcontext.regs[2];
  long arg3 = (long)ctx->uc_mcontext.regs[3];
  long arg4 = (long)ctx->uc_mcontext.regs[4];
  long arg5 = (long)ctx->uc_mcontext.regs[5];

  if (nr == __NR_listen) {
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(listen) spoofed to success");
    ctx->uc_mcontext.regs[0] = 0;
    in_sigsys_handler = false;
    return;
  }

  if (nr == __NR_statx) {
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(statx): replying not implemented");
    ctx->uc_mcontext.regs[0] = (__u64)-ENOSYS;
    in_sigsys_handler = false;
    return;
  }

  if (nr == __NR_sendmmsg) {
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(sendmmsg): replying not implemented");
    ctx->uc_mcontext.regs[0] = (__u64)-ENOSYS;
    in_sigsys_handler = false;
    return;
  }

  if (nr == __NR_getsockname) {
    long r = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);

    if (r != 0 || arg1 == 0) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "sockaddr to scrub is null and/or native getsockname failed!");
      BIPAN_PANIC();
    }

    struct sockaddr* s = (struct sockaddr*)arg1;
    scrub_socket(s);

    in_sigsys_handler = false;
    ctx->uc_mcontext.regs[0] = (__u64)r;
    return;
  }

  if (nr == __NR_socket) {
    // 1st arg is the "domain" of the socket
    if (arg0 == AF_NETLINK) {
      write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Blocked AF_NETLINK socket");
      ctx->uc_mcontext.regs[0] = (__u64)-EAFNOSUPPORT;
      in_sigsys_handler = false;
      return;
    }

    long r = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
    ctx->uc_mcontext.regs[0] = (__u64)r;
    in_sigsys_handler = false;
    return;
  }

#ifdef IN_APP_PERF_ANALYSIS
  pid_t injectedPid = (pid_t)arm64_raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
  char injectedThName[16] = {0};
  arm64_raw_syscall(__NR_prctl, PR_GET_NAME, (long)injectedThName, 0, 0, 0, 0);
  pid_t injectedTid = (pid_t)arm64_raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
  long long beforeIpcLock = ns_now();
#endif

  lock_ipc();

#ifdef IN_APP_PERF_ANALYSIS
  long long afterIpcLock = ns_now() - beforeIpcLock;
  write_to_logcat_async(ANDROID_LOG_DEBUG, PERF_TAG, "Thread %s (PID: %d | TID: %d) waited %lld ns (%.3f ms) to get lock on IPC memory",
                        injectedThName,
                        injectedPid,
                        injectedTid,
                        afterIpcLock,
                        (double)afterIpcLock / 1e6);
#endif

  ipc_mem->stack_trace[0] = ctx->uc_mcontext.regs[30];  // Link Register (x30)
  ipc_mem->caller_pc = ctx->uc_mcontext.pc;             // Program counter at time of trap
  ipc_mem->caller_fp = ctx->uc_mcontext.regs[29];       // Frame Pointer (x29)
  ipc_mem->target_pid = (pid_t)arm64_raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
  ipc_mem->nr = nr;
  ipc_mem->arg0 = arg0;
  ipc_mem->arg1 = arg1;
  ipc_mem->arg2 = arg2;
  ipc_mem->arg3 = arg3;
  ipc_mem->arg4 = arg4;
  ipc_mem->arg5 = arg5;

  // Zero-out string payloads
  local_memset(ipc_mem->string_payload, 0, sizeof(ipc_mem->string_payload));
  local_memset(ipc_mem->struct_payload, 0, sizeof(ipc_mem->struct_payload));
  local_memset(ipc_mem->out_buffer, 0, sizeof(ipc_mem->out_buffer));
  __sync_synchronize();

  int pre_fd = -1;  // app-side fd to be filled by Broker open-like syscalls

  // Serialization of strings
  if (nr == __NR_openat) {
    pre_fd = (int)arm64_raw_syscall(__NR_memfd_create, (long)arg1, MFD_CLOEXEC, 0, 0, 0, 0);
    ipc_mem->arg5 = pre_fd;
    local_strncpy(ipc_mem->string_payload, (const char*)arg1, 255);
  } else if (nr == __NR_faccessat ||
             nr == __NR_newfstatat ||
             nr == __NR_inotify_add_watch ||
             nr == __NR_readlinkat) {
    local_strncpy(ipc_mem->string_payload, (const char*)arg1, 255);
  } else if (nr == __NR_execve ||
             nr == __NR_execveat) {
    local_strncpy(ipc_mem->string_payload, (const char*)arg0, 255);
  }

  // Serialization of structs
  long sock_ptr = 0;
  long sock_len = 0;
  struct sockaddr_storage temp_addr;  // Used for the Pre-Flight check

  if (nr == __NR_bind || nr == __NR_connect) {
    sock_ptr = arg1;
    sock_len = arg2;
  } else if (nr == __NR_sendto || nr == __NR_sendmsg) {
    long sockfd = arg0;
    if (nr == __NR_sendto) {
      sock_ptr = arg4;
      sock_len = arg5;
    } else {
      struct msghdr* msg = (struct msghdr*)arg1;

      sock_ptr = (long)msg->msg_name;
      sock_len = msg->msg_namelen;

      // get message's length
      long total_len = 0;
      for (size_t i = 0; i < msg->msg_iovlen; i++) {
        total_len += msg->msg_iov[i].iov_len;
      }
      // sendmsg takes 3 so pass its size in this empty slot
      ipc_mem->arg3 = total_len;
    }

    /**
     * If msg_name inside msghdr (sendmsg) or
     * dest_addr (sendto) is empty, we are talking about
     * an already connected socket. Ask the kernel
     * its address to prevent LAN chatter
     */
    if (sock_ptr == 0) {
      long temp_len = sizeof(temp_addr);
      local_memset(&temp_addr, 0, sizeof(temp_addr));

      // getpeername gives us the destination IP of a connected socket
      if (arm64_raw_syscall(__NR_getpeername, sockfd, (long)&temp_addr, (long)&temp_len, 0, 0, 0) == 0) {
        sock_ptr = (long)&temp_addr;
        sock_len = temp_len;
      }
    }
  }

  // getsockname populates the struct on return, no need to send it upfront
  if (sock_ptr != 0 && sock_len > 0) {
    size_t copy_len = (sock_len > 127) ? 127 : (size_t)sock_len;
    local_memcpy(ipc_mem->struct_payload, (const void*)sock_ptr, copy_len);
  }

#ifdef IN_APP_PERF_ANALYSIS
  long long beforeBrokerResponse = ns_now();
#endif

  // Wake Broker
  ipc_mem->status = REQUEST_SYSCALL;
  futex_wake(&ipc_mem->status);
  // Go to sleep...
  while (ipc_mem->status != BROKER_ANSWERED) {
    futex_wait(&ipc_mem->status, REQUEST_SYSCALL);
  }

// Thread woke up...
#ifdef IN_APP_PERF_ANALYSIS
  long long afterBrokerResponse = ns_now() - beforeBrokerResponse;
  write_to_logcat_async(ANDROID_LOG_DEBUG, PERF_TAG, "Thread %s (PID: %d | TID: %d) waited %lld ns (%.3f ms) for Broker to answer",
                        injectedThName,
                        injectedPid,
                        injectedTid,
                        afterBrokerResponse,
                        (double)afterBrokerResponse / 1e6);
#endif

  long result = 0;
  int action = ipc_mem->action;

  // Route action based on Broker policy decision
  if (action == ACTION_EXIT_PROCESS) {
    if (pre_fd >= 0) {
      arm64_raw_syscall(__NR_close, pre_fd, 0, 0, 0, 0, 0);
    }
    ipc_mem->status = IDLE;
    unlock_ipc();

    in_sigsys_handler = false;

    arm64_raw_syscall(__NR_exit, ipc_mem->ret, 0, 0, 0, 0, 0);
  } else if (action == ACTION_EXECUTE_NATIVE) {
    if (pre_fd >= 0) {
      arm64_raw_syscall(__NR_close, pre_fd, 0, 0, 0, 0, 0);
    }

    // fork/exec family handling:
    // clear reentrancy flag and IPC lock before the exec'ing
    if (nr == __NR_execve || nr == __NR_execveat) {
      in_sigsys_handler = false;
      ipc_mem->status = IDLE;
      unlock_ipc();
    }

    result = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);

    // if exec actually fails, we reach here,
    // so we restore the state so that the cleanup
    // code at the bottom doesn't double-unlock
    if (nr == __NR_execve || nr == __NR_execveat) {
      lock_ipc();
      in_sigsys_handler = true;
    }
  } else if (action == ACTION_USE_RET) {
    if (pre_fd >= 0 && ipc_mem->ret != pre_fd) {
      // Cleanup if Broker rejected
      arm64_raw_syscall(__NR_close, pre_fd, 0, 0, 0, 0, 0);
    }

    result = ipc_mem->ret;

    // Deserialize outputs
    if (nr == __NR_uname && result == 0) {
      local_memcpy((void*)arg0, ipc_mem->out_buffer, sizeof(struct utsname));
    }
    if (nr == __NR_readlinkat && result > 0) {
      char* buf = (char*)ipc_mem->arg2;
      size_t bufsiz = (size_t)ipc_mem->arg3;
      size_t copy_len = local_strnlen((char*)ipc_mem->out_buffer, bufsiz - 1);
      local_memcpy(buf, ipc_mem->out_buffer, copy_len);
    }
    if (nr == __NR_newfstatat && result == 0) {
      struct stat* buf = (struct stat*)ipc_mem->arg2;
      local_memcpy(buf, ipc_mem->out_buffer, sizeof(struct stat));
    }
    if (nr == __NR_fstat && result == 0) {
      struct stat* buf = (struct stat*)ipc_mem->arg1;
      local_memcpy(buf, ipc_mem->out_buffer, sizeof(struct stat));
    }
  }

  ipc_mem->status = IDLE;
  unlock_ipc();

  ctx->uc_mcontext.regs[0] = (__u64)result;
  in_sigsys_handler = false;
}

static inline void scrub_socket(struct sockaddr* s) {
  if (!s) return;

  if (s->sa_family == AF_INET) {
    struct sockaddr_in* sin = (struct sockaddr_in*)s;

    sin->sin_addr.s_addr = 0x01DE6F0A;  // 10.111.222.1

    // write_to_logcat_async(ANDROID_LOG_INFO, TAG, "IPv4 (getsockname) scrubbed");
  } else if (s->sa_family == AF_INET6) {
    struct sockaddr_in6* sin6 = (struct sockaddr_in6*)s;

    // Unique Local Address (ULA) like fd00::1
    local_memset(&sin6->sin6_addr, 0, 16);
    sin6->sin6_addr.s6_addr[0] = 0xfd;
    sin6->sin6_addr.s6_addr[15] = 0x01;

    // write_to_logcat_async(ANDROID_LOG_INFO, TAG, "IPv6 (getsockname) scrubbed");
  }
}

#ifdef IN_APP_ADDITIONAL_HANDLERS
static thread_local bool inside_additional_handler = false;
static void bipan_additional_sig_handler(int sig, siginfo_t* info, void* void_context) {
  if (sig == SIGABRT) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Injected app got SIGABRT!");
  } else if (sig == SIGSEGV) {
    if (info->si_code == SEGV_MAPERR) {
      write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Injected app got SIGSEGV SEGV_MAPERR");
    } else if (info->si_code == SEGV_ACCERR) {
      write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Injected app got SIGSEGV SEGV_ACCERR");
    } else {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Injected app got unknown SIGSEGV(%d)", info->si_code);
    }
  } else if (sig == SIGQUIT) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Injected app got SIGQUIT!");
  } else {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Injected app got unknown signal: (%d). Aborting!", sig);
    BIPAN_PANIC();
  }

  if (inside_additional_handler) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Recursed additional signal handler. Aborting!");
    BIPAN_PANIC();
  }
  inside_additional_handler = true;

  ucontext_t* ctx = (ucontext_t*)void_context;

  int nr = info->si_syscall;
  __u64 faultAddr = ctx->uc_mcontext.fault_address;

  long x0 = (long)ctx->uc_mcontext.regs[0];
  long x1 = (long)ctx->uc_mcontext.regs[1];
  long x2 = (long)ctx->uc_mcontext.regs[2];
  long x3 = (long)ctx->uc_mcontext.regs[3];
  long x4 = (long)ctx->uc_mcontext.regs[4];
  long x5 = (long)ctx->uc_mcontext.regs[5];

  __u64 pc = ctx->uc_mcontext.pc;
  __u64 lr = ctx->uc_mcontext.regs[30];
  __u64 fp = ctx->uc_mcontext.regs[29];
  __u64 sp = ctx->uc_mcontext.sp;

  write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Syscall that triggered segfault: %d | Fault addr: %p", nr, faultAddr);

  write_to_logcat_async(ANDROID_LOG_FATAL, TAG,
                        "x0=%ld | x1=%ld | x2=%ld | x3=%ld | x4=%ld | x5=%ld",
                        x0, x1, x2, x3, x4, x5);

  write_to_logcat_async(ANDROID_LOG_FATAL, TAG,
                        "pc=%p | lr=%p | fp=%p | sp=%p",
                        pc, lr, fp, sp);

  print_backtrace();
  BIPAN_PANIC();
}

static _Unwind_Reason_Code unwind_callback(struct _Unwind_Context* context, void* arg) {
  BacktraceState* state = (BacktraceState*)arg;

  uintptr_t pc = _Unwind_GetIP(context);
  if (pc == 0) {
    return _URC_END_OF_STACK;
  }

  if (state->count >= state->max) {
    return _URC_END_OF_STACK;
  }

  state->frames[state->count++] = (void*)pc;
  return _URC_NO_REASON;
}

static int capture_backtrace(void** out_frames, int max_frames) {
  BacktraceState state = {out_frames, 0, max_frames};
  _Unwind_Backtrace(unwind_callback, &state);
  return state.count;
}

static void print_backtrace() {
  void* frames[MAX_STACK_TRACE];
  int count = capture_backtrace(frames, MAX_STACK_TRACE);

  for (int i = 0; i < count; i++) {
    Dl_info info;
    if (dladdr(frames[i], &info) && info.dli_sname) {
      uintptr_t offset = (uintptr_t)frames[i] - (uintptr_t)info.dli_saddr;
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "#%02d pc %p %s (%s+0x%lx)",
                            i, frames[i],
                            info.dli_fname ? info.dli_fname : "?",
                            info.dli_sname,
                            (unsigned long)offset);
    } else if (dladdr(frames[i], &info) && info.dli_fname) {
      uintptr_t offset = (uintptr_t)frames[i] - (uintptr_t)info.dli_fbase;
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "#%02d pc 0x%lx %s", i, (unsigned long)offset, info.dli_fname);
    } else {
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "#%02d pc %p <unknown>", i, frames[i]);
    }
  }
}

#endif
