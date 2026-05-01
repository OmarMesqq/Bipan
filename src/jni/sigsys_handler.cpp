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
#include "utils.hpp"
#include "logger.hpp"
#include <atomic>

#include "blocker.hpp"
#include "shared.hpp"
#include "spoofer.hpp"
#include "synchronization.hpp"
#include "unwinder.hpp"

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
static void sigill_diagnostic_handler(int sig, siginfo_t* info, void* void_context);
static void sigsegv_recovery_handler(int sig, siginfo_t* info, void* void_context);

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

  // Register for SIGILL
  struct kernel_sigaction sa_ILL = {};
  sa_ILL.sa_handler = sigill_diagnostic_handler;
  sa_ILL.sa_flags = SA_SIGINFO;
  ret = arm64_raw_syscall(__NR_rt_sigaction, SIGILL, (long)&sa_ILL, 0, 8, 0, 0);
  if (ret != 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Failed to set SIGILL handler. Aborting for safety!");
    _exit(1);
  }

  // 3. Register SIGSEGV and SAVE the old handler (ART)
  struct kernel_sigaction sa_SEGV = {};
  sa_SEGV.sa_handler = sigsegv_recovery_handler;
  sa_SEGV.sa_flags = SA_SIGINFO;

  // The (long)&old_sa_segv captures ART's existing handler
  ret = arm64_raw_syscall(__NR_rt_sigaction, SIGSEGV, (long)&sa_SEGV, (long)&old_sa_segv, 8, 0, 0);

  if (ret != 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Failed to set SIGSEGV handler.");
    _exit(1);
  }
}

static thread_local bool in_sigsys_handler = false;
static void sigsys_handler(int sig, siginfo_t* info, void* void_context) {
  // 1. REENTRANCY GUARD
  if (in_sigsys_handler) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "!!!Recursed signal handler! Aborting");
    arm64_raw_syscall(__NR_exit, -1, 0, 0, 0, 0, 0);
    return;
  }
  in_sigsys_handler = true;
  ucontext_t* ctx = (ucontext_t*)void_context;
  int nr = info->si_syscall;  // syscalls go in x8 in aarch64

  long arg0 = ctx->uc_mcontext.regs[0];
  long arg1 = ctx->uc_mcontext.regs[1];
  long arg2 = ctx->uc_mcontext.regs[2];
  long arg3 = ctx->uc_mcontext.regs[3];
  long arg4 = ctx->uc_mcontext.regs[4];
  long arg5 = ctx->uc_mcontext.regs[5];

  uintptr_t patch_pc = 0;

  switch (nr) {
    case __NR_execve:
    case __NR_execveat: {
      const char* path = (const char*)ctx->uc_mcontext.regs[0];
      if (is_trusted_system_caller(path, &patch_pc, false)) {
        ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
        break;
      }
      write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Violation: execve/execveat");
      log_violation_trace(path);
      ctx->uc_mcontext.regs[0] = -EAGAIN;
      if (patch_pc != 0) {
        patchInstruction(patch_pc - 4, -EAGAIN);
      }
      break;
    }
    case __NR_uname: {
      struct utsname* buf = (struct utsname*)ctx->uc_mcontext.regs[0];
      write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Spoofing uname");
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

      if (is_trusted_system_caller("(openat/faccessat/newfstatat)", &patch_pc, false)) {
        ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
        break;
      }

      const bool is_vfs = is_maps(pathname) || is_smaps(pathname) || is_mounts(pathname);

      if (is_vfs) {
        if (is_maps(pathname)) {
          ctx->uc_mcontext.regs[0] = clean_proc_maps(dirfd, pathname, flags, mode);
          log_violation_trace(pathname);
        } else if (is_smaps(pathname)) {
          ctx->uc_mcontext.regs[0] = clean_proc_smaps(dirfd, pathname, flags, mode);
          log_violation_trace(pathname);
        } else {
          ctx->uc_mcontext.regs[0] = clean_proc_mounts(dirfd, pathname, flags, mode);
          log_violation_trace(pathname);
        }
        break;
      }

      ctx->uc_mcontext.regs[0] = filterPathname(nr, arg0, arg1, arg2, arg3, arg4, arg5);
      break;
    }
    case __NR_rt_sigaction: {
      int signum = arg0;

      if (signum == SIGSYS) {
        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "App tried to install SIGSYS handler! Spoofing success...");
        log_violation_trace("SIGSYS handler hijacking");
        ctx->uc_mcontext.regs[0] = 0;
      } else {
        ctx->uc_mcontext.regs[0] = arm64_raw_syscall(
            nr,
            arg0,
            arg1,
            arg2,
            arg3,
            arg4,
            arg5);
      }

      break;
    }
    case __NR_bind: {
      int sockfd = (int)arg0;
      struct sockaddr* sockAddrStruct = (struct sockaddr*)arg1;
      if (sockAddrStruct == nullptr) {
        ctx->uc_mcontext.regs[0] = -EFAULT;
        break;
      }
      if (is_trusted_system_caller("(bind)", &patch_pc)) {
        ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
        break;
      }

      char protocol[8] = {0};
      int port = -1;
      char ipAddr[INET6_ADDRSTRLEN] = {0};
      char family[8] = {0};
      get_socket_info(sockfd,
                      sockAddrStruct,
                      protocol,
                      &port,
                      ipAddr,
                      family);

      if (is_network_socket(family)) {
        if (port == 0) {  // Random high ports
          bool is_lan_bind = is_lan_address(sockAddrStruct);

          if (is_lan_bind) {
            write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Violation: client bind on LAN: Protocol: %s, Port: %d, IP address: %s, Family: %s", protocol, port, ipAddr, family);
            log_violation_trace("(bind)");
            ctx->uc_mcontext.regs[0] = -EADDRNOTAVAIL;
            if (patch_pc != 0) {
              patchInstruction(patch_pc - 4, -EADDRNOTAVAIL);
            }
            break;
          }

          // "Client" behavior: requesting a random temporary port
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "Allowing ephemeral (bind): Protocol: %s, Port: %d, IP address: %s, Family: %s", protocol, port, ipAddr, family);
          ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
        } else {
          // "Server" behavior: setting up a port for listening
          write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Violation: server (bind): Protocol: %s, Port: %d, IP address: %s, Family: %s", protocol, port, ipAddr, family);
          log_violation_trace("(bind)");
          ctx->uc_mcontext.regs[0] = 0;
          if (patch_pc != 0) {
            patchInstruction(patch_pc - 4, 0);
          }
        }
      } else {
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(bind) Allowing non-IP bind request");
        ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
      }
      break;
    }
    case __NR_listen: {
      int sockfd = (int)arg0;

      if (is_trusted_system_caller("(listen)", &patch_pc)) {
        ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
        break;
      }

      struct sockaddr_storage sockAddrStorageStruct = {};
      socklen_t len = sizeof(sockAddrStorageStruct);
      long ret = arm64_raw_syscall(__NR_getsockname, sockfd, (long)&sockAddrStorageStruct, (long)&len, 0, 0, 0);
      if (ret != 0) {
        // Fail natively...
        ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
        break;
      }

      char protocol[8] = {0};
      int port = -1;
      char ipAddr[INET6_ADDRSTRLEN] = {0};
      char family[8] = {0};
      get_socket_info(sockfd,
                      (struct sockaddr*)&sockAddrStorageStruct,
                      protocol,
                      &port,
                      ipAddr,
                      family);

      if (is_network_socket(family)) {
        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Violation: (listen): Protocol: %s, Port: %d, IP address: %s, Family: %s", protocol, port, ipAddr, family);
        log_violation_trace("(listen)");
        ctx->uc_mcontext.regs[0] = 0;
        if (patch_pc != 0) {
          patchInstruction(patch_pc - 4, 0);
        }
      } else {
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(listen) Allowing for local/UNIX socket");
        ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
      }
      break;
    }
    case __NR_sendto: {
      int sockfd = (int)arg0;
      struct sockaddr* sockAddrStruct = (struct sockaddr*)arg4;
      if (sockAddrStruct != nullptr) {
        if (is_trusted_system_caller("(sendto)", &patch_pc)) {
          ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
          break;
        }

        char protocol[8] = {0};
        int port = -1;
        char ipAddr[INET6_ADDRSTRLEN] = {0};
        char family[8] = {0};

        get_socket_info(sockfd,
                        sockAddrStruct,
                        protocol,
                        &port,
                        ipAddr,
                        family);

        if (is_network_socket(family)) {
          write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Violation: (sendto): Protocol: %s, Port: %d, IP address: %s, Family: %s", protocol, port, ipAddr, family);
          log_violation_trace("(sendto)");
          ctx->uc_mcontext.regs[0] = (long)arg2;  // amount of bytes sent to fool the app into thinking it succeeded
          if (patch_pc != 0) {
            patchInstruction(patch_pc - 4, (int)arg2);
          }
          break;
        }
      }

      ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
      break;
    }
    case __NR_getsockname: {
      // Let kernel execute the real syscall to populate the sockaddr struct
      long ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);

      // If it succeeded, inspect and scrub the returned struct
      if (ret == 0 && arg1 != 0) {
        if (is_trusted_system_caller("(getsockname)", &patch_pc, false)) {
          ctx->uc_mcontext.regs[0] = ret;
          break;
        }

        int sockfd = (int)arg0;
        struct sockaddr* sockAddrStruct = (struct sockaddr*)arg1;

        char protocol[8] = {0};
        int port = -1;
        char ipAddr[INET6_ADDRSTRLEN] = {0};
        char family[8] = {0};

        get_socket_info(sockfd,
                        sockAddrStruct,
                        protocol,
                        &port,
                        ipAddr,
                        family);

        if (is_network_socket(family)) {
          write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Violation: (getsockname): Protocol: %s, Port: %d, IP address: %s, Family: %s", protocol, port, ipAddr, family);
          // log_violation_trace("(getsockname)");

          if (sockAddrStruct->sa_family == AF_INET) {
            ((struct sockaddr_in*)sockAddrStruct)->sin_addr.s_addr = htonl(INADDR_ANY);  // 0.0.0.0

          } else if (sockAddrStruct->sa_family == AF_INET6) {
            memset(&(((struct sockaddr_in6*)sockAddrStruct)->sin6_addr), 0, 16);  // ::
          }
          ctx->uc_mcontext.regs[0] = ret;
          break;
        }
      }

      ctx->uc_mcontext.regs[0] = ret;
      break;
    }
    case __NR_socket: {
      int domain = (int)arg0;  // AF_INET, AF_NETLINK, etc.
      int type = (int)arg1;    // SOCK_STREAM, SOCK_RAW, etc.
      int protocol = (int)arg2;

      if (domain == AF_NETLINK) {
        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "(socket) Blocking AF_NETLINK");
        is_trusted_system_caller("(socket) AF_NETLINK", &patch_pc);
        ctx->uc_mcontext.regs[0] = -EACCES;
        if (patch_pc != 0) {
          patchInstruction(patch_pc - 4, -EACCES);  // Spoof Permission Denied!
        }
        break;
      }

      ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
      break;
    }
    case __NR_sendmsg: {
      int sockfd = (int)arg0;
      struct msghdr* msg = (struct msghdr*)arg1;

      if (msg != nullptr && msg->msg_name != nullptr) {
        struct sockaddr* sockAddrStruct = (struct sockaddr*)msg->msg_name;

        if (is_trusted_system_caller("(sendmsg)", &patch_pc)) {
          ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
          break;
        }

        char protocol[8] = {0};
        int port = -1;
        char ipAddr[INET6_ADDRSTRLEN] = {0};
        char family[8] = {0};

        get_socket_info(sockfd,
                        sockAddrStruct,
                        protocol,
                        &port,
                        ipAddr,
                        family);

        if (is_network_socket(family)) {
          write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Violation: (sendmsg): Protocol: %s, Port: %d, IP address: %s, Family: %s", protocol, port, ipAddr, family);
          log_violation_trace("(sendmsg)");
          // Fool the app: return the length it tried to send
          ctx->uc_mcontext.regs[0] = (long)get_msghdr_len(msg);
          if (patch_pc != 0) {
            patchInstruction(patch_pc - 4, (int)get_msghdr_len(msg));
          }
          break;
        }
      }
      ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
      break;
    }
    case __NR_readlinkat: {
      const char* pathname = (const char*)arg1;
      char* buf = (char*)arg2;
      size_t bufsiz = (size_t)arg3;

      if (pathname && local_strstr(pathname, "/proc/self/fd/")) {
        int target_fd = local_atoi(pathname + 14);

        // Spinlock instead of Mutex
        while (fds_lock.test_and_set(std::memory_order_acquire));

        int count = spoofed_fd_count.load();
        for (int i = 0; i < count; i++) {
          if (global_spoofed_fds[i].fd == target_fd) {
            const char* orig = global_spoofed_fds[i].original_path;
            size_t len = 0;
            while (orig[len]) len++;

            size_t to_copy = (len < bufsiz - 1) ? len : bufsiz - 1;
            for (size_t j = 0; j < to_copy; j++) buf[j] = orig[j];
            buf[to_copy] = '\0';

            ctx->uc_mcontext.regs[0] = to_copy;
            fds_lock.clear(std::memory_order_release);
            in_sigsys_handler = false;  // Remember to unlock guard before returning
            return;
          }
        }
        fds_lock.clear(std::memory_order_release);
      }
      ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
      break;
    }
    case __NR_mmap: {
      void* addr = (void*)arg0;
      size_t length = (size_t)arg1;
      int prot = (int)arg2;
      int flags = (int)arg3;
      int fd = (int)arg4;
      off_t offset = (off_t)arg5;

      if (is_trusted_system_caller("(mmap)", &patch_pc, false)) {
        ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
        break;
      }
      write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Violation: mmap");
      // log_violation_trace("(mmap)");

      ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
      break;
    }
    case __NR_mprotect: {
      void* addr = (void*)arg0;
      size_t len = (size_t)arg1;
      int prot = (int)arg2;

      if (is_trusted_system_caller("(mprotect)", &patch_pc, false)) {
        ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
        break;
      }
      write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Violation: mprotect");
      // log_violation_trace("(mprotect)");

      ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
      break;
    }
    default: {
      write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Violation: got unexpected syscall(%d). Allowing...", nr);
      ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
      break;
    }
  }
  in_sigsys_handler = false;
}

static void sigill_diagnostic_handler(int sig, siginfo_t* info, void* void_context) {
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
static void sigsegv_recovery_handler(int sig, siginfo_t* info, void* void_context) {
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

