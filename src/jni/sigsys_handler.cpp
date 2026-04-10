#include "sigsys_handler.hpp"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <linux/memfd.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
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

struct kernel_sigaction {
  void (*sa_handler)(int, siginfo_t*, void*);
  unsigned long sa_flags;
  void (*sa_restorer)(void);
  uint64_t sa_mask;
};

void registerSigSysHandler() {
  struct kernel_sigaction sa = {};
  sa.sa_handler = sigsys_log_handler;
  sa.sa_flags = SA_SIGINFO;

  // Install the signal handler directly with the kernel
  // to avoid issues with libsigchain
  // sizeof(sigset_t) should be 8 bytes on aarch64
  long ret = arm64_raw_syscall(__NR_rt_sigaction, SIGSYS, (long)&sa, 0, 8, 0, 0);

  if (ret != 0) {
    LOGE("registerSigSysHandler: Failed to set SIGSYS handler directly (error: %ld)", ret);
    _exit(1);
  }
}

static void sigsys_log_handler(int sig, siginfo_t* info, void* void_context) {
  ucontext_t* ctx = (ucontext_t*)void_context;
  uintptr_t pc = ctx->uc_mcontext.pc;
  uintptr_t lr = ctx->uc_mcontext.regs[30];
  int nr = info->si_syscall;  // syscalls go in x8 in aarch64

  bool is_critical_syscall = (nr == __NR_rt_sigaction ||
                              nr == __NR_execve ||
                              nr == __NR_execveat);

  // Don't block legitimate system threads
  if (!is_critical_syscall && is_system_thread()) {
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
      LOGE("Violation: execve/execveat");

      // log_address_info("PC", pc);
      // log_address_info("LR", lr);

      LOGE("Binary: %s", path);
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

      bool reading_smaps = (strcmp(pathname, "/proc/self/smaps") == 0) ||
                           ((safe_proc_pid_path[0] != '\0') &&
                            starts_with(pathname, safe_proc_pid_path) &&
                            strstr(pathname, "/smaps") != nullptr);

      if (reading_maps) {
        ctx->uc_mcontext.regs[0] = clean_proc_maps(dirfd, pathname, flags, mode);
        break;
      } else if (reading_smaps) {
        ctx->uc_mcontext.regs[0] = clean_proc_smaps(dirfd, pathname, flags, mode);
        break;
      }

      bool reading_mounts = (strcmp(pathname, "/proc/mounts") == 0) ||
                            (strcmp(pathname, "/proc/self/mounts") == 0) ||
                            ((safe_proc_pid_path[0] != '\0') &&
                             starts_with(pathname, safe_proc_pid_path) &&
                             strstr(pathname, "/mounts") != nullptr);

      if (reading_mounts) {
        ctx->uc_mcontext.regs[0] = clean_proc_mounts(dirfd, pathname, flags, mode);
        break;
      }

      // Filters senstive files and uses magic number under the hood
      ctx->uc_mcontext.regs[0] = filterPathname(
          nr,
          arg0,
          arg1,
          arg2,
          arg3,
          arg4);
      break;
    }
    case __NR_rt_sigaction: {
      int signum = arg0;
      const struct kernel_sigaction* act = (const struct kernel_sigaction*)arg1;
      struct kernel_sigaction* oldact = (struct kernel_sigaction*)arg2;

      if (signum == SIGSYS) {
        LOGE("App tried to install SIGSYS handler! Blocking.");

        if (act != nullptr) {
          uintptr_t sigaction_handler = (uintptr_t)act->sa_handler;
          LOGW("sa_flags: %lu", act->sa_flags);
          LOGW("sa_mask: %llu", (unsigned long long)act->sa_mask);

          if (act->sa_restorer) {
            LOGW("sa_restorer: %p", act->sa_restorer);
          } else {
            LOGW("no sa_restorer defined");
          }

          if (act->sa_handler) {
            LOGW("sa_handler: %p", act->sa_handler);
          } else {
            LOGE("no sa_handler defined");
          }
        } else {
          LOGW("App is querying SIGSYS handler (act is NULL)");
        }

        ctx->uc_mcontext.regs[0] = -EPERM;
      } else {
        LOGW("Allowing sigaction for signal different from SIGSYS");
        ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(
            nr,
            arg0,
            arg1,
            arg2,
            arg3,
            arg4);
      }

      break;
    }
    case __NR_bind: {
      int sockfd = (int)arg0;

      struct sockaddr* addr = (struct sockaddr*)arg1;
      if (addr == nullptr) {
        LOGE("bind address is NULL! Replying with EFAULT");
        ctx->uc_mcontext.regs[0] = -EFAULT;
        return;
      }
      int sock_type = 0;
      socklen_t optlen = sizeof(sock_type);

      long ret = arm64_bypassed_syscall(__NR_getsockopt, sockfd, SOL_SOCKET, SO_TYPE, (long)&sock_type, (long)&optlen);
      if (ret != 0) {
        LOGE("getsockopt returned error: %ld. Allowing bind to fail natively", ret);
        ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
        return;
      }

      const char* proto = "UNKNOWN";
      if (sock_type == SOCK_STREAM) {
        proto = "TCP";
      } else if (sock_type == SOCK_DGRAM) {
        proto = "UDP";
      }

      char ipAddrStr[INET6_ADDRSTRLEN] = {0};  // use IPv6 as its larger and fits IPv4
      int port = -1;
      bool shouldBlock = false;

      if (addr->sa_family == AF_INET) {
        struct sockaddr_in* ipv4 = (struct sockaddr_in*)addr;
        port = ntohs(ipv4->sin_port);
        inet_ntop(AF_INET, &(ipv4->sin_addr), ipAddrStr, INET_ADDRSTRLEN);
        shouldBlock = true;

      } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)addr;
        port = ntohs(ipv6->sin6_port);
        inet_ntop(AF_INET6, &(ipv6->sin6_addr), ipAddrStr, INET6_ADDRSTRLEN);
        shouldBlock = true;
      }

      if (shouldBlock) {
        if (port == 0) {
          // "Client" behavior: requesting a random temporary port
          LOGW("(bind) Allowing ephemeral bind on Port 0/%s", proto);
          ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
          return;
        } else {
          // "Server" behavior: setting up a port for listening
          LOGE("(bind) Spoofing success of bind on %s:%d (%s)", ipAddrStr, port, proto);
          ctx->uc_mcontext.regs[0] = 0;
          return;
        }
      } else {
        LOGW("(bind) Allowing non-IP bind request");
        ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
        return;
      }
    }
    case __NR_listen: {
      int sockfd = (int)arg0;

      struct sockaddr_storage addr;
      socklen_t len = sizeof(addr);
      long ret = arm64_bypassed_syscall(__NR_getsockname, sockfd, (long)&addr, (long)&len, 0, 0);

      if (ret != 0) {
        LOGE("getsockname returned error: %ld. Allowing native failure", ret);
        ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
        return;
      }
      if (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
        // Don't allow network sockets to listen...
        LOGE("(listen) spoofing success");
        ctx->uc_mcontext.regs[0] = 0;
        return;
      } else {
        LOGD("(listen) Allowing for local/UNIX socket");
        ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
        return;
      }
    }
    case __NR_sendto: {
      struct sockaddr* dest_addr = (struct sockaddr*)arg4;
      if (dest_addr != nullptr) {
        int dest_port = -1;
        char ipAddrStr[INET6_ADDRSTRLEN] = {0};
        const char* proto = "UNKNOWN";
        bool is_lan = false;

        if (dest_addr->sa_family == AF_INET) {
          struct sockaddr_in* ipv4 = (struct sockaddr_in*)dest_addr;
          dest_port = ntohs(ipv4->sin_port);
          uint32_t ip4 = ntohl(ipv4->sin_addr.s_addr);
          inet_ntop(AF_INET, &(ipv4->sin_addr), ipAddrStr, INET_ADDRSTRLEN);
          proto = "IPv4";

          is_lan = filterIPv4LanAccess(ip4);
        } else if (dest_addr->sa_family == AF_INET6) {
          struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)dest_addr;
          dest_port = ntohs(ipv6->sin6_port);
          uint8_t* ip6 = ipv6->sin6_addr.s6_addr;
          inet_ntop(AF_INET6, &(ipv6->sin6_addr), ipAddrStr, INET6_ADDRSTRLEN);
          proto = "IPv6";

          is_lan = filterIPv6LanAccess(ip6);
        }

        if (is_lan && dest_port == 53) {
          LOGE("(sendto) Permitting local DNS query to %s:%d (%s)", ipAddrStr, dest_port, proto);
          is_lan = false;  // Unflag it so it doesn't get blocked
        }

        if (is_lan) {
          LOGE("(sendto) %s LAN scan to address %s spoofed", proto, ipAddrStr);
          // Return the number of bytes sent to fool the app into thinking it succeeded
          ctx->uc_mcontext.regs[0] = (long)arg2;
          return;
        }
      }

      ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
      return;
    }
    default: {
      LOGE("Violation: got UNEXPECTED syscall! (%d)", nr);
      ctx->uc_mcontext.regs[0] = -ENOSYS;  // mimic the kernel's response
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
