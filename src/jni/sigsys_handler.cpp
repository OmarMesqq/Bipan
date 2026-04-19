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

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>

#include "assembly.hpp"
#include "blocker.hpp"
#include "shared.hpp"
#include "spoofer.hpp"
#include "synchronization.hpp"
#include "unwinder.hpp"

std::map<int, std::string> spoofed_fds;
std::mutex fds_mutex;

void register_spoofed_fd(int fd, const char* original_path) {
  std::lock_guard<std::mutex> lock(fds_mutex);
  spoofed_fds[fd] = original_path;
}

struct kernel_sigaction {
  void (*sa_handler)(int, siginfo_t*, void*);
  unsigned long sa_flags;
  void (*sa_restorer)(void);
  uint64_t sa_mask;
};

inline static bool is_smaps(const char* pathname);
inline static bool is_maps(const char* pathname);
inline static bool is_mounts(const char* pathname);
inline bool is_address_lan(struct sockaddr* addr);
static size_t get_msghdr_len(const struct msghdr* msg);
static void sigsys_log_handler(int sig, siginfo_t* info, void* void_context);

void registerSigSysHandler() {
  struct kernel_sigaction sa = {};
  sa.sa_handler = sigsys_log_handler;
  sa.sa_flags = SA_SIGINFO;

  // Talk directly to the kernel in order to avoid libsigchain
  // sizeof(sigset_t) should be 8 bytes on aarch64
  long ret = arm64_raw_syscall(__NR_rt_sigaction, SIGSYS, (long)&sa, 0, 8, 0, 0);

  if (ret != 0) {
    LOGE("registerSigSysHandler: Failed to set SIGSYS handler directly (error: %ld)", ret);
    _exit(1);
  }
}

static void sigsys_log_handler(int sig, siginfo_t* info, void* void_context) {
  ucontext_t* ctx = (ucontext_t*)void_context;
  int nr = info->si_syscall;  // syscalls go in x8 in aarch64

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
      if (is_trusted_system_caller(path, false)) {
        ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
        return;
      }
      LOGE("Violation: execve/execveat(%s)", path);

      ctx->uc_mcontext.regs[0] = -EACCES;
      break;
    }
    case __NR_uname: {
      struct utsname* buf = (struct utsname*)ctx->uc_mcontext.regs[0];
      LOGD("Spoofing uname");
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

      ctx->uc_mcontext.regs[0] = filterPathname(nr, arg0, arg1, arg2, arg3, arg4);
      break;
    }
    case __NR_rt_sigaction: {
      int signum = arg0;
      const struct kernel_sigaction* act = (const struct kernel_sigaction*)arg1;
      struct kernel_sigaction* oldact = (struct kernel_sigaction*)arg2;

      if (signum == SIGSYS) {
        LOGE("App tried to install SIGSYS handler! Spoofing success...");

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
            LOGW("no sa_handler defined");
          }
        } else {
          LOGW("App just queried SIGSYS handler (act is NULL)");
        }
        ctx->uc_mcontext.regs[0] = 0;
      } else {
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
        ctx->uc_mcontext.regs[0] = -EFAULT;
        return;
      }
      int sock_type = 0;
      socklen_t optlen = sizeof(sock_type);

      long ret = arm64_bypassed_syscall(__NR_getsockopt, sockfd, SOL_SOCKET, SO_TYPE, (long)&sock_type, (long)&optlen);
      if (ret != 0) {
        // Allow to fail natively
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
          bool is_lan_bind = false;
          if (addr->sa_family == AF_INET) {
            is_lan_bind = filterIPv4LanAccess(ntohl(((struct sockaddr_in*)addr)->sin_addr.s_addr));
          } else if (addr->sa_family == AF_INET6) {
            is_lan_bind = filterIPv6LanAccess(((struct sockaddr_in6*)addr)->sin6_addr.s6_addr);
          }

          if (is_lan_bind) {
            LOGE("(bind) Blocking probe on LAN IP %s", ipAddrStr);
            log_violation_trace("(bind): LAN binding");
            ctx->uc_mcontext.regs[0] = -EADDRNOTAVAIL;
            return;
          }

          // "Client" behavior: requesting a random temporary port
          LOGW("(bind) Allowing ephemeral bind on Port 0/%s", proto);
          ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
          return;
        } else {
          // "Server" behavior: setting up a port for listening
          LOGE("(bind) Spoofing success of bind on %s:%d (%s)", ipAddrStr, port, proto);
          log_violation_trace("(bind): server behavior");
          ctx->uc_mcontext.regs[0] = 0;
          return;
        }
      } else {
        LOGI("(bind) Allowing non-IP bind request");
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
        // Fail natively...
        ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
        return;
      }
      if (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
        log_violation_trace("(listen): network socket");
        LOGE("(listen) spoofing success");
        ctx->uc_mcontext.regs[0] = 0;
        return;
      } else {
        LOGI("(listen) Allowing for local/UNIX socket");
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
          LOGW("(sendto) Permitting local DNS query to %s:%d (%s)", ipAddrStr, dest_port, proto);
          is_lan = false;
        }

        if (is_lan) {
          LOGE("(sendto) %s LAN probing to address %s spoofed", proto, ipAddrStr);
          log_violation_trace("(sendto) LAN probing");
          ctx->uc_mcontext.regs[0] = (long)arg2;  // amount of bytes sent to fool the app into thinking it succeeded
          return;
        }
      }

      ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
      return;
    }
    case __NR_getsockname: {
      // Let kernel execute the real syscall to populate the sockaddr struct
      long ret = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);

      // If it succeeded, inspect and scrub the returned struct
      if (ret == 0 && arg1 != 0) {
        struct sockaddr* addr = (struct sockaddr*)arg1;

        if (addr->sa_family == AF_INET) {
          struct sockaddr_in* ipv4 = (struct sockaddr_in*)addr;
          uint32_t ip4 = ntohl(ipv4->sin_addr.s_addr);

          if (filterIPv4LanAccess(ip4)) {
            LOGE("(getsockname) LAN leak prevented: Spoofed IPv4 address");
            log_violation_trace("(getsockname): LAN leak IPv4");
            ipv4->sin_addr.s_addr = htonl(INADDR_ANY);
          }
        } else if (addr->sa_family == AF_INET6) {
          struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)addr;

          if (filterIPv6LanAccess(ipv6->sin6_addr.s6_addr)) {
            LOGE("(getsockname) LAN leak prevented: Spoofed IPv6 address");
            log_violation_trace("(getsockname): LAN leak IPv6");
            memset(&ipv6->sin6_addr, 0, sizeof(ipv6->sin6_addr));
          }
        }
      }

      ctx->uc_mcontext.regs[0] = ret;
      return;
    }
    default: {
      LOGE("Violation: got UNEXPECTED syscall! (%d)", nr);
      ctx->uc_mcontext.regs[0] = -ENOSYS;  // mimic the kernel's response
      break;
    }
  }
}

/**
 * TODO:
 */
inline bool is_address_lan(struct sockaddr* addr) {
  if (addr == nullptr) return false;
  if (addr->sa_family == AF_INET) {
    return filterIPv4LanAccess(ntohl(((struct sockaddr_in*)addr)->sin_addr.s_addr));
  }
  if (addr->sa_family == AF_INET6) {
    return filterIPv6LanAccess(((struct sockaddr_in6*)addr)->sin6_addr.s6_addr);
  }
  return false;
}

static size_t get_msghdr_len(const struct msghdr* msg) {
  size_t total = 0;
  if (msg && msg->msg_iov) {
    for (size_t i = 0; i < (size_t)msg->msg_iovlen; ++i) {
      total += msg->msg_iov[i].iov_len;
    }
  }
  return total;
}

inline static bool is_smaps(const char* pathname) {
  return (strcmp(pathname, "/proc/self/smaps") == 0) ||
         ((safe_proc_pid_path[0] != '\0') &&
          starts_with(pathname, safe_proc_pid_path) &&
          strstr(pathname, "/smaps") != nullptr);
}
inline static bool is_maps(const char* pathname) {
  return (strcmp(pathname, "/proc/self/maps") == 0) ||
         ((safe_proc_pid_path[0] != '\0') &&
          starts_with(pathname, safe_proc_pid_path) &&
          strstr(pathname, "/maps") != nullptr);
}
inline static bool is_mounts(const char* pathname) {
  return (strcmp(pathname, "/proc/mounts") == 0) ||
         (strcmp(pathname, "/proc/self/mounts") == 0) ||
         ((safe_proc_pid_path[0] != '\0') &&
          starts_with(pathname, safe_proc_pid_path) &&
          strstr(pathname, "/mounts") != nullptr);
}
