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
inline static size_t get_msghdr_len(const struct msghdr* msg);
inline static bool is_lan_address(struct sockaddr* addr);
static void sigsys_log_handler(int sig, siginfo_t* info, void* void_context);

void registerSigSysHandler() {
  struct kernel_sigaction sa = {};
  sa.sa_handler = sigsys_log_handler;
  sa.sa_flags = SA_SIGINFO;

  // Talk directly to the kernel in order to avoid libsigchain
  // sizeof(sigset_t) should be 8 bytes on aarch64
  long ret = arm64_raw_syscall(__NR_rt_sigaction, SIGSYS, (long)&sa, 0, 8, 0, 0);

  if (ret != 0) {
    LOGE("Failed to set SIGSYS handler. Aborting for safety!");
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
        break;
      }
      LOGE("Violation: execve/execveat");
      log_violation_trace(path);

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

      if (signum == SIGSYS) {
        LOGE("App tried to install SIGSYS handler! Spoofing success...");
        log_violation_trace("SIGSYS handler hijacking");
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
        break;
      }
      int sock_type = 0;
      socklen_t optlen = sizeof(sock_type);

      long ret = arm64_bypassed_syscall(__NR_getsockopt, sockfd, SOL_SOCKET, SO_TYPE, (long)&sock_type, (long)&optlen);
      if (ret != 0) {
        // Allow to fail natively
        ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
        break;
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
            break;
          }

          // "Client" behavior: requesting a random temporary port
          LOGW("(bind) Allowing ephemeral bind on Port 0/%s", proto);
          ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
          break;
        } else {
          // "Server" behavior: setting up a port for listening
          LOGE("(bind) Spoofing success of bind on %s:%d (%s)", ipAddrStr, port, proto);
          log_violation_trace("(bind): server behavior");
          ctx->uc_mcontext.regs[0] = 0;
          break;
        }
      } else {
        // TODO: https://www.youtube.com/watch?v=Zi7FKB2AU58
        LOGW("(bind) Allowing non-IP bind request");
        ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
        break;
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
        break;
      }
      if (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
        log_violation_trace("(listen): network socket");
        LOGE("(listen) spoofing success");
        ctx->uc_mcontext.regs[0] = 0;
        break;
      } else {
        // TODO: https://www.youtube.com/watch?v=Zi7FKB2AU58
        LOGW("(listen) Allowing for local/UNIX socket");
        ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
        break;
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
          break;
        }
      }

      ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
      break;
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
      break;
    }
    case __NR_socket: {
      int domain = (int)arg0;  // AF_INET, AF_NETLINK, etc.
      int type = (int)arg1;    // SOCK_STREAM, SOCK_RAW, etc.
      int protocol = (int)arg2;

      if (domain == 16) {  // 16 is the constant for AF_NETLINK
        LOGE("(socket) Blocking AF_NETLINK");
        log_violation_trace("(socket): AF_NETLINK");
        ctx->uc_mcontext.regs[0] = -EACCES;
        break;
      }

      // Allow everything else (AF_INET, AF_UNIX, etc.) to proceed normally
      // TODO: https://www.youtube.com/watch?v=Zi7FKB2AU58
      ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
      break;
    }
    case __NR_sendmsg: {
      int sockfd = (int)arg0;
      struct msghdr* msg = (struct msghdr*)arg1;

      if (msg != nullptr && msg->msg_name != nullptr) {
        struct sockaddr* dest_addr = (struct sockaddr*)msg->msg_name;

        // Reuse your LAN check logic here
        bool is_lan = false;
        if (dest_addr->sa_family == AF_INET) {
          uint32_t ip4 = ntohl(((struct sockaddr_in*)dest_addr)->sin_addr.s_addr);
          is_lan = filterIPv4LanAccess(ip4);
        } else if (dest_addr->sa_family == AF_INET6) {
          is_lan = filterIPv6LanAccess(((struct sockaddr_in6*)dest_addr)->sin6_addr.s6_addr);
        }

        if (is_lan) {
          LOGE("(sendmsg) LAN probing via sendmsg spoofed");
          // Fool the app: return the length it tried to send
          ctx->uc_mcontext.regs[0] = (long)get_msghdr_len(msg);
          break;
        }
      }
      ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
      break;
    }
    case __NR_readlinkat: {
      int dirfd = (int)arg0;
      const char* pathname = (const char*)arg1;
      char* buf = (char*)arg2;
      size_t bufsiz = (size_t)arg3;

      // Check if the app is trying to readlink an FD
      if (pathname != nullptr && strstr(pathname, "/proc/self/fd/") != nullptr) {
        int target_fd = atoi(pathname + 14);  // Extract FD number after "/proc/self/fd/"

        std::lock_guard<std::mutex> lock(fds_mutex);
        if (spoofed_fds.count(target_fd)) {
          std::string original = spoofed_fds[target_fd];

          // TODO: too noisy!
          // LOGW("(readlinkat) Correcting symlink for spoofed FD %d -> %s", target_fd, original.c_str());

          // Manually fill the buffer with the "honest" path
          size_t len = std::min(bufsiz - 1, original.length());
          memcpy(buf, original.c_str(), len);
          buf[len] = '\0';

          ctx->uc_mcontext.regs[0] = len;  // Return length of string
          break;
        }
      }

      // Otherwise, let the real readlinkat proceed
      ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
      break;
    }
    default: {
      LOGE("Violation: got unexpected syscall: (%d)", nr);
      ctx->uc_mcontext.regs[0] = -ENOSYS;  // mimic the kernel's response
      break;
    }
  }
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

inline static size_t get_msghdr_len(const struct msghdr* msg) {
  size_t total = 0;
  if (msg && msg->msg_iov) {
    for (size_t i = 0; i < (size_t)msg->msg_iovlen; ++i) {
      total += msg->msg_iov[i].iov_len;
    }
  }
  return total;
}

/**
 * TODO:
 */
inline static bool is_lan_address(struct sockaddr* addr) {
  if (addr == nullptr) return false;
  if (addr->sa_family == AF_INET) {
    return filterIPv4LanAccess(ntohl(((struct sockaddr_in*)addr)->sin_addr.s_addr));
  }
  if (addr->sa_family == AF_INET6) {
    return filterIPv6LanAccess(((struct sockaddr_in6*)addr)->sin6_addr.s6_addr);
  }
  return false;
}
