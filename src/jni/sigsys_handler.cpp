#include "sigsys_handler.hpp"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <linux/memfd.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
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

struct kernel_sigaction {
  void (*sa_handler)(int, siginfo_t*, void*);
  unsigned long sa_flags;
  void (*sa_restorer)(void);
  uint64_t sa_mask;
};

void registerSigSysHandler() {
  struct kernel_sigaction sa = {0};
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

      int sock_type = 0;
      socklen_t optlen = sizeof(sock_type);
      long gso_ret = arm64_bypassed_syscall(__NR_getsockopt, sockfd, SOL_SOCKET, SO_TYPE, (long)&sock_type, (long)&optlen);

      const char* protocol = "UNKNOWN";
      if (gso_ret == 0) {
        if (sock_type == SOCK_STREAM) {
          protocol = "TCP";
        } else if (sock_type == SOCK_DGRAM) {
          protocol = "UDP";
        }
      }

      char ip_str[INET6_ADDRSTRLEN] = {0};
      int port = -1;
      bool should_block = false;

      if (addr != nullptr) {
        if (addr->sa_family == AF_INET) {
          struct sockaddr_in* ipv4 = (struct sockaddr_in*)addr;
          port = ntohs(ipv4->sin_port);
          inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);
          should_block = true;
        } else if (addr->sa_family == AF_INET6) {
          struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)addr;
          port = ntohs(ipv6->sin6_port);
          inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip_str, INET6_ADDRSTRLEN);
          should_block = true;
        }
      }

      if (should_block) {
        if (port == 0) {
          // Client behavior: requesting a random temporary port for outbound traffic
          LOGD("[%s] Allowing ephemeral bind on Port 0", protocol);
          ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
        } else {
          // Server behavior: trying to open a specific listening port
          LOGE("[%s] SERVER BLOCKED: bind on %s:%d", protocol, ip_str, port);
          ctx->uc_mcontext.regs[0] = -EACCES;
        }
      } else {
        LOGD("Allowing non-IP bind request");
        ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
      }
      break;
    }
    case __NR_socket: {
      int domain = (int)arg0;
      int type = (int)arg1;

      // Allow the socket creation so DNS and basic OS routing works.
      // We will stop the bad behavior in the bind() and connect() hooks instead.
      const char* domain_name = (domain == AF_INET || domain == AF_INET6) ? "NETWORK" : (domain == AF_UNIX ? "AF_UNIX" : "OTHER");

      LOGD("Allowing socket creation (Domain: %s [%d], Type: %d)", domain_name, domain, type);
      ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
      break;
    }
    case __NR_listen: {
      // The listen() syscall signature is: int listen(int sockfd, int backlog);
      // If an app tries to listen, it is acting as a server. Period.

      int sockfd = (int)arg0;

      // We only care about network sockets. Let's check if it's AF_UNIX.
      struct sockaddr_storage addr;
      socklen_t len = sizeof(addr);
      long getname_ret = arm64_bypassed_syscall(__NR_getsockname, sockfd, (long)&addr, (long)&len, 0, 0);

      if (getname_ret == 0 && (addr.ss_family == AF_INET || addr.ss_family == AF_INET6)) {
        LOGE("SERVER BLOCKED: Prevented listen() on network socket");
        ctx->uc_mcontext.regs[0] = -EACCES;  // Permission Denied
      } else {
        LOGD("Allowing listen() on local/UNIX socket");
        ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
      }
      break;
    }
    case __NR_sendto: {
      // sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
      struct sockaddr* dest_addr = (struct sockaddr*)arg4;
      bool is_lan = false;
      int dest_port = -1;  // Added to track the destination port
      char ip_str[INET6_ADDRSTRLEN] = {0};
      const char* proto_str = "UNKNOWN";

      if (dest_addr != nullptr) {
        if (dest_addr->sa_family == AF_INET) {
          struct sockaddr_in* ipv4 = (struct sockaddr_in*)dest_addr;
          dest_port = ntohs(ipv4->sin_port);  // Extract the Port
          uint32_t ip = ntohl(ipv4->sin_addr.s_addr);
          inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);
          proto_str = "IPv4";

          // --- IPv4 BLOCKS ---
          if ((ip & 0xFF000000) == 0x0A000000) {  // 10.0.0.0/8 (Class A Private)
            is_lan = true;
          } else if ((ip & 0xFFF00000) == 0xAC100000) {  // 172.16.0.0/12 (Class B Private)
            is_lan = true;
          } else if ((ip & 0xFFFF0000) == 0xC0A80000) {  // 192.168.0.0/16 (Class C Private)
            is_lan = true;
          } else if ((ip & 0xF0000000) == 0xE0000000) {  // 224.0.0.0/4 (Multicast)
            is_lan = true;
          } else if (ip == 0xFFFFFFFF) {  // 255.255.255.255 (Broadcast)
            is_lan = true;
          }

        } else if (dest_addr->sa_family == AF_INET6) {
          struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)dest_addr;
          dest_port = ntohs(ipv6->sin6_port);      // Extract the Port
          uint8_t* ip6 = ipv6->sin6_addr.s6_addr;  // Array of 16 bytes
          inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip_str, INET6_ADDRSTRLEN);
          proto_str = "IPv6";

          // --- IPv6 BLOCKS ---
          // fe80::/10 (Link-Local): First byte is 0xFE, top 2 bits of second byte are 10 (0x80)
          if (ip6[0] == 0xFE && (ip6[1] & 0xC0) == 0x80) {
            is_lan = true;
          }
          // fc00::/7 (Unique Local): Top 7 bits are 1111 110 (0xFC)
          else if ((ip6[0] & 0xFE) == 0xFC) {
            is_lan = true;
          }
          // ff00::/8 (Multicast): First byte is 0xFF
          else if (ip6[0] == 0xFF) {
            is_lan = true;
          }
        }
      }

      if (is_lan && dest_port == 53) {
        LOGE("[%s] Permitting local DNS query to %s:%d", proto_str, ip_str, dest_port);
        is_lan = false;  // Unflag it so it doesn't get blocked
      }

      if (is_lan) {
        LOGE("[%s] LAN SCAN BLOCKED: sendto %s", proto_str, ip_str);
        // -EACCES works, but -ENETUNREACH (Network is unreachable) is the
        // POSIX standard way to tell an app a subnet is blocked by routing rules.
        ctx->uc_mcontext.regs[0] = -EACCES;
        break;  // exit switch
      }

      // Allow if it's a global internet IP, or if it's AF_UNIX
      ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
      break;
    }
    case __NR_connect: {
      struct sockaddr* dest_addr = (struct sockaddr*)arg1;
      bool is_lan = false;
      int dest_port = -1;
      char ip_str[INET6_ADDRSTRLEN] = {0};
      const char* proto_str = "UNKNOWN";

      if (dest_addr != nullptr) {
        if (dest_addr->sa_family == AF_INET) {
          struct sockaddr_in* ipv4 = (struct sockaddr_in*)dest_addr;
          dest_port = ntohs(ipv4->sin_port);
          uint32_t ip = ntohl(ipv4->sin_addr.s_addr);
          inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);
          proto_str = "IPv4";

          if ((ip & 0xFF000000) == 0x0A000000)
            is_lan = true;  // 10.0.0.0/8
          else if ((ip & 0xFFF00000) == 0xAC100000)
            is_lan = true;  // 172.16.0.0/12
          else if ((ip & 0xFFFF0000) == 0xC0A80000)
            is_lan = true;  // 192.168.0.0/16
          else if ((ip & 0xF0000000) == 0xE0000000)
            is_lan = true;  // 224.0.0.0/4
          else if (ip == 0xFFFFFFFF)
            is_lan = true;  // Broadcast

        } else if (dest_addr->sa_family == AF_INET6) {
          struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)dest_addr;
          dest_port = ntohs(ipv6->sin6_port);
          uint8_t* ip6 = ipv6->sin6_addr.s6_addr;
          inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip_str, INET6_ADDRSTRLEN);
          proto_str = "IPv6";

          if (ip6[0] == 0xFE && (ip6[1] & 0xC0) == 0x80)
            is_lan = true;  // fe80::/10
          else if ((ip6[0] & 0xFE) == 0xFC)
            is_lan = true;  // fc00::/7
          else if (ip6[0] == 0xFF)
            is_lan = true;  // ff00::/8
        }
      }

      if (is_lan && dest_port == 53) {
        LOGD("[%s] Permitting local DNS connect to %s:%d", proto_str, ip_str, dest_port);
        is_lan = false;  // Unflag it
      }

      if (is_lan) {
        LOGE("[%s] LAN SCAN BLOCKED: connect to %s:%d", proto_str, ip_str, dest_port);
        ctx->uc_mcontext.regs[0] = -ENETUNREACH;
        break;
      }

      ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
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
