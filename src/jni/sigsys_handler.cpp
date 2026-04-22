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

void storeSpoofedFD(int fd, const char* original_path) {
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
inline static void get_socket_info(int sockfd,
                                   struct sockaddr* sockAddrStruct,
                                   char* protocol,
                                   int* port,
                                   char* ipAddr,
                                   char* family);
inline static bool is_lan_address(struct sockaddr* addr);
inline static bool is_network_socket(const char* family);
static void sigsys_handler(int sig, siginfo_t* info, void* void_context);

void registerSignalHandler() {
  struct kernel_sigaction sa = {};
  sa.sa_handler = sigsys_handler;
  sa.sa_flags = SA_SIGINFO;

  // Talk directly to the kernel in order to avoid libsigchain
  // sizeof(sigset_t) should be 8 bytes on aarch64
  long ret = arm64_raw_syscall(__NR_rt_sigaction, SIGSYS, (long)&sa, 0, 8, 0, 0);

  if (ret != 0) {
    LOGE("Failed to set SIGSYS handler. Aborting for safety!");
    _exit(1);
  }
}

static void sigsys_handler(int sig, siginfo_t* info, void* void_context) {
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
      LOGE("Violation: execve/execveat");
      log_violation_trace(path);
      ctx->uc_mcontext.regs[0] = -EAGAIN;
      if (patch_pc != 0) {
        patchInstruction(patch_pc - 4, -EAGAIN);
      }
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

      ctx->uc_mcontext.regs[0] = filterPathname(nr, arg0, arg1, arg2, arg3, arg4, arg5);
      break;
    }
    case __NR_rt_sigaction: {
      int signum = arg0;

      if (signum == SIGSYS) {
        LOGE("App tried to install SIGSYS handler! Spoofing success...");
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
            LOGE("Violation: client bind on LAN: Protocol: %s, Port: %d, IP address: %s, Family: %s", protocol, port, ipAddr, family);
            log_violation_trace("(bind)");
            ctx->uc_mcontext.regs[0] = -EADDRNOTAVAIL;
            if (patch_pc != 0) {
              patchInstruction(patch_pc - 4, -EADDRNOTAVAIL);
            }
            break;
          }

          // "Client" behavior: requesting a random temporary port
          LOGW("Allowing ephemeral (bind): Protocol: %s, Port: %d, IP address: %s, Family: %s", protocol, port, ipAddr, family);
          ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
        } else {
          // "Server" behavior: setting up a port for listening
          LOGE("Violation: server (bind): Protocol: %s, Port: %d, IP address: %s, Family: %s", protocol, port, ipAddr, family);
          log_violation_trace("(bind)");
          ctx->uc_mcontext.regs[0] = 0;
          if (patch_pc != 0) {
            patchInstruction(patch_pc - 4, 0);
          }
        }
      } else {
        LOGW("(bind) Allowing non-IP bind request");
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
        LOGE("Violation: (listen): Protocol: %s, Port: %d, IP address: %s, Family: %s", protocol, port, ipAddr, family);
        log_violation_trace("(listen)");
        ctx->uc_mcontext.regs[0] = 0;
        if (patch_pc != 0) {
          patchInstruction(patch_pc - 4, 0);
        }
      } else {
        LOGW("(listen) Allowing for local/UNIX socket");
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
          LOGE("Violation: (sendto): Protocol: %s, Port: %d, IP address: %s, Family: %s", protocol, port, ipAddr, family);
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
          // LOGE("Violation: (getsockname): Protocol: %s, Port: %d, IP address: %s, Family: %s", protocol, port, ipAddr, family);
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
        LOGE("(socket) Blocking AF_NETLINK");
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
          LOGE("Violation: (sendmsg): Protocol: %s, Port: %d, IP address: %s, Family: %s", protocol, port, ipAddr, family);
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
      LOGE("Violation: mmap");
      log_violation_trace("(mmap)");

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
      LOGE("Violation: mprotect");
      log_violation_trace("(mprotect)");

      ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
      break;
    }
    default: {
      LOGE("Violation: got unexpected syscall(%d). Allowing...", nr);
      ctx->uc_mcontext.regs[0] = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
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
 * Returns `true` if `sa_family` of given socket struct `addr`
 * is either IPv4 (`AF_INET`) or IPv6 (`AF_INET6`) **AND**
 * its address falls within LAN IP ranges defined by RFCs
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

inline static void get_socket_info(int sockfd,
                                   struct sockaddr* sockAddrStruct,
                                   char* protocol,
                                   int* port,
                                   char* ipAddr,
                                   char* family) {
  if (sockAddrStruct == nullptr) {
    return;
  }
  int sock_type = 0;
  socklen_t optlen = sizeof(sock_type);

  long ret = arm64_raw_syscall(__NR_getsockopt,
                               sockfd, SOL_SOCKET,
                               SO_TYPE,
                               (long)&sock_type,
                               (long)&optlen,
                               0);

  if (ret != 0) {
    LOGE("Failed to get socket info! Aborting!");
    _exit(-1);
  }

  if (sock_type == SOCK_STREAM) {
    write_to_char_buf(protocol, "TCP", 4);
  } else if (sock_type == SOCK_DGRAM) {
    write_to_char_buf(protocol, "UDP", 4);
  } else {
    write_to_char_buf(protocol, "UNKNOWN", 8);
  }

  if (sockAddrStruct->sa_family == AF_INET) {
    struct sockaddr_in* ipv4 = (struct sockaddr_in*)sockAddrStruct;

    *port = ntohs(ipv4->sin_port);
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipAddr, INET_ADDRSTRLEN);
    write_to_char_buf(family, "IPv4", 5);
  } else if (sockAddrStruct->sa_family == AF_INET6) {
    struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)sockAddrStruct;

    *port = ntohs(ipv6->sin6_port);
    inet_ntop(AF_INET6, &(ipv6->sin6_addr), ipAddr, INET6_ADDRSTRLEN);
    write_to_char_buf(family, "IPv6", 5);
  } else {
    write_to_char_buf(family, "UNKNOWN", 8);
  }
}

inline static bool is_network_socket(const char* family) {
  return (strcmp(family, "IPv4") == 0) ||
         (strcmp(family, "IPv6") == 0);
}