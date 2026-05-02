#include "broker.hpp"

#include <fcntl.h>
#include <linux/memfd.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <fstream>
#include <string>

#include "blocker.hpp"
#include "logger.hpp"
#include "shared.hpp"
#include "spoofer.hpp"
#include "synchronization.hpp"
#include "unwinder.hpp"

void startBroker(int sock) {
  prctl(PR_SET_NAME, "K67v3741S1Xm", 0, 0, 0);

  while (true) {
    while (ipc_mem->status != REQUEST_SYSCALL) {
      futex_wait(&ipc_mem->status, ipc_mem->status);
    }
    __sync_synchronize();

    long ret = -ENOSYS;
    uintptr_t patch_pc = 0;
    int nr = ipc_mem->nr;
    long arg0 = ipc_mem->arg0;
    long arg1 = ipc_mem->arg1;
    long arg2 = ipc_mem->arg2;
    long arg3 = ipc_mem->arg3;
    long arg4 = ipc_mem->arg4;
    long arg5 = ipc_mem->arg5;

    switch (nr) {
      case __NR_execve:
      case __NR_execveat: {
        const char* path = (const char*)arg0;
        if (is_trusted_system_caller(path, &patch_pc, false)) {
          ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
          break;
        }
        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Violation: execve/execveat");
        log_violation_trace(path);
        ret = -EAGAIN;
        if (patch_pc != 0) {
          patchInstruction(patch_pc - 4, -EAGAIN);
        }
        break;
      }
      case __NR_uname: {
        struct utsname* buf = (struct utsname*)arg0;
        write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Spoofing uname");
        ret = uname_spoofer(buf);
        break;
      }
      case __NR_faccessat:
      case __NR_newfstatat:
      case __NR_openat: {
        int dirfd = (int)arg0;
        const char* pathname = (const char*)arg1;
        int flags = (int)arg2;
        mode_t mode = (mode_t)arg3;

        if (is_trusted_system_caller("(openat/faccessat/newfstatat)", &patch_pc, false)) {
          ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
          break;
        }

        const bool is_vfs = is_maps(pathname) || is_smaps(pathname) || is_mounts(pathname);

        if (is_vfs) {
          if (is_maps(pathname)) {
            ret = clean_proc_maps(dirfd, pathname, flags, mode);
            log_violation_trace(pathname);
          } else if (is_smaps(pathname)) {
            ret = clean_proc_smaps(dirfd, pathname, flags, mode);
            log_violation_trace(pathname);
          } else {
            ret = clean_proc_mounts(dirfd, pathname, flags, mode);
            log_violation_trace(pathname);
          }
          break;
        }

        ret = filterPathname(nr, arg0, arg1, arg2, arg3, arg4, arg5);
        break;
      }
      case __NR_rt_sigaction: {
        int signum = arg0;

        if (signum == SIGSYS) {
          write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "App tried to install SIGSYS handler! Spoofing success...");
          log_violation_trace("SIGSYS handler hijacking");
          ret = 0;
        } else {
          ret = arm64_raw_syscall(
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
          ret = -EFAULT;
          break;
        }
        if (is_trusted_system_caller("(bind)", &patch_pc)) {
          ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
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
              ret = -EADDRNOTAVAIL;
              if (patch_pc != 0) {
                patchInstruction(patch_pc - 4, -EADDRNOTAVAIL);
              }
              break;
            }

            // "Client" behavior: requesting a random temporary port
            write_to_logcat_async(ANDROID_LOG_WARN, TAG, "Allowing ephemeral (bind): Protocol: %s, Port: %d, IP address: %s, Family: %s", protocol, port, ipAddr, family);
            ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
          } else {
            // "Server" behavior: setting up a port for listening
            write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Violation: server (bind): Protocol: %s, Port: %d, IP address: %s, Family: %s", protocol, port, ipAddr, family);
            log_violation_trace("(bind)");
            ret = 0;
            if (patch_pc != 0) {
              patchInstruction(patch_pc - 4, 0);
            }
          }
        } else {
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(bind) Allowing non-IP bind request");
          ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
        }
        break;
      }
      case __NR_listen: {
        int sockfd = (int)arg0;

        if (is_trusted_system_caller("(listen)", &patch_pc)) {
          ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
          break;
        }

        struct sockaddr_storage sockAddrStorageStruct = {};
        socklen_t len = sizeof(sockAddrStorageStruct);
        long ret = arm64_raw_syscall(__NR_getsockname, sockfd, (long)&sockAddrStorageStruct, (long)&len, 0, 0, 0);
        if (ret != 0) {
          // Fail natively...
          ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
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
          ret = 0;
          if (patch_pc != 0) {
            patchInstruction(patch_pc - 4, 0);
          }
        } else {
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(listen) Allowing for local/UNIX socket");
          ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
        }
        break;
      }
      case __NR_sendto: {
        int sockfd = (int)arg0;
        struct sockaddr* sockAddrStruct = (struct sockaddr*)arg4;
        if (sockAddrStruct != nullptr) {
          if (is_trusted_system_caller("(sendto)", &patch_pc)) {
            ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
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
            ret = (long)arg2;  // amount of bytes sent to fool the app into thinking it succeeded
            if (patch_pc != 0) {
              patchInstruction(patch_pc - 4, (int)arg2);
            }
            break;
          }
        }

        ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
        break;
      }
      case __NR_getsockname: {
        // Let kernel execute the real syscall to populate the sockaddr struct
        long ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);

        // If it succeeded, inspect and scrub the returned struct
        if (ret == 0 && arg1 != 0) {
          if (is_trusted_system_caller("(getsockname)", &patch_pc, false)) {
            ret = ret;
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
            ret = ret;
            break;
          }
        }

        ret = ret;
        break;
      }
      case __NR_socket: {
        int domain = (int)arg0;  // AF_INET, AF_NETLINK, etc.
        int type = (int)arg1;    // SOCK_STREAM, SOCK_RAW, etc.
        int protocol = (int)arg2;

        if (domain == AF_NETLINK) {
          write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "(socket) Blocking AF_NETLINK");
          is_trusted_system_caller("(socket) AF_NETLINK", &patch_pc);
          ret = -EACCES;
          if (patch_pc != 0) {
            patchInstruction(patch_pc - 4, -EACCES);  // Spoof Permission Denied!
          }
          break;
        }

        ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
        break;
      }
      case __NR_sendmsg: {
        int sockfd = (int)arg0;
        struct msghdr* msg = (struct msghdr*)arg1;

        if (msg != nullptr && msg->msg_name != nullptr) {
          struct sockaddr* sockAddrStruct = (struct sockaddr*)msg->msg_name;

          if (is_trusted_system_caller("(sendmsg)", &patch_pc)) {
            ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
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
            ret = (long)get_msghdr_len(msg);
            if (patch_pc != 0) {
              patchInstruction(patch_pc - 4, (int)get_msghdr_len(msg));
            }
            break;
          }
        }
        ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
        break;
      }
      case __NR_readlinkat: {
        const char* pathname = (const char*)arg1;
        char* buf = (char*)arg2;
        size_t bufsiz = (size_t)arg3;

        if (pathname && local_strstr(pathname, "/proc/self/fd/")) {
          int target_fd = local_atoi(pathname + 14);

          // Spinlock
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

              ret = to_copy;
              fds_lock.clear(std::memory_order_release);
              return;
            }
          }
          fds_lock.clear(std::memory_order_release);
        }
        ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
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
          ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
          break;
        }
        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Violation: mmap");
        // log_violation_trace("(mmap)");

        ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
        break;
      }
      case __NR_mprotect: {
        void* addr = (void*)arg0;
        size_t len = (size_t)arg1;
        int prot = (int)arg2;

        if (is_trusted_system_caller("(mprotect)", &patch_pc, false)) {
          ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
          break;
        }
        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Violation: mprotect");
        // log_violation_trace("(mprotect)");

        ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
        break;
      }
      default: {
        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Violation: got unexpected syscall(%d). Allowing...", nr);
        ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
        break;
      }
    }

    ipc_mem->ret = ret;
    if (ret >= 0) {
      send_fd(sock, (int)ret);  // Teleport it
      close((int)ret);          // Close broker's local copy to prevent -24
      ipc_mem->ret = 0;         // Signal success to target
    } else {
      ipc_mem->ret = ret;  // Signal error to target
    }

    __sync_synchronize();
    ipc_mem->status = BROKER_ANSWERED;
    futex_wake(&ipc_mem->status);
  }
}
