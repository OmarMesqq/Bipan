#include "broker.hpp"

#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/memfd.h>
#include <linux/netlink.h>
#include <linux/sched.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <syscall.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "broker_assist.hpp"
#include "common_utils.hpp"
#include "feature_flags.hpp"
#include "ipc_communication.hpp"
#include "logger/logger.hpp"
#include "policies.hpp"
#include "spoofer.hpp"
#include "synchronization.hpp"
#include "unwinder.hpp"

#define TAG "BipanBroker"

// Arbitrary, relatively high `wfd` for `inotify_add_watch`
#define SPOOFED_WFD 224
#define BROKER_THREAD_WAKEUP_TIMEOUT 500  // milliseconds

static inline void patch_instruction_remote(pid_t target_pid, uintptr_t caller_pc, int return_value, std::unordered_set<uintptr_t>& patched_pcs);
static std::string get_sockaddr_info(const struct sockaddr* sa);
static inline bool client_is_dead(int epfd, int sock, int pidfd);
static inline int bipan_pidfd_open(pid_t pid, unsigned int flags);
static char* extract_real_path_from_memfd(const char* memfdPath);
static char* assemble_proc_pid_fd(pid_t pid, int fd);
static inline bool looks_like_proc_fd(const char* pathname, pid_t pid);
static void set_broker_proctitle(const char* pkgName);

static thread_local bool inside_remote_patcher = false;

/**
 * `BipanBroker` runs as thread of root companion, as such,
 * it inherits its powerful capabilities.
 *
 * Its role is to provide a safe space for deeply inspecting
 * and evaluating if the trapped syscalls should executed natively
 * or if they should have some special treatment i.e. getting a spoofed
 * file, getting permission denied or get lied about the existence of some file
 * (`-ENOENT`).
 *
 * As this process is unseccomped we don't have to worry (so much) about recursive
 * signal handler issues and are free to use libc wrappers here.
 * This code should definitely be thread-safe but, perhaps not necessarily,
 * AS-safe.
 *
 * The latter burden lies with the in-process `SIGSYS` handler which basically
 * dispatches trapped syscall info to the broker, yields, and takes some action
 * according the Broker's policies here defined.
 */
void startBroker(int sock, SharedIPC* ipc_mem) {
  if (!initializeLogger()) {
    close(sock);
    return;
  }

  pid_t client_pid = ipc_mem->target_pid;

  // Broker Assist setup
  g_current_client_pid = client_pid;
  bool registrationRet = registerAssistSigHandlers();
  if (!registrationRet) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Couldn't setup debug signal handlers for Broker. Proceeding anyway...");
  } else {
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Broker assistance handlers registered successfuly :)");
  }

  set_broker_proctitle(ipc_mem->package_name);
  prctl(PR_SET_NAME, "BrokerMainTh");

  pid_t pid = getpid();
  pid_t tid = gettid();
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[*] Broker (PID: %d | TID: %d) started for: %s (PID: %d)", pid, tid, ipc_mem->package_name, ipc_mem->target_pid);

  std::unordered_set<uintptr_t> patched_pcs;
  std::unordered_set<uintptr_t> trusted_pcs;
  std::unordered_set<uintptr_t> malicious_pcs;
  std::unordered_set<uintptr_t> lan_bound_pcs;

  // Create epoll watcher
  int epfd = epoll_create1(EPOLL_CLOEXEC);
  if (epfd < 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] epoll_create1 failed!");
    // Will cause thread leak if we can't monitor the app, won't proceed
    munmap(ipc_mem, sizeof(SharedIPC));
    close(sock);
    destroyLogger();
    return;
  }
  struct epoll_event ev{};
  ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;

  // Open target's pidfd
  int pidfd = -1;
  pidfd = bipan_pidfd_open(client_pid, 0);
  if (pidfd < 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "pidfd_open failed for PID %d. errno: %s. Proceeding with just sockfd monitoring.", client_pid, strerror(pidfd));

    // Just monitor the in-app sockfd
    ev.data.fd = sock;
    epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);
  } else {
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Monitoring target app using sockfd and pidfd");

    // Monitor both in-app sockfd and target's pidfd
    ev.data.fd = sock;
    epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);

    ev.data.fd = pidfd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, pidfd, &ev);
  }

  prefetchMaps(ipc_mem->target_pid);
  bool client_dead = false;
  while (!client_dead) {
    while (ipc_mem->status != REQUEST_SYSCALL) {
      int ret = futex_wait_timeout(&ipc_mem->status, ipc_mem->status, BROKER_THREAD_WAKEUP_TIMEOUT);
      if (ret == -ETIMEDOUT) {
        if (client_is_dead(epfd, sock, pidfd)) {
          client_dead = true;
          goto dead_client_exit;
        }
      }
    }

    __sync_synchronize();

    int nr = ipc_mem->nr;
    const char* path_payload = ipc_mem->string_payload;
    struct sockaddr* sock_payload = (struct sockaddr*)ipc_mem->struct_payload;

    uintptr_t pc = ipc_mem->caller_pc;
    uintptr_t fp = ipc_mem->caller_fp;
    uintptr_t lr = ipc_mem->stack_trace[0];

    // Assuming well intentioned
    UNWIND_DECISION is_trusted = SAFE;
    ipc_mem->action = ACTION_EXECUTE_NATIVE;  // Allow syscall

    // Check if it's a legitimate lib/bin making the call
    if (trusted_pcs.count(pc)) {
      goto standard_exit;
    }

    // Check the bad guys collection
    if (malicious_pcs.count(pc)) {
      is_trusted = UNSAFE;
    }

    // If still trusted, unwind to check its ancestors and actual safety
    if (is_trusted == SAFE) {
      is_trusted = unwinder(pc, fp, lr, ipc_mem->target_pid);

      if (is_trusted == SAFE) {
        trusted_pcs.insert(pc);
        goto standard_exit;
      } else {
        malicious_pcs.insert(pc);
      }
    }

    switch (nr) {
      case __NR_execve:
      case __NR_execveat: {
        const char* action_name = (nr == __NR_execve) ? "execve" : "execveat";
        ipc_mem->ret = 0;
        ipc_mem->action = ACTION_EXIT_PROCESS;
        write_to_logcat_async(ANDROID_LOG_INFO, TAG, "%s(%s) spoofed to success", action_name, path_payload);
        break;
      }
      case __NR_uname: {
        struct utsname spoofed_buf;
        ipc_mem->ret = uname_spoofer(&spoofed_buf);
        memcpy(ipc_mem->out_buffer, &spoofed_buf, sizeof(struct utsname));
        ipc_mem->action = ACTION_USE_RET;
        break;
      }
      case __NR_openat: {
        if (shouldDenyOpen(path_payload)) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "openat(%s) denied", path_payload);
          ipc_mem->ret = -EACCES;
          ipc_mem->action = ACTION_USE_RET;
          break;
        } else if (shouldSpoofExistence(path_payload)) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "openat(%s) does not exist...", path_payload);
          ipc_mem->ret = -ENOENT;
          ipc_mem->action = ACTION_USE_RET;
          break;
        } else if (is_maps(path_payload) || is_smaps(path_payload) || shouldFakeFile(path_payload)) {
          // Translate target's /proc/self/ to /proc/[target_pid]/ so the Broker reads the app's maps rather than its own
          char real_path[IPC_STRING_STRUCT_BUF_SIZ];
          if (strncmp(path_payload, "/proc/self/", 11) == 0) {
            snprintf(real_path, sizeof(real_path), "/proc/%d/%s", ipc_mem->target_pid, path_payload + 11);
          } else {
            strncpy(real_path, path_payload, sizeof(real_path));
          }

          // Broker generates the fake file locally
          int fake_fd = -1;
          if (is_maps(path_payload)) {
            fake_fd = clean_proc_maps((int)ipc_mem->arg0, real_path, (int)ipc_mem->arg2, (mode_t)ipc_mem->arg3);
          } else if (is_smaps(path_payload)) {
            fake_fd = clean_proc_smaps((int)ipc_mem->arg0, real_path, (int)ipc_mem->arg2, (mode_t)ipc_mem->arg3);
          } else {
            fake_fd = create_spoofed_file(shouldFakeFile(path_payload));
          }

          if (fake_fd < 0) {
            // fallback to denying if Broker can't create a fake fd
            ipc_mem->ret = -EACCES;
            ipc_mem->action = ACTION_USE_RET;
            write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] (openat): Failed to create fake fd!");
            break;
          }

          // Broker opens signal handler's pre_fd and fills it
          int target_fd = (int)ipc_mem->arg5;
          char proc_path[64];
          snprintf(proc_path, sizeof(proc_path), "/proc/%d/fd/%d", ipc_mem->target_pid, target_fd);

          int root_fd = open(proc_path, O_WRONLY);
          if (root_fd < 0) {
            // same logic:
            // fallback to denying if Broker can't open target's remote fd
            write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] (openat): Failed to open target's pre_fd!");
            ipc_mem->ret = -EACCES;
            ipc_mem->action = ACTION_USE_RET;
            close(fake_fd);
            break;
          }

          char buf[PATH_MAX] = {0};
          ssize_t n;
          lseek(fake_fd, 0, SEEK_SET);
          while ((n = read(fake_fd, buf, sizeof(buf))) > 0) {
            // `n` is already positive here: safe cast
            write(root_fd, buf, (size_t)n);
          }
          lseek(root_fd, 0, SEEK_SET);

          close(root_fd);  // Cleanup daemon's ref of target's pre_fd
          close(fake_fd);  // Cleanup daemon's own fake fd

          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "openat(%s) spoofed with fd %d", path_payload, target_fd);
          // Tell target to use the fd it already has
          ipc_mem->ret = target_fd;
          ipc_mem->action = ACTION_USE_RET;
          break;
        }
#ifdef BROKER_DEBUG_LOGGING
        if (shouldLog(path_payload)) {
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "Allowing untrusted openat(%s)", path_payload);
        }
#endif
        break;
      }
      case __NR_faccessat: {
        const char* path = ipc_mem->string_payload;

        ipc_mem->action = ACTION_USE_RET;
        if (shouldDenyStat(path)) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "faccessat(%s) denied", path);
          ipc_mem->ret = -EPERM;
          break;
        }
        if (shouldSpoofExistence(path)) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "faccessat(%s) spoofed", path);
          ipc_mem->ret = -ENOENT;
          break;
        }

        ipc_mem->action = ACTION_EXECUTE_NATIVE;
#ifdef BROKER_DEBUG_LOGGING
        if (shouldLog(path)) {
          int dirfd = (int)ipc_mem->arg0;
          bool isRelativeLookup = (dirfd == AT_FDCWD);
          if (isRelativeLookup) {
            write_to_logcat_async(ANDROID_LOG_WARN, TAG, "faccessat(%s) (fd: AT_FDCWD) allowed", path);
          } else {
            write_to_logcat_async(ANDROID_LOG_WARN, TAG, "faccessat(%s) (fd: %d) allowed", path, dirfd);
          }
        }
#endif
        break;
      }
      case __NR_fstat: {
        int fd = (int)ipc_mem->arg0;

        ipc_mem->action = ACTION_USE_RET;
        char* proc_pid_fd_path = assemble_proc_pid_fd(ipc_mem->target_pid, fd);
        if (!proc_pid_fd_path) {
          ipc_mem->ret = -ENOENT;
          break;
        }

        char resolved_link_path[PATH_MAX] = {0};
        ssize_t len = readlinkat(0, proc_pid_fd_path, resolved_link_path, sizeof(resolved_link_path) - 1);
        if (len == -1) {
          write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Failed to resolve path (%s) in fstat. errno: %s", proc_pid_fd_path, strerror(errno));
          free(proc_pid_fd_path);
          // Bubble up to app
          ipc_mem->ret = len;
          break;
        }
        resolved_link_path[len] = '\0';

        if (shouldDenyStat(resolved_link_path)) {
          free(proc_pid_fd_path);
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "fstat(%s) denied", resolved_link_path);
          ipc_mem->ret = -EPERM;
          break;
        }

        if (shouldSpoofExistence(resolved_link_path)) {
          free(proc_pid_fd_path);
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "fstat(%s) spoofed", resolved_link_path);
          ipc_mem->ret = -ENOENT;
          break;
        }

        if (strstr(resolved_link_path, "/memfd:")) {
          char* actualPath = extract_real_path_from_memfd(resolved_link_path);
          if (!actualPath) {
            free(proc_pid_fd_path);
            ipc_mem->ret = -ENOENT;
            break;
          }

          if (isHostsFile(actualPath)) {
            struct stat* fixedStatBuf = fixHostsFileStat(actualPath, 0);
            if (!fixedStatBuf) {
              free(actualPath);
              free(proc_pid_fd_path);
              write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "(fstat): failed to fix hosts!");
              ipc_mem->ret = -1;
              break;
            }
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(fstat): fixed hosts file.");
            memcpy(ipc_mem->out_buffer, fixedStatBuf, sizeof(struct stat));
            free(fixedStatBuf);
            free(actualPath);
            free(proc_pid_fd_path);
            ipc_mem->ret = 0;
            break;
          }

          free(actualPath);
        }
#ifdef BROKER_DEBUG_LOGGING
        if (shouldLog(resolved_link_path)) {
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "fstat(%s) (fd: %d) allowed", resolved_link_path, fd);
        }
#endif
        free(proc_pid_fd_path);
        ipc_mem->action = ACTION_EXECUTE_NATIVE;
        break;
      }
      case __NR_newfstatat: {
        const char* path = ipc_mem->string_payload;
        int flags = (int)ipc_mem->arg3;

        ipc_mem->action = ACTION_USE_RET;
        if (shouldDenyStat(path)) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "newfstatat(%s) denied", path);
          ipc_mem->ret = -EPERM;
          break;
        }
        if (shouldSpoofExistence(path)) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "newfstatat(%s) spoofed", path);
          ipc_mem->ret = -ENOENT;
          break;
        }

        // for absolute path lookups
        if (isHostsFile(path)) {
          struct stat* fixedStatBuf = fixHostsFileStat(path, flags);
          if (!fixedStatBuf) {
            write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "(newfstatat): failed to fix hosts!");
            ipc_mem->ret = -1;
            break;
          }
          memcpy(ipc_mem->out_buffer, fixedStatBuf, sizeof(struct stat));
          free(fixedStatBuf);
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(newfstatat): fixed hosts file.");
          ipc_mem->ret = 0;
          break;
        }

        ipc_mem->action = ACTION_EXECUTE_NATIVE;

#ifdef BROKER_DEBUG_LOGGING
        if (shouldLog(path)) {
          int fd = (int)ipc_mem->arg0;
          bool isRelativeLookup = (fd == AT_FDCWD);
          if (isRelativeLookup) {
            write_to_logcat_async(ANDROID_LOG_WARN, TAG, "newfstatat(%s) (fd: AT_FDCWD) allowed", path);
          } else {
            write_to_logcat_async(ANDROID_LOG_WARN, TAG, "newfstatat(%s) (fd: %d) allowed", path, fd);
          }
        }
#endif
        break;
      }
      case __NR_bind: {
        bool should_block = false;

        if (sock_payload->sa_family == AF_INET) {
          struct sockaddr_in* sin = (struct sockaddr_in*)sock_payload;
          uint16_t port = ntohs(sin->sin_port);

          // Multicast DNS, UPnP/SSDP, Spotify Connect
          if (isLanAddress(sock_payload) || port == 5353 || port == 1900 || port == 57621) {
            should_block = true;
          }
        } else if (sock_payload->sa_family == AF_INET6) {
          struct sockaddr_in6* sin6 = (struct sockaddr_in6*)sock_payload;
          uint16_t port = ntohs(sin6->sin6_port);

          // Multicast DNS, UPnP/SSDP, Spotify Connect
          if (isLanAddress(sock_payload) || port == 5353 || port == 1900 || port == 57621) {
            should_block = true;
          }
        }

        if (should_block) {
          ipc_mem->ret = 0;
          ipc_mem->action = ACTION_USE_RET;

          std::string sockInfo = get_sockaddr_info(sock_payload);
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(bind) to LAN spoofed. Socket info: %s", sockInfo.c_str());
          patch_instruction_remote(ipc_mem->target_pid, pc, 0, patched_pcs);
        }
        break;
      }
      case __NR_connect: {
        // Ad-blockers that change `hosts` will redirect domains to unspecified
        // Save context-switches and just refuse it in userspace + avoid logging
        if (sock_payload->sa_family == AF_INET) {
          uint32_t ip4 = ntohl(((struct sockaddr_in*)sock_payload)->sin_addr.s_addr);
          if (ip4 == 0x00000000) {
            ipc_mem->ret = -ECONNREFUSED;
            ipc_mem->action = ACTION_USE_RET;
            break;
          }
        } else if (sock_payload->sa_family == AF_INET6) {
          uint8_t* ip6 = ((struct sockaddr_in6*)sock_payload)->sin6_addr.s6_addr;
          if (!ip6) {
            ipc_mem->ret = -ECONNREFUSED;
            ipc_mem->action = ACTION_USE_RET;
            break;
          }

          bool is_unspecified = true;
          for (int i = 0; i < 16; i++) {
            if (ip6[i] != 0) is_unspecified = false;
          }
          if (is_unspecified) {
            ipc_mem->ret = -ECONNREFUSED;
            ipc_mem->action = ACTION_USE_RET;
            break;
          }
        }

        if (isLanAddress(sock_payload)) {
          std::string sockInfo = get_sockaddr_info(sock_payload);
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(connect) to LAN refused. Socket info: %s", sockInfo.c_str());

          ipc_mem->ret = -ECONNREFUSED;
          ipc_mem->action = ACTION_USE_RET;
        }
        break;
      }
      case __NR_sendto: {
        if (isLanAddress(sock_payload)) {
          int ghost_len = (int)ipc_mem->arg2;
          ipc_mem->ret = ghost_len;
          ipc_mem->action = ACTION_USE_RET;

          if (!lan_bound_pcs.count(pc)) {
            lan_bound_pcs.insert(pc);
            std::string sockInfo = get_sockaddr_info(sock_payload);
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(sendto) LAN spoofed | Socket info: %s", sockInfo.c_str());
          }
        }
        break;
      }
      case __NR_sendmsg: {
        if (isLanAddress(sock_payload)) {
          int ghost_len = (int)ipc_mem->arg3;
          ipc_mem->ret = ghost_len;
          ipc_mem->action = ACTION_USE_RET;

          std::string sockInfo = get_sockaddr_info(sock_payload);
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(sendmsg) to LAN address spoofed. Socket info: %s", sockInfo.c_str());
          patch_instruction_remote(ipc_mem->target_pid, pc, ghost_len, patched_pcs);
        }
        break;
      }
      case __NR_inotify_add_watch: {
        int fd = (int)ipc_mem->arg0;
        const char* path = (const char*)ipc_mem->string_payload == nullptr ? "NULL path" : ipc_mem->string_payload;
        uint32_t mask = (uint32_t)ipc_mem->arg2;

        if (strstr(path, "Screenshots")) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(inotify_add_watch): Neutered for path: %s", path);
          ipc_mem->ret = SPOOFED_WFD;
          ipc_mem->action = ACTION_USE_RET;
          break;
        }

        if (shouldLog(path)) {
          std::string maskAnalysis = "";
          maskAnalysis.reserve(500);
          if (mask & IN_ACCESS) maskAnalysis += " File accessed |";
          if (mask & IN_ATTRIB) maskAnalysis += " Metadata changes (perms, timestamps) |";
          if (mask & IN_CLOSE_WRITE) maskAnalysis += " File opened for writing was closed |";
          if (mask & IN_CLOSE_NOWRITE) maskAnalysis += " File or directory not opened for writing was closed |";
          if (mask & IN_CREATE) maskAnalysis += " File/directory created in watched directory |";
          if (mask & IN_DELETE) maskAnalysis += " File/directory deleted from watched directory |";
          if (mask & IN_DELETE_SELF) maskAnalysis += " Watched file/directory was deleted/moved |";
          if (mask & IN_MODIFY) maskAnalysis += " File modifed |";
          if (mask & IN_MOVE_SELF) maskAnalysis += " File was moved |";
          if (mask & IN_MOVED_FROM) maskAnalysis += " Generated for the directory containing the old filename when a file is renamed |";
          if (mask & IN_MOVED_TO) maskAnalysis += " Generated for the directory containing the new filename when a file is renamed. |";
          if (mask & IN_OPEN) maskAnalysis += " File or directory was opened";

          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(inotify_add_watch): fd=%d, path=%s, flags= [%s]", fd, path, maskAnalysis.c_str());
        }

        break;
      }
      case __NR_inotify_rm_watch: {
        int wd = (int)ipc_mem->arg2;
        if (wd == SPOOFED_WFD) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(inotify_rm_watch): Closed spoofed watch");
          ipc_mem->ret = 0;
          ipc_mem->action = ACTION_USE_RET;
          break;
        }
        break;
      }
      case __NR_readlinkat: {
        int dirfd = (int)ipc_mem->arg0;
        const char* path = ipc_mem->string_payload;
        ipc_mem->action = ACTION_USE_RET;

        if (dirfd > 0) {
          char* proc_pid_fd_path = assemble_proc_pid_fd(ipc_mem->target_pid, dirfd);
          if (!proc_pid_fd_path) {
            ipc_mem->ret = -1;
            break;
          }

          char resolved_link_path[PATH_MAX] = {0};
          ssize_t len = readlink(proc_pid_fd_path, resolved_link_path, sizeof(resolved_link_path) - 1);
          if (len == -1) {
            write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Failed to resolve path (%s) in readlinkat (dirfd). errno: %s", proc_pid_fd_path, strerror(errno));
            free(proc_pid_fd_path);
            // Bubble up to app
            ipc_mem->ret = len;
            break;
          }
          resolved_link_path[len] = '\0';

          if (strstr(resolved_link_path, "/memfd:")) {
            char* actualPath = extract_real_path_from_memfd(resolved_link_path);
            if (!actualPath) {
              free(proc_pid_fd_path);
              ipc_mem->ret = -ENOENT;
              break;
            }
            char* fixedSymlink = fixMemfdSymlink(resolved_link_path, ipc_mem->target_pid);
            if (!fixedSymlink) {
              free(actualPath);
              free(proc_pid_fd_path);
              ipc_mem->ret = -ENOENT;
              break;
            }

            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(readlinkat with dirfd) spoofed: original res: %s | extracted path: %s | fixed link: %s", resolved_link_path, actualPath, fixedSymlink);
            if (strcmp(fixedSymlink, "ENOENT") == 0) {
              ipc_mem->ret = -ENOENT;
              free(actualPath);
              free(fixedSymlink);
              free(proc_pid_fd_path);
              break;
            }

            memcpy(ipc_mem->out_buffer, fixedSymlink, sizeof(ipc_mem->out_buffer));
            ipc_mem->ret = (long)strlen(fixedSymlink);

            free(fixedSymlink);
            free(actualPath);
            free(proc_pid_fd_path);
            break;
          }

          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(readlinkat with dirfd): %s -> %s", proc_pid_fd_path, resolved_link_path);
          free(proc_pid_fd_path);

          memcpy(ipc_mem->out_buffer, resolved_link_path, sizeof(ipc_mem->out_buffer));
          ipc_mem->ret = (long)strlen(resolved_link_path);
        } else if (dirfd == AT_FDCWD) {
          if (!looks_like_proc_fd(path, ipc_mem->target_pid)) {
            ipc_mem->action = ACTION_EXECUTE_NATIVE;
            if (shouldLog(path)) {
              write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(readlinkat AT_FDCWD) with apparently not fd path(%s). Letting through...", path);
            }
            break;
          }

          size_t pathLength = strlen(path);
          char reversedDirfdStr[6] = {0};

          char c = '*';  // just any char that's not `/`
          int i = 0;

          while ((c = path[pathLength - 1]) != '/') {
            reversedDirfdStr[i++] = c;
            pathLength--;
          }

          char dirfdStr[6] = {0};
          // has to be unsigned so loop below works!
          ssize_t idx = (ssize_t)strlen(reversedDirfdStr) - 1;
          int j = 0;
          while (idx >= 0) {
            dirfdStr[j++] = reversedDirfdStr[idx--];
          }
          int extractedDirfd = atoi(dirfdStr);

          char* proc_pid_fd_path = assemble_proc_pid_fd(ipc_mem->target_pid, extractedDirfd);
          if (!proc_pid_fd_path) {
            ipc_mem->ret = -1;
            break;
          }

          char resolved_link_path[PATH_MAX] = {0};
          ssize_t len = readlinkat(dirfd, proc_pid_fd_path, resolved_link_path, sizeof(resolved_link_path) - 1);
          if (len == -1) {
            free(proc_pid_fd_path);
            write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Failed to resolve path (%s) in readlinkat (AT_FDCWD). errno: %s", path, strerror(errno));
            // Bubble up to app
            ipc_mem->ret = len;
            break;
          }
          resolved_link_path[len] = '\0';

          if (strstr(resolved_link_path, "/memfd:")) {
            char* actualPath = extract_real_path_from_memfd(resolved_link_path);
            if (!actualPath) {
              free(proc_pid_fd_path);
              ipc_mem->ret = -ENOENT;
              break;
            }
            char* fixedSymlink = fixMemfdSymlink(resolved_link_path, ipc_mem->target_pid);
            if (!fixedSymlink) {
              free(actualPath);
              free(proc_pid_fd_path);
              ipc_mem->ret = -ENOENT;
              break;
            }

            write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(readlinkat AT_FDCWD) spoofed: original link: %s | true path: %s | fixed link: %s", resolved_link_path, actualPath, fixedSymlink);
            if (strcmp(fixedSymlink, "ENOENT") == 0) {
              free(actualPath);
              free(fixedSymlink);
              free(proc_pid_fd_path);
              ipc_mem->ret = -ENOENT;
              break;
            }

            free(fixedSymlink);
            free(actualPath);
            free(proc_pid_fd_path);

            memcpy(ipc_mem->out_buffer, fixedSymlink, sizeof(ipc_mem->out_buffer));
            ipc_mem->ret = (long)strlen(fixedSymlink);
            break;
          }

          free(proc_pid_fd_path);
#ifdef BROKER_DEBUG_LOGGING
          if (shouldLog(resolved_link_path)) {
            write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(readlinkat AT_FDCWD): %s -> %s", path, resolved_link_path);
          }
#endif

          memcpy(ipc_mem->out_buffer, resolved_link_path, sizeof(ipc_mem->out_buffer));
          ipc_mem->ret = (long)strlen(resolved_link_path);
        } else {
          char resolved_link_path[PATH_MAX] = {0};
          ssize_t len = readlinkat(0, path, resolved_link_path, sizeof(resolved_link_path) - 1);
          if (len == -1) {
            write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Failed to resolve path (%s) in readlinkat (abs path). errno: %s", path, strerror(errno));
            // Bubble up to app
            ipc_mem->ret = len;
            break;
          }
          resolved_link_path[len] = '\0';
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(readlinkat with abs path): %s -> %s", path, resolved_link_path);
        }
        break;
      }
      default: {
        write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Broker got unexpected syscall: %d. Returning ENOSYS.", nr);
        ipc_mem->ret = -ENOSYS;
        ipc_mem->action = ACTION_USE_RET;
      }
    }

  standard_exit:
    __sync_synchronize();
    ipc_mem->status = BROKER_ANSWERED;
    futex_wake(&ipc_mem->status);
  }

dead_client_exit:
  munmap(ipc_mem, sizeof(SharedIPC));
  if (pidfd >= 0) {
    close(pidfd);
  }
  close(epfd);

  write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] Broker (PID: %d | TID: %d) exiting for dead client (PID: %d)", pid, tid, client_pid);
  close(sock);
  destroyLogger();
}

static bool get_arg_bounds(unsigned long* arg_start, unsigned long* arg_end) {
  FILE* f = fopen("/proc/self/stat", "r");
  if (!f) return false;

  char buf[4096] = {0};
  if (!fgets(buf, sizeof(buf), f)) {
    fclose(f);
    return false;
  }
  fclose(f);

  char* p = strrchr(buf, ')');
  if (!p) return false;
  p += 2;  // skip ") "

  int field = 3;
  char* tok = strtok(p, " ");
  unsigned long as = 0, ae = 0;
  while (tok) {
    if (field == 48) as = strtoul(tok, nullptr, 10);  // arg_start
    if (field == 49) {                                // arg_end
      ae = strtoul(tok, nullptr, 10);
      break;
    }
    tok = strtok(nullptr, " ");
    field++;
  }
  if (as == 0 || ae == 0) return false;
  *arg_start = as;
  *arg_end = ae;
  return true;
}

static bool set_linux_proctitle(const char* new_title) {
  unsigned long arg_start = 0, arg_end = 0;
  if (!get_arg_bounds(&arg_start, &arg_end)) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "[!] set_linux_proctitle: get_arg_bounds failed");
    return false;
  }

  char* argv0 = reinterpret_cast<char*>(arg_start);
  size_t avail = arg_end - arg_start;

  size_t title_len = strlen(new_title);
  size_t to_write = title_len < avail ? title_len : avail - 1;

  memset(argv0, 0, avail);
  memcpy(argv0, new_title, to_write);

  unsigned long new_end = arg_start + to_write + 1;
  if (prctl(PR_SET_MM, PR_SET_MM_ARG_END, new_end, 0, 0) != 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG,
                          "[!] set_linux_proctitle: PR_SET_MM_ARG_END failed: %s (avail=%zu, wanted=%zu)",
                          strerror(errno), avail, title_len);
    return false;
  }

  return true;
}

static void set_broker_proctitle(const char* pkgName) {
  if (!pkgName) {
    set_linux_proctitle("BB-empty");
    return;
  }

  std::vector<std::string> segments;
  std::stringstream ss(pkgName);
  std::string segment;
  while (std::getline(ss, segment, '.')) {
    segments.push_back(segment);
  }

  std::string procTitle;
  switch (segments.size()) {
    case 2:
    case 4:
      procTitle = segments.back();
      break;
    case 3:
      procTitle = segments[1];
      if (procTitle == "android") {
        procTitle = segments.back();
      }
      break;
    default:
      procTitle = segments.empty() ? "" : segments.back();
      break;
  }

  std::string fullTitle = "BB-" + procTitle;
  set_linux_proctitle(fullTitle.c_str());
}

static inline void patch_instruction_remote(pid_t target_pid, uintptr_t caller_pc, int return_value, std::unordered_set<uintptr_t>& patched_pcs) {
  if (inside_remote_patcher) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "[!] Thread reentrancy in remote patcher!");
    return;
  }
  inside_remote_patcher = true;

  // Seccomp traps the instruction *after* the syscall.
  // We subtract 4 to target the actual 'svc #0' instruction.
  uintptr_t target_addr = caller_pc - 4;

  if (patched_pcs.count(target_addr)) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "[!] Reentrancy in remote patcher: PC already patched!");
    inside_remote_patcher = false;
    return;
  }

  uint32_t opcode = 0xd503201f;  // Default to NOP

  if (return_value >= 0 && return_value <= 65535) {
    // Generate 'MOV x0, #return_value'
    opcode = 0xD2800000 | ((uint32_t)return_value << 5);
  } else if (return_value == -13) {  // -EACCES
    opcode = 0x92800180;
  } else if (return_value == -99) {  // -EADDRNOTAVAIL
    opcode = 0x92800C40;
  } else if (return_value == -11) {  // -EAGAIN
    opcode = 0x92800140;
  } else if (return_value == -2) {  // -ENOENT
    opcode = 0x92800040;
  }

  char mem_path[64];
  snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", target_pid);

  // Open target's memory for writing
  int mem_fd = open(mem_path, O_WRONLY);
  if (mem_fd < 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] failed to open app's memory for checking trust");
    return;
  }

  // TODO: ideally the remote app should flush its instruction cache

  // Interpret uintptr_t (unsigned) as off_t (signed)
  // Both are 64-bit and fit in the data type, but I
  // shall cast only to reduce warnings
  ssize_t written = pwrite(mem_fd, &opcode, sizeof(opcode), (off_t)target_addr);
  close(mem_fd);

  if (written == sizeof(opcode)) {
    patched_pcs.insert(target_addr);
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Remote Patch succeeded: PC %p now returns %d.", (void*)target_addr, return_value);
  } else {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Remote patch (pwrite) failed for PID %d (errno: %s)", target_pid, strerror(errno));
  }
  inside_remote_patcher = false;
}

static std::string get_sockaddr_info(const struct sockaddr* sa) {
  if (sa == nullptr) return "NULL Address";

  char addr_str[INET6_ADDRSTRLEN] = {0};
  uint16_t port = 0;

  switch (sa->sa_family) {
    case AF_INET: {
      struct sockaddr_in* sin = (struct sockaddr_in*)sa;
      inet_ntop(AF_INET, &(sin->sin_addr), addr_str, INET_ADDRSTRLEN);
      port = ntohs(sin->sin_port);
      return "[IPv4] " + std::string(addr_str) + ":" + std::to_string(port);
    }
    case AF_INET6: {
      struct sockaddr_in6* sin6 = (struct sockaddr_in6*)sa;
      inet_ntop(AF_INET6, &(sin6->sin6_addr), addr_str, INET6_ADDRSTRLEN);
      port = ntohs(sin6->sin6_port);
      return "[IPv6] " + std::string(addr_str) + ":" + std::to_string(port);
    }
    case AF_UNIX:
      return "[Local] AF_UNIX (Internal IPC)";
    case AF_NETLINK:
      return "[Kernel] AF_NETLINK (Interface/MAC discovery)";
    default:
      return "Family " + std::to_string(sa->sa_family);
  }
}

static inline bool client_is_dead(int epfd, int sock, int pidfd) {
  struct epoll_event events[2];
  int n = epoll_wait(epfd, events, 2, 0);

  for (int i = 0; i < n; i++) {
    int fd = events[i].data.fd;
    uint32_t ev = events[i].events;

    if (fd == sock && (ev & (EPOLLHUP | EPOLLERR))) {
      // Peer socket closed/errored -> client side gone
      return true;
    }

    if (pidfd >= 0 && fd == pidfd &&
        (ev & (EPOLLHUP | EPOLLERR | EPOLLIN))) {
      // pidfd signals process exit
      return true;
    }
  }

  return false;
}

/**
 * Wrapper for `pidfd_open` as even with correct headers, the NDK
 * says it's an 'undeclared identifier'
 */
static inline int bipan_pidfd_open(pid_t pid, unsigned int flags) {
  return (int)raw_syscall(__NR_pidfd_open, (long)pid, (long)flags, 0, 0, 0, 0);
}

// HEAP ALLOCATION:
static char* extract_real_path_from_memfd(const char* memfdPath) {
  char* extractedPath = (char*)calloc(PATH_MAX, sizeof(char));
  if (!extractedPath) {
    return nullptr;
  }

  // start of the real path in the memfd symlink
  char* p = (char*)&memfdPath[7];
  size_t i = 0;
  while (*p != ' ' && *p != '\0' && i < PATH_MAX - 1) {
    extractedPath[i++] = *p;
    p++;
  }
  return extractedPath;
}

// HEAP ALLOCATION:
static char* assemble_proc_pid_fd(pid_t pid, int fd) {
  char* proc_pid_fd_path = (char*)calloc(PATH_MAX, sizeof(char));
  if (!proc_pid_fd_path) {
    return nullptr;
  }

  snprintf(proc_pid_fd_path, PATH_MAX, "/proc/%d/fd/%d", pid, fd);
  return proc_pid_fd_path;
}

static inline bool looks_like_proc_fd(const char* pathname, pid_t pid) {
  char proc_pid[PATH_MAX] = {0};
  snprintf(proc_pid, PATH_MAX, "/proc/%d", pid);

  if (
      (starts_with(pathname, "/proc/self") ||
       starts_with(pathname, proc_pid)) &&
      strstr(pathname, "/fd/")) {
    return true;
  }
  return false;
}
