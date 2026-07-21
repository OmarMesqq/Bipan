#include "broker.hpp"

#include <arpa/inet.h>
#include <dirent.h>
#include <elf.h>
#include <inttypes.h>
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
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <syscall.h>

#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "common_utils.hpp"
#include "compile_time_flags.hpp"
#include "ipc_communication.hpp"
#include "logger/logger.hpp"
#include "policies.hpp"
#include "spoofer.hpp"
#include "synchronization.hpp"

typedef struct {
  uintptr_t pc;  // Program Counter
  uintptr_t sp;  // TODO: ???
} StackFrame;

typedef struct {
  char dli_fname[PATH_MAX];  // Path to the library
  uintptr_t dli_fbase;       // Base address of the library
  uintptr_t dli_offset;      // Relative offset inside the file
} ManualDlInfo;

#define TAG "BipanBroker"
#define SPOOFED_WD 224

// 64-bit ELF structures for ARM64
typedef Elf64_Ehdr ElfHeader;
typedef Elf64_Shdr ElfSection;
typedef Elf64_Sym ElfSymbol;

static inline void patch_instruction_remote(pid_t target_pid, uintptr_t caller_pc, int return_value, std::unordered_set<uintptr_t>& patched_pcs);
static std::string get_sockaddr_info(const struct sockaddr* sa);
static inline bool client_is_dead(int epfd, int pidfd);
static inline int bipan_pidfd_open(pid_t pid, unsigned int flags);
static char* get_thread_name(pid_t parentPid, __aligned_u64 tid);
static char* get_ptrace_op_name(int op);
static char* extract_real_path_from_memfd(const char* memfdPath);
static char* assemble_proc_pid_fd(pid_t pid, int fd);
static inline bool is_hosts_file(const char* pathname);
static inline bool looks_like_proc_fd(const char* pathname, pid_t pid);
static bool unwinder(uintptr_t fp, uintptr_t lr, pid_t pid);

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
    return;
  }

  std::unordered_set<uintptr_t> patched_pcs;

  pid_t pid = getpid();
  pid_t tid = gettid();
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[*] Starting Broker: PID: %d | TID: %d", pid, tid);

  // Open target's pidfd
  pid_t client_pid = ipc_mem->target_pid;
  int pidfd = bipan_pidfd_open(client_pid, 0);
  if (pidfd < 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] pidfd_open failed for client PID %d", client_pid);
  }

  // epoll monitoring socket and pidfd
  int epfd = epoll_create1(EPOLL_CLOEXEC);
  if (epfd < 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] epoll_create1 failed!");
    // without epoll we don't have a watchdog, kill broker
    munmap(ipc_mem, sizeof(SharedIPC));
    return;
  }

  struct epoll_event ev{};
  ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
  ev.data.fd = sock;
  epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);
  if (pidfd < 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] epoll_ctl for Broker's socket and pidfd failed!");
    munmap(ipc_mem, sizeof(SharedIPC));
    return;
  }

  ev.data.fd = pidfd;
  epoll_ctl(epfd, EPOLL_CTL_ADD, pidfd, &ev);

  bool client_dead = false;
  while (!client_dead) {
    while (ipc_mem->status != REQUEST_SYSCALL) {
      int ret = futex_wait_timeout(&ipc_mem->status, ipc_mem->status, 500);
      if (ret == -ETIMEDOUT) {
        if (client_is_dead(epfd, pidfd)) {
          client_dead = true;
          goto dead_client_exit;
        }
      }
    }

    __sync_synchronize();

    int nr = ipc_mem->nr;
    const char* path_payload = ipc_mem->string_payload;
    struct sockaddr* sock_payload = (struct sockaddr*)ipc_mem->struct_payload;

    uintptr_t current_pc = ipc_mem->stack_trace[0];  // Start with LR (`x30`)
    uintptr_t current_fp = ipc_mem->caller_fp;
    bool is_trusted = unwinder(current_fp, current_pc, ipc_mem->target_pid);
    ipc_mem->action = ACTION_EXECUTE_NATIVE;  // Default to allow

    // if (is_trusted) {
    //   goto standard_exit;
    // }

    switch (nr) {
      case __NR_execve:
      case __NR_execveat: {
        const char* action_name = (nr == __NR_execve) ? "execve" : "execveat";
        ipc_mem->ret = 0;
        ipc_mem->action = ACTION_EXIT_PROCESS;
        write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[%s(%s) spoofed to success]", action_name, path_payload);
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
        if (shouldDenyOpen(path_payload) || handleSuRelatedNode(path_payload) == DENY) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[openat(%s)] denied", path_payload);
          ipc_mem->ret = -EACCES;
          ipc_mem->action = ACTION_USE_RET;
          break;
        } else if (shouldSpoofExistence(path_payload) || handleSuRelatedNode(path_payload) == SPOOF || shouldReportEmptyDir(path_payload)) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[openat(%s)] spoofed", path_payload);
          ipc_mem->ret = -ENOENT;
          ipc_mem->action = ACTION_USE_RET;
          break;
        } else if (is_maps(path_payload) || is_smaps(path_payload) || is_proc_status(path_payload) || is_mounts(path_payload) || shouldFakeFile(path_payload)) {
          // Translate target's /proc/self/ to /proc/[target_pid]/ so the Broker reads the app's maps rather than its own
          char real_path[256];
          if (strncmp(path_payload, "/proc/self/", 11) == 0) {
            snprintf(real_path, sizeof(real_path), "/proc/%d/%s", ipc_mem->target_pid, path_payload + 11);
          } else {
            strncpy(real_path, path_payload, sizeof(real_path));
          }

          // Broker generates the fake file locally
          int fake_fd = -1;
          if (is_mounts(path_payload)) {
            fake_fd = clean_proc_mounts((int)ipc_mem->arg0, real_path, (int)ipc_mem->arg2, (mode_t)ipc_mem->arg3);
          } else if (is_maps(path_payload)) {
            fake_fd = clean_proc_maps((int)ipc_mem->arg0, real_path, (int)ipc_mem->arg2, (mode_t)ipc_mem->arg3);
          } else if (is_smaps(path_payload)) {
            fake_fd = clean_proc_smaps((int)ipc_mem->arg0, real_path, (int)ipc_mem->arg2, (mode_t)ipc_mem->arg3);
          } else if (is_proc_status(path_payload)) {
            fake_fd = clean_proc_status((int)ipc_mem->arg0, real_path, (int)ipc_mem->arg2, (mode_t)ipc_mem->arg3);
          } else {
            fake_fd = create_spoofed_file(shouldFakeFile(path_payload));
          }

          if (fake_fd < 0) {
            // fallback to denying if Broker can't create a fake fd
            ipc_mem->ret = -EACCES;
            ipc_mem->action = ACTION_USE_RET;
            write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to create fake FD!");
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
            write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to open target's pre_fd!");
            ipc_mem->ret = -EACCES;
            ipc_mem->action = ACTION_USE_RET;
            close(fake_fd);
            break;
          }

          char buf[4096];
          ssize_t n;
          lseek(fake_fd, 0, SEEK_SET);
          while ((n = read(fake_fd, buf, sizeof(buf))) > 0) {
            write(root_fd, buf, n);
          }
          lseek(root_fd, 0, SEEK_SET);

          // Cleanup daemon's ref of target's pre_fd
          close(root_fd);
          // Cleanup daemon's own fake fd
          close(fake_fd);

          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[openat(%s)] spoofed with fd %d", path_payload, target_fd);
          // Tell target to use the fd it already has
          ipc_mem->ret = target_fd;
          ipc_mem->action = ACTION_USE_RET;
          break;
        }
#ifdef BROKER_DEBUG_LOGGING
        if (shouldLog(path_payload)) {
          write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Allowing untrusted openat(%s)", path_payload);
        }
#endif
        break;
      }
      case __NR_faccessat: {
        int dirfd = (int)ipc_mem->arg0;
        const char* path = ipc_mem->string_payload;
        int mode = (int)ipc_mem->arg2;
        int flags = (int)ipc_mem->arg3;

        ipc_mem->action = ACTION_USE_RET;
        if (shouldDenyStat(path) || handleSuRelatedNode(path) == DENY) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[faccessat(%s)] denied", path);
          ipc_mem->ret = -EPERM;
          break;
        }
        if (shouldSpoofExistence(path) || handleSuRelatedNode(path) == SPOOF || shouldReportEmptyDir(path_payload)) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[faccessat(%s)] spoofed", path);
          ipc_mem->ret = -ENOENT;
          break;
        }

        ipc_mem->action = ACTION_EXECUTE_NATIVE;
#ifdef BROKER_DEBUG_LOGGING
        if (shouldLog(path)) {
          write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "faccessat(%s) (fd: %d) allowed", path, dirfd);
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

        if (shouldDenyStat(resolved_link_path) || handleSuRelatedNode(resolved_link_path) == DENY) {
          free(proc_pid_fd_path);
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[fstat(%s)] denied", resolved_link_path);
          ipc_mem->ret = -EPERM;
          break;
        }

        if (shouldSpoofExistence(resolved_link_path) || handleSuRelatedNode(resolved_link_path) == SPOOF || shouldReportEmptyDir(path_payload)) {
          free(proc_pid_fd_path);
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[fstat(%s)] spoofed", resolved_link_path);
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
          if (is_hosts_file(actualPath)) {
            struct stat* fixedStatBuf = fixHostsFileStat(actualPath, 0);
            if (!fixedStatBuf) {
              free(actualPath);
              free(proc_pid_fd_path);
              write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[fstat] failed to fix hosts!");
              ipc_mem->ret = -1;
              break;
            }
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[fstat] fixed hosts file.");
            memcpy(ipc_mem->out_buffer, fixedStatBuf, sizeof(struct stat));
            free(fixedStatBuf);
            free(actualPath);
            free(proc_pid_fd_path);
            ipc_mem->ret = 0;
            break;
          }
          char* fixedSymlink = fixMemfdSymlink(resolved_link_path, ipc_mem->target_pid);
          if (!fixedSymlink) {
            free(actualPath);
            free(proc_pid_fd_path);
            ipc_mem->ret = -ENOENT;
            break;
          }

          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(fstat) spoofed: original res: %s | extracted path: %s | fixed link: %s", resolved_link_path, actualPath, fixedSymlink);
          if (strcmp(fixedSymlink, "ENOENT") == 0) {
            ipc_mem->ret = -ENOENT;
            free(actualPath);
            free(fixedSymlink);
            free(proc_pid_fd_path);
            break;
          }

          memcpy(ipc_mem->out_buffer, fixedSymlink, sizeof(ipc_mem->out_buffer));
          ipc_mem->ret = 0;

          free(fixedSymlink);
          free(actualPath);
          free(proc_pid_fd_path);
          break;
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
      case __NR_statfs: {
        const char* path = ipc_mem->string_payload;

        ipc_mem->action = ACTION_USE_RET;
        if (shouldDenyOpen(path) || handleSuRelatedNode(path) == DENY) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[statfs(%s)] denied", path);
          ipc_mem->ret = -EPERM;
          break;
        }
        if (shouldSpoofExistence(path) || handleSuRelatedNode(path) == SPOOF || shouldReportEmptyDir(path_payload)) {
          ipc_mem->ret = -ENOENT;
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[statfs(%s)] spoofed", path);
          break;
        }

        ipc_mem->action = ACTION_EXECUTE_NATIVE;
#ifdef BROKER_DEBUG_LOGGING
        if (shouldLog(path)) {
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "statfs(%s) allowed", path);
        }
#endif
        break;
      }
      case __NR_fstatfs: {
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
          write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Failed to resolve path (%s) in fstatfs. errno: %s", proc_pid_fd_path, strerror(errno));
          free(proc_pid_fd_path);
          // Bubble up to app
          ipc_mem->ret = len;
          break;
        }
        resolved_link_path[len] = '\0';

        if (shouldDenyStat(resolved_link_path) || handleSuRelatedNode(resolved_link_path) == DENY) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[fstatfs(%s)] denied", resolved_link_path);
          free(proc_pid_fd_path);
          ipc_mem->ret = -EPERM;
          break;
        }
        if (shouldSpoofExistence(resolved_link_path) || handleSuRelatedNode(resolved_link_path) == SPOOF || shouldReportEmptyDir(path_payload)) {
          free(proc_pid_fd_path);
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[fstatfs(%s)] spoofed", resolved_link_path);
          ipc_mem->ret = -ENOENT;
          break;
        }
#ifdef BROKER_DEBUG_LOGGING
        if (shouldLog(resolved_link_path)) {
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "fstatfs(%s) (fd: %d) allowed", resolved_link_path, fd);
        }
#endif
        free(proc_pid_fd_path);

        ipc_mem->action = ACTION_EXECUTE_NATIVE;
        break;
      }
      case __NR_newfstatat: {
        int fd = (int)ipc_mem->arg0;
        const char* path = ipc_mem->string_payload;
        int flags = (int)ipc_mem->arg3;

        ipc_mem->action = ACTION_USE_RET;
        if (shouldDenyStat(path) || handleSuRelatedNode(path) == DENY) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[newfstatat(%s)] denied", path);
          ipc_mem->ret = -EPERM;
          break;
        }
        if (shouldSpoofExistence(path) || handleSuRelatedNode(path) == SPOOF || shouldReportEmptyDir(path_payload)) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[newfstatat(%s)] spoofed", path);
          ipc_mem->ret = -ENOENT;
          break;
        }

        // for absolute path lookups
        if (is_hosts_file(path)) {
          struct stat* fixedStatBuf = fixHostsFileStat(path, flags);
          if (!fixedStatBuf) {
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[newfstatat] failed to fix hosts!");
            ipc_mem->ret = -1;
            break;
          }
          memcpy(ipc_mem->out_buffer, fixedStatBuf, sizeof(struct stat));
          free(fixedStatBuf);
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[newfstatat] fixed hosts file.");
          ipc_mem->ret = 0;
          break;
        }

        ipc_mem->action = ACTION_EXECUTE_NATIVE;

#ifdef BROKER_DEBUG_LOGGING
        if (shouldLog(path)) {
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "newfstatat(%s) (fd: %d) allowed", path, fd);
        }
#endif
        break;
      }
      case __NR_statx: {
        int fd = (int)ipc_mem->arg0;
        const char* path = ipc_mem->string_payload;
        int flags = (int)ipc_mem->arg2;
        unsigned int mask = (unsigned int)ipc_mem->arg3;

        ipc_mem->action = ACTION_USE_RET;
        if (shouldDenyStat(path) || handleSuRelatedNode(path) == DENY) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[statx(%s)] denied", path);
          ipc_mem->ret = -EPERM;
          break;
        }
        if (shouldSpoofExistence(path) || handleSuRelatedNode(path) == SPOOF || shouldReportEmptyDir(path_payload)) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[statx(%s)] spoofed", path);
          ipc_mem->ret = -ENOENT;
          break;
        }

        ipc_mem->action = ACTION_EXECUTE_NATIVE;
#ifdef BROKER_DEBUG_LOGGING
        if (shouldLog(path)) {
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "statx(%s) (fd: %d) allowed: flags: %d | mask: %u", path, fd, flags, mask);
        }
#endif
        break;
      }
      case __NR_rt_sigaction: {
        long signal = ipc_mem->arg0;

        if (signal == SIGSYS) {
          ipc_mem->ret = 0;
          ipc_mem->action = ACTION_USE_RET;

          // log_violation("sigaction(SIGSYS)", culprit_lib, ipc_mem->caller_pc, offset);
        }
        if (signal == SIGSEGV) {
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[!!] App installed SIGSEGV handler");
        }
        if (signal == SIGQUIT) {
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[!!] App installed SIGQUIT handler");
          // log_violation("sigaction(SIGQUIT)", culprit_lib, ipc_mem->caller_pc, offset);
        }

        break;
      }
      case __NR_bind: {
        bool should_block = false;

        if (sock_payload->sa_family == AF_INET) {
          struct sockaddr_in* sin = (struct sockaddr_in*)sock_payload;
          uint16_t port = ntohs(sin->sin_port);
          uint32_t ip4 = ntohl(sin->sin_addr.s_addr);

          // Allow 0.0.0.0 and loopback (127.0.0.0/8)
          if (ip4 != 0x00000000 || ((ip4 & 0xFF000000) != 0x7F000000)) {
            if (isLanAddress(sock_payload) || port == 5353 || port == 1900) {
              should_block = true;
            }
          }
        } else if (sock_payload->sa_family == AF_INET6) {
          struct sockaddr_in6* sin6 = (struct sockaddr_in6*)sock_payload;
          uint16_t port = ntohs(sin6->sin6_port);

          if (isLanAddress(sock_payload) || port == 5353 || port == 1900) {
            should_block = true;
          }
        }

        if (should_block) {
          ipc_mem->ret = 0;
          ipc_mem->action = ACTION_USE_RET;

          if (!is_trusted) {
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "App-originated (bind) to LAN blocked");
            // patch_instruction_remote(ipc_mem->target_pid, malicious_pc, 0, patched_pcs);
          } else {
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "System (bind) to LAN blocked");
          }
        }
        break;
      }
      case __NR_connect: {
        if (isLanAddress(sock_payload)) {
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

          std::string sockInfo = get_sockaddr_info(sock_payload);
          if (!is_trusted) {
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "App-originated (sendto) LAN/discovery spoofed. Socket info:\n %s", sockInfo.c_str());
            // patch_instruction_remote(ipc_mem->target_pid, malicious_pc, ghost_len, patched_pcs);
          } else {
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "System (sendto) LAN/discovery spoofed. Socket info:\n %s", sockInfo.c_str());
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
          if (!is_trusted) {
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "App-originated (sendmsg) to LAN address blocked. Socket info:\n %s", sockInfo.c_str());
            // patch_instruction_remote(ipc_mem->target_pid, malicious_pc, ghost_len, patched_pcs);
          } else {
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "System (sendmsg) to LAN address blocked. Socket info:\n %s", sockInfo.c_str());
          }
        }
        break;
      }
      case __NR_inotify_add_watch: {
        int fd = (int)ipc_mem->arg0;
        const char* path = (const char*)ipc_mem->string_payload == nullptr ? "NULL path" : ipc_mem->string_payload;
        uint32_t mask = (uint32_t)ipc_mem->arg2;

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

        if (strstr(path, "Screenshots")) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(inotify_add_watch): Neutered for path: %s", path);
          ipc_mem->ret = SPOOFED_WD;
          ipc_mem->action = ACTION_USE_RET;
          break;
        }

        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(inotify_add_watch): fd=%d, path=%s, flags= [%s]", fd, path, maskAnalysis.c_str());
        break;
      }
      case __NR_inotify_rm_watch: {
        int wd = (int)ipc_mem->arg2;
        if (wd == SPOOFED_WD) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(inotify_rm_watch): Closed spoofed watch");
          ipc_mem->ret = 0;
          ipc_mem->action = ACTION_USE_RET;
          break;
        }
        break;
      }
      case __NR_getdents64: {
        int fd = (int)ipc_mem->arg0;
        struct linux_dirent64* dirp = (struct linux_dirent64*)ipc_mem->arg1;
        size_t count = (size_t)ipc_mem->arg2;

        char* proc_pid_fd_path = assemble_proc_pid_fd(ipc_mem->target_pid, fd);
        if (!proc_pid_fd_path) {
          ipc_mem->ret = -1;
          break;
        }
        char filename[512] = {0};
        ssize_t flen = readlinkat(0, proc_pid_fd_path, filename, sizeof(filename) - 1);
        if (flen == -1) {
          write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Failed to get filename of in getdents64. errno: %s", strerror(errno));
          free(proc_pid_fd_path);
          break;
        }
        filename[flen] = '\0';

        if (
            !starts_with(filename, "/data/data") &&
            !starts_with(filename, "/data/app") &&
            !starts_with(filename, "/storage/emulated/0/Android")) {
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] getdents64(%s)", filename);
        }
        free(proc_pid_fd_path);
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

            write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(readlinkat with dirfd) spoofed: original res: %s | extracted path: %s | fixed link: %s", resolved_link_path, actualPath, fixedSymlink);
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
          free(proc_pid_fd_path);
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(readlinkat with dirfd): %s -> %s", proc_pid_fd_path, resolved_link_path);

          memcpy(ipc_mem->out_buffer, resolved_link_path, sizeof(ipc_mem->out_buffer));
          ipc_mem->ret = (long)strlen(resolved_link_path);
        } else if (dirfd == AT_FDCWD) {
          if (!looks_like_proc_fd(path, ipc_mem->target_pid)) {
            ipc_mem->action = ACTION_EXECUTE_NATIVE;
            write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(readlinkat AT_FDCWD) with apparently not fd path(%s). Letting through...", path);
            break;
          }

          size_t pathLength = strlen(path);
          char reversedDirfdStr[6] = {0};

          char c = -1;
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
          if (shouldLog(resolved_link_path)) {
            write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(readlinkat AT_FDCWD): %s -> %s", path, resolved_link_path);
          }

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
      case __NR_syslog: {
        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "[*] (syslog)!");
        break;
      }
      case __NR_mq_notify: {
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] (mq_notify)!");
        break;
      }

#ifdef TRAP_EXPERIMENTAL_SYSCALLS
      case __NR_pipe2: {
        int* pipefd = (int*)ipc_mem->pipefd_payload;
        int flags = (int)ipc_mem->arg1;

        std::string flagsAnalysis = "";
        flagsAnalysis.reserve(100);
        if (flags & O_NONBLOCK) flagsAnalysis += "O_NONBLOCK";
        if (flags & O_CLOEXEC) flagsAnalysis += "Close-on-exec";

        if (!pipefd) {
          write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "(pipe2): Flags: %s", flagsAnalysis.c_str());
        } else {
          write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "(pipe2): pipefd[0]: %d | pipefd[1]: %d | Flags: %s", pipefd[0], pipefd[1], flagsAnalysis.c_str());
        }

        break;
      }
      case __NR_clone: {
        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "[*] (clone)!");
        break;
      }
      case __NR_clone3: {
        struct clone_args* cl_args = (struct clone_args*)ipc_mem->struct_payload;

        char* childThName = get_thread_name(ipc_mem->target_pid, cl_args->child_tid);
        if (!childThName) {
          break;
        }

        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "(clone3): Child TID: %llu | Thread name: %s | Exit signal: %llu", cl_args->child_tid, childThName, cl_args->exit_signal);
        free(childThName);
        break;
      }
      case __NR_mremap: {
        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "[*] (mremap)!");
        break;
      }
      case __NR_mincore: {
        void* addr = (void*)ipc_mem->arg0;
        size_t length = (size_t)ipc_mem->arg1;
        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "(mincore) addr: %p | vecsiz: %ld", addr, length);
        break;
      }
      case __NR_gettimeofday: {
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] (gettimeofday)!");
        break;
      }
      case __NR_clock_getres: {
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] (clock_getres)!");
        break;
      }
      case __NR_clock_nanosleep: {
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] (clock_nanosleep)!");
        break;
      }
      case __NR_mknodat: {
        int dirfd = (int)ipc_mem->arg0;
        const char* pathname = ipc_mem->string_payload[0] != '\0' ? ipc_mem->string_payload : nullptr;
        mode_t mode = (mode_t)ipc_mem->arg2;
        dev_t dev = (dev_t)ipc_mem->arg3;

        int file_type = mode & S_IFMT;
        const char* type_str =
            (file_type == S_IFIFO) ? "FIFO" : (file_type == S_IFCHR) ? "char_dev"
                                          : (file_type == S_IFBLK)   ? "block_dev"
                                          : (file_type == S_IFSOCK)  ? "socket"
                                          : (file_type == S_IFREG)   ? "regular"
                                                                     : "unknown";

        char dev_str[32] = "n/a";
        if (file_type == S_IFCHR || file_type == S_IFBLK) {
          snprintf(dev_str, sizeof(dev_str), "%u:%u", major(dev), minor(dev));
        }

        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] mknodat(dirfd=%d, path=%s, type=%s, perms=%#o, dev=%s)", dirfd, pathname, type_str, mode & 0777, dev_str);
        break;
      }
      case __NR_process_vm_readv:
      case __NR_process_vm_writev: {
        pid_t target_pid = (pid_t)ipc_mem->arg0;
        const struct iovec* local_iov = (const struct iovec*)ipc_mem->arg1;
        unsigned long liovcnt = (unsigned long)ipc_mem->arg2;
        const struct iovec* remote_iov = (const struct iovec*)ipc_mem->arg3;
        unsigned long riovcnt = (unsigned long)ipc_mem->arg4;
        unsigned long flags = (unsigned long)ipc_mem->arg5;

        const char* call_name = (nr == __NR_process_vm_readv) ? "process_vm_readv" : "process_vm_writev";

        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] %s(pid=%d, local_iov=%p liovcnt=%lu, remote_iov=%p riovcnt=%lu, flags=%lu)", call_name, target_pid, (void*)local_iov, liovcnt, (void*)remote_iov, riovcnt, flags);

        if (target_pid == ipc_mem->target_pid) {
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[!] %s targeting SELF (pid=%d) — possible memory self-scan", call_name, target_pid);
        }

        break;
      }
      case __NR_clock_gettime: {
        if (is_trusted) break;
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] (clock_gettime)!");
        break;
      }
      case __NR_prctl: {
        int op = (int)ipc_mem->arg0;
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] prctl(%d)", op);
        break;
      }
      case __NR_epoll_ctl: {
        int fd = (int)ipc_mem->arg2;
        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "[!] epoll_ctl on fd %d", fd);
        break;
      }
      case __NR_nanosleep: {
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] (nanosleep)!");
        break;
      }
      case __NR_ptrace: {
        int op = (int)ipc_mem->arg0;
        pid_t pid = (pid_t)ipc_mem->arg2;

        char* opName = get_ptrace_op_name(op);
        if (!opName) {
          break;
        }

        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "(ptrace): op: %s | PID: %d", opName, pid);
        free(opName);
        break;
      }
      case __NR_mmap: {
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] executable (mmap)!");
        break;
      }
      case __NR_mprotect: {
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] (mprotect)!");
        break;
      }
#endif

      default: {
        write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Broker got unexpected syscall: %d. Returning ENOSYS.", nr);
        ipc_mem->ret = -ENOSYS;
        ipc_mem->action = ACTION_USE_RET;
      }
    }

    // standard_exit:
    __sync_synchronize();
    ipc_mem->status = BROKER_ANSWERED;
    futex_wake(&ipc_mem->status);
  }
dead_client_exit:
  munmap(ipc_mem, sizeof(SharedIPC));
  if (pidfd >= 0) close(pidfd);
  close(epfd);
  write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] Broker (PID: %d) (TID: %d) exiting for dead client (PID: %d)", pid, tid, client_pid);
}

static inline void patch_instruction_remote(pid_t target_pid, uintptr_t caller_pc, int return_value, std::unordered_set<uintptr_t>& patched_pcs) {
  if (inside_remote_patcher) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Thread reentrancy in remote patcher!");
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

  // __builtin___clear_cache
  ssize_t written = pwrite(mem_fd, &opcode, sizeof(opcode), target_addr);
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

  char addr_str[INET6_ADDRSTRLEN];
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

static inline bool client_is_dead(int epfd, int pidfd) {
  struct epoll_event events[2];
  int n = epoll_wait(epfd, events, 2, 0);
  for (int i = 0; i < n; i++) {
    if (
        events[i].data.fd == pidfd &&
        (events[i].events & (EPOLLHUP | EPOLLERR | EPOLLIN))) {
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
  return (int)arm64_raw_syscall(__NR_pidfd_open, (long)pid, (long)flags, 0, 0, 0, 0);
}

// HEAP ALLOCATION:
static char* get_thread_name(pid_t parentPid, __aligned_u64 tid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/task/%llu/comm", parentPid, tid);

  FILE* f = fopen(path, "r");
  if (!f) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "get_thread_name: Failed to open /proc/<parent-pid>/task/<tid>/comm");
    return nullptr;
  }

  char* name = (char*)calloc(16, sizeof(char));
  if (!name) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "get_thread_name: Failed to allocate memory!");
    return nullptr;
  }

  fgets(name, sizeof(name), f);
  fclose(f);
  return name;
}

// HEAP ALLOCATION:
static char* get_ptrace_op_name(int op) {
  const char* name;
  switch (op) {
    case PTRACE_TRACEME:
      name = "PTRACE_TRACEME";
      break;
    case PTRACE_PEEKTEXT:
      name = "PTRACE_PEEKTEXT";
      break;
    case PTRACE_PEEKDATA:
      name = "PTRACE_PEEKDATA";
      break;
    case PTRACE_PEEKUSER:
      name = "PTRACE_PEEKUSER";
      break;
    case PTRACE_POKETEXT:
      name = "PTRACE_POKETEXT";
      break;
    case PTRACE_POKEDATA:
      name = "PTRACE_POKEDATA";
      break;
    case PTRACE_POKEUSER:
      name = "PTRACE_POKEUSER";
      break;
    case PTRACE_GETREGSET:
      name = "PTRACE_GETREGSET";
      break;
    case PTRACE_SETREGSET:
      name = "PTRACE_SETREGSET";
      break;
    case PTRACE_GETSIGINFO:
      name = "PTRACE_GETSIGINFO";
      break;
    case PTRACE_SETSIGINFO:
      name = "PTRACE_SETSIGINFO";
      break;
    case PTRACE_PEEKSIGINFO:
      name = "PTRACE_PEEKSIGINFO";
      break;
    case PTRACE_GETSIGMASK:
      name = "PTRACE_GETSIGMASK";
      break;
    case PTRACE_SETSIGMASK:
      name = "PTRACE_SETSIGMASK";
      break;
    case PTRACE_SETOPTIONS:
      name = "PTRACE_SETOPTIONS";
      break;
    case PTRACE_GETEVENTMSG:
      name = "PTRACE_GETEVENTMSG";
      break;
    case PTRACE_CONT:
      name = "PTRACE_CONT";
      break;
    case PTRACE_SYSCALL:
      name = "PTRACE_SYSCALL";
      break;
    case PTRACE_SINGLESTEP:
      name = "PTRACE_SINGLESTEP";
      break;
    case PTRACE_SYSEMU:
      name = "PTRACE_SYSEMU";
      break;
    case PTRACE_SYSEMU_SINGLESTEP:
      name = "PTRACE_SYSEMU_SINGLESTEP";
      break;
    case PTRACE_LISTEN:
      name = "PTRACE_LISTEN";
      break;
    case PTRACE_KILL:
      name = "PTRACE_KILL";
      break;
    case PTRACE_INTERRUPT:
      name = "PTRACE_INTERRUPT";
      break;
    case PTRACE_ATTACH:
      name = "PTRACE_ATTACH";
      break;
    case PTRACE_SEIZE:
      name = "PTRACE_SEIZE";
      break;
    case PTRACE_SECCOMP_GET_FILTER:
      name = "PTRACE_SECCOMP_GET_FILTER";
      break;
    case PTRACE_DETACH:
      name = "PTRACE_DETACH";
      break;
    case PTRACE_GET_SYSCALL_INFO:
      name = "PTRACE_GET_SYSCALL_INFO";
      break;
    default:
      name = "Unknown ptrace operation!!";
      break;
  }

  size_t len = strlen(name) + 1;
  char* result = (char*)calloc(len, sizeof(char));
  if (!result) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "get_ptrace_op_name: Failed to allocate memory!");
    return nullptr;
  }
  memcpy(result, name, len);
  return result;
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

static inline bool is_hosts_file(const char* pathname) {
  return (
      (strcmp(pathname, "/etc/hosts") == 0) ||
      (strcmp(pathname, "/system/etc/hosts") == 0));
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

/**
 * Parses the physical (in-disk ?) ELF file to find a name for a relative offset.
 * This sees STATIC labels that `dladdr` cannot. (really?)
 */
static void find_label_in_elf(const char* path, uintptr_t offset, char* out_name, size_t max_len) {
  if (!path) {
    write_to_logcat_async(ANDROID_LOG_ERROR, "BipanBrokerUnwinder", "find_label_in_elf: got empty path. early returning!");
    return;
  }

  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, "BipanBrokerUnwinder", "find_label_in_elf: Failed to open %s", path);
    return;
  }

  struct stat st;
  if (fstat(fd, &st) < 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, "BipanBrokerUnwinder", "find_label_in_elf: Failed to fstat fd: %d (from %s)", fd, path);
    close(fd);
    return;
  }

  if (st.st_size < (off_t)sizeof(ElfHeader)) {
    write_to_logcat_async(ANDROID_LOG_WARN, "BipanBrokerUnwinder", "find_label_in_elf: %s st_size's too small to be an ELF. Not searching symbols.", path);
    close(fd);
    strncpy(out_name, "[Too Small]", max_len - 1);
    return;
  }

  void* map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (map == MAP_FAILED) {
    write_to_logcat_async(ANDROID_LOG_ERROR, "BipanBrokerUnwinder", "find_label_in_elf: Failed to mmap fd-backed mem");
    return;
  }

  ElfHeader* ehdr = (ElfHeader*)map;

  // If this is an APK (ZIP), it will fail this check and safely return
  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
    write_to_logcat_async(ANDROID_LOG_WARN, "BipanBrokerUnwinder", "find_label_in_elf: %s not an ELF. Not searching symbols.", path);
    strncpy(out_name, "[APK/ZIP File]", max_len - 1);
    munmap(map, st.st_size);
    return;
  }

  ElfSection* shdr = (ElfSection*)((uintptr_t)map + ehdr->e_shoff);

  uintptr_t best_diff = (uintptr_t)-1;
  char* found_name = NULL;

  // Search both SYMTAB (Static) and DYNSYM (Dynamic)
  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_DYNSYM) {
      ElfSymbol* syms = (ElfSymbol*)((uintptr_t)map + shdr[i].sh_offset);
      size_t count = shdr[i].sh_size / sizeof(ElfSymbol);

      // sh_link automatically points to the correct string table for this symbol table
      char* strings = (char*)((uintptr_t)map + shdr[shdr[i].sh_link].sh_offset);

      for (size_t j = 0; j < count; j++) {
        char* current_name = &strings[syms[j].st_name];

        // TWEAK: Skip empty names, mapping symbols ($x, $d),
        // and symbols that start after our offset.
        if (syms[j].st_name == 0 || current_name[0] == '$' || syms[j].st_value > offset) {
          continue;
        }

        uintptr_t diff = offset - syms[j].st_value;
        if (diff < best_diff) {
          best_diff = diff;
          found_name = current_name;
        }
      }

      // If we found a perfect match (diff 0) in SYMTAB, we can stop early
      if (best_diff == 0 && shdr[i].sh_type == SHT_SYMTAB) {
        break;
      }
    }
  }

  if (found_name && strlen(found_name) > 0) {
    strncpy(out_name, found_name, max_len - 1);
  } else {
    strncpy(out_name, "???", max_len);
  }

  munmap(map, st.st_size);
}

/**
 * `dladdr` mimicking:
 * - opens /proc/<PID>/maps
 * - finds which region contains `addr`
 * - calculates the in-file offset of it
 */
static bool manual_dladdr(uintptr_t addr, ManualDlInfo* info, pid_t pid) {
  char proc_pid_maps_path[PATH_MAX] = {0};
  snprintf(proc_pid_maps_path, PATH_MAX, "/proc/%d/maps", pid);

  FILE* f = fopen(proc_pid_maps_path, "r");
  if (!f) {
    write_to_logcat_async(ANDROID_LOG_WARN, "BipanBrokerUnwinder", "Failed to open remote's %s", proc_pid_maps_path);
    return false;
  }

  char line[PATH_MAX];
  int found = false;

  while (fgets(line, sizeof(line), f)) {
    uintptr_t start, end, file_offset;
    char perms[5];
    // Standard `maps` format: start-end perms offset dev inode path
    if (sscanf(line, "%lx-%lx %4s %lx", &start, &end, perms, &file_offset) < 4) {
      // Silently skip broken lines...
      continue;
    }

    if (addr >= start && addr < end) {
      info->dli_fbase = start;

      // Calculate offset: (Actual Addr - Map Start) + File Offset
      info->dli_offset = (addr - start) + file_offset;

      // Extract the path
      // Look for the first '/' or '[' (for [stack], [vdso], etc)
      char* path_start = strchr(line, '/');
      if (!path_start) {
        path_start = strchr(line, '[');
      }

      if (path_start) {
        char* newline = strchr(path_start, '\n');
        if (newline) *newline = '\0';
        strncpy(info->dli_fname, path_start, sizeof(info->dli_fname) - 1);
      } else {
        strcpy(info->dli_fname, "[anonymous memory]");
      }

      found = true;
      break;
    }
  }

  fclose(f);
  return found;
}

static inline bool is_trusted_lib(const char* lib_path) {
  return (
      starts_with(lib_path, "/apex") ||
      starts_with(lib_path, "/vendor") ||
      starts_with(lib_path, "/system") ||
      starts_with(lib_path, "/product") ||
      starts_with(lib_path, "/system_ext"));
}

static bool unwinder(uintptr_t fp, uintptr_t lr, pid_t pid) {
  // Immediate caller is in LR (x30)
  lr &= 0x0000FFFFFFFFFFFFULL;

  char mem_path[64];
  snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
  int mem_fd = open(mem_path, O_RDONLY);
  if (mem_fd < 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, "BipanBrokerUnwinder", "unwinder: failed to open %s", mem_path);
    return false;  // fail closed, assuming untrusted
  }

  ManualDlInfo info;
  char sym_name[PATH_MAX] = "???";

  if (manual_dladdr(lr, &info, pid)) {
    find_label_in_elf(info.dli_fname, info.dli_offset, sym_name, sizeof(sym_name));

    if (!is_trusted_lib(info.dli_fname)) {
      write_to_logcat_async(ANDROID_LOG_INFO, "BipanBrokerUnwinder", "Very first LR (%p) is a malicious lib: %s. Unwinding over :)", (void*)lr, info.dli_fname);
      close(mem_fd);
      return false;
    }

    write_to_logcat_async(ANDROID_LOG_DEBUG, "BipanBrokerUnwinder", "Starting unwinding at LR:  %p -> %-15s | %s (+0x%lx)", (void*)lr, sym_name, info.dli_fname, info.dli_offset);
  } else {
    write_to_logcat_async(ANDROID_LOG_DEBUG, "BipanBrokerUnwinder", "Failed to resolve very first LR (%p)!", (void*)lr);
    close(mem_fd);
    return false;
  }

  // Walk the Frame Pointer chain (x29)
  for (int i = 0; i < MAX_STACK_TRACE; ++i) {
    if (!fp || (fp & 0x7)) {
      /**
       * Trying to take one more step, but
       * the value we'd use as the next FP isn't a valid pointer.
       * Typical in leaf functions.
       */
      write_to_logcat_async(ANDROID_LOG_ERROR, "BipanBrokerUnwinder", "Unwinder exhausted: frame ptr is null/misaligned!");
      close(mem_fd);
      return true;
    }

    /**
     * Read [x29] and [x29+8] from the target
     * On arm64, the return address is 8 bytes above the Frame Pointer
     */
    uintptr_t next_fp = 0, return_addr = 0;
    if (
        pread(mem_fd, &next_fp, sizeof(next_fp), fp) != sizeof(next_fp) ||
        pread(mem_fd, &return_addr, sizeof(return_addr), fp + 8) != sizeof(return_addr)) {
      /**
       * Address we're about to dereference isn't
       * backed by a readable page in the target's address space.
       * Could be garbage or we're at the edge of the stack region.
       */
      write_to_logcat_async(ANDROID_LOG_ERROR, "BipanBrokerUnwinder", "Unwinder exhausted: couldn't read remote frame at %p", (void*)fp);
      close(mem_fd);
      return true;
    }

    if (!return_addr) {
      /**
       * All 8 bytes at fp+8 are zero (nullptr).
       * We can have walked past the bottom of the frame chain
       */
      write_to_logcat_async(ANDROID_LOG_ERROR, "BipanBrokerUnwinder", "Unwinder exhausted: null return addr");
      close(mem_fd);
      return true;
    }

    // Strip ARM64 PAC (Pointer Authentication) bits
    return_addr &= 0x0000FFFFFFFFFFFFULL;

    ManualDlInfo info;
    char sym_name[PATH_MAX] = "???";

    if (manual_dladdr(return_addr, &info, pid)) {
      find_label_in_elf(info.dli_fname, info.dli_offset, sym_name, sizeof(sym_name));
      write_to_logcat_async(ANDROID_LOG_DEBUG, "BipanBrokerUnwinder", "  Ancestor:      %p -> %-15s | %s (+0x%lx)\n", (void*)return_addr, sym_name, info.dli_fname, info.dli_offset);

      if (!is_trusted_lib(info.dli_fname)) {
        write_to_logcat_async(ANDROID_LOG_INFO, "BipanBrokerUnwinder", "Found malicious lib: %s at %p after %d unwindings", info.dli_fname, (void*)return_addr, i);
        close(mem_fd);
        return false;
      }
    } else {
      write_to_logcat_async(ANDROID_LOG_WARN, "BipanBrokerUnwinder", "Failed to resolve ancestor addr: %p. Continuing...", (void*)return_addr);
    }

    if (next_fp <= fp) {
      /**
       * Sanity check for stack direction.
       * In other words, the Frame Pointer isn't increasing.
       * As the stack grows downward on arm64,
       * a legitimate frame chain should show monotonically
       * increasing addresses we walk towards the ultimate caller.
       * TLDR: each caller's frame sits at a higher address than the callee's.
       */
      write_to_logcat_async(ANDROID_LOG_ERROR, "BipanBrokerUnwinder", "Unwinder exhausted: FP not increasing");
      close(mem_fd);
      return true;
    }

    fp = next_fp;
  }

  close(mem_fd);
  write_to_logcat_async(ANDROID_LOG_WARN, "BipanBrokerUnwinder", "Walked %d frames and found only safe libs. Allowing!", MAX_STACK_TRACE);
  return true;
}
