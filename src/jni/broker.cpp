#include "broker.hpp"

#include <arpa/inet.h>
#include <elf.h>
#include <inttypes.h>
#include <linux/filter.h>
#include <linux/memfd.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

#include "logger.hpp"
#include "shared.hpp"
#include "spoofer.hpp"
#include "synchronization.hpp"
#include "utils.hpp"

#define TAG "BipanBroker"

// Use 64-bit ELF structures for ARM64
typedef Elf64_Ehdr ElfHeader;
typedef Elf64_Shdr ElfSection;
typedef Elf64_Sym ElfSymbol;

typedef struct {
  char dli_fname[256];   // Path to the library
  uintptr_t dli_fbase;   // Base address of the library
  uintptr_t dli_offset;  // Relative offset inside the file
} ManualDlInfo;

struct MapEntry {
  uintptr_t start, end, offset;
  std::string path;
};

static void refresh_maps(pid_t pid, std::vector<MapEntry>& current_maps);
static std::string get_culprit_so(pid_t pid, uintptr_t pc, uintptr_t* out_offset, std::vector<MapEntry>& current_maps);
static void find_label_in_elf(const char* path, uintptr_t offset, char* out_name, size_t max_len);
static void log_violation(const char* action, const std::string& culprit, uintptr_t pc, uintptr_t offset);
static inline bool is_trusted_library(const std::string& lib_path);
static inline bool safe_read(int mem_fd, uintptr_t addr, uintptr_t* out);
static inline void patch_instruction_remote(pid_t target_pid, uintptr_t caller_pc, int return_value, std::unordered_set<uintptr_t>& patched_pcs);
static void format_ip_addr(struct sockaddr* addr, char* out_buf, size_t buf_len);
static inline bool is_discovery_probe(struct sockaddr* addr);
std::string get_sockaddr_info(const struct sockaddr* sa);
static void read_argv_from_tracee(pid_t pid, uintptr_t argv_ptr, char* out, size_t out_size);
static inline bool client_is_dead(int epfd, int pidfd);
static inline int bipan_pidfd_open(pid_t pid, unsigned int flags);

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
  prctl(PR_SET_NAME, "K67v3741S1Xm", 0, 0, 0);

  std::vector<MapEntry> current_maps;
  std::unordered_set<uintptr_t> patched_pcs;

  pid_t pid = (pid_t)arm64_raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
  std::__thread_id tid = std::this_thread::get_id();
  write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] Starting Broker: PID: %d | TID: %d", pid, tid);

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

    uintptr_t offset = 0;
    uintptr_t malicious_pc = ipc_mem->caller_pc;
    std::string culprit_lib = get_culprit_so(ipc_mem->target_pid, ipc_mem->caller_pc, &offset, current_maps);
    bool is_trusted = is_trusted_library(culprit_lib);

    // If the program counter is "trusted" - like libc - check its ancestors
    if (is_trusted) {
      char mem_path[64];
      snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", ipc_mem->target_pid);
      int mem_fd = open(mem_path, O_RDONLY);

      if (mem_fd < 0) {
        write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] startBroker: open /proc/%d/mem failed!", ipc_mem->target_pid);
        return;
      }
      uintptr_t current_pc = ipc_mem->stack_trace[0];  // Start with LR
      uintptr_t current_fp = ipc_mem->caller_fp;

      for (int i = 0; i < MAX_STACK_TRACE; i++) {
        if (current_pc == 0) break;

        // Stip arm64 PAC bits
        current_pc &= 0x0000FFFFFFFFFFFFULL;

        uintptr_t frame_offset = 0;
        std::string frame_lib = get_culprit_so(ipc_mem->target_pid, current_pc, &frame_offset, current_maps);

        if (!is_trusted_library(frame_lib)) {
          malicious_pc = current_pc;
          culprit_lib = frame_lib;
          offset = frame_offset;
          is_trusted = false;
          break;
        }

        // Walk to the next frame in the target process
        uintptr_t next_fp, next_lr;
        if (
            !safe_read(mem_fd, current_fp, &next_fp) ||
            !safe_read(mem_fd, current_fp + 8, &next_lr)) {
          break;
        }

        current_fp = next_fp;
        current_pc = next_lr;
        if (!current_fp || (current_fp & 0x7)) {
          break;
        }
      }
      close(mem_fd);
    }

    // Default to allow
    ipc_mem->action = ACTION_EXECUTE_NATIVE;

    switch (nr) {
      case __NR_execve:
      case __NR_execveat: {
        if (!is_trusted) {
          const char* action_name = (nr == __NR_execve) ? "execve" : "execveat";
          ipc_mem->ret = 0;
          ipc_mem->action = ACTION_EXIT_PROCESS;
#ifdef DEBUG
          if (nr == __NR_execve) {
            char argv_dump[512] = {0};
            char envp_dump[512] = {0};

            read_argv_from_tracee(ipc_mem->target_pid, (uintptr_t)ipc_mem->arg1, argv_dump, sizeof(argv_dump));

            // read just first few of envp
            read_argv_from_tracee(ipc_mem->target_pid, (uintptr_t)ipc_mem->arg2, envp_dump, sizeof(envp_dump));

            write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "[execve denied INFO!] path=%s argv=%s", ipc_mem->string_payload, argv_dump);
          }
#endif

          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[%s(%s) denied]", action_name, path_payload);
        }
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
        if (!is_trusted) {
          if (shouldAllowDevProps(path_payload)) {
            break;
          }
          if (shouldDenyAccess(path_payload)) {
            if (starts_with(path_payload, "/dev/__properties__")) {
              write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[openat(%s)] denied", path_payload);
            }
            ipc_mem->ret = -EACCES;
            ipc_mem->action = ACTION_USE_RET;
          } else if (shouldSpoofExistence(path_payload)) {
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[openat(%s)] spoofed", path_payload);
            ipc_mem->ret = -ENOENT;
            ipc_mem->action = ACTION_USE_RET;
          } else if (is_maps(path_payload) || is_smaps(path_payload) || is_mounts(path_payload) || shouldFakeFile(path_payload)) {
            // Translate target's /proc/self/ to /proc/[target_pid]/ so the Broker reads the app's maps rather than its own
            char real_path[256];
            if (strncmp(path_payload, "/proc/self/", 11) == 0) {
              snprintf(real_path, sizeof(real_path), "/proc/%d/%s", ipc_mem->target_pid, path_payload + 11);
            } else {
              strncpy(real_path, path_payload, sizeof(real_path));
            }

            // Broker generates the fake file locally
            int fake_fd = -1;
            if (is_maps(path_payload)) {
              fake_fd = clean_proc_maps((int)ipc_mem->arg0, real_path, (int)ipc_mem->arg2, (mode_t)ipc_mem->arg3);
              write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[openat VFS:(%s)] spoofed", path_payload);
            } else if (is_smaps(path_payload)) {
              fake_fd = clean_proc_smaps((int)ipc_mem->arg0, real_path, (int)ipc_mem->arg2, (mode_t)ipc_mem->arg3);
              write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[openat VFS:(%s)] spoofed", path_payload);
            } else if (is_mounts(path_payload)) {
              fake_fd = clean_proc_mounts((int)ipc_mem->arg0, real_path, (int)ipc_mem->arg2, (mode_t)ipc_mem->arg3);
              write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[openat VFS:(%s)] spoofed", path_payload);
            } else {
              fake_fd = create_spoofed_file(shouldFakeFile(path_payload));
              write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[openat(%s)] spoofed", path_payload);
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
              break;
            }
            write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] Filled target's fd: %s", proc_path);

            char buf[4096];
            ssize_t n;
            lseek(fake_fd, 0, SEEK_SET);
            while ((n = read(fake_fd, buf, sizeof(buf))) > 0) {
              write(root_fd, buf, n);
            }
            lseek(root_fd, 0, SEEK_SET);

            // Cleanup daemon's ref of target's pre_fd and its own fake fd
            close(root_fd);
            close(fake_fd);

            // Tell target to use the fd it already has
            ipc_mem->ret = target_fd;
            ipc_mem->action = ACTION_USE_RET;
          }
#ifdef DEBUG
          else {
            if (shouldLog(path_payload)) {
              write_to_logcat_async(ANDROID_LOG_WARN, TAG, "Allowing untrusted open: %s", path_payload);
            }
          }
#endif
        }
        break;
      }
      case __NR_faccessat:
      case __NR_newfstatat:
      case __NR_statx: {
        const char* action_name;
        if (nr == __NR_faccessat) {
          action_name = "faccessat";
        } else if (nr == __NR_newfstatat) {
          action_name = "newfstatat";
        } else {
          action_name = "statx";
        }

        if (shouldSpoofExistence(path_payload)) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[%s(%s)] spoofed", action_name, path_payload);
          ipc_mem->ret = -ENOENT;
          ipc_mem->action = ACTION_USE_RET;
          break;
        }
        if (!is_trusted) {
          if (shouldAllowDevProps(path_payload)) {
            break;
          }
          if (shouldDenyAccess(path_payload)) {
            if (starts_with(path_payload, "/dev/__properties__")) {
              write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[%s(%s)] denied", action_name, path_payload);
            }
            ipc_mem->ret = -EACCES;
            ipc_mem->action = ACTION_USE_RET;
          } else if (is_maps(path_payload) || is_smaps(path_payload) || is_mounts(path_payload) || shouldFakeFile(path_payload)) {
            write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[%s(%s)] executing natively...", action_name, path_payload);
            ipc_mem->ret = 0;
            ipc_mem->action = ACTION_USE_RET;
          }
#ifdef DEBUG
          else {
            if (shouldLog(path_payload)) {
              write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Allowing untrusted open: %s", path_payload);
            }
          }
#endif
        }
        break;
      }
      case __NR_rt_sigaction: {
        if (ipc_mem->arg0 == SIGSYS) {
          ipc_mem->ret = 0;
          ipc_mem->action = ACTION_USE_RET;

          log_violation("(sigaction)", culprit_lib, ipc_mem->caller_pc, offset);
        }
        break;
      }
      case __NR_bind: {
        bool should_block = false;

        if (sock_payload->sa_family == AF_INET) {
          struct sockaddr_in* sin = (struct sockaddr_in*)sock_payload;
          uint16_t port = ntohs(sin->sin_port);
          uint32_t ip4 = ntohl(sin->sin_addr.s_addr);
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "Got IPv4 bind request to port %d", port);

          // Allow 0.0.0.0
          if (ip4 != 0x00000000) {
            if (is_lan_address(sock_payload) || port == 5353 || port == 1900) {
              should_block = true;
            }
          }
        } else if (sock_payload->sa_family == AF_INET6) {
          struct sockaddr_in6* sin6 = (struct sockaddr_in6*)sock_payload;
          uint16_t port = ntohs(sin6->sin6_port);
          uint8_t* ip6 = sin6->sin6_addr.s6_addr;
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "Got IPv6 bind request to port %d", port);

          // TODO: Allow :: ?
          bool is_v6_unspecified = true;
          for (int i = 0; i < 16; i++) {
            if (ip6[i] != 0) {
              is_v6_unspecified = false;
              break;
            }
          }

          if (!is_v6_unspecified) {
            if (is_lan_address(sock_payload) || port == 5353 || port == 1900) {
              should_block = true;
            }
          }
        }

        if (should_block) {
          ipc_mem->ret = -EADDRNOTAVAIL;
          ipc_mem->action = ACTION_USE_RET;

          if (!is_trusted) {
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "App-originated (bind) to LAN blocked");
            // patch_instruction_remote(ipc_mem->target_pid, malicious_pc, -EADDRNOTAVAIL, patched_pcs);
          } else {
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "System (bind) to LAN blocked");
          }
        }
        break;
      }
      case __NR_connect: {
        bool is_discovery = false;

        if (sock_payload->sa_family == AF_INET) {
          uint16_t port = ntohs(((struct sockaddr_in*)sock_payload)->sin_port);
          if (port == 5353 || port == 1900) is_discovery = true;
        } else if (sock_payload->sa_family == AF_INET6) {
          uint16_t port = ntohs(((struct sockaddr_in6*)sock_payload)->sin6_port);
          if (port == 5353 || port == 1900) is_discovery = true;
        }

        if (is_lan_address(sock_payload) || is_discovery) {
          char addr_str[64];
          format_ip_addr(sock_payload, addr_str, sizeof(addr_str));

          ipc_mem->ret = -ECONNREFUSED;
          ipc_mem->action = ACTION_USE_RET;

          const char* type = is_discovery ? "discovery" : "LAN";
        }
        break;
      }
      case __NR_listen: {
        if (sock_payload->sa_family == AF_INET || sock_payload->sa_family == AF_INET6) {
          ipc_mem->ret = 0;
          ipc_mem->action = ACTION_USE_RET;

          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(listen) spoofed to success");
          patch_instruction_remote(ipc_mem->target_pid, malicious_pc, 0, patched_pcs);
        }
        break;
      }
      case __NR_sendto: {
        if (is_lan_address(sock_payload) || is_discovery_probe(sock_payload)) {
          int ghost_len = (int)ipc_mem->arg2;
          ipc_mem->ret = ghost_len;
          ipc_mem->action = ACTION_USE_RET;

          std::string sockInfo = get_sockaddr_info(sock_payload);
          if (!is_trusted) {
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "App-originated (sendto) LAN/discovery spoofed. Socket info:\n %s", sockInfo.c_str());
            patch_instruction_remote(ipc_mem->target_pid, malicious_pc, ghost_len, patched_pcs);
          } else {
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "System (sendto) LAN/discovery spoofed. Socket info:\n %s", sockInfo.c_str());
          }
        }
        break;
      }
      case __NR_sendmsg: {
        if (is_lan_address(sock_payload) || is_discovery_probe(sock_payload)) {
          int ghost_len = (int)ipc_mem->arg3;
          ipc_mem->ret = ghost_len;
          ipc_mem->action = ACTION_USE_RET;

          std::string sockInfo = get_sockaddr_info(sock_payload);
          if (!is_trusted) {
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "App-originated (sendmsg) to LAN address blocked. Socket info:\n %s", sockInfo.c_str());
            patch_instruction_remote(ipc_mem->target_pid, malicious_pc, ghost_len, patched_pcs);
          } else {
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "System (sendmsg) to LAN address blocked. Socket info:\n %s", sockInfo.c_str());
          }
        }
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
      case __NR_memfd_create: {
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] (memfd_create)!");
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
        if (mask & IN_OPEN) maskAnalysis += " File or directory was opened |";

        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(inotify_add_watch): fd=%d, path=%s, flags= [%s]", fd, path, maskAnalysis.c_str());
        break;
      }
      case __NR_inotify_init1: {
        int flags = (int)ipc_mem->arg0;
        if (!flags) {
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(inotify_init1) with no flags, behave like 'inotify_init'");
          break;
        }

        if (flags & (IN_NONBLOCK | IN_CLOEXEC)) {
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(inotify_init1) with nonblocking and close-on-exec");
        } else if (flags & IN_NONBLOCK) {
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(inotify_init1) with nonblocking I/O");
        } else if (flags & IN_CLOEXEC) {
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(inotify_init1) with close-on-exec on the new FD");
        }

        break;
      }
      case __NR_inotify_rm_watch: {
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] (inotify_rm_watch)!");
        break;
      }
      case __NR_mq_notify: {
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] (mq_notify)!");
        break;
      }
      case __NR_getdents64: {
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] (getdents64)!");
        break;
      }
      case __NR_readlinkat: {
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] (readlinkat)!");
        break;
      }
      case __NR_mincore: {
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] (mincore)!");
        break;
      }
      case __NR_nanosleep: {
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] (nanosleep)!");
        break;
      }
      case __NR_clock_gettime: {
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] (clock_gettime)!");
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
      default: {
        write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Broker got unexpected syscall: %d. Returning ENOSYS.", nr);
        ipc_mem->ret = -ENOSYS;
        ipc_mem->action = ACTION_USE_RET;
      }
    }

    __sync_synchronize();
    ipc_mem->status = BROKER_ANSWERED;
    futex_wake(&ipc_mem->status);
  }
dead_client_exit:
  munmap(ipc_mem, sizeof(SharedIPC));
  if (pidfd >= 0) close(pidfd);
  close(epfd);
  write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] Broker (TID: %d) exiting for dead client PID %d", tid, client_pid);
}

/**
 * Parses the physical ELF file to find a name for a relative offset.
 * This sees STATIC labels that dladdr cannot.
 */
static void find_label_in_elf(const char* path, uintptr_t offset, char* out_name, size_t max_len) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) return;

  struct stat st;
  if (fstat(fd, &st) < 0) {
    close(fd);
    return;
  }

  void* map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (map == MAP_FAILED) return;

  ElfHeader* ehdr = (ElfHeader*)map;

  // Verify ELF Magic before parsing
  // If this is an APK (ZIP), it will fail this check and safely return
  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
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

        // Skip empty names, mapping symbols ($x, $d) and symbols that start after our offset.
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
      if (best_diff == 0 && shdr[i].sh_type == SHT_SYMTAB) break;
    }
  }

  if (found_name && strlen(found_name) > 0) {
    strncpy(out_name, found_name, max_len - 1);
  } else {
    strncpy(out_name, "???", max_len);
  }

  munmap(map, st.st_size);
}

static void log_violation(const char* action, const std::string& culprit, uintptr_t pc, uintptr_t offset) {
  write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Action:  %s", action);
  write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Culprit: %s", culprit.c_str());
  write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "PC:      %p", (void*)pc);
  write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Offset:  0x%lx", offset);
  write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "-----------------------");
}

static inline bool is_trusted_library(const std::string& lib_path) {
  return (lib_path.find("/system/") == 0 ||
          lib_path.find("/vendor/") == 0 ||
          lib_path.find("/apex/") == 0 ||
          lib_path.find("/product/") == 0 ||
          lib_path.find("/system_ext/") == 0);
}

static inline bool safe_read(int mem_fd, uintptr_t addr, uintptr_t* out) {
  return pread(mem_fd, out, sizeof(uintptr_t), addr) == sizeof(uintptr_t);
}

static void refresh_maps(pid_t pid, std::vector<MapEntry>& current_maps) {
  // 1. Clear the old state
  current_maps.clear();

  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);

  // 'e' is O_CLOEXEC - essential to prevent FD leakage into child processes
  FILE* f = fopen(path, "re");
  if (!f) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to open %s (errno: %d - %s)", path, errno, strerror(errno));
    return;
  }

  char line[1024];  // Increased buffer to handle exceptionally long paths
  int line_count = 0;

  while (fgets(line, sizeof(line), f)) {
    if (!isxdigit(line[0])) {
      continue;
    }
    line_count++;
    uintptr_t start = 0, end = 0, offset = 0;
    int path_pos = -1;  // Initialize to -1 to detect if %n was actually hit

    // Format: address(start-end) perms offset dev inode pathname
    // Example: 7b1c428000-7b1c517000 r--p 00000000 fd:29 259069 /lib/libiconv.so
    int matches = sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %*s %" SCNxPTR " %*s %*s %n",
                         &start, &end, &offset, &path_pos);

    // Basic structural check
    if (matches < 3) {
      // If we see a non-empty line that doesn't match our regex, it's a parse error
      if (line[0] != '\n' && line[0] != '\0') {
        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Parse failure on line %d: %s", line_count, line);
      }
      continue;
    }

    std::string lib_path;
    if (path_pos != -1 && (size_t)path_pos < strlen(line)) {
      lib_path = &line[path_pos];

      // Remove trailing newline
      if (!lib_path.empty() && lib_path.back() == '\n') {
        lib_path.pop_back();
      }

      // Standardize empty paths
      if (lib_path.empty()) {
        lib_path = "[Anonymous Memory]";
      }
    } else {
      lib_path = "[Anonymous Memory]";
    }

    // Safety: Verify range integrity before adding
    if (start < end) {
      current_maps.push_back({start, end, offset, lib_path});
    } else {
      write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Malformed map range at line %d: %p-%p", line_count, (void*)start, (void*)end);
    }
  }

  if (ferror(f)) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Error while reading %s", path);
  }

  fclose(f);

  if (current_maps.empty()) {
    write_to_logcat_async(ANDROID_LOG_WARN, TAG, "refresh_maps: No maps found for PID %d", pid);
  }
}

static std::string get_culprit_so(pid_t pid, uintptr_t pc, uintptr_t* out_offset, std::vector<MapEntry>& current_maps) {
  for (const auto& m : current_maps) {
    if (pc >= m.start && pc < m.end) {
      if (out_offset) *out_offset = (pc - m.start) + m.offset;
      return m.path;
    }
  }

  // Cache MISS: something was loaded -> refresh maps and try again
  refresh_maps(pid, current_maps);

  for (const auto& m : current_maps) {
    if (pc >= m.start && pc < m.end) {
      if (out_offset) *out_offset = (pc - m.start) + m.offset;
      return m.path;
    }
  }

  if (out_offset) {
    *out_offset = 0;
  }
  return "[Unknown]";
}

static thread_local bool inside_remote_patcher = false;
static inline void patch_instruction_remote(pid_t target_pid, uintptr_t caller_pc, int return_value, std::unordered_set<uintptr_t>& patched_pcs) {
  if (inside_remote_patcher) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Thread reentrancy in remote patcher!");
    return;
  }
  inside_remote_patcher = true;

  // Seccomp traps the instruction *after* the syscall.
  // We subtract 4 to target the actual 'svc #0' instruction.
  uintptr_t target_addr = caller_pc - 4;

  // anti reentrancy if already patched
  if (patched_pcs.count(target_addr)) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Reentrancy in remote patcher: PC already patched!");
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
    patched_pcs.insert(target_addr);  // put in thread local cache (TODO: really?)
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Remote Patch succeeded: PC %p now returns %d.", (void*)target_addr, return_value);
  } else {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Remote Patch failed: pwrite error on PID %d", target_pid);
  }
  inside_remote_patcher = false;
}

static void format_ip_addr(struct sockaddr* addr, char* out_buf, size_t buf_len) {
  if (addr->sa_family == AF_INET) {
    struct sockaddr_in* sin = (struct sockaddr_in*)addr;
    uint32_t ip = ntohl(sin->sin_addr.s_addr);
    snprintf(out_buf, buf_len, "%d.%d.%d.%d:%d",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
             ntohs(sin->sin_port));
  } else if (addr->sa_family == AF_INET6) {
    snprintf(out_buf, buf_len, "[IPv6 Address]");
  } else {
    snprintf(out_buf, buf_len, "non-IP");
  }
}

/**
 * Returns `true` if an IPv4 or IPv6 socket
 * has either port 5353 or 1900
 *
 * TODO: necessary?
 */
static inline bool is_discovery_probe(struct sockaddr* addr) {
  if (!addr) return false;

  // IPv4
  if (addr->sa_family == AF_INET) {
    uint16_t port = ntohs(((struct sockaddr_in*)addr)->sin_port);
    return (port == 5353 || port == 1900);
  }

  // IPv6
  if (addr->sa_family == AF_INET6) {
    uint16_t port = ntohs(((struct sockaddr_in6*)addr)->sin6_port);
    return (port == 5353 || port == 1900);
  }

  return false;
}

std::string get_sockaddr_info(const struct sockaddr* sa) {
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

static void read_argv_from_tracee(pid_t pid, uintptr_t argv_ptr, char* out, size_t out_size) {
  char mem_path[64];
  snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

  int fd = open(mem_path, O_RDONLY);
  if (fd < 0) return;

  // Read the argv pointer array (up to N pointers)
  uintptr_t ptrs[32] = {0};
  pread(fd, ptrs, sizeof(ptrs), (off_t)argv_ptr);

  size_t written = 0;
  for (int i = 0; i < 32 && ptrs[i] != 0 && written < out_size - 1; i++) {
    char arg[256] = {0};
    pread(fd, arg, sizeof(arg) - 1, (off_t)ptrs[i]);
    int n = snprintf(out + written, out_size - written, "[%d]=%s ", i, arg);
    written += (size_t)n;
  }

  close(fd);
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
