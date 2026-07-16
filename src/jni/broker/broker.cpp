#include "broker.hpp"

#include <arpa/inet.h>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
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
#include <stdio.h>
#include <stdlib.h>
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
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "logger/logger.hpp"
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

struct linux_dirent64 {
  ino64_t d_ino;           /* 64-bit inode number */
  off64_t d_off;           /* Not an offset; see getdents() */
  unsigned short d_reclen; /* Size of this dirent */
  unsigned char d_type;    /* File type */
  char d_name[];           /* Filename (null-terminated) */
};

#define SPOOFED_WD 224

static void refresh_maps(pid_t pid, std::vector<MapEntry>& current_maps);
static std::string get_culprit_so(pid_t pid, uintptr_t pc, uintptr_t* out_offset, std::vector<MapEntry>& current_maps);
static void find_label_in_elf(const char* path, uintptr_t offset, char* out_name, size_t max_len);
static void log_violation(const char* action, const std::string& culprit, uintptr_t pc, uintptr_t offset);
static inline bool is_trusted_library(const std::string& lib_path);
static inline bool safe_read(int mem_fd, uintptr_t addr, uintptr_t* out);
static inline void patch_instruction_remote(pid_t target_pid, uintptr_t caller_pc, int return_value, std::unordered_set<uintptr_t>& patched_pcs);
std::string get_sockaddr_info(const struct sockaddr* sa);
static inline bool client_is_dead(int epfd, int pidfd);
static inline int bipan_pidfd_open(pid_t pid, unsigned int flags);
static char* get_thread_name(pid_t parentPid, __aligned_u64 tid);
static char* get_ptrace_op_name(int op);

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

  char threadName[16];
  snprintf(threadName, sizeof(threadName), "bb-%s", ipc_mem->package_name);
  prctl(PR_SET_NAME, threadName, 0, 0, 0);

  std::vector<MapEntry> current_maps;
  std::unordered_set<uintptr_t> patched_pcs;

  pid_t pid = (pid_t)arm64_raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
  pid_t tid = (pid_t)arm64_raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
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

  /**
   * TODO:
   * Does this create something in /proc/<PID>/fd(info)?
   * 'anon_inode:[eventfd]'
   * 'anon_inode:[eventpoll]'
   */
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
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[%s(%s) spoofed to success]", action_name, path_payload);
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
          if (shouldDenyAccess(path_payload)) {
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[openat(%s)] denied", path_payload);
            ipc_mem->ret = -EACCES;
            ipc_mem->action = ACTION_USE_RET;
          } else if (shouldSpoofExistence(path_payload)) {
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[openat(%s)] spoofed", path_payload);
            ipc_mem->ret = -ENOENT;
            ipc_mem->action = ACTION_USE_RET;
          } else if (is_mounts(path_payload) || shouldFakeFile(path_payload)) {
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

            // Tell target to use the fd it already has
            ipc_mem->ret = target_fd;
            ipc_mem->action = ACTION_USE_RET;
          }
#ifdef BROKER_EXTENDED_LOGGING
          else {
            if (shouldLog(path_payload)) {
              write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] Allowing untrusted openat(%s)", path_payload);
            }
          }
#endif
        }
        break;
      }
      case __NR_faccessat:
      case __NR_newfstatat:
      case __NR_faccessat2: {
        const char* action_name;
        if (nr == __NR_faccessat) {
          action_name = "faccessat";
        } else if (nr == __NR_newfstatat) {
          action_name = "newfstatat";
        } else if (nr == __NR_faccessat2) {
          action_name = "faccessat2";
        }

        if (shouldSpoofExistence(path_payload)) {
          write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[%s(%s)] spoofed", action_name, path_payload);
          ipc_mem->ret = -ENOENT;
          ipc_mem->action = ACTION_USE_RET;
          break;
        }
        if (!is_trusted) {
          if (shouldDenyAccess(path_payload)) {
            ipc_mem->ret = -EACCES;
            ipc_mem->action = ACTION_USE_RET;
          } else if (is_mounts(path_payload) || shouldFakeFile(path_payload)) {
            write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[%s(%s)] executing natively...", action_name, path_payload);
            ipc_mem->ret = 0;
            ipc_mem->action = ACTION_USE_RET;
          }
#ifdef BROKER_EXTENDED_LOGGING
          else {
            if (shouldLog(path_payload)) {
              write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] Allowing untrusted %s(%s)", action_name, path_payload);
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

          // Allow 0.0.0.0 and loopback (127.0.0.0/8)
          if (ip4 != 0x00000000 || ((ip4 & 0xFF000000) != 0x7F000000)) {
            if (is_lan_address(sock_payload) || port == 5353 || port == 1900) {
              should_block = true;
            }
          }
        } else if (sock_payload->sa_family == AF_INET6) {
          struct sockaddr_in6* sin6 = (struct sockaddr_in6*)sock_payload;
          uint16_t port = ntohs(sin6->sin6_port);
          uint8_t* ip6 = sin6->sin6_addr.s6_addr;

          if (is_lan_address(sock_payload) || port == 5353 || port == 1900) {
            should_block = true;
          }
        }

        if (should_block) {
          ipc_mem->ret = 0;
          ipc_mem->action = ACTION_USE_RET;

          if (!is_trusted) {
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "App-originated (bind) to LAN blocked");
            patch_instruction_remote(ipc_mem->target_pid, malicious_pc, 0, patched_pcs);
          } else {
            write_to_logcat_async(ANDROID_LOG_INFO, TAG, "System (bind) to LAN blocked");
          }
        }
        break;
      }
      case __NR_connect: {
        if (is_lan_address(sock_payload)) {
          ipc_mem->ret = -ECONNREFUSED;
          ipc_mem->action = ACTION_USE_RET;
        }
        break;
      }
      case __NR_sendto: {
        if (is_lan_address(sock_payload)) {
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
        if (is_lan_address(sock_payload)) {
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
        if (is_trusted) break;
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] executable (mmap)!");
        break;
      }
      case __NR_mprotect: {
        if (is_trusted) break;
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] (mprotect)!");
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
      case __NR_mq_notify: {
        write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] (mq_notify)!");
        break;
      }
      case __NR_getdents64: {
        if (is_trusted) break;
        int fd = (int)ipc_mem->arg0;
        struct linux_dirent64* dirp = (struct linux_dirent64*)ipc_mem->arg1;
        size_t count = (size_t)ipc_mem->arg2;

        char proc_self_fd_path[512];
        snprintf(proc_self_fd_path, sizeof(proc_self_fd_path), "/proc/%d/fd/%d", ipc_mem->target_pid, fd);
        char filename[512];
        if (readlinkat(0, proc_self_fd_path, filename, sizeof(filename)) == -1) {
          write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Failed to get filename of in getdents64. errno: %s", strerror(errno));
          break;
        }
        if (
            !starts_with(filename, "/data/data") &&
            !starts_with(filename, "/data/app") &&
            !starts_with(filename, "/storage/emulated/0/Android")) {
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] getdents64(%s)", filename);
        }
        break;
      }
      case __NR_readlinkat: {
        if (is_trusted) break;
        int dirfd = (int)ipc_mem->arg0;
        const char* path = ipc_mem->string_payload;

        if (dirfd > 0) {
          char proc_dirfd_path[512] = {0};
          snprintf(proc_dirfd_path, sizeof(proc_dirfd_path), "/proc/%d/fd/%d", ipc_mem->target_pid, dirfd);

          char resolved_link_path[512] = {0};
          ssize_t len = readlink(proc_dirfd_path, resolved_link_path, sizeof(resolved_link_path) - 1);
          if (len == -1) {
            write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Failed to resolve path in readlinkat. errno: %s", strerror(errno));
            break;
          }
          resolved_link_path[len] = '\0';
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(readlinkat with dirfd): %s -> %s", proc_dirfd_path, resolved_link_path);
        } else if (dirfd == AT_FDCWD) {
          char resolved_link_path[512] = {0};
          ssize_t len = readlinkat(dirfd, path, resolved_link_path, sizeof(resolved_link_path));
          if (len == -1) {
            write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Failed to resolve path in readlinkat. errno: %s", strerror(errno));
            break;
          }
          resolved_link_path[len] = '\0';
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(readlinkat AT_FDCWD): %s -> %s", path, resolved_link_path);
        } else {
          char resolved_link_path[512] = {0};
          ssize_t len = readlinkat(0, path, resolved_link_path, sizeof(resolved_link_path));
          if (len == -1) {
            write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Failed to resolve path in readlinkat. errno: %s", strerror(errno));
            break;
          }
          resolved_link_path[len] = '\0';
          write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(readlinkat with abs path): %s -> %s", path, resolved_link_path);
        }
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
        // TODO: logic for our FD
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
      case __NR_syslog: {
        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "[*] (syslog)!");
        break;
      }
      case __NR_pipe2: {
        int* pipefd = (int*)ipc_mem->pipefd_payload;
        int flags = ipc_mem->arg1;

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
        size_t size = ipc_mem->arg1;

        char* childThName = get_thread_name(ipc_mem->target_pid, cl_args->child_tid);
        if (!childThName) {
          break;
        }

        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "(clone3): Child TID: %llu | Thread name: %s | Exit signal: %llu", cl_args->child_tid, childThName, cl_args->exit_signal);
        free(childThName);
        break;
      }
      case __NR_mremap: {
        if (is_trusted) break;
        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "[*] (mremap)!");
        break;
      }
      case __NR_mincore: {
        if (is_trusted) break;
        void* addr = (void*)ipc_mem->arg0;
        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "(mincore) addr: %p!", addr);
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
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to open %s (errno: %s)", path, strerror(errno));
    return;
  }

  char line[2048];
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
    int matches = sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %*s %" SCNxPTR " %*s %*s %n", &start, &end, &offset, &path_pos);

    // Basic structural check
    if (matches < 3) {
      // If we see a non-empty line that doesn't match our regex, it's a parse error
      if (line[0] != '\n' && line[0] != '\0') {
        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Parse failure on line[%d] = %s", line_count, line);
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
    patched_pcs.insert(target_addr);  // TODO: patched_pcs should be thread_local
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Remote Patch succeeded: PC %p now returns %d.", (void*)target_addr, return_value);
  } else {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Remote patch (pwrite) failed for PID %d (errno: %s)", target_pid, strerror(errno));
  }
  inside_remote_patcher = false;
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

static char* get_thread_name(pid_t parentPid, __aligned_u64 tid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/task/%llu/comm", parentPid, tid);

  FILE* f = fopen(path, "r");
  if (!f) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "get_thread_name: Failed to open /proc/parentPid/task/TID/comm");
    return nullptr;
  }

  char* name = (char*)calloc(16, sizeof(char));
  if (!name) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "get_thread_name: Failed to calloc!");
    return nullptr;
  }

  fgets(name, sizeof(name), f);
  fclose(f);
  return name;
}

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
      name = "Unknown...";
      break;
  }

  size_t len = strlen(name) + 1;
  char* result = (char*)calloc(len, sizeof(char));
  if (result == NULL) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "get_ptrace_op_name: Failed to calloc!");
    return NULL;
  }
  memcpy(result, name, len);
  return result;
}
