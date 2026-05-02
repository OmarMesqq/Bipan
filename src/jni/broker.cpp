#include "broker.hpp"

#include <fcntl.h>
#include <linux/memfd.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <fstream>
#include <string>

#include "blocker.hpp"
#include "logger.hpp"
#include "shared.hpp"
#include "spoofer.hpp"
#include "synchronization.hpp"
#include "utils.hpp"

static void log_violation(const char* action, const std::string& culprit, uintptr_t pc, uintptr_t offset) {
  write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "--- BipanBroker Violation ---");
  write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Action:  %s", action);
  write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Culprit: %s", culprit.c_str());
  write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "PC:      %p", (void*)pc);
  write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Offset:  0x%lx", offset);
  write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "-----------------------");
}

static std::string get_culprit_so(pid_t pid, uintptr_t pc, uintptr_t* out_offset) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);

  std::ifstream maps(path);
  std::string line;

  while (std::getline(maps, line)) {
    uintptr_t start, end;
    size_t offset_in_file;
    // Extract start, end, and the file offset from the maps line
    if (sscanf(line.c_str(), "%lx-%lx %*s %lx", &start, &end, &offset_in_file) >= 2) {
      if (pc >= start && pc < end) {
        if (out_offset) *out_offset = (pc - start) + offset_in_file;
        size_t slash = line.find('/');
        if (slash != std::string::npos) return line.substr(slash);
        return "[Anonymous Memory]";
      }
    }
  }
  if (out_offset) *out_offset = 0;
  return "[Unknown Source]";
}

/**
 * Allowlists everything from:
 * - `/system`
 * - `/vendor`
 * - `/apex`
 *
 * WebView is denied (`/product`)
 */
static bool is_trusted_library(const std::string& lib_path) {
  return (lib_path.find("/system/") == 0 ||
          lib_path.find("/vendor/") == 0 ||
          lib_path.find("/apex/") == 0);
}

void startBroker(int sock, SharedIPC* ipc_mem) {
  prctl(PR_SET_NAME, "K67v3741S1Xm", 0, 0, 0);

  while (true) {
    while (ipc_mem->status != REQUEST_SYSCALL) {
      futex_wait(&ipc_mem->status, ipc_mem->status);
    }
    __sync_synchronize();

    int nr = ipc_mem->nr;
    const char* path_payload = ipc_mem->string_payload;
    struct sockaddr* sock_payload = (struct sockaddr*)ipc_mem->struct_payload;

    uintptr_t offset = 0;
    std::string culprit_lib = get_culprit_so(ipc_mem->target_pid, ipc_mem->caller_pc, &offset);
    bool is_trusted = is_trusted_library(culprit_lib);

    ipc_mem->action = ACTION_EXECUTE_NATIVE;

    // TODO: eventually allow trusted callers
    switch (nr) {
      case __NR_execve:
      case __NR_execveat: {
        if (!is_trusted) {
          log_violation(path_payload, culprit_lib, ipc_mem->caller_pc, offset);
          ipc_mem->ret = -EAGAIN;
          ipc_mem->action = ACTION_USE_RET;
        }
        break;
      }

      case __NR_uname: {
        struct utsname spoofed_buf;
        ipc_mem->ret = uname_spoofer(&spoofed_buf);
        if (ipc_mem->ret == 0) memcpy(ipc_mem->out_buffer, &spoofed_buf, sizeof(struct utsname));
        ipc_mem->action = ACTION_USE_RET;
        break;
      }

      case __NR_openat: {
        if (!is_trusted) {
          if (shouldDenyAccess(path_payload)) {
            log_violation(path_payload, culprit_lib, ipc_mem->caller_pc, offset);
            ipc_mem->ret = -EACCES;
            ipc_mem->action = ACTION_USE_RET;
          } else if (shouldSpoofExistence(path_payload)) {
            log_violation(path_payload, culprit_lib, ipc_mem->caller_pc, offset);
            ipc_mem->ret = -ENOENT;
            ipc_mem->action = ACTION_USE_RET;
          } else if (is_maps(path_payload) || is_smaps(path_payload) || is_mounts(path_payload) || shouldFakeFile(path_payload)) {
            log_violation(path_payload, culprit_lib, ipc_mem->caller_pc, offset);

            // Broker generates the fake file locally
            int fake_fd = -1;
            if (is_maps(path_payload))
              fake_fd = clean_proc_maps(ipc_mem->arg0, path_payload, ipc_mem->arg2, ipc_mem->arg3);
            else if (is_smaps(path_payload))
              fake_fd = clean_proc_smaps(ipc_mem->arg0, path_payload, ipc_mem->arg2, ipc_mem->arg3);
            else if (is_mounts(path_payload))
              fake_fd = clean_proc_mounts(ipc_mem->arg0, path_payload, ipc_mem->arg2, ipc_mem->arg3);
            else
              fake_fd = create_spoofed_file(shouldFakeFile(path_payload));

            if (fake_fd >= 0) {
              // GHOST FILL: Root opens the Target's pre_fd and fills it!
              int target_fd = ipc_mem->arg5;
              char proc_path[64];
              snprintf(proc_path, sizeof(proc_path), "/proc/%d/fd/%d", ipc_mem->target_pid, target_fd);

              int root_fd = open(proc_path, O_WRONLY);
              if (root_fd >= 0) {
                char buf[4096];
                ssize_t n;
                lseek(fake_fd, 0, SEEK_SET);
                while ((n = read(fake_fd, buf, sizeof(buf))) > 0) write(root_fd, buf, n);
                close(root_fd);
              }
              close(fake_fd);  // Cleanup daemon's copy

              ipc_mem->ret = target_fd;  // Tell Target to use the FD it already has!
            } else {
              ipc_mem->ret = -EACCES;
            }
            ipc_mem->action = ACTION_USE_RET;
          }
        }
        break;
      }

      case __NR_faccessat:
      case __NR_newfstatat: {
        if (!is_trusted) {
          if (shouldDenyAccess(path_payload)) {
            log_violation(path_payload, culprit_lib, ipc_mem->caller_pc, offset);
            ipc_mem->ret = -EACCES;
            ipc_mem->action = ACTION_USE_RET;
          } else if (shouldSpoofExistence(path_payload)) {
            log_violation(path_payload, culprit_lib, ipc_mem->caller_pc, offset);
            ipc_mem->ret = -ENOENT;
            ipc_mem->action = ACTION_USE_RET;
          } else if (is_maps(path_payload) || is_smaps(path_payload) || is_mounts(path_payload) || shouldFakeFile(path_payload)) {
            log_violation(path_payload, culprit_lib, ipc_mem->caller_pc, offset);
            ipc_mem->ret = 0;
            ipc_mem->action = ACTION_USE_RET;
          }
        }
        break;
      }

      case __NR_rt_sigaction: {
        if (ipc_mem->arg0 == SIGSYS) {
          log_violation("SIGSYS hijacking", culprit_lib, ipc_mem->caller_pc, offset);
          ipc_mem->ret = 0;
          ipc_mem->action = ACTION_USE_RET;
        }
        break;
      }

      case __NR_bind: {
        if (sock_payload && is_lan_address(sock_payload)) {
          log_violation("(bind)", culprit_lib, ipc_mem->caller_pc, offset);
          ipc_mem->ret = -EADDRNOTAVAIL;
          ipc_mem->action = ACTION_USE_RET;
        }
        break;
      }

      case __NR_listen: {
        ipc_mem->action = ACTION_EXECUTE_NATIVE;
        log_violation("(listen)", culprit_lib, ipc_mem->caller_pc, offset);
        break;
      }

      case __NR_sendto:
      case __NR_sendmsg: {
        if (sock_payload && is_lan_address(sock_payload)) {
          log_violation("(sendto/sendmsg)", culprit_lib, ipc_mem->caller_pc, offset);
          ipc_mem->ret = (nr == __NR_sendto) ? ipc_mem->arg2 : get_msghdr_len((struct msghdr*)ipc_mem->arg1);
          ipc_mem->action = ACTION_USE_RET;
        }
        break;
      }

      case __NR_getsockname: {
        ipc_mem->action = ACTION_EXECUTE_AND_SCRUB_SOCK;
        log_violation("(getsockname)", culprit_lib, ipc_mem->caller_pc, offset);
        break;
      }

      case __NR_socket: {
        if (ipc_mem->arg0 == AF_NETLINK) {
          log_violation("(socket) AF_NETLINK", culprit_lib, ipc_mem->caller_pc, offset);
          ipc_mem->ret = -EACCES;
          ipc_mem->action = ACTION_USE_RET;
        }
        break;
      }
    }

    __sync_synchronize();
    ipc_mem->status = BROKER_ANSWERED;
    futex_wake(&ipc_mem->status);
  }
}
