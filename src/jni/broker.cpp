#include "broker.hpp"

#include <elf.h>
#include <linux/filter.h>
#include <linux/memfd.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <syscall.h>
#include <unistd.h>

#include <fstream>
#include <string>
#include <vector>

#include "blocker.hpp"
#include "logger.hpp"
#include "shared.hpp"
#include "spoofer.hpp"
#include "synchronization.hpp"
#include "utils.hpp"

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
static std::vector<MapEntry> current_maps;

static void refresh_maps(pid_t pid);
static void find_label_in_elf(const char* path, uintptr_t offset, char* out_name, size_t max_len);
static void log_violation(const char* action, const std::string& culprit, uintptr_t pc, uintptr_t offset);
static std::string get_culprit_so(pid_t pid, uintptr_t pc, uintptr_t* out_offset);
static inline bool is_trusted_library(const std::string& lib_path);
static inline bool safe_read(int mem_fd, uintptr_t addr, uintptr_t* out);

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

    // IF PC is trusted, we must verify the ancestors remotely
    if (is_trusted) {
      char mem_path[64];
      snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", ipc_mem->target_pid);
      int mem_fd = open(mem_path, O_RDONLY);

      if (mem_fd >= 0) {
        uintptr_t current_pc = ipc_mem->stack_trace[0];  // Start with LR
        uintptr_t current_fp = ipc_mem->caller_fp;

        for (int i = 0; i < MAX_STACK_TRACE; i++) {
          if (current_pc == 0) break;

          // STRIP PAC BITS
          current_pc &= 0x0000FFFFFFFFFFFFULL;

          uintptr_t frame_offset = 0;
          std::string frame_lib = get_culprit_so(ipc_mem->target_pid, current_pc, &frame_offset);

          if (!is_trusted_library(frame_lib)) {
            culprit_lib = frame_lib;
            offset = frame_offset;
            is_trusted = false;
            break;
          }

          // Walk to the next frame in the target process
          uintptr_t next_fp, next_lr;
          if (!safe_read(mem_fd, current_fp, &next_fp) ||
              !safe_read(mem_fd, current_fp + 8, &next_lr)) break;

          current_fp = next_fp;
          current_pc = next_lr;
          if (!current_fp || (current_fp & 0x7)) break;
        }
        close(mem_fd);
      }
    }
    ipc_mem->action = ACTION_EXECUTE_NATIVE;

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
        if (!is_trusted) {
          struct utsname spoofed_buf;
          ipc_mem->ret = uname_spoofer(&spoofed_buf);
          if (ipc_mem->ret == 0) memcpy(ipc_mem->out_buffer, &spoofed_buf, sizeof(struct utsname));
          ipc_mem->action = ACTION_USE_RET;
        }

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
            // --- THE FIX: The Perspective Shift ---
            // Translate /proc/self/ to /proc/[target_pid]/ so the Broker reads the App's maps!
            char real_path[256];
            if (strncmp(path_payload, "/proc/self/", 11) == 0) {
              snprintf(real_path, sizeof(real_path), "/proc/%d/%s", ipc_mem->target_pid, path_payload + 11);
            } else {
              strncpy(real_path, path_payload, sizeof(real_path));
            }

            // Broker generates the fake file locally
            int fake_fd = -1;
            if (is_maps(path_payload))
              fake_fd = clean_proc_maps(ipc_mem->arg0, real_path, ipc_mem->arg2, ipc_mem->arg3);
            else if (is_smaps(path_payload))
              fake_fd = clean_proc_smaps(ipc_mem->arg0, real_path, ipc_mem->arg2, ipc_mem->arg3);
            else if (is_mounts(path_payload))
              fake_fd = clean_proc_mounts(ipc_mem->arg0, real_path, ipc_mem->arg2, ipc_mem->arg3);
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
                lseek(root_fd, 0, SEEK_SET);
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
        if (sock_payload && is_lan_address(sock_payload) && !is_trusted) {
          log_violation("(bind)", culprit_lib, ipc_mem->caller_pc, offset);
          ipc_mem->ret = -EADDRNOTAVAIL;
          ipc_mem->action = ACTION_USE_RET;
        }
        break;
      }

      case __NR_listen: {
        if (!is_trusted) {
          ipc_mem->action = ACTION_EXECUTE_NATIVE;
          log_violation("(listen)", culprit_lib, ipc_mem->caller_pc, offset);
        }
        break;
      }

      case __NR_sendto:
      case __NR_sendmsg: {
        if (sock_payload && is_lan_address(sock_payload) && !is_trusted) {
          log_violation("(sendto/sendmsg)", culprit_lib, ipc_mem->caller_pc, offset);
          ipc_mem->ret = (nr == __NR_sendto) ? ipc_mem->arg2 : get_msghdr_len((struct msghdr*)ipc_mem->arg1);
          ipc_mem->action = ACTION_USE_RET;
        }
        break;
      }

      case __NR_getsockname: {
        if (!is_trusted) {
          ipc_mem->action = ACTION_EXECUTE_AND_SCRUB_SOCK;
          log_violation("(getsockname)", culprit_lib, ipc_mem->caller_pc, offset);
        }

        break;
      }

      case __NR_socket: {
        if (ipc_mem->arg0 == AF_NETLINK && !is_trusted) {
          // Resolve label for the log
          char sym_name[256] = "???";
          find_label_in_elf(culprit_lib.c_str(), offset, sym_name, sizeof(sym_name));

          write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Blocked AF_NETLINK socket from %s (%s)",
                                culprit_lib.c_str(), sym_name);

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
  write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "--- BipanBroker Violation ---");
  write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Action:  %s", action);
  write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Culprit: %s", culprit.c_str());
  write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "PC:      %p", (void*)pc);
  write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Offset:  0x%lx", offset);
  write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "-----------------------");
}

static inline bool is_trusted_library(const std::string& lib_path) {
  return (lib_path.find("/system/") == 0 ||
          lib_path.find("/vendor/") == 0 ||
          lib_path.find("/apex/") == 0);
}

static inline bool safe_read(int mem_fd, uintptr_t addr, uintptr_t* out) {
  return pread(mem_fd, out, sizeof(uintptr_t), addr) == sizeof(uintptr_t);
}

static void refresh_maps(pid_t pid) {
  current_maps.clear();
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);

  FILE* f = fopen(path, "re");
  if (!f) return;

  char line[512];
  while (fgets(line, sizeof(line), f)) {
    uintptr_t start, end, offset;
    if (sscanf(line, "%lx-%lx %*s %lx", &start, &end, &offset) >= 2) {
      char* slash = strchr(line, '/');
      if (!slash) slash = strchr(line, '[');  // Catch [stack], [vdso], etc.

      std::string lib = slash ? slash : "[Anonymous Memory]";
      if (!lib.empty() && lib.back() == '\n') lib.pop_back();

      current_maps.push_back({start, end, offset, lib});
    }
  }
  fclose(f);
}

// --- THE FIX: Smart Cache Lookup ---
static std::string get_culprit_so(pid_t pid, uintptr_t pc, uintptr_t* out_offset) {
  for (const auto& m : current_maps) {
    if (pc >= m.start && pc < m.end) {
      if (out_offset) *out_offset = (pc - m.start) + m.offset;
      return m.path;
    }
  }

  // CACHE MISS: A new library was loaded! Refresh maps and try exactly once more.
  refresh_maps(pid);

  for (const auto& m : current_maps) {
    if (pc >= m.start && pc < m.end) {
      if (out_offset) *out_offset = (pc - m.start) + m.offset;
      return m.path;
    }
  }

  if (out_offset) *out_offset = 0;
  return "[Unknown Source]";
}
