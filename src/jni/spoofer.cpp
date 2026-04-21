#include "spoofer.hpp"

#include <linux/memfd.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <syscall.h>
#include <unistd.h>

#include <string>

#include "assembly.hpp"
#include "shared.hpp"

int uname_spoofer(struct utsname* buf) {
  if (!buf) return -1;

  memset(buf, 0, sizeof(struct utsname));
  strncpy(buf->sysname, "Linux", 64);
  strncpy(buf->nodename, "localhost", 64);
  strncpy(buf->release, "6.6.56-android16-11-g8a3e2b1c4d5f", 64);
  strncpy(buf->version, "#1 SMP PREEMPT Fri Dec 05 12:00:00 UTC 2025", 64);
  strncpy(buf->machine, "aarch64", 64);
  strncpy(buf->domainname, "(none)", 64);

  return 0;
}

/**
 * Uses `memfd` to create an anonymous in-memory file so Bipan can fill
 * it with fake data.
 *
 * @returns file descriptor on success, -1 on failure
 * 
 * TODO: find a way of handling lifetime of this FD or
 * we get too many file descriptors open
 */
int create_spoofed_file(const char* fake_content) {
  // memfd_create requires a name, but it hopefully doesn't appear in the filesystem
  int fd = (int) syscall(__NR_memfd_create, "Q4Blp8TKdag5", MFD_CLOEXEC);

  if (fd >= 0) {
    write(fd, fake_content, strlen(fake_content));
    lseek(fd, 0, SEEK_SET);  // Rewind it so the app can read it
  } else {
    LOGE("memfd_create failed!");
  }
  return fd;
}

/**
 * Scrubs mappings that could reveal Zygisk and/or Bipan
 * from `/proc/self/maps` and `/proc/<PID>/maps`
 */
long clean_proc_maps(int dirfd, const char* pathname, int flags, mode_t mode) {
  // Open the real file
  long real_fd = arm64_bypassed_syscall(__NR_openat, dirfd, (long)pathname, flags, mode, 0);
  if (real_fd < 0) {
    LOGE("openat memory maps failed!");
    return -1;
  }

  // Create a fake in-memory file
  long fake_fd = arm64_bypassed_syscall(__NR_memfd_create, (long)"F4ON5SYGiut0", MFD_CLOEXEC, 0, 0, 0);
  if (fake_fd < 0) {
    LOGE("memfd failed!");
    arm64_bypassed_syscall(__NR_close, real_fd, 0, 0, 0, 0);
    return -1;
  }

  // Read the real file line-by-line
  char buf[4096];
  long bytes_read;
  char line[4096];
  unsigned long line_pos = 0;

  while ((bytes_read = arm64_bypassed_syscall(__NR_read, real_fd, (long)buf, sizeof(buf), 0, 0)) > 0) {
    for (int i = 0; i < bytes_read; i++) {
      if (line_pos < sizeof(line) - 1) {
        line[line_pos++] = buf[i];
      }

      if (buf[i] == '\n') {
        line[line_pos] = '\0';  // Null-terminate the line

        // 1. Check for forbidden keywords
        bool has_magisk = strstr(line, "magisk") != nullptr;
        bool has_zygisk = strstr(line, "zygisk") != nullptr;
        bool has_bipan = strstr(line, "bipan") != nullptr;

        // 2. Check for Zygisk's disguised ELF payload
        // We match ANY private mapping (-p) of memfd:jit to catch r-xp, r--p, and rw-p
        bool is_fake_jit = (strstr(line, "/memfd:jit") != nullptr) && 
                           (strstr(line, "r-xp") != nullptr || 
                            strstr(line, "r--p") != nullptr || 
                            strstr(line, "rw-p") != nullptr);

        // 3. Check for specific anomalous memory flags
        bool is_deleted_zero = (strstr(line, "rw-s") != nullptr) && (strstr(line, "/dev/zero (deleted)") != nullptr);

        // Anti-tamper/Zygisk trampolines (executable anon memory)
        bool is_anon_exec = (strstr(line, "r-xp") != nullptr) && (strstr(line, "[anon:") != nullptr || strchr(line, '/') == nullptr);

        if (!has_magisk && !has_zygisk && !has_bipan && !is_fake_jit && !is_deleted_zero && !is_anon_exec) {
          // Line is clean: write it to the fake file
          arm64_bypassed_syscall(__NR_write, fake_fd, (long)line, (long) line_pos, 0, 0);
        }

        line_pos = 0;  // Reset for next line
      }
    }
  }

  // Cleanup
  arm64_bypassed_syscall(__NR_close, real_fd, 0, 0, 0, 0);
  arm64_bypassed_syscall(__NR_lseek, fake_fd, 0, SEEK_SET, 0, 0);  // Rewind

  LOGW("Spoofed memory maps");
  return fake_fd;
}

/**
 * Scrubs mappings that could reveal Zygisk and/or Bipan
 * from `/proc/self/smaps` and `/proc/<PID>/smaps`
 */
long clean_proc_smaps(int dirfd, const char* pathname, int flags, mode_t mode) {
  // Open the real file
  long real_fd = arm64_bypassed_syscall(__NR_openat, dirfd, (long)pathname, flags, mode, 0);
  if (real_fd < 0) {
    LOGE("openat memory smaps failed!");
    return -1;
  }

  // Create a fake in-memory file
  long fake_fd = arm64_bypassed_syscall(__NR_memfd_create, (long)"F4ON5SYGiut0", MFD_CLOEXEC, 0, 0, 0);
  if (fake_fd < 0) {
    LOGE("memfd failed!");
    arm64_bypassed_syscall(__NR_close, real_fd, 0, 0, 0, 0);
    return -1;
  }

  char buf[4096];
  long bytes_read;
  char line[4096];
  unsigned long line_pos = 0;

  // FSM flag: tracks whether we are currently inside a "dirty" memory region
  bool skip_current_region = false;

  while ((bytes_read = arm64_bypassed_syscall(__NR_read, real_fd, (long)buf, sizeof(buf), 0, 0)) > 0) {
    for (int i = 0; i < bytes_read; i++) {
      if (line_pos < sizeof(line) - 1) {
        line[line_pos++] = buf[i];
      }

      if (buf[i] == '\n') {
        line[line_pos] = '\0';  // Null-terminate the line for strstr

        // Heuristic: Header lines start with a hex address (0-9, a-f) AND contain a hyphen.
        bool is_header = ((line[0] >= '0' && line[0] <= '9') ||
                          (line[0] >= 'a' && line[0] <= 'f')) &&
                         strstr(line, "-") != nullptr;

        if (is_header) {
          // 1. Check for forbidden keywords
          bool has_magisk = strstr(line, "magisk") != nullptr;
          bool has_zygisk = strstr(line, "zygisk") != nullptr;
          bool has_bipan = strstr(line, "bipan") != nullptr;

          // 2. Check for Zygisk's disguised ELF payload (-p catches r-xp, r--p, and rw-p)
          bool is_fake_jit = (strstr(line, "/memfd:jit") != nullptr) && 
                           (strstr(line, "r-xp") != nullptr || 
                            strstr(line, "r--p") != nullptr || 
                            strstr(line, "rw-p") != nullptr);

          // 3. Check for specific anomalous memory flags
          bool is_deleted_zero = (strstr(line, "rw-s") != nullptr) && (strstr(line, "/dev/zero (deleted)") != nullptr);

          // Anti-tamper/Zygisk trampolines (executable anonymous memory)
          bool is_anon_exec = (strstr(line, "r-xp") != nullptr) && (strstr(line, "[anon:") != nullptr || strchr(line, '/') == nullptr);

          // State Machine: Turn the 'skip' flag on or off based on the header
          if (has_magisk || has_zygisk || has_bipan || is_fake_jit || is_deleted_zero || is_anon_exec) {
            skip_current_region = true;
          } else {
            skip_current_region = false;
          }
        }

        // If we are NOT in a bad region, write the line (whether it's a header or a metric)
        if (!skip_current_region) {
          arm64_bypassed_syscall(__NR_write, fake_fd, (long)line, (long) line_pos, 0, 0);
        }

        line_pos = 0;  // Reset for next line
      }
    }
  }

  // Cleanup
  arm64_bypassed_syscall(__NR_close, real_fd, 0, 0, 0, 0);
  arm64_bypassed_syscall(__NR_lseek, fake_fd, 0, SEEK_SET, 0, 0);  // Rewind

  LOGW("Spoofed memory smaps");
  return fake_fd;
}

/**
 * Scrubs mount points that could reveal Magisk's OverlayFS,
 * custom CAs at system trust store and whatnot
 * from `/proc/self/mounts`, `/proc/<PID>/mounts`, and `/proc/mounts`
 */
long clean_proc_mounts(int dirfd, const char* pathname, int flags, mode_t mode) {
  // Open the real file
  long real_fd = arm64_bypassed_syscall(__NR_openat, dirfd, (long)pathname, flags, mode, 0);
  if (real_fd < 0) {
    LOGE("openat memory mounts failed!");
    return -1;
  }

  // Create a fake in-memory file
  long fake_fd = arm64_bypassed_syscall(__NR_memfd_create, (long)"X7bA1Zkq9R", MFD_CLOEXEC, 0, 0, 0);
  if (fake_fd < 0) {
    LOGE("memfd failed!");
    arm64_bypassed_syscall(__NR_close, real_fd, 0, 0, 0, 0);
    return -1;
  }

  char buf[4096];
  long bytes_read;
  char line[4096];
  unsigned long line_pos = 0;

  while ((bytes_read = arm64_bypassed_syscall(__NR_read, real_fd, (long)buf, sizeof(buf), 0, 0)) > 0) {
    for (int i = 0; i < bytes_read; i++) {
      if (line_pos < sizeof(line) - 1) {
        line[line_pos++] = buf[i];
      }

      if (buf[i] == '\n') {
        line[line_pos] = '\0';  // Null-terminate the line

        // 1. Check for standard Root/Injection keywords
        bool has_magisk = strstr(line, "magisk") != nullptr;
        bool has_zygisk = strstr(line, "zygisk") != nullptr;
        bool has_bipan = strstr(line, "bipan") != nullptr;
        bool has_ksu = strstr(line, "KSU") != nullptr || strstr(line, "KernelSU") != nullptr;
        bool has_apatch = strstr(line, "APatch") != nullptr;

        // 2. Check for Magisk internal paths
        bool has_core_mirror = strstr(line, "core/mirror") != nullptr;

        // 3. Catch custom CA certificate overlays
        bool is_cert_overlay = (strstr(line, "/system/etc/security/cacerts") != nullptr) && 
                               (strstr(line, "tmpfs") != nullptr);

        if (!has_magisk && !has_zygisk && !has_bipan && !has_ksu && !has_apatch && !has_core_mirror && !is_cert_overlay) {
          // Line is clean: write it to the fake file
          arm64_bypassed_syscall(__NR_write, fake_fd, (long)line, (long) line_pos, 0, 0);
        }

        line_pos = 0;  // Reset for next line
      }
    }
  }

  // Cleanup
  arm64_bypassed_syscall(__NR_close, real_fd, 0, 0, 0, 0);
  arm64_bypassed_syscall(__NR_lseek, fake_fd, 0, SEEK_SET, 0, 0);  // Rewind

  LOGW("Spoofed memory mounts");
  return fake_fd;
}
