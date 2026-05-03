#include "spoofer.hpp"

#include <linux/memfd.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <syscall.h>
#include <unistd.h>

#include <string>

#include "logger.hpp"
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

int create_spoofed_file(const char* fake_content) {
  int fd = (int)arm64_raw_syscall(__NR_memfd_create, (long)"BipanAnon", MFD_CLOEXEC, 0, 0, 0, 0);
  if (fd >= 0) {
    size_t len = local_strlen(fake_content);
    arm64_raw_syscall(__NR_write, fd, (long)fake_content, (long)len, 0, 0, 0);
    arm64_raw_syscall(__NR_lseek, fd, 0, SEEK_SET, 0, 0, 0);
  } else {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "memfd_create failed");
  }
  return fd;
}

long clean_proc_maps(int dirfd, const char* pathname, int flags, mode_t mode) {
  long real_fd = arm64_raw_syscall(__NR_openat, dirfd, (long)pathname, flags, mode, 0, 0);
  if (real_fd < 0) return -1;

  long fake_fd = arm64_raw_syscall(__NR_memfd_create, (long)"JpWOjmVl33X2", MFD_CLOEXEC, 0, 0, 0, 0);
  if (fake_fd < 0) {
    arm64_raw_syscall(__NR_close, real_fd, 0, 0, 0, 0, 0);
    return -1;
  }

  char buf[1024];
  char line[1024];
  long bytes_read;
  unsigned long line_pos = 0;

  auto process_and_write_line = [&](char* l, unsigned long len) {
    l[len] = '\0';

    // CRITICAL: Always allow these or the app will crash
    bool is_vital = local_strstr(l, "[stack]") ||
                    local_strstr(l, "[vdso]") ||
                    local_strstr(l, "[vvar]") ||
                    local_strstr(l, "[vectors]") ||
                    local_strstr(l, "/system/bin/linker");

    if (is_vital) {
      arm64_raw_syscall(__NR_write, fake_fd, (long)l, (long)len, 0, 0, 0);
      return;
    }

    bool is_dirty = local_strstr(l, "magisk") || local_strstr(l, "zygisk") ||
                    local_strstr(l, "bipan") ||
                    (local_strstr(l, "/memfd:jit") && (local_strstr(l, "r-xp") || local_strstr(l, "r--p"))) ||
                    (local_strstr(l, "rw-s") && local_strstr(l, "/dev/zero (deleted)")) ||
                    ((local_strstr(l, "r-xp") && (local_strstr(l, "[anon:") || !local_strchr(l, '/'))));

    if (!is_dirty) {
      arm64_raw_syscall(__NR_write, fake_fd, (long)l, (long)len, 0, 0, 0);
    }
  };

  while ((bytes_read = arm64_raw_syscall(__NR_read, real_fd, (long)buf, sizeof(buf), 0, 0, 0)) > 0) {
    for (int i = 0; i < bytes_read; i++) {
      if (line_pos < sizeof(line) - 1) line[line_pos++] = buf[i];
      if (buf[i] == '\n') {
        process_and_write_line(line, line_pos);
        line_pos = 0;
      }
    }
  }

  // THE FIX: Flush the last line if it didn't end in \n
  if (line_pos > 0) {
    process_and_write_line(line, line_pos);
  }

  arm64_raw_syscall(__NR_close, real_fd, 0, 0, 0, 0, 0);
  arm64_raw_syscall(__NR_lseek, fake_fd, 0, SEEK_SET, 0, 0, 0);
  return fake_fd;
}

long clean_proc_smaps(int dirfd, const char* pathname, int flags, mode_t mode) {
  long real_fd = arm64_raw_syscall(__NR_openat, dirfd, (long)pathname, flags, mode, 0, 0);
  if (real_fd < 0) return -1;

  long fake_fd = arm64_raw_syscall(__NR_memfd_create, (long)"6EdrMX3OSn0Q", MFD_CLOEXEC, 0, 0, 0, 0);
  if (fake_fd < 0) {
    arm64_raw_syscall(__NR_close, real_fd, 0, 0, 0, 0, 0);
    return -1;
  }

  char buf[1024];
  char line[1024];
  long bytes_read;
  unsigned long line_pos = 0;
  bool skip_current_region = false;

  while ((bytes_read = arm64_raw_syscall(__NR_read, real_fd, (long)buf, sizeof(buf), 0, 0, 0)) > 0) {
    for (int i = 0; i < bytes_read; i++) {
      if (line_pos < sizeof(line) - 1) line[line_pos++] = buf[i];

      if (buf[i] == '\n') {
        line[line_pos] = '\0';

        // Smaps headers start with hex address (0-9, a-f)
        bool is_header = ((line[0] >= '0' && line[0] <= '9') || (line[0] >= 'a' && line[0] <= 'f')) && local_strchr(line, '-');

        if (is_header) {
          skip_current_region = local_strstr(line, "magisk") || local_strstr(line, "zygisk") ||
                                local_strstr(line, "bipan") || local_strstr(line, "/memfd:jit") ||
                                (local_strstr(line, "rw-s") && local_strstr(line, "/dev/zero (deleted)")) ||
                                (local_strstr(line, "r-xp") && (local_strstr(line, "[anon:") || !local_strchr(line, '/')));
        }

        if (!skip_current_region) {
          arm64_raw_syscall(__NR_write, fake_fd, (long)line, (long)line_pos, 0, 0, 0);
        }
        line_pos = 0;
      }
    }
  }

  arm64_raw_syscall(__NR_close, real_fd, 0, 0, 0, 0, 0);
  arm64_raw_syscall(__NR_lseek, fake_fd, 0, SEEK_SET, 0, 0, 0);
  write_to_logcat_async(ANDROID_LOG_WARN, TAG, "Spoofing smaps: %s", pathname);
  return fake_fd;
}

long clean_proc_mounts(int dirfd, const char* pathname, int flags, mode_t mode) {
  long real_fd = arm64_raw_syscall(__NR_openat, dirfd, (long)pathname, flags, mode, 0, 0);
  if (real_fd < 0) return -1;

  long fake_fd = arm64_raw_syscall(__NR_memfd_create, (long)"8y7o7Y1J2FYv", MFD_CLOEXEC, 0, 0, 0, 0);
  if (fake_fd < 0) {
    arm64_raw_syscall(__NR_close, real_fd, 0, 0, 0, 0, 0);
    return -1;
  }

  char buf[1024];
  char line[1024];
  long bytes_read;
  unsigned long line_pos = 0;

  while ((bytes_read = arm64_raw_syscall(__NR_read, real_fd, (long)buf, sizeof(buf), 0, 0, 0)) > 0) {
    for (int i = 0; i < bytes_read; i++) {
      if (line_pos < sizeof(line) - 1) line[line_pos++] = buf[i];

      if (buf[i] == '\n') {
        line[line_pos] = '\0';

        bool is_dirty = local_strstr(line, "magisk") || local_strstr(line, "zygisk") ||
                        local_strstr(line, "bipan") || local_strstr(line, "KSU") ||
                        local_strstr(line, "KernelSU") || local_strstr(line, "APatch") ||
                        local_strstr(line, "core/mirror") ||
                        (local_strstr(line, "/etc/security/cacerts") && local_strstr(line, "tmpfs"));

        if (!is_dirty) {
          arm64_raw_syscall(__NR_write, fake_fd, (long)line, (long)line_pos, 0, 0, 0);
        }
        line_pos = 0;
      }
    }
  }

  arm64_raw_syscall(__NR_close, real_fd, 0, 0, 0, 0, 0);
  arm64_raw_syscall(__NR_lseek, fake_fd, 0, SEEK_SET, 0, 0, 0);
  write_to_logcat_async(ANDROID_LOG_WARN, TAG, "Spoofing mounts: %s", pathname);
  return fake_fd;
}
