#include "spoofer.hpp"

#include <linux/memfd.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <syscall.h>

#include <string>

#include "common_utils.hpp"
#include "logger/logger.hpp"

#define TAG "BipanSpoofer"

int uname_spoofer(struct utsname* buf) {
  if (!buf) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "uname_spoofer: received null utsname buf!");
    return -1;
  }

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
 * Calls to `memfd_create` in the functions below could, and imo, should use the bionic
 * wrapper, but NDK says it was introduced only on API 30, so I kept the raw syscall
 * calls for backwards-compatibility so Bipan works on most phones.
 * Hopefully your kernel will be recent enough so that the syscall exists.
 */

int create_spoofed_file(const char* fake_content) {
  if (fake_content == nullptr) {
    return -1;
  }

  int fd = (int)arm64_raw_syscall(__NR_memfd_create, (long)"SUGcv6fF5U1O", MFD_CLOEXEC, 0, 0, 0, 0);
  if (fd < 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "create_spoofed_file: memfd_create failed");
    return fd;
  }

  size_t len = strlen(fake_content);
  write(fd, fake_content, len);
  lseek(fd, 0, SEEK_SET);

  return fd;
}

int clean_proc_maps(int dirfd, const char* pathname, int flags, mode_t mode) {
  int real_fd = openat(dirfd, pathname, flags, mode);
  if (real_fd < 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "clean_proc_maps: openat real dir failed!");
    return -1;
  }

  int fake_fd = (int)arm64_raw_syscall(__NR_memfd_create, (long)"JpWOjmVl33X2", MFD_CLOEXEC, 0, 0, 0, 0);
  if (fake_fd < 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "clean_proc_maps: memfd_create failed");
    close(real_fd);
    return -1;
  }

  char buf[1024];
  char line[1024];
  long bytes_read;
  unsigned long line_pos = 0;

  auto process_and_write_line = [&](char* l, unsigned long len) {
    l[len] = '\0';

    bool is_dirty = strstr(l, "/memfd:jit-cache (deleted)") ||
                    strstr(l, "7EFE8wVJq686"); // RAM-backed SharedIPC

    if (!is_dirty) {
      write(fake_fd, l, len);
    }
  };

  while ((bytes_read = read(real_fd, buf, sizeof(buf))) > 0) {
    for (int i = 0; i < bytes_read; i++) {
      if (line_pos < sizeof(line) - 1) line[line_pos++] = buf[i];
      if (buf[i] == '\n') {
        process_and_write_line(line, line_pos);
        line_pos = 0;
      }
    }
  }

  // flush the last line if it didn't end in \n
  if (line_pos > 0) {
    process_and_write_line(line, line_pos);
  }

  close(real_fd);
  lseek(fake_fd, 0, SEEK_SET);
  return fake_fd;
}

int clean_proc_smaps(int dirfd, const char* pathname, int flags, mode_t mode) {
  int real_fd = openat(dirfd, pathname, flags, mode);
  if (real_fd < 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "clean_proc_smaps: openat real dir failed!");
    return -1;
  }

  int fake_fd = (int)arm64_raw_syscall(__NR_memfd_create, (long)"6EdrMX3OSn0Q", MFD_CLOEXEC, 0, 0, 0, 0);
  if (fake_fd < 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "clean_proc_smaps: memfd_create failed");
    close(real_fd);
    return -1;
  }

  char buf[1024];
  char line[1024];
  long bytes_read;
  unsigned long line_pos = 0;
  bool skip_current_region = false;

  while ((bytes_read = read(real_fd, buf, sizeof(buf))) > 0) {
    for (int i = 0; i < bytes_read; i++) {
      if (line_pos < sizeof(line) - 1) line[line_pos++] = buf[i];

      if (buf[i] == '\n') {
        line[line_pos] = '\0';

        // Smaps headers start with hex address (0-9, a-f)
        bool is_header = ((line[0] >= '0' && line[0] <= '9') || (line[0] >= 'a' && line[0] <= 'f')) && strchr(line, '-');

        if (is_header) {
          skip_current_region = strstr(line, "/memfd:jit-cache (deleted)") ||
                                strstr(line, "7EFE8wVJq686"); // RAM-backed SharedIPC
        }

        if (!skip_current_region) {
          write(fake_fd, line, line_pos);
        }
        line_pos = 0;
      }
    }
  }

  close(real_fd);
  lseek(fake_fd, 0, SEEK_SET);
  return fake_fd;
}

int clean_proc_mounts(int dirfd, const char* pathname, int flags, mode_t mode) {
  int real_fd = openat(dirfd, pathname, flags, mode);
  if (real_fd < 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "clean_proc_mounts: openat real dir failed!");
    return -1;
  }

  int fake_fd = (int)arm64_raw_syscall(__NR_memfd_create, (long)"8y7o7Y1J2FYv", MFD_CLOEXEC, 0, 0, 0, 0);
  if (fake_fd < 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "clean_proc_mounts: memfd_create failed");
    close(real_fd);
    return -1;
  }

  char buf[1024];
  char line[1024];
  long bytes_read;
  unsigned long line_pos = 0;

  while ((bytes_read = read(real_fd, buf, sizeof(buf))) > 0) {
    for (int i = 0; i < bytes_read; i++) {
      if (line_pos < sizeof(line) - 1) line[line_pos++] = buf[i];

      if (buf[i] == '\n') {
        line[line_pos] = '\0';

        bool is_dirty = strstr(line, "/product/bin") ||
                        strstr(line, "debug_ramdisk") ||
                        strstr(line, "mdnsd") ||
                        strstr(line, "magisk") ||
                        strstr(line, "zygisk") ||
                        strstr(line, "/system/etc/hosts") ||
                        strstr(line, "/etc/security/cacerts") ||
                        strstr(line, "/system/lib");

        if (!is_dirty) {
          write(fake_fd, line, line_pos);
        }
        line_pos = 0;
      }
    }
  }

  close(real_fd);
  lseek(fake_fd, 0, SEEK_SET);
  return fake_fd;
}

int clean_proc_status(int dirfd, const char* pathname, int flags, mode_t mode) {
  int real_fd = openat(dirfd, pathname, flags, mode);
  if (real_fd < 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "clean_proc_status: openat real dir failed!");
    return -1;
  }

  int fake_fd = (int)arm64_raw_syscall(__NR_memfd_create, (long)"QST42iyo0wWX", MFD_CLOEXEC, 0, 0, 0, 0);
  if (fake_fd < 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "clean_proc_status: memfd_create failed");
    close(real_fd);
    return -1;
  }

  char buf[1024];
  char line[1024];
  long bytes_read;
  size_t line_pos = 0;

  while ((bytes_read = read(real_fd, buf, sizeof(buf))) > 0) {
    for (int i = 0; i < bytes_read; i++) {
      // Avoid buffer overflow in the line accumulation buffer
      if (line_pos < sizeof(line) - 1) {
        line[line_pos++] = buf[i];
      }

      // Process when a newline is encountered or line buffer is full
      if (buf[i] == '\n' || line_pos >= sizeof(line) - 1) {
        line[line_pos] = '\0';  // Null-terminate for string functions

        const char* output_line = line;
        size_t output_len = line_pos;

        // Check and replace target keys
        if (starts_with(line, "TracerPid:")) {
          output_line = "TracerPid:\t0\n";
          output_len = strlen(output_line);
        } else if (starts_with(line, "NoNewPrivs:")) {
          output_line = "NoNewPrivs:\t0\n";
          output_len = strlen(output_line);
        }

        // Write the line to the anonymous file descriptor
        write(fake_fd, output_line, output_len);
        // Reset line position counter for the next line
        line_pos = 0;
      }
    }
  }

  // Handle any remaining data if the file didn't end with a newline
  if (line_pos > 0) {
    line[line_pos] = '\0';
    const char* output_line = line;
    size_t output_len = line_pos;

    if (starts_with(line, "TracerPid:")) {
      output_line = "TracerPid:\t0\n";
      output_len = strlen(output_line);
    } else if (starts_with(line, "NoNewPrivs:")) {
      output_line = "NoNewPrivs:\t0\n";
      output_len = strlen(output_line);
    } else if (starts_with(line, "Cpus_allowed_list:")) {
      output_line = "Cpus_allowed_list:\t0-3\n";
      output_len = strlen(output_line);
    }

    write(fake_fd, output_line, output_len);
  }

  close(real_fd);
  lseek(fake_fd, 0, SEEK_SET);
  return fake_fd;
}
