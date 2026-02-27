#include "spoofer.hpp"

#include <linux/memfd.h>
#include <sys/mman.h>
#include <syscall.h>
#include <unistd.h>
#include <sys/utsname.h>

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
 */
int create_spoofed_file(const char* fake_content) {
  // memfd_create requires a name, but it doesn't appear in the filesystem
  int fd = syscall(__NR_memfd_create, "bipanfd", MFD_CLOEXEC);

  if (fd >= 0) {
    write(fd, fake_content, strlen(fake_content));
    lseek(fd, 0, SEEK_SET);  // Rewind it so the app can read it
  } else {
    LOGE("memfd_create failed!");
  }
  return fd;
}

long clean_proc_maps(int dirfd, const char* pathname, int flags, mode_t mode) {
  // Open the real maps file
  long real_fd = arm64_bypassed_syscall(__NR_openat, dirfd, (long)pathname, flags, mode, 0);
  if (real_fd < 0) {
    LOGE("openat memory maps failed!");
    return -1;
  }

  // Create a fake in-memory file to hold the scrubbed data (6 args)
  long fake_fd = arm64_bypassed_syscall(__NR_memfd_create, (long)"spoofed_maps", MFD_CLOEXEC, 0, 0, 0);
  if (fake_fd < 0) {
    LOGE("memfd failed!");
    arm64_bypassed_syscall(__NR_close, real_fd, 0, 0, 0, 0);
    return -1;
  }

  // Read the real file line-by-line
  char buf[4096];
  long bytes_read;
  char line[4096];
  int line_pos = 0;

  while ((bytes_read = arm64_bypassed_syscall(__NR_read, real_fd, (long)buf, sizeof(buf), 0, 0)) > 0) {
    for (int i = 0; i < bytes_read; i++) {
      if (line_pos < sizeof(line) - 1) {
        line[line_pos++] = buf[i];
      }

      if (buf[i] == '\n') {
        line[line_pos] = '\0';  // Null-terminate the line

        if (
            // Forbidden keywords...
            strstr(line, "magisk") == nullptr &&
            strstr(line, "zygisk") == nullptr &&
            strstr(line, "bipan") == nullptr &&
            // Specific memory flags
            !(strstr(line, "rw-s") != nullptr && strstr(line, "/dev/zero (deleted)") != nullptr) &&
            !(strstr(line, "r-xp") != nullptr && (strstr(line, "[anon:") != nullptr || strchr(line, '/') == nullptr))) {
          // Line is clean: write it to the fake file
          arm64_bypassed_syscall(__NR_write, fake_fd, (long)line, line_pos, 0, 0);
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
