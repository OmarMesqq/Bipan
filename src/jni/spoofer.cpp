#include "spoofer.hpp"

#include <linux/memfd.h>
#include <sys/mman.h>
#include <syscall.h>
#include <unistd.h>

#include <string>

#include "shared.hpp"

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
