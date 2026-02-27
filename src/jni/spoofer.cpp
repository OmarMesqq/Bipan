#include "spoofer.hpp"

#include <linux/memfd.h>
#include <sys/mman.h>
#include <syscall.h>
#include <unistd.h>

#include <string>

// Creates an anonymous in-memory file with fake contents and returns its FD
int create_spoofed_file(const char* fake_content) {
  // memfd_create requires a name, but it doesn't appear in the filesystem
  int fd = syscall(__NR_memfd_create, "spoofed_file", MFD_CLOEXEC);
  if (fd >= 0) {
    write(fd, fake_content, strlen(fake_content));
    lseek(fd, 0, SEEK_SET);  // Rewind the fd to the beginning so the app can read it
  }
  return fd;
}