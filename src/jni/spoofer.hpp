#ifndef SPOOFER_HPP
#define SPOOFER_HPP

#include <unistd.h>

int uname_spoofer(struct utsname* buf);
int create_spoofed_file(const char* fake_content);
int clean_proc_maps(int dirfd, const char* pathname, int flags, mode_t mode);
int clean_proc_smaps(int dirfd, const char* pathname, int flags, mode_t mode);
int clean_proc_mounts(int dirfd, const char* pathname, int flags, mode_t mode);
int clean_proc_status(int dirfd, const char* pathname, int flags, mode_t mode);

#endif
