#ifndef POLICIES_HPP
#define POLICIES_HPP

#include <sys/stat.h>

#include <string>

bool isLanAddress(struct sockaddr* addr);
bool shouldLog(const char* pathname);
bool shouldDenyOpen(const char* pathname);
const char* shouldFakeFile(const char* pathname);
bool isMapsFile(const char* pathname);
bool isSmapsFile(const char* pathname);
bool isMountsFile(const char* pathname);
char* fixMemfdSymlink(const char* resolvedPath, pid_t pid);
struct stat* fixHostsFileStat(const char* pathname, int flags);

#endif