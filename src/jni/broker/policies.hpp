#ifndef POLICIES_HPP
#define POLICIES_HPP

#include <string>

typedef enum {
  OK,
  DENY,   // -EPERM
  SPOOF,  // -ENOENT
} SuNodeHandlerResponse;

bool isLanAddress(struct sockaddr* addr);
bool shouldLog(const char* pathname);
bool shouldSpoofExistence(const char* pathname);
bool shouldReportEmptyDir(const char* pathname);
SuNodeHandlerResponse handleSuRelatedNode(const char* pathname);
bool shouldDenyStat(const char* path);
bool shouldDenyAccess(const char* pathname);
const char* shouldFakeFile(const char* pathname);
bool is_maps(const char* pathname);
bool is_proc_status(const char* pathname);
bool is_smaps(const char* pathname);
bool is_mounts(const char* pathname);
char* fixMemfdSymlink(const char* resolvedPath, pid_t pid);

#endif