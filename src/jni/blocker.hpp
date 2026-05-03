#ifndef BLOCKER_HPP
#define BLOCKER_HPP

#include <cstdint>

int filterPathname(long sysno, long a0, long a1, long a2, long a3, long a4, long a5);
bool filterIPv4LanAccess(uint32_t ip4);
bool filterIPv6LanAccess(uint8_t* ip6);
void patchInstruction(uintptr_t address, int return_value);
bool shouldLog(const char* pathname);
bool shouldSpoofExistence(const char* pathname);
bool shouldDenyAccess(const char* pathname);
const char* shouldFakeFile(const char* pathname);

#endif
