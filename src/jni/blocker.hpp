#ifndef BLOCKER_HPP
#define BLOCKER_HPP

#include <cstdint>

int filterPathname(long sysno, long a0, long a1, long a2, long a3, long a4);
bool filterIPv4LanAccess(uint32_t ip4);
bool filterIPv6LanAccess(uint8_t* ip6);
void patchInstructionWithNop(uintptr_t address);

#endif
