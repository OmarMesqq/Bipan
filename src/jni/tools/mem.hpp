#ifndef MEM_TOOLS_HPP
#define MEM_TOOLS_HPP

#include <stdint.h>

struct LibBounds {
  uintptr_t start = 0;
  uintptr_t end = 0;
};

int findBipansBounds(struct dl_phdr_info* info, size_t size, void* data);
void dumpBytes(void* addr, int bytes);
int dumpBipanLinkerInfo(struct dl_phdr_info* info, size_t size, void* data);
void readAuxVector();
bool scrubBipansElfHeader();

#endif
