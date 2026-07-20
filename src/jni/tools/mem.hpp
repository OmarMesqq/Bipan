#ifndef MEM_TOOLS_HPP
#define MEM_TOOLS_HPP

#include <stdint.h>

void dumpBytes(void* addr, int bytes);
int dumpBipanLinkerInfo(struct dl_phdr_info* info, size_t size, void* data);
void readAuxVector();

#endif
