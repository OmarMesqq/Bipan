#ifndef MEM_TOOLS_HPP
#define MEM_TOOLS_HPP

#include <stdint.h>

struct LibBounds {
  uintptr_t start = 0;
  uintptr_t end = 0;
};

struct DumpContext {
  const char* target_soname;
};

int find_lib_bounds(struct dl_phdr_info* info, size_t size, void* data);
int find_loaded_shared_libs(struct dl_phdr_info* info, size_t size, void* data);
void dump_mem(void* addr, int bytes);
int dump_lib_info_with_dlitphdr(struct dl_phdr_info* info, size_t size, void* data);
void dump_lib_info_with_auxv();
bool scrub_elf_header();

#endif
