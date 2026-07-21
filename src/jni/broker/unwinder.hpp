#ifndef UNWINDER_HPP
#define UNWINDER_HPP

#include <elf.h>
#include <linux/limits.h>
#include <stdint.h>
#include <sys/types.h>

#include <string>

typedef struct {
  char dli_fname[PATH_MAX];  // Path to the library
  // uintptr_t dli_fbase;       // Base address of the library
  // uintptr_t dli_offset;      // Relative offset inside the file
} ManualDlInfo;

// 64-bit ELF structures for ARM64
typedef Elf64_Ehdr ElfHeader;
typedef Elf64_Shdr ElfSection;
typedef Elf64_Sym ElfSymbol;

struct MapEntry {
  uintptr_t start, end, offset;
  std::string libName;
};

bool unwinder(uintptr_t pc, uintptr_t fp, uintptr_t lr, pid_t pid, int nr);
void initializeUnwinder(pid_t pid);

#endif
