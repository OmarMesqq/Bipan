#ifndef UNWINDER_HPP
#define UNWINDER_HPP

#include <elf.h>
#include <linux/limits.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct {
  uintptr_t pc;  // Program Counter
  uintptr_t sp;  // TODO: ???
} StackFrame;

typedef struct {
  char dli_fname[PATH_MAX];  // Path to the library
  uintptr_t dli_fbase;       // Base address of the library
  uintptr_t dli_offset;      // Relative offset inside the file
} ManualDlInfo;

// 64-bit ELF structures for ARM64
typedef Elf64_Ehdr ElfHeader;
typedef Elf64_Shdr ElfSection;
typedef Elf64_Sym ElfSymbol;

bool unwinder(uintptr_t fp, uintptr_t lr, pid_t pid);

#endif
