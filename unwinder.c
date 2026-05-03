

#include <elf.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <syscall.h>
#include <unistd.h>

typedef struct {
  uintptr_t pc;
  uintptr_t sp;
} StackFrame;

typedef struct {
  char dli_fname[256];   // Path to the library
  uintptr_t dli_fbase;   // Base address of the library
  uintptr_t dli_offset;  // Relative offset inside the file
} ManualDlInfo;

static void foo(void);
static void bar(void);
static void baz(void);
static void applySeccomp(void);
static void sigsys_handler(int sig, siginfo_t* info, void* void_context);

#define MAX_FRAMES 20
#define MAX_INSTRUCTIONS 2048

// Use 64-bit ELF structures for ARM64
typedef Elf64_Ehdr ElfHeader;
typedef Elf64_Shdr ElfSection;
typedef Elf64_Sym ElfSymbol;

/**
 * Parses the physical ELF file to find a name for a relative offset.
 * This sees STATIC labels that dladdr cannot.
 */
static void find_label_in_elf(const char* path, uintptr_t offset, char* out_name, size_t max_len) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) return;

  struct stat st;
  if (fstat(fd, &st) < 0) {
    close(fd);
    return;
  }

  // Map the ELF file into memory to parse headers
  void* map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (map == MAP_FAILED) return;

  ElfHeader* ehdr = (ElfHeader*)map;
  ElfSection* shdr = (ElfSection*)((uintptr_t)map + ehdr->e_shoff);
  char* shstrtab = (char*)((uintptr_t)map + shdr[ehdr->e_shstrndx].sh_offset);

  ElfSymbol* symtab = NULL;
  char* strtab = NULL;
  size_t sym_count = 0;

  // 1. Locate Symbol Table and String Table
  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (shdr[i].sh_type == SHT_SYMTAB) {
      symtab = (ElfSymbol*)((uintptr_t)map + shdr[i].sh_offset);
      sym_count = shdr[i].sh_size / sizeof(ElfSymbol);
    } else if (shdr[i].sh_type == SHT_STRTAB && strcmp(&shstrtab[shdr[i].sh_name], ".strtab") == 0) {
      strtab = (char*)((uintptr_t)map + shdr[i].sh_offset);
    }
  }

  // 2. Search for the offset in the symbols
  if (symtab && strtab) {
    for (size_t i = 0; i < sym_count; i++) {
      // Check if our offset falls within this symbol's range
      if (offset >= symtab[i].st_value && offset < (symtab[i].st_value + symtab[i].st_size)) {
        strncpy(out_name, &strtab[symtab[i].st_name], max_len - 1);
        goto cleanup;
      }
    }
  }
  strncpy(out_name, "???", max_len);

cleanup:
  munmap(map, st.st_size);
}

/**
 * REPLICATING dladdr:
 * Opens /proc/self/maps, finds which region contains 'addr',
 * and calculates the offset.
 */
static int manual_dladdr(uintptr_t addr, ManualDlInfo* info) {
  FILE* f = fopen("/proc/self/maps", "re");
  if (!f) return 0;

  char line[512];
  int found = 0;

  while (fgets(line, sizeof(line), f)) {
    uintptr_t start, end, file_offset;
    char perms[5];
    // Format: start-end perms offset dev inode path
    if (sscanf(line, "%lx-%lx %4s %lx", &start, &end, perms, &file_offset) < 4)
      continue;

    if (addr >= start && addr < end) {
      info->dli_fbase = start;

      // Calculate offset: (Actual Addr - Map Start) + File Offset
      info->dli_offset = (addr - start) + file_offset;

      // Extract the path (it starts after the inode field)
      // We look for the first '/' or '[' (for [stack], [vdso], etc)
      char* path_start = strchr(line, '/');
      if (!path_start) path_start = strchr(line, '[');

      if (path_start) {
        char* newline = strchr(path_start, '\n');
        if (newline) *newline = '\0';
        strncpy(info->dli_fname, path_start, sizeof(info->dli_fname) - 1);
      } else {
        strcpy(info->dli_fname, "[anonymous memory]");
      }

      found = 1;
      break;
    }
  }

  fclose(f);
  return found;
}

static void print_resolved_frame(const char* label, uintptr_t addr) {
  // CRITICAL: Strip ARM64 PAC (Pointer Authentication) bits
  addr &= 0x0000FFFFFFFFFFFFULL;

  ManualDlInfo info;
  char sym_name[256] = "???";

  if (manual_dladdr(addr, &info)) {
    // Resolve static labels from the file on disk
    find_label_in_elf(info.dli_fname, info.dli_offset, sym_name, sizeof(sym_name));

    printf("%s %p -> %-15s | %s (+0x%lx)\n",
           label, (void*)addr, sym_name, info.dli_fname, info.dli_offset);
  } else {
    printf("%s %p -> [unresolved]\n", label, (void*)addr);
  }
}

static void unwinder(uintptr_t fp, uintptr_t lr) {
  // 1. The immediate caller is in the Link Register (x30)
  print_resolved_frame("  Culprit (LR): ", lr);

  // 2. Walk the Frame Pointer chain (x29)
  for (int i = 0; i < MAX_FRAMES; ++i) {
    if (!fp || (fp & 0x7)) break;

    // On ARM64, the return address is 8 bytes above the Frame Pointer
    uintptr_t* stack = (uintptr_t*)fp;
    uintptr_t next_fp = stack[0];
    uintptr_t return_addr = stack[1];

    if (!return_addr) break;
    print_resolved_frame("  Ancestor:     ", return_addr);

    if (next_fp <= fp) break;  // Sanity check for stack direction
    fp = next_fp;
  }
}

static void sigsys_handler(int sig, siginfo_t* info, void* void_context) {
  ucontext_t* ctx = (ucontext_t*)void_context;
  int nr = info->si_syscall;

  long arg0 = ctx->uc_mcontext.regs[0];
  long arg1 = ctx->uc_mcontext.regs[1];
  long arg2 = ctx->uc_mcontext.regs[2];
  long arg3 = ctx->uc_mcontext.regs[3];
  long arg4 = ctx->uc_mcontext.regs[4];
  long arg5 = ctx->uc_mcontext.regs[5];

  uintptr_t pc = ctx->uc_mcontext.pc;
  uintptr_t sp = ctx->uc_mcontext.sp;
  uintptr_t lr = ctx->uc_mcontext.regs[30];
  uintptr_t fp = ctx->uc_mcontext.regs[29];

  if (nr == __NR_uname) {
    fprintf(stderr, "trapped uname\n");
    unwinder(fp, lr);
  }
}

int main(void) {
  struct sigaction sa = {0};
  sa.sa_sigaction = sigsys_handler;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGSYS, &sa, NULL) == -1) {
    fprintf(stderr, "error: sigaction\n");
    return -1;
  }

  applySeccomp();
  foo();
  return 0;
}

static void applySeccomp(void) {
  struct sock_filter trapFilter[] = {
      // Load syscall number into accumulator
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

      // System info
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_uname, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(trapFilter) / sizeof(trapFilter[0])),
      .filter = trapFilter,
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    fprintf(stderr, "prctl");
    return;
  }

  long seccompApplyRet = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog);
  if (seccompApplyRet == -1) {
    fprintf(stderr, "seccomp");
  }
}

static void foo(void) {
  int x = 0;
  x += 1;
  bar();
}

static void bar(void) {
  int y = 3;
  y += 1;
  baz();
}

static void baz(void) {
  struct utsname buffer = {0};
  if (uname(&buffer) == 0) {
    printf("System Name: %s\n", buffer.sysname);
    printf("Node Name:   %s\n", buffer.nodename);
    printf("Release:     %s\n", buffer.release);
    printf("Version:     %s\n", buffer.version);
    printf("Machine:     %s\n", buffer.machine);
  } else {
    fprintf(stderr, "error: uname\n");
  }
}
