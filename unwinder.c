

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

  void* map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (map == MAP_FAILED) return;

  ElfHeader* ehdr = (ElfHeader*)map;
  ElfSection* shdr = (ElfSection*)((uintptr_t)map + ehdr->e_shoff);

  uintptr_t best_diff = (uintptr_t)-1;
  char* found_name = NULL;

  // Search both SYMTAB (Static) and DYNSYM (Dynamic)
  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_DYNSYM) {
      ElfSymbol* syms = (ElfSymbol*)((uintptr_t)map + shdr[i].sh_offset);
      size_t count = shdr[i].sh_size / sizeof(ElfSymbol);

      // sh_link automatically points to the correct string table for this symbol table
      char* strings = (char*)((uintptr_t)map + shdr[shdr[i].sh_link].sh_offset);

      for (size_t j = 0; j < count; j++) {
        char* current_name = &strings[syms[j].st_name];

        // TWEAK: Skip empty names, mapping symbols ($x, $d),
        // and symbols that start after our offset.
        if (syms[j].st_name == 0 || current_name[0] == '$' || syms[j].st_value > offset) {
          continue;
        }

        uintptr_t diff = offset - syms[j].st_value;
        if (diff < best_diff) {
          best_diff = diff;
          found_name = current_name;
        }
      }

      // If we found a perfect match (diff 0) in SYMTAB, we can stop early
      if (best_diff == 0 && shdr[i].sh_type == SHT_SYMTAB) break;
    }
  }

  if (found_name && strlen(found_name) > 0) {
    strncpy(out_name, found_name, max_len - 1);
  } else {
    strncpy(out_name, "???", max_len);
  }

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
