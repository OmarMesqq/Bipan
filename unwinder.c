

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
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
  ManualDlInfo info;
  if (manual_dladdr(addr, &info)) {
    printf("%s %p -> %s (+0x%lx)\n", label, (void*)addr, info.dli_fname, info.dli_offset);
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
