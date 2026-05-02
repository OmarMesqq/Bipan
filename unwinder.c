#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <syscall.h>
#include <unistd.h>

typedef struct {
  uintptr_t pc;
  uintptr_t sp;
} StackFrame;

static void foo(void);
static void bar(void);
static void baz(void);
static void applySeccomp(void);
static void sigsys_handler(int sig, siginfo_t* info, void* void_context);
static void unwinder(uintptr_t pc, uintptr_t sp);

#define MAX_FRAMES 20
#define MAX_INSTRUCTIONS 2048

static void unwinder(uintptr_t pc, uintptr_t sp) {
  printf("Starting Unwind from PC: %p, SP: %p\n", (void*)pc, (void*)sp);
  printf("\n--- STACK HEXDUMP (Top (SP) at %p) ---\n", (void*)sp);
  printf("  Offset  |      Address      |        Value        |  Note\n");
  printf("----------|-------------------|---------------------|-------\n");

  uint32_t* search_ptr = (uint32_t*)pc;
  for (int i = 0; i < MAX_INSTRUCTIONS; i++) {
    uintptr_t addr = (uintptr_t)&search_ptr[i];
    uintptr_t val = search_ptr[i];

    printf(" +%04zx    | %p | %016lx\n",
           i * sizeof(uintptr_t), (void*)addr, (unsigned long)val);
  }
  printf("--- END DUMP ---\n\n");
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

  if (nr == __NR_uname) {
    fprintf(stderr, "trapped uname\n");
    unwinder(pc, sp);
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
