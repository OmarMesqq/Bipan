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
static uintptr_t get_sub_imm(uint32_t inst);
static uintptr_t get_stp_imm(uint32_t inst);

#define IS_SUB_SP_IMM(inst) ((inst & 0xffc003ff) == 0xd10003ff)
#define IS_STR_X30_PRE(inst) ((inst & 0xfff00fff) == 0xf8100fe3)  // str x30, [sp, #imm]!

static uintptr_t get_sub_imm(uint32_t inst) {
  // Extracts the 12-bit immediate from 'sub sp, sp, #imm'
  return (inst >> 10) & 0xfff;
}

static uintptr_t get_stp_imm(uint32_t inst) {
  // Extract 7-bit signed offset, multiply by 8 (AArch64 scaling)
  int64_t imm = (inst >> 15) & 0x7f;
  if (imm & 0x40) imm |= ~0x7f;  // Sign extend
  return (uintptr_t)(imm * -8);  // We want the positive magnitude
}

static void unwinder(uintptr_t pc, uintptr_t sp) {
  printf("Starting Unwind from PC: %p, SP: %p\n", (void*)pc, (void*)sp);

  for (int frame = 0; frame < 10; frame++) {
    uint32_t* search_ptr = (uint32_t*)pc;
    uintptr_t frame_size = 0;

    // Scan backwards to find the prologue
    // Limit search to 100 instructions so we don't scan forever
    for (int i = 0; i < 1024; i++) {
      uint32_t inst = *(--search_ptr);

      if (IS_SUB_SP_IMM(inst)) {
        frame_size = get_sub_imm(inst);
        break;
      }
      if (IS_STR_X30_PRE(inst)) {
        // This instruction stores LR and moves SP in one go
        // Simplified: extraction logic for signed offsets is trickier
        frame_size = 16;
        break;
      }
      // If we hit a 'ret' (0xd65f03c0), we went too far
      if (inst == 0xd65f03c0) break;
    }

    if (frame_size == 0) {
      printf("Could not find prologue for frame %d. Stopping.\n", frame);
      break;
    }

    // The "Jump" logic:
    // 1. Return address is usually at the top of the stack frame
    uintptr_t* lr_location = (uintptr_t*)(sp + frame_size - 16);
    uintptr_t next_pc = *lr_location;
    uintptr_t next_sp = sp + frame_size;

    printf("Frame %d: PC=%p, Next SP=%p\n", frame, (void*)next_pc, (void*)next_sp);

    pc = next_pc;
    sp = next_sp;
    if (pc == 0) break;
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
