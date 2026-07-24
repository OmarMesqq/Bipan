#include "broker_assist.hpp"

#include <dlfcn.h>
#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "logger/logger.hpp"

#define TAG "BipanBrokerAssistant"

static void sigsegv_handler(int sig, siginfo_t* info, void* void_context);
static void sigabrt_handler(int sig, siginfo_t* info, void* void_context);
static void log_fatal_common(int sig, siginfo_t* info, void* void_context);
static void log_backtrace(void* void_context);
static void kill_current_client();

// Set at the top of each Broker thread's loop iteration, so the handler
// knows which client this specific thread was servicing when it died.
thread_local pid_t g_current_client_pid = -1;

// Saved original dispositions, so we can chain to them for a real tombstone
static struct sigaction g_old_segv = {};
static struct sigaction g_old_abrt = {};

static char g_altstack[SIGSTKSZ * 4];


bool registerDebugSigHandlers() {
  stack_t ss = {};
  ss.ss_sp = g_altstack;
  ss.ss_size = sizeof(g_altstack);
  ss.ss_flags = 0;
  if (sigaltstack(&ss, nullptr) != 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "[!] sigaltstack failed (errno: %s)", strerror(errno));
    return false;  // don't proceed with a handler you know can't safely run
  }

  struct sigaction segvAct = {};
  segvAct.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
  segvAct.sa_sigaction = &sigsegv_handler;
  sigemptyset(&segvAct.sa_mask);
  int segvRegistration = sigaction(SIGSEGV, &segvAct, &g_old_segv);
  if (segvRegistration != 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] sigaction(SIGSEGV) failed (errno: %s)", strerror(errno));
    return false;
  }

  struct sigaction abrtAct = {};
  abrtAct.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
  abrtAct.sa_sigaction = &sigabrt_handler;
  sigemptyset(&abrtAct.sa_mask);
  int abrtRegistration = sigaction(SIGABRT, &abrtAct, &g_old_abrt);
  if (abrtRegistration != 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] sigaction(SIGABRT) failed (errno: %s)", strerror(errno));
    return false;
  }

  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[!] Debug handlers registered on altstack, size=%zu", sizeof(g_altstack));
  return true;
}

static void sigsegv_handler(int sig, siginfo_t* info, void* void_context) {
  write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] INSIDE SIGSEGV HANDLER!");

  if (sig != SIGSEGV) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Received signal %d != SIGSEGV");
  }

  
  log_fatal_common(sig, info, void_context);
}
static void sigabrt_handler(int sig, siginfo_t* info, void* void_context) {
  if (sig != SIGABRT) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Received signal %d != SIGABRT");
  }
  write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] SIGABRT received (tid=%d)", gettid());
  log_fatal_common(sig, info, void_context);
}

static void log_fatal_common(int sig, siginfo_t* info, void* void_context) {
  (void)info;  // not using

  write_to_logcat_async(ANDROID_LOG_FATAL, TAG,
                        "[!] Fatal signal %d in Broker thread pid=%d tid=%d, servicing client pid=%d",
                        sig, getpid(), gettid(), g_current_client_pid);

  log_backtrace(void_context);

  // Don't let the client app hang forever waiting on a Broker reply
  // that will never come now that this thread is about to die.
  kill_current_client();

  // Restore the original (pre-Bipan) disposition and re-raise so the
  // kernel's normal coredump/tombstone path runs for this process.
  // We're a standalone daemon here, not sandboxed like the target app,
  // so debuggerd should actually be able to service this cleanly.
  struct sigaction* old = (sig == SIGSEGV) ? &g_old_segv : &g_old_abrt;
  sigaction(sig, old, nullptr);
  raise(sig);

  // If for some reason re-raising didn't kill us (shouldn't happen),
  // don't fall back into normal execution with a wrecked signal state.
  _exit(128 + sig);
}

static void log_backtrace(void* void_context) {
  ucontext_t* ctx = (ucontext_t*)void_context;
  uintptr_t pc = ctx->uc_mcontext.pc;
  uintptr_t fp = ctx->uc_mcontext.regs[29];

  write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "  pc=%p fp=%p lr=%p sp=%p",
                        (void*)pc, (void*)fp, (void*)ctx->uc_mcontext.regs[30], (void*)ctx->uc_mcontext.sp);

  Dl_info info;
  if (dladdr((void*)pc, &info) && info.dli_fname) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "  #00 pc %p %s (%s)",
                          (void*)pc, info.dli_fname, info.dli_sname ? info.dli_sname : "???");
  } else {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "  #00 pc %p <unresolved>", (void*)pc);
  }

  for (int i = 1; i < 32 && fp && !(fp & 0x7); i++) {
    uintptr_t next_fp = *(uintptr_t*)fp;
    uintptr_t ret_addr = *(uintptr_t*)(fp + 8);
    if (!ret_addr) break;
    ret_addr &= 0x0000FFFFFFFFFFFFULL;  // strip PAC bits

    if (dladdr((void*)ret_addr, &info) && info.dli_fname) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "  #%02d pc %p %s (%s)",
                            i, (void*)ret_addr, info.dli_fname, info.dli_sname ? info.dli_sname : "???");
    } else {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "  #%02d pc %p <unresolved>", i, (void*)ret_addr);
    }

    if (next_fp <= fp) break;  // stack must grow upward frame-to-frame
    fp = next_fp;
  }
}

static void kill_current_client() {
  if (g_current_client_pid <= 0) return;
  write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[!] Killing orphaned client pid=%d", g_current_client_pid);
  // Root-privileged daemon, plain kill() is fine here
  kill(g_current_client_pid, SIGKILL);
}
