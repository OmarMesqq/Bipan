#include "broker_assist.hpp"

#include <dlfcn.h>
#include <signal.h>
#include <unistd.h>
#include <unwind.h>

#include <cerrno>
#include <cstring>

#include "logger/logger.hpp"

#define TAG "BipanBrokerAssistant"

static constexpr int MAX_FRAMES_BROKER_ASSIST = 120;

typedef struct {
  void** frames;
  int count;
  int max;
} BacktraceState;

static void bipan_broker_signal_handler(int sig, siginfo_t* info, void* void_context);
static void kill_current_client();
static _Unwind_Reason_Code unwind_callback(struct _Unwind_Context* context, void* arg);
int capture_backtrace(void** out_frames, int max_frames);
void print_backtrace();

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
  segvAct.sa_sigaction = &bipan_broker_signal_handler;
  sigemptyset(&segvAct.sa_mask);
  int segvRegistration = sigaction(SIGSEGV, &segvAct, &g_old_segv);
  if (segvRegistration != 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] sigaction(SIGSEGV) failed (errno: %s)", strerror(errno));
    return false;
  }

  struct sigaction abrtAct = {};
  abrtAct.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
  abrtAct.sa_sigaction = &bipan_broker_signal_handler;
  sigemptyset(&abrtAct.sa_mask);
  int abrtRegistration = sigaction(SIGABRT, &abrtAct, &g_old_abrt);
  if (abrtRegistration != 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] sigaction(SIGABRT) failed (errno: %s)", strerror(errno));
    return false;
  }

  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[!] Debug handlers registered on altstack, size=%zu", sizeof(g_altstack));
  return true;
}

static void bipan_broker_signal_handler(int sig, siginfo_t* info, void* void_context) {
  (void)info;
  (void)void_context;

  if (sig == SIGABRT) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Broker got SIGABRT!");
  } else if (sig == SIGSEGV) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Broker got SIGSEGV!");
  } else {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Broker got unexpected signal: %d", sig);
  }
  print_backtrace();
  kill_current_client();
}

static void kill_current_client() {
  if (g_current_client_pid <= 0) {
    return;
  }

  write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[!] Killing orphaned client pid=%d", g_current_client_pid);
  kill(g_current_client_pid, SIGKILL);
}

static _Unwind_Reason_Code unwind_callback(struct _Unwind_Context* context, void* arg) {
  BacktraceState* state = (BacktraceState*)arg;

  uintptr_t pc = _Unwind_GetIP(context);
  if (pc == 0) {
    return _URC_END_OF_STACK;
  }

  if (state->count >= state->max) {
    return _URC_END_OF_STACK;
  }

  state->frames[state->count++] = (void*)pc;
  return _URC_NO_REASON;
}

int capture_backtrace(void** out_frames, int max_frames) {
  BacktraceState state = {out_frames, 0, max_frames};
  _Unwind_Backtrace(unwind_callback, &state);
  return state.count;
}

void print_backtrace() {
  void* frames[MAX_FRAMES_BROKER_ASSIST];
  int count = capture_backtrace(frames, MAX_FRAMES_BROKER_ASSIST);

  for (int i = 0; i < count; i++) {
    Dl_info info;
    if (dladdr(frames[i], &info) && info.dli_sname) {
      uintptr_t offset = (uintptr_t)frames[i] - (uintptr_t)info.dli_saddr;
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "#%02d pc %p %s (%s+0x%lx)",
                            i, frames[i],
                            info.dli_fname ? info.dli_fname : "?",
                            info.dli_sname,
                            (unsigned long)offset);
    } else if (dladdr(frames[i], &info) && info.dli_fname) {
      uintptr_t offset = (uintptr_t)frames[i] - (uintptr_t)info.dli_fbase;
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "#%02d pc 0x%lx %s", i, (unsigned long)offset, info.dli_fname);
    } else {
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "#%02d pc %p <unknown>", i, frames[i]);
    }
  }
}
