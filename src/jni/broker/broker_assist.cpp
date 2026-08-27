#include "broker_assist.hpp"

#include <dlfcn.h>
#include <signal.h>
#include <sys/syscall.h>
#include <unwind.h>

#include <cerrno>
#include <cstring>

#include "common_utils.hpp"
#include "logger/logger.hpp"

#define TAG "BipanBrokerAssist"

static constexpr int MAX_FRAMES_BROKER_ASSIST = 50;

typedef struct {
  void** frames;
  int count;
  int max;
} BacktraceState;

static void bipan_broker_signal_handler(int sig, siginfo_t* info, void* void_context);
static void kill_current_client();
static _Unwind_Reason_Code unwind_callback(struct _Unwind_Context* context, void* arg);
static int capture_backtrace(void** out_frames, int max_frames);
static void print_backtrace();

/**
 * Broker's responsibility to set this at the top of `startBroker`
 * Informs the daemon-side which client was being served when it crashed.
 * Also used for killing the app since without Broker we deadlock on the IPC
 */
thread_local pid_t g_current_client_pid = -1;

// Original dispositions, so they can be chained to create a tombstone
static struct sigaction g_old_segv_act = {};
static struct sigaction g_old_abrt_act = {};
static struct sigaction g_old_bus_act = {};
static struct sigaction g_old_ill_act = {};

static char g_altstack[SIGSTKSZ * 4];

bool registerAssistSigHandlers() {
  int ret = -1;

  // Setup auxiliary stack
  stack_t ss = {};
  ss.ss_sp = g_altstack;
  ss.ss_size = sizeof(g_altstack);
  ss.ss_flags = 0;

  ret = sigaltstack(&ss, nullptr);
  if (ret != 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "sigaltstack failed (errno: %s)", strerror(errno));
    return false;
  }

  // Unified act for important signals
  struct sigaction act = {};
  act.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
  act.sa_sigaction = &bipan_broker_signal_handler;

  ret = sigemptyset(&act.sa_mask);
  if (ret != 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "sigemptyset failed (errno: %s)", strerror(errno));
    return false;
  }

  // Register the actual signal handlers for their corresponding signals
  ret = sigaction(SIGSEGV, &act, &g_old_segv_act);
  if (ret != 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "sigaction(SIGSEGV) failed (errno: %s)", strerror(errno));
    return false;
  }

  ret = sigaction(SIGABRT, &act, &g_old_abrt_act);
  if (ret != 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "sigaction(SIGABRT) failed (errno: %s)", strerror(errno));
    return false;
  }

  ret = sigaction(SIGBUS, &act, &g_old_bus_act);
  if (ret != 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "sigaction(SIGBUS) failed (errno: %s)", strerror(errno));
    return false;
  }

  ret = sigaction(SIGILL, &act, &g_old_ill_act);
  if (ret != 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "sigaction(SIGILL) failed (errno: %s)", strerror(errno));
    return false;
  }

  write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Assist handlers registered on altstack, size=%zu", sizeof(g_altstack));
  return true;
}

/**
 * TODO:
 * - think of something which allows `write_to_logcat_async` to be AS-safe with
 * diagnostic information (`%`)
 * - Backtrace printing should be before `kill_current_client`, but for now the 
 * priority is eliminating the deadlock
 */
static void bipan_broker_signal_handler(int sig, siginfo_t* info, void* void_context) {
  (void)info;
  (void)void_context;

  switch (sig) {
    case SIGABRT: {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Broker got SIGABRT");
      break;
    }
    case SIGSEGV: {
      if (info->si_code == SEGV_MAPERR) {
        write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Broker got SIGSEGV of type SEGV_MAPERR");
      } else if (info->si_code == SEGV_ACCERR) {
        write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Broker got SIGSEGV of type SEGV_ACCERR");
      } else {
        write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Broker got SIGSEGV of unknown type");
      }
      break;
    }
    case SIGBUS: {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Broker got SIGBUS");
      break;
    }
    case SIGILL: {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Broker got SIGILL");
      break;
    }
    default: {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!!!] Broker unknown signal");
      break;
    }
  }

  kill_current_client();
  print_backtrace();
}

static void kill_current_client() {
  if (g_current_client_pid <= 0) {
    return;
  }

  write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Broker dead. Killing orphaned client");
  arm64_raw_syscall(__NR_kill, g_current_client_pid, SIGKILL, 0, 0, 0, 0);
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

static int capture_backtrace(void** out_frames, int max_frames) {
  BacktraceState state = {out_frames, 0, max_frames};
  _Unwind_Backtrace(unwind_callback, &state);
  return state.count;
}

/**
 * TODO: extensive use of `unwind.h`and `dlfcn.h` exports.
 * Definitely NOT AS-safe.
 */
static void print_backtrace() {
  void* frames[MAX_FRAMES_BROKER_ASSIST];
  int count = capture_backtrace(frames, MAX_FRAMES_BROKER_ASSIST);

  for (int i = 0; i < count; i++) {
    Dl_info info;
    if (dladdr(frames[i], &info) && info.dli_sname) {
      uintptr_t offset = (uintptr_t)frames[i] - (uintptr_t)info.dli_saddr;
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "#%02d pc %p %s (%s+0x%lx)",
                            i, frames[i],
                            info.dli_fname ? info.dli_fname : "?",
                            info.dli_sname,
                            (unsigned long)offset);
    } else if (dladdr(frames[i], &info) && info.dli_fname) {
      uintptr_t offset = (uintptr_t)frames[i] - (uintptr_t)info.dli_fbase;
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "#%02d pc 0x%lx %s", i, (unsigned long)offset, info.dli_fname);
    } else {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "#%02d pc %p <unknown>", i, frames[i]);
    }
  }
}
