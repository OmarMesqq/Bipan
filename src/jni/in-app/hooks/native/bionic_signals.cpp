#include "bionic_signals.hpp"

#include <dlfcn.h>
#include <signal.h>

#include <cstring>

#include "../../../logger/logger.hpp"
#include "common_utils.hpp"
#include "deps/dobby.h"
#include "in-app/globals.hpp"

#define SIGNALS_TAG "BipanSignals"

#define BIONIC_SIGNAL_SYM_1 "sigaction"
#define BIONIC_SIGNAL_SYM_2 "signal"
#define BIONIC_SIGNAL_SYM_3 "bsd_signal"
#define BIONIC_SIGNAL_SYM_4 "sigprocmask"
#define BIONIC_SIGNAL_SYM_5 "pthread_sigmask"
#define BIONIC_SIGNAL_SYM_6 "sigsuspend"
#define BIONIC_SIGNAL_SYM_7 "signalfd"
#define BIONIC_METHODS_COUNT 7

// Original functions
static int (*orig_sigaction)(int, const struct sigaction*, struct sigaction*) = nullptr;
static sighandler_t (*orig_signal)(int, sighandler_t) = nullptr;
static int (*orig_signalfd)(int, const sigset_t*, int) = nullptr;
static int (*orig_sigprocmask)(int, const sigset_t*, sigset_t*) = nullptr;
static int (*orig_sigsuspend)(const sigset_t*) = nullptr;
static int (*orig_pthread_sigmask)(int, const sigset_t*, sigset_t*) = nullptr;

// Hooks
static int hook_sigaction(int signum, const struct sigaction* act, struct sigaction* oldact);
static sighandler_t hook_signal(int signum, sighandler_t handler);
static int hook_signalfd(int fd, const sigset_t* mask, int flags);
static int hook_sigprocmask(int how, const sigset_t* set, sigset_t* oldset);
static int hook_sigsuspend(const sigset_t* mask);
static int hook_pthread_sigmask(int how, const sigset_t* set, sigset_t* oldset);

// Helpers
static void dump_sigset(const sigset_t* set, char* out, size_t out_size);

void registerDobbyBionicSignalHooks(void) {
  const int bionicSignalMethodsCount = 7;

  const char* symbols[] = {
      BIONIC_SIGNAL_SYM_1,
      BIONIC_SIGNAL_SYM_2,
      BIONIC_SIGNAL_SYM_4,
      BIONIC_SIGNAL_SYM_5,
      BIONIC_SIGNAL_SYM_6,
      BIONIC_SIGNAL_SYM_7,

  };

  void* hooks[] = {
      (void*)hook_sigaction,
      (void*)hook_signal,
      (void*)hook_signalfd,
      (void*)hook_sigprocmask,
      (void*)hook_sigsuspend,
      (void*)hook_pthread_sigmask,
  };

  void** originals[] = {
      (void**)&orig_sigaction,
      (void**)&orig_signal,
      (void**)&orig_signalfd,
      (void**)&orig_sigprocmask,
      (void**)&orig_sigsuspend,
      (void**)&orig_pthread_sigmask,
  };

  for (int i = 0; i < bionicSignalMethodsCount; i++) {
    void* addr = dlsym(RTLD_DEFAULT, symbols[i]);
    if (!addr) {
      write_to_logcat_async(ANDROID_LOG_FATAL, SIGNALS_TAG, "[!] Failed to resolve: %s", symbols[i]);
      continue;
    }

    int rc = DobbyHook(addr, hooks[i], originals[i]);
    if (rc != 0) {
      write_to_logcat_async(ANDROID_LOG_FATAL, SIGNALS_TAG, "[!] Failed to hook: %s", symbols[i]);
      BIPAN_PANIC();
    }

    __builtin___clear_cache((char*)addr, (char*)addr + 32);
    write_to_logcat_async(ANDROID_LOG_DEBUG, SIGNALS_TAG, "Dobby hooked: %s", symbols[i]);
  }
}

static int hook_sigaction(int signum, const struct sigaction* act, struct sigaction* oldact) {
  if (signum == SIGSYS) {
    write_to_logcat_async(ANDROID_LOG_DEBUG, SIGNALS_TAG, "[sigaction] for SIGSYS!");
  }
  if (act) {  // cheap non-zero check before formatting, optional
    char maskbuf[256] = {0};
    dump_sigset(&act->sa_mask, maskbuf, sizeof(maskbuf));
    write_to_logcat_async(ANDROID_LOG_DEBUG, SIGNALS_TAG, "[sigaction] sig=%d mask=%s", signum, maskbuf);
  }
  return orig_sigaction(signum, act, oldact);
}

static sighandler_t hook_signal(int signum, sighandler_t handler) {
  if (signum == SIGSYS) {
    write_to_logcat_async(ANDROID_LOG_DEBUG, SIGNALS_TAG, "[signal] for SIGSYS!", signum);
  }
  return (orig_signal(signum, handler));
}

static int hook_signalfd(int fd, const sigset_t* mask, int flags) {
  if (mask) {
    char maskbuf[256] = {0};
    dump_sigset(mask, maskbuf, sizeof(maskbuf));
    write_to_logcat_async(ANDROID_LOG_DEBUG, SIGNALS_TAG, "[signalfd] fd=%d flags=%d mask=%s", fd, flags, maskbuf);
  }
  return orig_signalfd(fd, mask, flags);
}

static int hook_sigprocmask(int how, const sigset_t* set, sigset_t* oldset) {
  if (set) {
    char maskbuf[256] = {0};
    dump_sigset(set, maskbuf, sizeof(maskbuf));
    write_to_logcat_async(ANDROID_LOG_DEBUG, SIGNALS_TAG, "[sigprocmask] how=%d mask=%s", how, maskbuf);
  }
  return orig_sigprocmask(how, set, oldset);
}

static int hook_sigsuspend(const sigset_t* mask) {
  if (mask) {
    char maskbuf[256] = {0};
    dump_sigset(mask, maskbuf, sizeof(maskbuf));
    write_to_logcat_async(ANDROID_LOG_DEBUG, SIGNALS_TAG, "[sigsuspend] mask=%s", maskbuf);
  }
  return orig_sigsuspend(mask);
}

static int hook_pthread_sigmask(int how, const sigset_t* set, sigset_t* oldset) {
  if (set) {
    char maskbuf[256] = {0};
    dump_sigset(set, maskbuf, sizeof(maskbuf));
    write_to_logcat_async(ANDROID_LOG_DEBUG, SIGNALS_TAG, "[pthread_sigmask] how=%d mask=%s", how, maskbuf);
  }
  return orig_pthread_sigmask(how, set, oldset);
}

// Helpers
static void dump_sigset(const sigset_t* set, char* out, size_t out_size) {
  if (!set) {
    snprintf(out, out_size, "(null)");
    return;
  }

  out[0] = '\0';
  size_t used = 0;

  for (int sig = 1; sig < NSIG; sig++) {
    int member = sigismember(set, sig);
    if (member < 0) {
      // sigismember returns -1 + EINVAL for signal numbers it doesn't
      // recognize; just skip those rather than aborting the dump.
      continue;
    }
    if (member == 1) {
      const char* name = strsignal(sig);  // bionic provides this
      int written = snprintf(out + used, out_size - used, "%s%s(%d)",
                             used > 0 ? "," : "", name ? name : "?", sig);
      if (written < 0 || (size_t)written >= out_size - used) {
        break;  // truncated
      }
      used += (size_t)written;
    }
  }

  if (used == 0) {
    snprintf(out, out_size, "(empty)");
  }
}