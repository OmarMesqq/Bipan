#include "athena.h"
#include <signal.h>
#include <unwind.h>
#include <dlfcn.h>
#include <jni.h>
#include <errno.h>
#include <string.h>
#include <android/log.h>
#include <sys/syscall.h>

#define TAG "Athena"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGF(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#define MAX_FRAMES 20

typedef struct {
    void** frames;
    int    count;
    int    max;
} BacktraceState;

static _Unwind_Reason_Code unwind_callback(struct _Unwind_Context* context, void* arg);
static int capture_backtrace(void** out_frames, int max_frames);
static void print_native_backtrace(void);
static void athena_sig_handler(int sig, siginfo_t* info, void* void_context);
static inline long arm64_raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5);

static char g_altstack[SIGSTKSZ * 4];
static struct sigaction g_old_segv_act = {0}; // SIGSEGV
static struct sigaction g_old_abrt_act = {0}; // SIGABRT
static struct sigaction g_old_trap_act = {0}; // SIGTRAP
static struct sigaction g_old_quit_act = {0}; // SIGQUIT


void athenaInit(void) {
    int ret = -1;

    // Setup auxiliary stack
    stack_t ss = {0};
    ss.ss_sp = g_altstack;
    ss.ss_size = sizeof(g_altstack);
    ss.ss_flags = 0;

    ret = sigaltstack(&ss, NULL);
    if (ret != 0) {
        LOGE("sigaltstack failed (errno: %s)", strerror(errno));
        return;
    }

    // Unified act for important signals
    struct sigaction act = {0};
    act.sa_flags = SA_SIGINFO | SA_ONSTACK;
    act.sa_sigaction = &athena_sig_handler;

    ret = sigemptyset(&act.sa_mask);
    if (ret != 0) {
        LOGE("sigemptyset failed (errno: %s)", strerror(errno));
        return;
    }

    // Register the actual signal handlers for their corresponding signals
    ret = sigaction(SIGSEGV, &act, &g_old_segv_act);
    if (ret != 0) {
        LOGE("sigaction(SIGSEGV) failed (errno: %s)", strerror(errno));
        return;
    }

    ret = sigaction(SIGABRT, &act, &g_old_abrt_act);
    if (ret != 0) {
        LOGE("sigaction(SIGABRT) failed (errno: %s)", strerror(errno));
        return;
    }

    ret = sigaction(SIGTRAP, &act, &g_old_trap_act);
    if (ret != 0) {
        LOGE("sigaction(SIGTRAP) failed (errno: %s)", strerror(errno));
        return;
    }

    ret = sigaction(SIGQUIT, &act, &g_old_quit_act);
    if (ret != 0) {
        LOGE("sigaction(SIGQUIT) failed (errno: %s)", strerror(errno));
        return;
    }

    LOGI("Athena initialized successfully!");
}

void requestNativeBacktrace(void) {
    print_native_backtrace();
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
    BacktraceState state = { out_frames, 0, max_frames };
    _Unwind_Backtrace(unwind_callback, &state);
    return state.count;
}

static void print_native_backtrace(void) {
    void* frames[MAX_FRAMES];
    int count = capture_backtrace(frames, MAX_FRAMES);

    for (int i = 0; i < count; i++) {
        Dl_info info;
        if (dladdr(frames[i], &info) && info.dli_sname) {
            uintptr_t offset = (uintptr_t)frames[i] - (uintptr_t)info.dli_saddr;
            LOGF("#%02d pc %p %s (%s+0x%lx)",
                 i, frames[i],
                 info.dli_fname ? info.dli_fname : "?",
                 info.dli_sname,
                 (unsigned long)offset);
        } else if (dladdr(frames[i], &info) && info.dli_fname) {
            uintptr_t offset = (uintptr_t)frames[i] - (uintptr_t)info.dli_fbase;
            LOGF("#%02d pc 0x%lx %s",i, (unsigned long)offset, info.dli_fname);
        } else {
            LOGF("#%02d pc %p <unknown>", i, frames[i]);
        }
    }
}

static void athena_sig_handler(int sig, siginfo_t* info, void* void_context) {
    switch (sig) {
        case SIGABRT: {
            LOGE("App got SIGABRT!");
            break;
        }
        case SIGSEGV: {
            switch (info->si_code) {
                case SEGV_MAPERR: {
                    LOGE("App got SIGSEGV SEGV_MAPERR");
                    break;
                }
                case SEGV_ACCERR: {
                    LOGE("App got SIGSEGV SEGV_ACCERR");
                    break;
                }
                default: {
                    LOGE("App got unknown SIGSEGV");
                    break;
                }
            }
            break;
        }
        case SIGTRAP: {
            LOGE("App got SIGTRAP");
            break;
        }
        case SIGQUIT: {
            LOGE("App got SIGQUIT");
            break;
        }
        default: {
            LOGF("App got unknown signal!");
            break;
        }
    }
    
    // TODO: not AS-safe
    print_native_backtrace();
    arm64_raw_syscall(__NR_exit_group, -1, 0, 0, 0, 0, 0);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wregister"
__attribute__((always_inline))  static inline long arm64_raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5) {
    register long x8 __asm__("x8") = sysno;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;

    __asm__ volatile(
            "svc #0\n"
            : "+r"(x0)
            : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
            : "memory", "cc"
            );

    return x0;
}
#pragma clang diagnostic pop
