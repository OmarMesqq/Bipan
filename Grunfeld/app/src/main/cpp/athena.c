#include "athena.h"
#include <signal.h>
#include <unwind.h>
#include <dlfcn.h>
#include <jni.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <android/log.h>

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
static void print_java_backtrace(JNIEnv *env);
static void athena_sig_handler(int sig, siginfo_t* info, void* void_context);

static char g_altstack[SIGSTKSZ * 4];
static struct sigaction g_old_segv_act = {0}; // SIGSEGV
static struct sigaction g_old_abrt_act = {0}; // SIGABRT
static JNIEnv* g_jniEnv = NULL;


void athenaInit(JNIEnv* env) {
    if (env == NULL) {
        LOGE("athenaInit: received null JNIEnv pointer. Won't install.");
        return;
    }
    g_jniEnv = env;
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
    act.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
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

    LOGI("Athena initialized successfully!");
}

void requestNativeBacktrace(void) {
    print_native_backtrace();
}

void requestJavaBacktrace(void) {
    print_java_backtrace(g_jniEnv);
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

static void print_java_backtrace(JNIEnv *env) {
    if (env == NULL) {
        LOGE("print_java_backtrace: received null JNIEnv pointer. Won't dump Java stacktrace");
        return;
    }

    jclass throwableClass = (*env)->FindClass(env, "java/lang/Throwable");
    jmethodID ctor = (*env)->GetMethodID(env, throwableClass, "<init>", "()V");
    jobject throwable = (*env)->NewObject(env, throwableClass, ctor);

    jmethodID getStackTrace = (*env)->GetMethodID(env, throwableClass,
                                                  "getStackTrace", "()[Ljava/lang/StackTraceElement;");
    jobjectArray stackTrace = (jobjectArray)(*env)->CallObjectMethod(env, throwable, getStackTrace);

    jsize len = (*env)->GetArrayLength(env, stackTrace);
    jclass steClass = (*env)->FindClass(env, "java/lang/StackTraceElement");
    jmethodID toString = (*env)->GetMethodID(env, steClass, "toString", "()Ljava/lang/String;");

    for (jsize i = 0; i < len; i++) {
        jobject frame = (*env)->GetObjectArrayElement(env, stackTrace, i);
        jstring str = (jstring)(*env)->CallObjectMethod(env, frame, toString);
        const char* cstr = (*env)->GetStringUTFChars(env, str, NULL);
        LOGF("Java frame #%d: %s", i, cstr);
        (*env)->ReleaseStringUTFChars(env, str, cstr);
        (*env)->DeleteLocalRef(env, str);
        (*env)->DeleteLocalRef(env, frame);
    }
}

static void athena_sig_handler(int sig, siginfo_t* info, void* void_context) {
    if (sig == SIGABRT) {
        LOGE("App got SIGABRT!");
    } else if (sig == SIGSEGV) {
        if (info->si_code == SEGV_MAPERR) {
            LOGE("App got SIGSEGV SEGV_MAPERR");
        } else if (info->si_code == SEGV_ACCERR) {
            LOGE("App got SIGSEGV SEGV_ACCERR");
        } else {
            LOGE("App got unknown SIGSEGV(%d)", info->si_code);
        }
    } else {
        LOGF("App got unknown signal: %d", sig);
    }
    
    print_native_backtrace();
    print_java_backtrace(g_jniEnv);
    _exit(-1);
}
