#include <android/log.h>
#include <android/sensor.h>
#include <android/looper.h>
#include <jni.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/fcntl.h>
#include <sys/system_properties.h>
#include <time.h>
#include <errno.h>
#include "test_runner.h"
#include <stdlib.h>
#include <sys/types.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <link.h>
#include <stdint.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/auxv.h>
#include <dlfcn.h>
#include <sys/wait.h>

#include "socket_helper.h"

#define TAG "GrunfeldNative"
#define MAX_REPORT_SIZE 8192

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#define PACKAGE_NAME "com.omarmesqq.grunfeld"
#define LOOPER_ID_USER 8998
#define SENSORS_SAMPLING_RATE 20000 // 50Hz (20ms)
#define LOCAL_SOCKET "/data/data/com.omarmesqq.grunfeld/ipc_socket"

/**
 * func-like macro to convert negative error values provided by the kernel to raw syscalls
 * back to nice libc/bionic errnos
 */
#define RAW_SYSCALL_TO_ERRNO(ret) strerror((int)-ret)


static inline void early_init_sysprop_tests(void);
static inline void early_init_stat_tests(void);
static const char* proto_to_str(int proto);
static const char* fam_to_str(int fam);
static void sigsys_log_handler(int sig, siginfo_t* info, void* void_context);
static inline long arm64_raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5);
static void get_sys_prop(const char* key, char* out_val, size_t max_len, const char* default_val);
static void prop_cb(void* cookie, const char* name, const char* value, uint32_t serial);
static inline void dump (void *p, int n, char* report);
static int dlIteratePhdrCallback(struct dl_phdr_info *info, size_t size, void *data);
static inline unsigned char starts_with(const char* str, const char* prefix);

__attribute__((constructor)) void grunfeld_early_init(void) {
    early_init_sysprop_tests();
    early_init_stat_tests();

    LOGI("Early init: __attribute__((constructor))");
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testForkExec(JNIEnv *env, jobject thiz, jstring progname) {
    char tmpBuffer[512] = {0};
    pid_t pid = fork();
    if (pid == -1) {
        snprintf(tmpBuffer, sizeof(tmpBuffer), "'fork' failed. errno: %s", strerror(errno));
        return (*env)->NewStringUTF(env, tmpBuffer);
    }

    if (pid == 0) {
        LOGI("Child: fork succeeded");
        sleep(2); // some delay to let log above to appear

        const char* path = "/system/bin/uname";
        char* const argv[] = {"uname", "-a", NULL};
        // char *const envp[] = {NULL};

        int execRet = execve(path, argv, environ);
        LOGE("[!] Something bad happened: execve returned. ret:%d | errno: %s", execRet, strerror(errno));
        _exit(execRet);
    }

    int wstatus = 0;
    /**
     * Suspends this calling thread (which is probably Main Thread (?), as it's called from MainActivity)
     * wait for any child process (`-1`), writes results into `wstatus`, and return immediately if no child has exited (`WNOHANG`)
     */
    pid_t waitRes = waitpid(-1, &wstatus, WNOHANG);
    if (waitRes == -1) {
        snprintf(tmpBuffer, sizeof(tmpBuffer), "'waitpid' failed. errno: %s", strerror(errno));
        return (*env)->NewStringUTF(env, tmpBuffer);
    }
    char finalReport[1024] = {0};

    snprintf(tmpBuffer, sizeof(tmpBuffer), "waitpid result: %d\n", waitRes);
    strcat(finalReport, tmpBuffer);

    if (WIFEXITED(wstatus)) {
        snprintf(tmpBuffer, sizeof(tmpBuffer), "Child terminated normally. Exit code: %d\n", WEXITSTATUS(wstatus));
        strcat(finalReport, tmpBuffer);
    }
    if (WIFSIGNALED(wstatus)) {
        snprintf(tmpBuffer, sizeof(tmpBuffer), "[!] Child terminated by signal: %d\n", WTERMSIG(wstatus));
        strcat(finalReport, tmpBuffer);
        if (WCOREDUMP(wstatus)) {
            snprintf(tmpBuffer, sizeof(tmpBuffer), "Child produced core dump.\n");
            strcat(finalReport, tmpBuffer);
        }
    }
    if (WIFSTOPPED(wstatus)) {
        snprintf(tmpBuffer, sizeof(tmpBuffer), "[! likely ptrace] Child stopped by a signal: %d\n", WSTOPSIG(wstatus));
        strcat(finalReport, tmpBuffer);
    }
    if (WIFCONTINUED(wstatus)) {
        snprintf(tmpBuffer, sizeof(tmpBuffer), "Child was resumed i.e. got SIGCONT\n");
        strcat(finalReport, tmpBuffer);
    }

    return (*env)->NewStringUTF(env, finalReport);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testProcSelfTask(JNIEnv *env, jobject thiz) {
    DIR *dir = opendir("/proc/self/task");
    if (!dir) {
        return (*env)->NewStringUTF(env, "Failed to open /proc/self/task");
    }

    char result[4096] = {0};
    size_t offset = 0;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Skip . and ..
        if (entry->d_name[0] == '.') continue;

        // Read /proc/self/task/<tid>/comm
        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/self/task/%s/comm", entry->d_name);

        int comm_fd = open(comm_path, O_RDONLY);
        if (comm_fd < 0) continue;

        char thread_name[64] = {0};
        ssize_t n = read(comm_fd, thread_name, sizeof(thread_name) - 1);
        close(comm_fd);

        if (n > 0) {
            // Strip trailing newline
            if (thread_name[n - 1] == '\n') thread_name[n - 1] = '\0';

            offset += (size_t) snprintf(result + offset, sizeof(result) - offset, "[%s] %s\n",entry->d_name, thread_name);
        }
    }

    closedir(dir);
    return (*env)->NewStringUTF(env, result[0] ? result : "No threads found");
}

JNIEXPORT jstring JNICALL Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testProcSelfAuxv(JNIEnv *env, jobject thiz) {
    char report[MAX_REPORT_SIZE] = {0};
    char entry[512] = {0};

    static const unsigned long types[] = {
            AT_PHDR, AT_PHNUM, AT_PAGESZ, AT_BASE, AT_ENTRY,
            AT_RANDOM, AT_HWCAP, AT_HWCAP2, AT_CLKTCK,
            AT_UID, AT_EUID, AT_GID, AT_EGID, AT_SECURE, AT_PLATFORM,
            AT_EXECFN, AT_EXECFD, AT_PHENT, AT_NOTELF,
            AT_RSEQ_FEATURE_SIZE, AT_RSEQ_ALIGN, AT_HWCAP3, AT_HWCAP4, AT_MINSIGSTKSZ,
            AT_NULL, AT_IGNORE, AT_FLAGS, AT_BASE_PLATFORM
    };

    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        unsigned long type = types[i];
        unsigned long val = getauxval(type);

        switch (type) {
            case AT_PHDR:     snprintf(entry, sizeof(entry), "AT_PHDR     = %#lx\n", val); break;
            case AT_PHNUM:    snprintf(entry, sizeof(entry), "AT_PHNUM    = %lu\n",  val); break;
            case AT_PAGESZ:   snprintf(entry, sizeof(entry), "AT_PAGESZ   = %lu\n",  val); break;
            case AT_BASE:     snprintf(entry, sizeof(entry), "AT_BASE     = %#lx\n", val); break;
            case AT_ENTRY:    snprintf(entry, sizeof(entry), "AT_ENTRY    = %#lx\n", val); break;
            case AT_RANDOM:   snprintf(entry, sizeof(entry), "AT_RANDOM   = %#lx\n", val); break;
            case AT_HWCAP:    snprintf(entry, sizeof(entry), "AT_HWCAP    = %#lx\n", val); break;
            case AT_HWCAP2:   snprintf(entry, sizeof(entry), "AT_HWCAP2   = %#lx\n", val); break;
            case AT_CLKTCK:   snprintf(entry, sizeof(entry), "AT_CLKTCK   = %lu\n",  val); break;
            case AT_UID:      snprintf(entry, sizeof(entry), "AT_UID      = %lu\n",  val); break;
            case AT_EUID:     snprintf(entry, sizeof(entry), "AT_EUID     = %lu\n",  val); break;
            case AT_GID:      snprintf(entry, sizeof(entry), "AT_GID      = %lu\n",  val); break;
            case AT_EGID:     snprintf(entry, sizeof(entry), "AT_EGID     = %lu\n",  val); break;
            case AT_SECURE:   snprintf(entry, sizeof(entry), "AT_SECURE   = %lu\n",  val); break;
            case AT_PLATFORM: snprintf(entry, sizeof(entry), "AT_PLATFORM = %s\n",   (char*)val); break;
            case AT_EXECFN:   snprintf(entry, sizeof(entry), "AT_EXECFN   = %s\n",  (char*)val); break;
            case AT_EXECFD:           snprintf(entry, sizeof(entry), "AT_EXECFD           = %lu\n",  val); break;
            case AT_PHENT:            snprintf(entry, sizeof(entry), "AT_PHENT            = %lu\n",  val); break;
            case AT_NOTELF:           snprintf(entry, sizeof(entry), "AT_NOTELF           = %lu\n",  val); break;
            case AT_RSEQ_FEATURE_SIZE:snprintf(entry, sizeof(entry), "AT_RSEQ_FEATURE_SIZE= %lu\n",  val); break;
            case AT_RSEQ_ALIGN:       snprintf(entry, sizeof(entry), "AT_RSEQ_ALIGN       = %lu\n",  val); break;
            case AT_HWCAP3:           snprintf(entry, sizeof(entry), "AT_HWCAP3           = %#lx\n", val); break;
            case AT_HWCAP4:           snprintf(entry, sizeof(entry), "AT_HWCAP4           = %#lx\n", val); break;
            case AT_MINSIGSTKSZ:      snprintf(entry, sizeof(entry), "AT_MINSIGSTKSZ      = %lu\n",  val); break;
            case AT_FLAGS:            snprintf(entry, sizeof(entry), "AT_FLAGS            = %#lx\n", val); break;
            case AT_BASE_PLATFORM:    snprintf(entry, sizeof(entry), "AT_BASE_PLATFORM    = %s\n",   (char*)val); break;
            case AT_NULL:             snprintf(entry, sizeof(entry), "AT_NULL             = %lu\n",  val); break;
            case AT_IGNORE:           snprintf(entry, sizeof(entry), "AT_IGNORE           = %lu\n",  val); break;
            default:                  snprintf(entry, sizeof(entry), "type(key): %lu -> no value\n",  type); break;
        }
        strncat(report, entry, sizeof(report) - strlen(report) - 1);
    }

    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_dl_1iterate_1phdrTest(JNIEnv *env, jobject thiz) {
    char* report = (char*) calloc(50000, sizeof(char));
    if (!report) {
        return (*env)->NewStringUTF(env, "Failed to allocate mem for report!");
    }
    dl_iterate_phdr(dlIteratePhdrCallback, report);

    jstring result = (*env)->NewStringUTF(env, report);
    free(report);
    return result;
}


JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_getDeviceData(JNIEnv *env, jobject thiz, jobject context) {

    // ── 1. System properties (native reads — bypasses Java Build fields) ──
    char board[PROP_VALUE_MAX]        = {0};
    char bootloader[PROP_VALUE_MAX]   = {0};
    char brand[PROP_VALUE_MAX]        = {0};
    char device[PROP_VALUE_MAX]       = {0};
    char display[PROP_VALUE_MAX]      = {0};
    char fingerprint[PROP_VALUE_MAX]  = {0};
    char hardware[PROP_VALUE_MAX]     = {0};
    char host[PROP_VALUE_MAX]         = {0};
    char build_id[PROP_VALUE_MAX]     = {0};
    char manufacturer[PROP_VALUE_MAX] = {0};
    char model[PROP_VALUE_MAX]        = {0};
    char odm_sku[PROP_VALUE_MAX]      = {0};
    char product[PROP_VALUE_MAX]      = {0};
    char sku[PROP_VALUE_MAX]          = {0};
    char soc_mfr[PROP_VALUE_MAX]      = {0};
    char soc_model[PROP_VALUE_MAX]    = {0};
    char abi1[PROP_VALUE_MAX]         = {0};
    char abi2[PROP_VALUE_MAX]         = {0};
    char abi3[PROP_VALUE_MAX]         = {0};
    char tags[PROP_VALUE_MAX]         = {0};
    char type[PROP_VALUE_MAX]         = {0};
    char user[PROP_VALUE_MAX]         = {0};
    char radio[PROP_VALUE_MAX]        = {0};
    char base_os[PROP_VALUE_MAX]      = {0};
    char codename[PROP_VALUE_MAX]     = {0};
    char incremental[PROP_VALUE_MAX]  = {0};
    char release[PROP_VALUE_MAX]      = {0};
    char release_or_codename[PROP_VALUE_MAX]       = {0};
    char release_or_preview_display[PROP_VALUE_MAX] = {0};
    char security_patch[PROP_VALUE_MAX] = {0};

    get_sys_prop("ro.product.board",              board,                      sizeof(board),                      "unknown");
    get_sys_prop("ro.bootloader",                 bootloader,                 sizeof(bootloader),                 "unknown");
    get_sys_prop("ro.product.brand",              brand,                      sizeof(brand),                      "unknown");
    get_sys_prop("ro.product.device",             device,                     sizeof(device),                     "unknown");
    get_sys_prop("ro.build.display.id",           display,                    sizeof(display),                    "unknown");
    get_sys_prop("ro.build.fingerprint",          fingerprint,                sizeof(fingerprint),                "unknown");
    get_sys_prop("ro.hardware",                   hardware,                   sizeof(hardware),                   "unknown");
    get_sys_prop("ro.build.host",                 host,                       sizeof(host),                       "unknown");
    get_sys_prop("ro.build.id",                   build_id,                   sizeof(build_id),                   "unknown");
    get_sys_prop("ro.product.manufacturer",       manufacturer,               sizeof(manufacturer),               "unknown");
    get_sys_prop("ro.product.model",              model,                      sizeof(model),                      "unknown");
    get_sys_prop("ro.product.odm.sku",            odm_sku,                    sizeof(odm_sku),                    "unknown");
    get_sys_prop("ro.product.name",               product,                    sizeof(product),                    "unknown");
    get_sys_prop("ro.boot.product.hardware.sku",  sku,                        sizeof(sku),                        "unknown");
    get_sys_prop("ro.soc.manufacturer",           soc_mfr,                    sizeof(soc_mfr),                    "unknown");
    get_sys_prop("ro.soc.model",                  soc_model,                  sizeof(soc_model),                  "unknown");
    get_sys_prop("ro.product.cpu.abilist",        abi1,                       sizeof(abi1),                       "unknown");
    get_sys_prop("ro.product.cpu.abilist32",      abi2,                       sizeof(abi2),                       "unknown");
    get_sys_prop("ro.product.cpu.abilist64",      abi3,                       sizeof(abi3),                       "unknown");
    get_sys_prop("ro.build.tags",                 tags,                       sizeof(tags),                       "unknown");
    get_sys_prop("ro.build.type",                 type,                       sizeof(type),                       "unknown");
    get_sys_prop("ro.build.user",                 user,                       sizeof(user),                       "unknown");
    get_sys_prop("gsm.version.baseband",          radio,                      sizeof(radio),                      "unknown");
    get_sys_prop("ro.build.version.base_os",      base_os,                    sizeof(base_os),                    "");
    get_sys_prop("ro.build.version.codename",     codename,                   sizeof(codename),                   "unknown");
    get_sys_prop("ro.build.version.incremental",  incremental,                sizeof(incremental),                "unknown");
    get_sys_prop("ro.build.version.release",      release,                    sizeof(release),                    "unknown");
    get_sys_prop("ro.build.version.release_or_codename",        release_or_codename,        sizeof(release_or_codename),        "unknown");
    get_sys_prop("ro.build.version.release_or_preview_display", release_or_preview_display, sizeof(release_or_preview_display), "unknown");
    get_sys_prop("ro.build.version.security_patch", security_patch,           sizeof(security_patch),             "unknown");

    // TIME is ro.build.date.utc (seconds) — Build.TIME is milliseconds
    char build_date_utc[32] = {0};
    get_sys_prop("ro.build.date.utc", build_date_utc, sizeof(build_date_utc), "0");
    long long build_time_ms = atoll(build_date_utc) * 1000LL;

    // SDK_INT
    char sdk_str[16] = {0};
    get_sys_prop("ro.build.version.sdk", sdk_str, sizeof(sdk_str), "0");
    int sdk_int = atoi(sdk_str);

    // PREVIEW_SDK_INT
    char preview_sdk_str[16] = {0};
    get_sys_prop("ro.build.version.preview_sdk", preview_sdk_str, sizeof(preview_sdk_str), "0");
    int preview_sdk_int = atoi(preview_sdk_str);

    // ── 2. Settings.Global via JNI ────────────────────────────────────────
    jclass contextClass     = (*env)->GetObjectClass(env, context);
    jmethodID getResolver   = (*env)->GetMethodID(env, contextClass,
                                                  "getContentResolver",
                                                  "()Landroid/content/ContentResolver;");
    jobject resolver        = (*env)->CallObjectMethod(env, context, getResolver);

    jclass globalClass      = (*env)->FindClass(env, "android/provider/Settings$Global");
    jmethodID getStr        = (*env)->GetStaticMethodID(env, globalClass, "getString",
                                                        "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;");
    jmethodID getInt        = (*env)->GetStaticMethodID(env, globalClass, "getInt",
                                                        "(Landroid/content/ContentResolver;Ljava/lang/String;I)I");

    jstring jDeviceNameKey  = (*env)->NewStringUTF(env, "device_name");
    jstring jDeviceName     = (*env)->CallStaticObjectMethod(env, globalClass, getStr,
                                                             resolver, jDeviceNameKey);
    const char *deviceName  = jDeviceName
                              ? (*env)->GetStringUTFChars(env, jDeviceName, NULL)
                              : "unknown";

    jstring jAdbKey         = (*env)->NewStringUTF(env, "adb_enabled");
    jstring jDevSettKey     = (*env)->NewStringUTF(env, "development_settings_enabled");
    jstring jBootCountKey   = (*env)->NewStringUTF(env, "boot_count");
    jstring jWaitDbgKey     = (*env)->NewStringUTF(env, "wait_for_debugger");

    jint adbEnabled         = (*env)->CallStaticIntMethod(env, globalClass, getInt,
                                                          resolver, jAdbKey,      -999);
    jint devSettings        = (*env)->CallStaticIntMethod(env, globalClass, getInt,
                                                          resolver, jDevSettKey,  -999);
    jint bootCount          = (*env)->CallStaticIntMethod(env, globalClass, getInt,
                                                          resolver, jBootCountKey,-999);
    jint waitForDebugger    = (*env)->CallStaticIntMethod(env, globalClass, getInt,
                                                          resolver, jWaitDbgKey,  -999);

    // Settings.Secure: ANDROID_ID
    jclass secureClass      = (*env)->FindClass(env, "android/provider/Settings$Secure");
    jmethodID getSecureStr  = (*env)->GetStaticMethodID(env, secureClass, "getString",
                                                        "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;");
    jstring jSsaidKey       = (*env)->NewStringUTF(env, "android_id");
    jstring jSsaid          = (*env)->CallStaticObjectMethod(env, secureClass, getSecureStr,
                                                             resolver, jSsaidKey);
    const char *ssaid       = jSsaid
                              ? (*env)->GetStringUTFChars(env, jSsaid, NULL)
                              : "unknown";

    // ── 3. Build output ───────────────────────────────────────────────────
    char buffer[4096] = {0};
    snprintf(buffer, sizeof(buffer),
             "BOARD: %s\n"
             "BOOTLOADER: %s\n"
             "BRAND: %s\n"
             "DEVICE: %s\n"
             "DISPLAY: %s\n"
             "FINGERPRINT: %s\n"
             "HARDWARE: %s\n"
             "HOST: %s\n"
             "ID: %s\n"
             "MANUFACTURER: %s\n"
             "MODEL: %s\n"
             "ODM_SKU: %s\n"
             "PRODUCT: %s\n"
             "SKU: %s\n"
             "SOC_MANUFACTURER: %s\n"
             "SOC_MODEL: %s\n"
             "SUPPORTED_CPU_ABIs: %s\n"
             "SUPPORTED_CPU_ABIs_32: %s\n"
             "SUPPORTED_CPU_ABIs_64: %s\n"
             "TAGS: %s\n"
             "TIME: %lld\n"
             "TYPE: %s\n"
             "USER: %s\n"
             "RADIO: %s\n"
             "BASE_OS: %s\n"
             "CODENAME: %s\n"
             "INCREMENTAL: %s\n"
             "PREVIEW_SDK_INT: %d\n"
             "RELEASE: %s\n"
             "RELEASE_OR_CODENAME: %s\n"
             "RELEASE_OR_PREVIEW_DISPLAY: %s\n"
             "SDK_INT: %d\n"
             "SECURITY_PATCH: %s\n"
             "\n"
             "DEVICE_NAME: %s\n"
             "SSAID: %s\n"
             "ADB_ENABLED: %d\n"
             "DEV_SETTINGS_ON: %d\n"
             "BOOT_COUNT: %d\n"
             "WAIT_FOR_DEBUGGER: %d",
             board, bootloader, brand, device, display, fingerprint,
             hardware, host, build_id, manufacturer, model,
             odm_sku, product, sku, soc_mfr, soc_model,
             abi1, abi2, abi3, tags, build_time_ms, type, user,
             radio, base_os, codename, incremental,
             preview_sdk_int, release, release_or_codename,
             release_or_preview_display, sdk_int, security_patch,
             deviceName, ssaid, adbEnabled, devSettings, bootCount, waitForDebugger);

    // ── 4. Cleanup ────────────────────────────────────────────────────────
    if (jSsaid)       { (*env)->ReleaseStringUTFChars(env, jSsaid, ssaid);           (*env)->DeleteLocalRef(env, jSsaid); }
    if (jDeviceName)  { (*env)->ReleaseStringUTFChars(env, jDeviceName, deviceName); (*env)->DeleteLocalRef(env, jDeviceName); }

    (*env)->DeleteLocalRef(env, jSsaidKey);
    (*env)->DeleteLocalRef(env, jWaitDbgKey);
    (*env)->DeleteLocalRef(env, jBootCountKey);
    (*env)->DeleteLocalRef(env, jDevSettKey);
    (*env)->DeleteLocalRef(env, jAdbKey);
    (*env)->DeleteLocalRef(env, jDeviceNameKey);
    (*env)->DeleteLocalRef(env, secureClass);
    (*env)->DeleteLocalRef(env, globalClass);
    (*env)->DeleteLocalRef(env, resolver);
    (*env)->DeleteLocalRef(env, contextClass);

    return (*env)->NewStringUTF(env, buffer);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_getifaddrs(JNIEnv *env, jobject thiz) {
    struct ifaddrs *ifaddr;
    const char* successBuf = "SUCCESS";
    const char* failBuf = "FAILED";

    if (getifaddrs(&ifaddr) == -1) {
        LOGE("getifaddrs failed! Errno: %d", errno);
        return (*env)->NewStringUTF(env, failBuf);
    }

    return (*env)->NewStringUTF(env, successBuf);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_inspectHooks(JNIEnv *env, jobject thiz) {
    char finalReport[MAX_REPORT_SIZE] = {0};
    char entry[256];
    int bytesToInspect = 28;

    snprintf(entry, sizeof(entry), "dlopen at %p. First %d bytes:\n\n", (void *) dlopen, bytesToInspect);
    strcat(finalReport, entry);
    dump((void*) dlopen, bytesToInspect, finalReport);

    // TODO: android_dlopen_ext

    snprintf(entry, sizeof(entry), "\ndl_iterate_phdr at %p. First %d bytes:\n\n", (void *) dl_iterate_phdr, bytesToInspect);
    strcat(finalReport, entry);
    dump((void*) dl_iterate_phdr, bytesToInspect, finalReport);

    snprintf(entry, sizeof(entry), "__system_property_get at %p. First %d bytes:\n\n", (void *) __system_property_get, bytesToInspect);
    strcat(finalReport, entry);
    dump((void*) __system_property_get, bytesToInspect, finalReport);

    snprintf(entry, sizeof(entry), "\n__system_property_read_callback at %p. First %d bytes:\n\n", (void *) __system_property_read_callback, bytesToInspect);
    strcat(finalReport, entry);
    dump((void*) __system_property_read_callback, bytesToInspect, finalReport);


    snprintf(entry, sizeof(entry), "\nASensorManager_getInstance at %p. First %d bytes:\n\n", (void *) ASensorManager_getInstance, bytesToInspect);
    strcat(finalReport, entry);
    dump((void*) ASensorManager_getInstance, bytesToInspect, finalReport);

    snprintf(entry, sizeof(entry), "\nASensorManager_getInstanceForPackage at %p. First %d bytes:\n\n", (void *) ASensorManager_getInstanceForPackage, bytesToInspect);
    strcat(finalReport, entry);
    dump((void*) ASensorManager_getInstanceForPackage, bytesToInspect, finalReport);

    snprintf(entry, sizeof(entry), "\nASensorManager_getSensorList at %p. First %d bytes:\n\n", (void *) ASensorManager_getSensorList, bytesToInspect);
    strcat(finalReport, entry);
    dump((void*) ASensorManager_getSensorList, bytesToInspect, finalReport);

    snprintf(entry, sizeof(entry), "\nASensorManager_getDefaultSensor at %p. First %d bytes:\n\n", (void *) ASensorManager_getDefaultSensor, bytesToInspect);
    strcat(finalReport, entry);
    dump((void*) ASensorManager_getDefaultSensor, bytesToInspect, finalReport);

    snprintf(entry, sizeof(entry), "\nASensorManager_createEventQueue at %p. First %d bytes:\n\n", (void *) ASensorManager_createEventQueue, bytesToInspect);
    strcat(finalReport, entry);
    dump((void*) ASensorManager_createEventQueue, bytesToInspect, finalReport);


    // Not hooked
    snprintf(entry, sizeof(entry), "\n__system_property_find at %p. First %d bytes:\n\n", (void *) __system_property_find, bytesToInspect);
    strcat(finalReport, entry);
    dump((void*) __system_property_find, bytesToInspect, finalReport);

    return (*env)->NewStringUTF(env, finalReport);
}

/**
 * TODO: xref with fdinfo?
 */
JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_getallsocketfds(JNIEnv *env, jobject thiz) {
    const char* path = "/proc/self/fd";
    char report[16384] = {0};
    size_t used = 0;
    report[0] = '\0';

    struct DIR* dir = opendir(path);
    if (dir == NULL) {
        return (*env)->NewStringUTF(env, "Failed to open directory");
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        // Build "/proc/self/fd/<entry>"
        char linkpath[PATH_MAX];
        int ret = snprintf(linkpath, sizeof(linkpath), "%s/%s", path, entry->d_name);
        if (ret < 0 || (size_t)ret >= sizeof(linkpath)) {
            continue;
        }

        // Read symlink target
        char target[PATH_MAX];
        ssize_t len = readlink(linkpath, target, sizeof(target) - 1);
        if (len < 0) {
            continue;
        }
        target[len] = '\0';

        if (!starts_with(target, "socket")) {
            continue;
        }

        int line = snprintf(report + used, sizeof(report) - used, "%s -> %s\n", entry->d_name, target);
        if (line < 0 || (size_t)line >= sizeof(report) - used) {
            break;
        }
        used += (size_t)line;
    }

    closedir(dir);
    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_getprocselfmapsFd(JNIEnv *env, jobject thiz) {
    const char* path = "/proc/self/maps";

    long fd = arm64_raw_syscall(__NR_openat, (long)AT_FDCWD, (long)path, (long)O_RDONLY, 0, 0, 0);
    if (fd == -1) {
        return (*env)->NewStringUTF(env, "Failed to openat(/proc/self/maps)");
    }

    const char* selfFdPath = "/proc/self/fd";
    char report[16384] = {0};
    size_t used = 0;
    report[0] = '\0';

    struct DIR* dir = opendir(selfFdPath);
    if (!dir) {
        return (*env)->NewStringUTF(env, "Failed to opendir(/proc/self/fd)");
    }


    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        // skip . and ..
        if (entry->d_name[0] == '.') {
            continue;
        }

        // Interested only in /proc/self/maps fd
        int conversionRet = atoi(entry->d_name);
        if (conversionRet != fd) {
            continue;
        }

        // Build "/proc/self/fd/<entry>"
        char linkpath[PATH_MAX];
        int ret = snprintf(linkpath, sizeof(linkpath), "%s/%s", selfFdPath, entry->d_name);
        if (ret < 0 || (size_t)ret >= sizeof(linkpath)) {
            continue;
        }

        // Read symlink target
        char target[PATH_MAX];
        ssize_t len = readlink(linkpath, target, sizeof(target) - 1);
        if (len < 0) {
            continue;
        }
        target[len] = '\0';

        int line = snprintf(report + used, sizeof(report) - used, "%s -> %s\n", entry->d_name, target);
        if (line < 0 || (size_t)line >= sizeof(report) - used) {
            break;
        }
        used += (size_t)line;
    }

    closedir(dir);
    close((int) fd);
    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testBind(JNIEnv *env, jobject thiz) {
    char report[MAX_REPORT_SIZE] = {0};
    char entry[256] = {0};
    long ret = 0;

    #define ADDRESS_COUNT 5
    #define PORT_COUNT 2
    #define PROTO_COUNT 2
    #define FAM_COUNT 2

    const char* addresses[ADDRESS_COUNT] = {
            "127.0.0.1", // IPv4 localhost
            "::1", // IPv6 localhost
            "0.0.0.0", // IPv4 unspecified
            "::", // IPv6 unspecified
            "10.111.222.1", // phone lan ip
    };

    const int ports[PORT_COUNT] = { RANDOM_EPHEMERAL_PORT,ARBITRARY_PORT };
    const SockType protocols[PROTO_COUNT] = { TCP, UDP };
    const SockFamily families[FAM_COUNT] = { IPv4, IPv6 };

    SockFactoryRes* res = NULL;
    for (int fam_idx = 0; fam_idx < FAM_COUNT; fam_idx++) {
        SockFamily fam = families[fam_idx];

        for (int addr_idx = 0; addr_idx < ADDRESS_COUNT; addr_idx++) {
            const char* addr_str = addresses[addr_idx];

            // Simple check: Don't try IPv4 strings with IPv6 family and vice versa
            bool is_v6_str = (strchr(addr_str, ':') != NULL);
            if ((fam == IPv4 && is_v6_str) || (fam == IPv6 && !is_v6_str && strcmp(addr_str, "localhost") != 0)) {
                continue;
            }

            for (int port_idx = 0; port_idx < PORT_COUNT; port_idx++) {
                for (int proto_idx = 0; proto_idx < 2; proto_idx++) {
                    res = CreateSocket(fam, protocols[proto_idx], addr_str, ports[port_idx], 0, 0);
                    if (!res) {
                        snprintf(entry, sizeof(entry), "Failed to create socket!\n");
                        strcat(report, entry);
                        continue;
                    }

                    ret = (fam == IPv4)
                               ? arm64_raw_syscall(__NR_bind, res->sock, (long)&res->sas.sas4, sizeof(res->sas.sas4), 0,0,0)
                               : arm64_raw_syscall(__NR_bind, res->sock, (long)&res->sas.sas6, sizeof(res->sas.sas6), 0,0,0);

                    snprintf(entry, sizeof(entry), "%s:%d | %s | %s | res: %s\n",
                             addr_str, ports[port_idx], proto_to_str((int) protocols[proto_idx]), fam_to_str((int) fam), ret == 0 ? "SUCESS" : "FAILED");
                    strcat(report, entry);

                    close(res->sock);
                    free(res);
                }
            }
            strcat(report, "\n");
        }
    }
    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testListen(JNIEnv *env, jobject thiz) {
    char report[MAX_REPORT_SIZE] = {0};
    char entry[256] = {0};
    long ret = 0;

    SockFactoryRes* res = CreateSocket(IPv4, TCP, "0.0.0.0", RANDOM_EPHEMERAL_PORT, 0, 0);
    if (!res) {
        return (*env)->NewStringUTF(env, "Failed to create socket!\n");
    }

    const int backlog = 10;
    ret = arm64_raw_syscall(__NR_listen, res->sock, backlog, 0, 0, 0, 0);

    snprintf(entry, sizeof(entry), "Result: %s\n", ret == 0 ? "SUCCESS" : "FAILED");
    strcat(report, entry);

    close(res->sock);
    free(res);
    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testSocket(JNIEnv *env, jobject thiz) {
    char report[MAX_REPORT_SIZE] = {0};
    char entry[256] = {0};

    SockFactoryRes* res = CreateSocket(Netlink, Raw, 0, 0, 0, NetlinkRoute);
    if (!res) {
        return (*env)->NewStringUTF(env, "Failed to create socket!\n");
    }
    close(res->sock);
    free(res);
    return (*env)->NewStringUTF(env, "OK");
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testSendto(JNIEnv *env, jobject thiz) {
    char report[MAX_REPORT_SIZE] = {0};
    char entry[256] = {0};
    // Multicast / LAN Discovery
    const char* msg = "M-SEARCH * HTTP/1.1";

    const int port_ssdp_upnp = 1900;
    const char* ipv4_multicast_addr = "239.255.255.250";
    SockFactoryRes* res = CreateSocket(IPv4, UDP, ipv4_multicast_addr, port_ssdp_upnp, 0, 0);
    if (!res) {
        return (*env)->NewStringUTF(env, "Failed to create socket!\n");
    }

    long ret = arm64_raw_syscall(__NR_sendto, res->sock, (long)msg, (long)strlen(msg), 0, (long)&res->sas.sas4, sizeof(res->sas.sas4));

    snprintf(entry, sizeof(entry), "Result: %ld bytes sent to %s\n", ret, ipv4_multicast_addr);
    strcat(report, entry);

    close(res->sock);
    free(res);
    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testGetsockname(JNIEnv *env, jobject thiz) {
    long ret = 0;
    char report[MAX_REPORT_SIZE] = {0};
    char entry[256] = {0};

    // As Bipan blocks binds to local IPs, we connect to a WAN IP and then check the socket to see if it leaks the local IP
    const int port_dns = 53;
    const char* cloudflareDnsIp4 = "1.1.1.1";
    SockFactoryRes* res = CreateSocket(IPv4, UDP, cloudflareDnsIp4, port_dns, 0, 0);
    if (!res) {
        return (*env)->NewStringUTF(env, "Failed to create socket!\n");
    }

    // use standard connect (Bipan allows public internet)
    if (connect(res->sock, (struct sockaddr*)&res->sas.sas4, sizeof(res->sas.sas4)) == -1) {
        snprintf(entry, sizeof(entry), "connect failed \n");
        strcat(report, entry);

        close(res->sock);
        free(res);
        return (*env)->NewStringUTF(env, report);
    }

    struct sockaddr_in leaked_addr;
    socklen_t len = sizeof(leaked_addr);

    ret = arm64_raw_syscall(__NR_getsockname, res->sock, (long)&leaked_addr, (long)&len, 0, 0, 0);

    if (ret == 0) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &leaked_addr.sin_addr, ip, INET_ADDRSTRLEN);
        snprintf(entry, sizeof(entry), "socket IP: %s\n", ip);
    } else {
        snprintf(entry, sizeof(entry), "failed with ret: %ld\n", ret);
    }

    strcat(report, entry);
    close(res->sock);
    free(res);
    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testSendmsg(JNIEnv *env, jobject thiz) {
    char report[MAX_REPORT_SIZE] = {0};
    char entry[256] = {0};

    #define DEST_ADDR "10.111.222.3"
    SockFactoryRes* res = CreateSocket(IPv4, UDP, DEST_ADDR, ARBITRARY_PORT, 0, 0);
    if (!res) {
        return (*env)->NewStringUTF(env, "Failed to create socket!\n");
    }

    // Data to be sent using the Scatter/Gather (iovec) structure
    char* data1 = "Message Header - ";
    char* data2 = "Hello from sendmsg!";

    struct iovec iov[2];
    iov[0].iov_base = data1;
    iov[0].iov_len = strlen(data1);

    iov[1].iov_base = data2;
    iov[1].iov_len = strlen(data2);

    //  msghdr structure
    struct msghdr msg = {0};
    msg.msg_name = &res->sas.sas4; // Destination address
    msg.msg_namelen = sizeof(res->sas.sas4);
    msg.msg_iov = iov;             // Pointer to the array of iovecs
    msg.msg_iovlen = 2;            // Number of elements in the iovec array

    long ret = arm64_raw_syscall(__NR_sendmsg, res->sock, (long)&msg, 0, 0, 0, 0);
    snprintf(entry, sizeof(entry), "Result: %ld bytes sent to %s\n", ret, DEST_ADDR);
    strcat(report, entry);

    close(res->sock);
    free(res);
    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_getUname(JNIEnv *env, jobject thiz) {
    struct utsname buffer = {0};
    long ret;
    __asm__ volatile(
            "mov x0, %[buf] \n\t"   // place `buffer`'s address in x0
            "mov x8, #160   \n\t"   // 160 is the syscall number for uname
            "svc #0         \n\t"   // Supervisor Call
            "mov %[res], x0 \n\t"   // Store return value in ret
            : [res] "=r"(ret)       // Output operand
    : [buf] "r"(&buffer)    // Input operand
    : "x0", "x8", "memory"  // Clobbered registers
    );

    if (ret < 0) {
        return (*env)->NewStringUTF(env, "Error: uname syscall failed");
    }

    char result_str[512];
    snprintf(result_str, sizeof(result_str),
             "System: %s\nNode: %s\nRelease: %s\nVersion: %s\nMachine: %s\nDomain Name: %s",
             buffer.sysname,
             buffer.nodename,
             buffer.release,
             buffer.version,
             buffer.machine,
             buffer.domainname
             );

    return (*env)->NewStringUTF(env, result_str);
}

JNIEXPORT jboolean JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_installSigsysHandler(JNIEnv* env, jobject thiz) {
  struct sigaction sa = {0};
  sa.sa_sigaction = sigsys_log_handler;
  sa.sa_flags = SA_SIGINFO;

  long ret = arm64_raw_syscall(__NR_rt_sigaction, SIGSYS, (long)&sa, 0, 8, 0, 0);
  if (ret != 0) {
      return JNI_FALSE;
  }

  return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_blockSigSys(JNIEnv* env, jobject thiz) {
    sigset_t mask;

    // 1. Initialize an empty signal set
    sigemptyset(&mask);

    // 2. Add SIGSYS to the set
    sigaddset(&mask, SIGSYS);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
        return JNI_FALSE;
    } else {
        return JNI_TRUE;
    }
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_queryProcStatus(JNIEnv* env, jobject thiz) {
    FILE* fp = fopen("/proc/self/status", "r");
    if (fp == NULL) {
        return (*env)->NewStringUTF(env, "Unable to open /proc/self/status");
    }

    char report[2048] = {0};
    char line[256] = {0};

    // Define the prefixes of the relevant lines you want to keep
    const char* relevant_prefixes[] = {
            "Name:",
            "State:",
            "Pid:",
            "PPid:",
            "TracerPid:",
            "Threads:",
            "NoNewPrivs:",
            "Seccomp:",
            "Cpus_allowed_list:"
    };
    int num_prefixes = sizeof(relevant_prefixes) / sizeof(relevant_prefixes[0]);

    // Read the status file line by line
    while (fgets(line, sizeof(line), fp)) {
        for (int i = 0; i < num_prefixes; i++) {
            if (strncmp(line, relevant_prefixes[i], strlen(relevant_prefixes[i])) == 0) {
                // Ensure buffer has enough space
                if (strlen(report) + strlen(line) < sizeof(report) - 1) {
                    strcat(report, line);
                } else {
                    // Truncate if we exceed the buffer
                    break;
                }
                break;
            }
        }
    }

    fclose(fp);

    // Return the filtered report to the JVM
    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testSensors(JNIEnv *env, jobject thiz) {
    char result_buffer[512];
    char* status_msg;
    char* queue_msg;

    // On API >= 26 we get the sensor sensorManager for our specific package
    ASensorManager* sensorManager = ASensorManager_getInstanceForPackage(PACKAGE_NAME);

    if (!sensorManager) {
        return (*env)->NewStringUTF(env, "Sensor Manager is NULL!");
    }

    // Enumerate all sensors
    ASensorList list;
    int count = ASensorManager_getSensorList(sensorManager, &list);

    if (count == 0) {
        status_msg = "SUCCESS: 0 Sensors found (Blocked)";
    } else {
        status_msg = "LEAK: Sensors detected";
        for (int i = 0; i < count; i++) {
            const char* name = ASensor_getName(list[i]);
            const char* vendor = ASensor_getVendor(list[i]);
            int type = ASensor_getType(list[i]);
            LOGI("Sensor name: %s, Vendor: %s, Type: %d", name, vendor, type);
        }
    }

    // Get some famous sensors
    const ASensor* accel = ASensorManager_getDefaultSensor(sensorManager, ASENSOR_TYPE_ACCELEROMETER);
    const ASensor* gyro = ASensorManager_getDefaultSensor(sensorManager, ASENSOR_TYPE_GYROSCOPE);
    if (!accel || !gyro) {
        LOGE("Accelerometer and or Gyroscope handle is NULL!");
    }

    // Get a looper for the current thread
    ALooper* looper = ALooper_prepare(ALOOPER_PREPARE_ALLOW_NON_CALLBACKS);
    if (!looper) {
        LOGE("[Sensors] Failed to get looper!\n");
    }

    // Create an event queue get streamed sensor data
    ASensorEventQueue* queue = ASensorManager_createEventQueue(sensorManager, looper, LOOPER_ID_USER, NULL, NULL);
    if (queue == NULL) {
        queue_msg = "SUCCESS: Event Queue Blocked";
    } else {
        queue_msg = "LEAK: Event Queue Created";

        // Add the "famous" sensors to the event stream queue
        ASensorEventQueue_enableSensor(queue, accel);
        ASensorEventQueue_enableSensor(queue, gyro);
        // and set the rate at which their data is transmitted
        ASensorEventQueue_setEventRate(queue, accel, SENSORS_SAMPLING_RATE);
        ASensorEventQueue_setEventRate(queue, gyro, SENSORS_SAMPLING_RATE);


        // Calculate the end time for our loop:  current time  + 3 seconds
        struct timespec start_time, current_time;
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        double start_secs = (double)start_time.tv_sec + (double)start_time.tv_nsec / 1e9;
        double end_secs = start_secs + 3.0;

        int ident;      // Identifier of the event source
        int events;     // Number of events available
        void* data;     // User data
        ASensorEvent event;

        // Polling loop
        bool sampling = true;
        // Change timeout from -1 to 100 (ms).
        // If it's -1, the loop "sleeps" until a sensor moves.
        // If the phone is still, it won't check the 3-second limit!
        while (sampling && (ident = ALooper_pollOnce(100, NULL, &events, &data)) >= ALOOPER_POLL_WAKE) {
            // Check if 3 seconds have passed and break if so
            clock_gettime(CLOCK_MONOTONIC, &current_time);
            double now = (double) current_time.tv_sec + (double)current_time.tv_nsec / 1e9;
            if (now >= end_secs) {
                sampling = false;
                continue;
            }

            // If the event came from our sensor queue, do stuff
            if (ident == LOOPER_ID_USER) {
                while (ASensorEventQueue_getEvents(queue, &event, 1) > 0) {
                    if (event.type == ASENSOR_TYPE_ACCELEROMETER) {
                        LOGI("Accel X: %f, Y: %f, Z: %f",
                             event.acceleration.x,
                             event.acceleration.y,
                             event.acceleration.z);
                    } else if (event.type == ASENSOR_TYPE_GYROSCOPE) {
                        LOGI("Gyro X: %f, Y: %f, Z: %f",
                             event.vector.x,
                             event.vector.y,
                             event.vector.z);
                    }
                }
            }
        }

        // Cleanup
        ASensorEventQueue_disableSensor(queue, accel);
        ASensorEventQueue_disableSensor(queue, gyro);
        ASensorManager_destroyEventQueue(sensorManager, queue);
    }

    // Format the final on-screen report
    snprintf(result_buffer, sizeof(result_buffer),
             "Sensor Count: %d\n%s\n%s",
             count, status_msg, queue_msg);

    return (*env)->NewStringUTF(env, result_buffer);
}

static const char* proto_to_str(int proto) {
    switch (proto) {
        case TCP: return "TCP";
        case UDP: return "UDP";
        default:  return "UNKNOWN_PROTO";
    }
}

static const char* fam_to_str(int fam) {
    switch (fam) {
        case IPv4: return "IPv4";
        case IPv6: return "IPv6";
        case Unix: return "Unix";
        default:   return "UNKNOWN_FAM";
    }
}

static void sigsys_log_handler(int sig, siginfo_t* info, void* void_context) {
  LOGE("Should never reach here...");
  _exit(-1);
}

static void get_sys_prop(const char* key, char* out_val, size_t max_len, const char* default_val) {
    int len = __system_property_get(key, out_val);
    if (len <= 0) {
        strncpy(out_val, default_val, max_len);
    }
}

static void prop_cb(void* cookie, const char* name, const char* value, uint32_t serial) {
    char* out = (char*)cookie;
    if (!out) {
        return;
    }
    strncpy(out, value, PROP_VALUE_MAX);
    out[PROP_VALUE_MAX] = '\0';
}

static inline void early_init_sysprop_tests(void) {
    char radio1[PROP_VALUE_MAX]  = {0};
    int len = __system_property_get("gsm.version.baseband", radio1);
    if (len <= 0) {
        strncpy(radio1, "gsm.version.baseband", sizeof(radio1));
    }

    const prop_info* pi = __system_property_find("gsm.version.baseband");
    char radio2[PROP_VALUE_MAX] = {0};
    if (pi) {
        __system_property_read_callback(pi, prop_cb, radio2);
    } else {
        strncpy(radio2, "gsm.version.baseband", sizeof(radio2));
    }

    char operator[PROP_VALUE_MAX] = {0};

    int len1 = __system_property_get("gsm.operator.alpha", operator);
    if (len1 <= 0) {
        strncpy(operator, "gsm.operator.alpha", sizeof(operator));
    }

    char fp[PROP_VALUE_MAX] = {0};

    int len2 = __system_property_get("ro.build.fingerprint", fp);
    if (len2 <= 0) {
        strncpy(fp, "ro.build.fingerprint", sizeof(fp));
    }

    LOGI("[LEGACY] RADIO: %s", radio1);
    LOGI("[MODERN] RADIO: %s", radio2);
    LOGI("[LEGACY] OPERATOR: %s", operator);
    LOGI("[LEGACY] FINGERPRINT: %s", fp);
}

static inline void early_init_stat_tests(void) {
    const char* hosts1 = "/etc/hosts";
    const char* hosts2 = "/system/etc/hosts";
    const char* perfEventParanoid = "/proc/sys/kernel/perf_event_paranoid";
    long ret = 0; // result of syscall


    // ----------------- start faccessat block ----------------------

    int faccessatMode1 = F_OK; // tests existence of file
    int faccessatMode2 = R_OK | W_OK | X_OK; // exists, has read, write, execute perms
    int faccessatMode3 = R_OK; // exists and has read

    int faccessatFlags1 = AT_EACCESS; // performs access using effective UID and GID
    int faccessatFlags2 = AT_SYMLINK_NOFOLLOW; // if symlink, return info about symlink
    int faccessatFlags3 = AT_SYMLINK_NOFOLLOW | AT_EACCESS;


    // should fail: requested permissions not satisfied
    ret = arm64_raw_syscall(__NR_faccessat, 0 , (long) hosts1, faccessatMode2, faccessatFlags1, 0, 0);
    if (ret == 0) {
        LOGI("faccessat(%s) - mode: R_OK | W_OK | X_OK - flags: AT_EACCESS -> SUCCESSFUL", hosts1);
    } else {
        LOGE("faccessat(%s) - mode: R_OK | W_OK | X_OK - flags: AT_EACCESS -> FAILED: %s", hosts1, RAW_SYSCALL_TO_ERRNO(ret));
    }

    // should return zero: perms granted
    ret = arm64_raw_syscall(__NR_faccessat, 0 , (long) hosts1, faccessatMode3, faccessatFlags1, 0, 0);
    if (ret == 0) {
        LOGI("faccessat(%s) - mode: R_OK - flags: AT_EACCESS -> SUCCESSFUL", hosts1);
    } else {
        LOGE("faccessat(%s) - mode: R_OK - flags: AT_EACCESS -> FAILED: %s", hosts1, RAW_SYSCALL_TO_ERRNO(ret));
    }

    // should return zero: mode is F_OK and file exists requested permissions granted
    ret = arm64_raw_syscall(__NR_faccessat, 0 , (long) hosts1, faccessatMode1, faccessatFlags1, 0, 0);
    if (ret == 0) {
        LOGI("faccessat(%s) - mode: F_OK - flags: AT_EACCESS -> SUCCESSFUL", hosts1);
    } else {
        LOGE("faccessat(%s) - mode: F_OK - flags: AT_EACCESS -> FAILED: %s", hosts1, RAW_SYSCALL_TO_ERRNO(ret));
    }

    // ----------------- end faccessat block ----------------------

    // ----------------- start newfstatat block ----------------------


    struct stat statbuf = {0};
    // if path = "", operate on the file referred to by dirfd
    // If path is a symbolic link, do not dereference it: instead return information about the link itself
    int newfstatatFlags = AT_EMPTY_PATH  | AT_SYMLINK_NOFOLLOW;

    ret = arm64_raw_syscall(__NR_newfstatat, 0 , (long) hosts1, (long) &statbuf, newfstatatFlags, 0, 0);
    if (ret == 0) {
        LOGI("newfstatat(%s) - flags: AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW -> SUCCESSFUL", hosts1);
        LOGI("--- struct stat Dump ---");
        LOGI("st_dev (Device ID):     %lu", (unsigned long)statbuf.st_dev);
        LOGI("st_ino (inode number):     %lu", (unsigned long)statbuf.st_ino);
        LOGI("Hard link count:   %lu", (unsigned long)statbuf.st_nlink);
        LOGI("UID:     %u", statbuf.st_uid);
        LOGI("GID:     %u", statbuf.st_gid);
        LOGI("st_rdev (Device ID for special files i.e under /dev):    %lu", (unsigned long)statbuf.st_rdev);
        LOGI("Size:    %ld bytes", (long)statbuf.st_size);
        LOGI("I/O Block Size (preferred size for doing I/O): %d bytes", statbuf.st_blksize);
        LOGI("Allocated Physical Blocks:  %ld (512B blocks)", statbuf.st_blocks);

        // Timestamps
        char access_time_str[64];
        char modify_time_str[64];
        char change_time_str[64];
        struct tm tm_info;

        // 1. Format Access Time
        localtime_r(&statbuf.st_atim.tv_sec, &tm_info);
        strftime(access_time_str, sizeof(access_time_str), "%Y-%m-%d %H:%M:%S", &tm_info);

        // 2. Format Modification Time
        localtime_r(&statbuf.st_mtim.tv_sec, &tm_info);
        strftime(modify_time_str, sizeof(modify_time_str), "%Y-%m-%d %H:%M:%S", &tm_info);

        // 3. Format Status Change Time
        localtime_r(&statbuf.st_ctim.tv_sec, &tm_info);
        strftime(change_time_str, sizeof(change_time_str), "%Y-%m-%d %H:%M:%S", &tm_info);

        // Log the human-readable versions with their nanoseconds appended
        LOGI("Access time:         %s.%09ld", access_time_str, statbuf.st_atim.tv_nsec);
        LOGI("Modification time:   %s.%09ld", modify_time_str, statbuf.st_mtim.tv_nsec);
        LOGI("Status Change Time (last time file metadata changed):  %s.%09ld", change_time_str, statbuf.st_ctim.tv_nsec);

        // st_mode: file type + permission/special flags
        // LOGI("st_mode:    0o%o (Octal)", statbuf.st_mode);
        const char* file_type = "Unknown";
        if (S_ISREG(statbuf.st_mode))  file_type = "Regular File";
        else if (S_ISDIR(statbuf.st_mode))  file_type = "Directory";
        else if (S_ISLNK(statbuf.st_mode))  file_type = "Symbolic Link";
        else if (S_ISCHR(statbuf.st_mode))  file_type = "Character Device";
        else if (S_ISBLK(statbuf.st_mode))  file_type = "Block Device";
        else if (S_ISFIFO(statbuf.st_mode)) file_type = "FIFO/Pipe";
        else if (S_ISSOCK(statbuf.st_mode)) file_type = "Socket";

        LOGI("  -> File Type: %s", file_type);

        // 2. Extract Special Flags (SUID, SGID, Sticky Bit)
        LOGI("  -> Special Flags: SUID=%d, SGID=%d, Sticky=%d",
             (statbuf.st_mode & S_ISUID) ? 1 : 0,
             (statbuf.st_mode & S_ISGID) ? 1 : 0,
             (statbuf.st_mode & S_ISVTX) ? 1 : 0);

        // 3. Extract Permissions (Owner, Group, Other)
        LOGI("  -> Permissions: User(%c%c%c) Group(%c%c%c) Other(%c%c%c)",
             (statbuf.st_mode & S_IRUSR) ? 'r' : '-',
             (statbuf.st_mode & S_IWUSR) ? 'w' : '-',
             (statbuf.st_mode & S_IXUSR) ? 'x' : '-',

             (statbuf.st_mode & S_IRGRP) ? 'r' : '-',
             (statbuf.st_mode & S_IWGRP) ? 'w' : '-',
             (statbuf.st_mode & S_IXGRP) ? 'x' : '-',

             (statbuf.st_mode & S_IROTH) ? 'r' : '-',
             (statbuf.st_mode & S_IWOTH) ? 'w' : '-',
             (statbuf.st_mode & S_IXOTH) ? 'x' : '-');
    } else {
        LOGE("newfstatat(%s) - flags: flags: AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW -> FAILED: %s", hosts1, RAW_SYSCALL_TO_ERRNO(ret));
    }

    // ----------------- end newfstatat block ----------------------

    // ----------------- start statx block ----------------------

    struct statx statxbuf = {0};
    int statxFlags = AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW;
    int statxMode = STATX_BASIC_STATS | STATX_BTIME;

    /**
     * int statx(
     *          int dirfd,
     *          const char *_Nullable restrict path,
     *          int flags,
     *          unsigned int mask,
     *          struct statx *restrict statxbuf
     * )
     */
    ret = arm64_raw_syscall(__NR_statx, 0 , (long) hosts1, (long) statxFlags, statxMode, (long) &statxbuf, 0);
    if (ret == 0) {
        LOGI("statx(%s) - mode: STATX_BASIC_STATS | STATX_BTIME - flags: AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW -> SUCCESSFUL", hosts1);
    } else {
        LOGE("statx(%s) - mode: STATX_BASIC_STATS | STATX_BTIME - flags: AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW -> FAILED: %s", hosts1, RAW_SYSCALL_TO_ERRNO(ret));
    }

    // ----------------- end statx block ----------------------

}

static inline void dump(void *p, int n, char *report) {
    char entry[64];
    unsigned char *p1 = p;
    while (n--) {
        if (n % 4 == 0) {
            snprintf(entry, sizeof(entry), "%02x\n", *p1);
        }
        else {
            snprintf(entry, sizeof(entry), "%02x ", *p1);
        }
        strcat(report, entry);
        p1++;
    }
}

static int dlIteratePhdrCallback(struct dl_phdr_info *info, size_t size, void *data) {
    char *type;
    int p_type;

    char entry[512];
    snprintf(entry, sizeof(entry), "%s (%d segments)\n", info->dlpi_name, info->dlpi_phnum);
    strcat((char*)data, entry);

    for (size_t j = 0; j < info->dlpi_phnum; j++) {
        if (!strstr(info->dlpi_name, "memfd"))  {
            continue;
        }
        p_type = info->dlpi_phdr[j].p_type;
        type = (p_type == PT_LOAD) ? "PT_LOAD" :
               (p_type == PT_DYNAMIC) ? "PT_DYNAMIC" :
               (p_type == PT_INTERP) ? "PT_INTERP" :
               (p_type == PT_NOTE) ? "PT_NOTE" :
               (p_type == PT_INTERP) ? "PT_INTERP" :
               (p_type == PT_PHDR) ? "PT_PHDR" :
               (p_type == PT_TLS) ? "PT_TLS" :
               (p_type == PT_GNU_EH_FRAME) ? "PT_GNU_EH_FRAME" :
               (p_type == PT_GNU_STACK) ? "PT_GNU_STACK" :
               (p_type == PT_GNU_RELRO) ? "PT_GNU_RELRO" : NULL;

        snprintf(entry, sizeof(entry), "    %2zu: [%14p; memsz:%7jx] flags: %#jx; ",  j,
                 (void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr),
                 (uintmax_t) info->dlpi_phdr[j].p_memsz,
                 (uintmax_t) info->dlpi_phdr[j].p_flags);
        strcat((char*)data, entry);

        if (type != NULL) {
            snprintf(entry, sizeof(entry), "%s\n", type);
        }
        else {
            snprintf(entry, sizeof(entry), "[other (%#x)]\n", p_type);
        }
        strcat((char*)data, entry);
    }
    return 0;
}

static inline unsigned char starts_with(const char* str, const char* prefix) {
    return strncmp(str, prefix, strlen(prefix)) == 0;
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
