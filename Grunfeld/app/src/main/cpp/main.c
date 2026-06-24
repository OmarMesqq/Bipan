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

#include "shared.h"
#include "socket_helper.h"

jmp_buf jump_buffer;

#define TAG "GrunfeldNative"
#define MAX_REPORT_SIZE 8192

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#define PACKAGE_NAME "com.omarmesqq.grunfeld"
#define LOOPER_ID_USER 8998
#define SENSORS_SAMPLING_RATE 20000 // 50Hz (20ms)
#define LOCAL_SOCKET "/data/data/com.omarmesqq.grunfeld/ipc_socket"


static inline void early_init_sysprop_test(void);
static const char* proto_to_str(int proto);
static const char* fam_to_str(int fam);
static void sigsys_log_handler(int sig, siginfo_t* info, void* void_context);
static inline long arm64_raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5);
static void get_sys_prop(const char* key, char* out_val, size_t max_len, const char* default_val);
static void prop_cb(void* cookie, const char* name, const char* value, uint32_t serial);
 static inline void dump (void *p, int n, char* report);
 static inline void print_bytes(void *p, int n);

__attribute__((constructor))
void grunfeld_early_init(void) {
    early_init_sysprop_test();

    LOGI("Early init: __attribute__((constructor))");
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
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_inspectLibcHooks(JNIEnv *env, jobject thiz) {
    char finalReport[8192] = {0};
    char entry[256];
    int bytesToInspect = 28;

    snprintf(entry, sizeof(entry), "__system_property_get at %p. First %d bytes:\n\n", (void *) __system_property_get, bytesToInspect);
    strcat(finalReport, entry);
    dump((void*) __system_property_get, bytesToInspect, finalReport);

    snprintf(entry, sizeof(entry), "\n__system_property_find at %p. First %d bytes:\n\n", (void *) __system_property_find, bytesToInspect);
    strcat(finalReport, entry);
    dump((void*) __system_property_find, bytesToInspect, finalReport);

    snprintf(entry, sizeof(entry), "\n__system_property_read_callback at %p. First %d bytes:\n\n", (void *) __system_property_read_callback, bytesToInspect);
    strcat(finalReport, entry);
    dump((void*) __system_property_read_callback, bytesToInspect, finalReport);

    return (*env)->NewStringUTF(env, finalReport);
}


JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_getallfds(JNIEnv *env, jobject thiz) {
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
    const char* mapsPath = "/proc/self/maps";

    long mapsFd = arm64_raw_syscall(__NR_openat,(long)AT_FDCWD,(long)mapsPath,(long)O_RDONLY,0, 0, 0);

    if (mapsFd == -1) {
        return (*env)->NewStringUTF(env, "Failed to open() /proc/self/maps");
    }

    const char* selfFdpath = "/proc/self/fd";
    char report[16384] = {0};
    size_t used = 0;
    report[0] = '\0';

    struct DIR* dir = opendir(selfFdpath);
    if (dir == NULL) {
        return (*env)->NewStringUTF(env, "Failed to opendir() /proc/self/fd");
    }


    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        // skip . and ..
        if (entry->d_name[0] == '.') {
            continue;
        }

        // Interested only in /proc/self/maps fd
        int conversionRet = atoi(entry->d_name);
        if (conversionRet != mapsFd) {
            continue;
        }

        // Build "/proc/self/fd/<entry>"
        char linkpath[PATH_MAX];
        int ret = snprintf(linkpath, sizeof(linkpath), "%s/%s", selfFdpath, entry->d_name);
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
    close((int) mapsFd);
    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testBind(JNIEnv *env, jobject thiz) {
    char report[8192] = {0};
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
    const int protocols[PROTO_COUNT] = { TCP, UDP };
    const int families[FAM_COUNT] = { IPv4, IPv6 };

    SockFactoryRes res = {0};
    for (int fam_idx = 0; fam_idx < FAM_COUNT; fam_idx++) {
        int fam = families[fam_idx];

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

                    ret = (fam == IPv4)
                               ? arm64_raw_syscall(__NR_bind, res.sock, (long)&res.sas.sas4, sizeof(res.sas.sas4), 0,0,0)
                               : arm64_raw_syscall(__NR_bind, res.sock, (long)&res.sas.sas6, sizeof(res.sas.sas6), 0,0,0);

                    snprintf(entry, sizeof(entry), "%s:%d | %s | %s | res: %s\n",
                             addr_str, ports[port_idx], proto_to_str(protocols[proto_idx]), fam_to_str(fam), ret == 0 ? "SUCESS" : "FAILED");
                    strcat(report, entry);

                    close(res.sock);
                }
            }
            strcat(report, "\n");
        }
    }
    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testListen(JNIEnv *env, jobject thiz) {
    char report[8192] = {0};
    char entry[256] = {0};
    long ret = 0;

    SockFactoryRes res = CreateSocket(IPv4, TCP, "0.0.0.0", RANDOM_EPHEMERAL_PORT, 0, 0);

    const int backlog = 10;
    ret = arm64_raw_syscall(__NR_listen, res.sock, backlog, 0, 0, 0, 0);

    snprintf(entry, sizeof(entry), "Result: %s\n", ret == 0 ? "SUCCESS" : "FAILED");
    strcat(report, entry);

    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testSocket(JNIEnv *env, jobject thiz) {
    if (setjmp(jump_buffer) != 0) {
        return (*env)->NewStringUTF(env, "Socket creation failed");;
    }
    char report[8192] = {0};
    char entry[256] = {0};
    long ret = 0;

    SockFactoryRes res = CreateSocket(Netlink, Raw, 0, 0, 0, NetlinkRoute);
    return (*env)->NewStringUTF(env, "OK");
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testSendto(JNIEnv *env, jobject thiz) {
    char report[8192] = {0};
    char entry[256] = {0};
    // Multicast / LAN Discovery
    const char* msg = "M-SEARCH * HTTP/1.1";

    const int port_ssdp_upnp = 1900;
    const char* ipv4_multicast_addr = "239.255.255.250";
    SockFactoryRes res = CreateSocket(IPv4, UDP, ipv4_multicast_addr, port_ssdp_upnp, 0, 0);

    long ret = arm64_raw_syscall(__NR_sendto, res.sock, (long)msg, (long)strlen(msg), 0, (long)&res.sas.sas4, sizeof(res.sas.sas4));

    snprintf(entry, sizeof(entry), "Result: %ld bytes sent to %s\n", ret, ipv4_multicast_addr);
    strcat(report, entry);

    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testGetsockname(JNIEnv *env, jobject thiz) {
    long ret = 0;
    char report[8192] = {0};
    char entry[256] = {0};

    // As Bipan blocks binds to local IPs, we connect to a WAN IP and then check the socket to see if it leaks the local IP
    const int port_dns = 53;
    const char* cloudflareDnsIp4 = "1.1.1.1";
    SockFactoryRes res = CreateSocket(IPv4, UDP, cloudflareDnsIp4, port_dns, 0, 0);

    // use standard connect (Bipan allows public internet)
    if (connect(res.sock, (struct sockaddr*)&res.sas.sas4, sizeof(res.sas.sas4)) == -1) {
        snprintf(entry, sizeof(entry), "connect failed \n");
        strcat(report, entry);
        return (*env)->NewStringUTF(env, report);
    }

    struct sockaddr_in leaked_addr;
    socklen_t len = sizeof(leaked_addr);

    ret = arm64_raw_syscall(__NR_getsockname, res.sock, (long)&leaked_addr, (long)&len, 0, 0, 0);

    if (ret == 0) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &leaked_addr.sin_addr, ip, INET_ADDRSTRLEN);
        snprintf(entry, sizeof(entry), "socket IP: %s\n", ip);
    } else {
        snprintf(entry, sizeof(entry), "failed with ret: %ld\n", ret);
    }

    strcat(report, entry);
    close(res.sock);
    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testSendmsg(JNIEnv *env, jobject thiz) {
    if (setjmp(jump_buffer) != 0) {
        return (*env)->NewStringUTF(env, "Socket creation failed");;
    }
    char report[8192] = {0};
    char entry[256] = {0};

    #define DEST_ADDR "10.111.222.3"
    SockFactoryRes res = CreateSocket(IPv4, UDP, DEST_ADDR, ARBITRARY_PORT, 0, 0);

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
    msg.msg_name = &res.sas.sas4; // Destination address
    msg.msg_namelen = sizeof(res.sas.sas4);
    msg.msg_iov = iov;             // Pointer to the array of iovecs
    msg.msg_iovlen = 2;            // Number of elements in the iovec array

    long ret = arm64_raw_syscall(__NR_sendmsg, res.sock, (long)&msg, 0, 0, 0, 0);
    snprintf(entry, sizeof(entry), "Result: %ld bytes sent to %s\n", ret, DEST_ADDR);
    strcat(report, entry);

    close(res.sock);

    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_getUname(JNIEnv *env, jobject thiz) {
    struct utsname buffer = {0};
    long ret;
    asm volatile(
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
            "TracerPid:"
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
        double start_secs = start_time.tv_sec + (double)start_time.tv_nsec / 1e9;
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
            double now = current_time.tv_sec + (double)current_time.tv_nsec / 1e9;
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

static inline void early_init_sysprop_test(void) {
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

static inline void print_bytes(void *p, int n) {
    unsigned char *p1 = p;

    for (int i = 0; i < n; i++) {
        // High nibble: shift right by 4 (since its unsigned, it safely does logical shift instead of arithmetic one)
        // Low nibble: mask with 0x0F.
        printf(" %02x   %02x  \n", *p1 >> 4, *p1 & 0x0F);
        for (int i = 7; i >= 0; i-- ) {
            if (i == 3) {
                printf(" ");
            }
            printf("%d", (*p1 >> i) & 1);
        }
        p1++;
        printf("\n\n");
    }
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wregister"
static inline long arm64_raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5) {
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
