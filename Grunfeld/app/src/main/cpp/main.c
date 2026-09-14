#include <android/log.h>
#include <android/sensor.h>
#include <android/looper.h>
#include <jni.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <dirent.h>
#include <sys/stat.h>
#include <link.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <media/NdkMediaDrm.h>
#include <linux/tcp.h>

#include "socket_helper.h"
#include "athena.h"

#define TAG "GrunfeldNative"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#define PACKAGE_NAME "com.omarmesqq.grunfeld"
#define LOOPER_ID_USER 8998
#define SENSORS_SAMPLING_RATE 20000 // 50Hz (20ms)

/**
 * func-like macro to convert negative error values provided by the kernel to raw syscalls
 * back to nice libc/bionic errnos
 */
#define RAW_SYSCALL_TO_ERRNO(ret) strerror((int)-ret)

#define FIND_BIPAN_TRACES(path) \
    strstr(path, "/memfd:jit-cache") || \
    strstr(path, "Bipan") || \
    strstr(path, "bipan") || \
    strstr(path, "zygisk")

static void grunfeld_sigsys_handler(int sig, siginfo_t* info, void* void_context);
static inline long arm64_raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5);
static int dl_iterate_phdr_cb(struct dl_phdr_info *info, size_t size, void *data);
static void bytes_to_hex(const uint8_t *in, size_t len, char *out, size_t out_cap);

static int sys_prop_get(const char* propName, char* outBuf);
static int sys_prop_read(const prop_info* pi, char* propName, char* outBuf);
static void sys_prop_read_cbFn(void* cookie, const char* name, const char* value, uint32_t serial);
static void sys_prop_read_cb(const prop_info* pi,
                             void (*cb)(void *, const char *, const char *, uint32_t),
                             void* cookie);
static const prop_info* sys_prop_find(const char* propName);

static const long BOGUS_SYSCALL = 0xB050517;
static const int  BOGUS_SYSCALL_EXPECTED_RET = 21;

// Widevine UUID: edef8ba9-79d6-4ace-a3c8-27dcd51d21ed
static const uint8_t kWidevineUuid[16] = {
        0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce,
        0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed
};


__attribute__((constructor)) void grunfeld_early_init(void) {
    LOGD("__attribute__((constructor))");
    athenaInit();
    // requestNativeBacktrace();
}

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGD("JNI_OnLoad");
    // requestNativeBacktrace();
    return JNI_VERSION_1_6;
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testStatfsToHosts(JNIEnv *env, jobject thiz) {
    char report[1024] = {0};
    char entry[256] = {0};

    struct statfs b1 = {0};
    struct statfs b2 = {0};

    int ret = -1;

    ret = statfs("/system/etc/hosts", &b1);
    if (ret != 0) {
        snprintf(entry, sizeof(entry), "%s\n", strerror(errno));
        strcat(report, entry);
    } else {
        snprintf(entry, sizeof(entry), "statfs(/system/etc/hosts) succeeded\n");
        strcat(report, entry);
    }

    ret = statfs("/etc/hosts", &b2);
    if (ret != 0) {
        snprintf(entry, sizeof(entry), "%s\n", strerror(errno));
        strcat(report, entry);
    } else {
        snprintf(entry, sizeof(entry), "statfs(/etc/hosts) succeeded\n");
        strcat(report, entry);
    }
    
    return (*env)->NewStringUTF(env, report);
}


JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_getMediaDrmIdNative(JNIEnv *env, jobject thiz) {
    char report[1024];
    report[0] = '\0';

    AMediaDrm *drm = AMediaDrm_createByUUID(kWidevineUuid);
    if (drm == NULL) {
        snprintf(report, sizeof(report), "AMediaDrm_createByUUID failed");
        return (*env)->NewStringUTF(env, report);
    }

    AMediaDrmByteArray prop;
    memset(&prop, 0, sizeof(prop));

    media_status_t st = AMediaDrm_getPropertyByteArray(
            drm,
            PROPERTY_DEVICE_UNIQUE_ID,  // deviceUniqueId
            &prop
    );

    if (st != AMEDIA_OK || prop.ptr == NULL || prop.length == 0) {
        snprintf(report, sizeof(report),
                 "AMediaDrm_getPropertyByteArray failed status=%d len=%zu",
                 (int)st, prop.length);
        AMediaDrm_release(drm);
        return (*env)->NewStringUTF(env, report);
    }

    char hex[512] = {0};
    bytes_to_hex(prop.ptr, prop.length, hex, sizeof(hex));

    snprintf(report, sizeof(report),"%s",hex);

    AMediaDrm_release(drm);
    return (*env)->NewStringUTF(env, report);
}


JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_scanMountPoint(JNIEnv *env, jobject thiz, jstring mountPoint) {
    char errBuf[128] = {0};
    unsigned char linesLogged = 0;

    const char* mountPointCstr = (*env)->GetStringUTFChars(env, mountPoint, NULL);
    if (mountPointCstr == NULL) {
        snprintf(errBuf, sizeof(errBuf), "C-string from JNI String in array is NULL!");
        (*env)->DeleteLocalRef(env, mountPoint);
        return (*env)->NewStringUTF(env, errBuf);
    }

    char report[PATH_MAX * 3] = {0};
    char entry[PATH_MAX] = {0};

    size_t reportLen = 0;

    FILE *fp = fopen(mountPointCstr, "r");
    if (!fp) {
        strerror_r(errno, errBuf, sizeof(errBuf));
        int errLen = snprintf(entry, sizeof(entry), "%s\n", errBuf);
        if (errLen > 0 && reportLen + (size_t)errLen < sizeof(report)) {
            memcpy(report + reportLen, entry, (size_t)errLen);
            reportLen += (size_t)errLen;
        }
        return (*env)->NewStringUTF(env, errBuf);
    }

    while (fgets(entry, sizeof(entry), fp) != NULL) {
        if (
                !strstr(entry, "magisk") &&
                !strstr(entry, "hosts") &&
                !strstr(entry, "zygisk") &&
                !strstr(entry, "debug_ramdisk") &&
                !strstr(entry, "/cache/") &&
                !strstr(entry, "/product/bin") &&
                !strstr(entry, "modules")
                ) {
            continue;
        }

        size_t lineLen = strlen(entry);
        if (reportLen + lineLen >= sizeof(report) - 1) {
            // Not enough room left in report; stop reading this file
            break;
        }
        if (linesLogged < 2) {
            memcpy(report + reportLen, entry, lineLen);
            reportLen += lineLen;
            linesLogged++;
        } else break;

    }
    fclose(fp);

    report[reportLen] = '\0';

    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testFaccessat(JNIEnv *env, jobject thiz, jobjectArray filenames) {
    jsize len = (*env)->GetArrayLength(env, filenames);
    char report[20000] = {0};
    char entry[PATH_MAX] = {0};
    char errorBuffer[128] = {0};

    for (int i = 0; i < len; i++) {
        jstring jstr = (jstring)(*env)->GetObjectArrayElement(env, filenames, i);
        if (jstr == NULL) {
            snprintf(errorBuffer, sizeof(errorBuffer), "Some jstring in array is NULL!");
            return (*env)->NewStringUTF(env, errorBuffer);
        }

        const char* filepath = (*env)->GetStringUTFChars(env, jstr, NULL);
        if (filepath == NULL) {
            snprintf(errorBuffer, sizeof(errorBuffer), "C-string from JNI String in array is NULL!");
            (*env)->DeleteLocalRef(env, jstr);
            return (*env)->NewStringUTF(env, errorBuffer);
        }

        long ret = -1;

        int chkExistenceMode = F_OK;
        int hasReadPermMode = R_OK;

        int flags = AT_EACCESS; // performs access using effective UID and GID

        ret = arm64_raw_syscall(__NR_faccessat, 0 , (long) filepath, chkExistenceMode, flags, 0, 0);
        if (ret == 0) {
            snprintf(entry, sizeof(entry), "%s (F_OK) successful\n", filepath);
            strcat(report, entry);
        } else {
            snprintf(entry, sizeof(entry), "%s (F_OK) failed: %s\n", filepath, RAW_SYSCALL_TO_ERRNO(ret));
            strcat(report, entry);
        }


        ret = arm64_raw_syscall(__NR_faccessat, 0 , (long) filepath, hasReadPermMode, flags, 0, 0);
        if (ret == 0) {
            snprintf(entry, sizeof(entry), "%s (R_OK) successful\n", filepath);
            strcat(report, entry);
        } else {
            snprintf(entry, sizeof(entry), "%s (R_OK) failed: %s\n", filepath, RAW_SYSCALL_TO_ERRNO(ret));
            strcat(report, entry);
        }
    }

    return (*env)->NewStringUTF(env, report);
}


JNIEXPORT jobject JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testFstat(JNIEnv *env, jobject thiz,jstring filename) {

    const char* cstr = (*env)->GetStringUTFChars(env, filename, NULL);
    if (cstr == NULL) {
        LOGE("filePath NULL");
        return NULL;
    }

    int fd = (int) arm64_raw_syscall(__NR_openat, (long)AT_FDCWD, (long)cstr, (long)O_RDONLY, 0, 0, 0);
    if (fd < 0) {
        LOGE("openat failed");
        return NULL;
    }

    long ret = 0;
    struct stat statbuf = {0};

    // int fstat(int fd, struct stat *statbuf);
    ret = arm64_raw_syscall(__NR_fstat, fd , (long) &statbuf, 0, 0, 0, 0);

    if (ret != 0) {
        LOGE("fstat failed");
        return NULL;
    }

    jclass statResultClass = (*env)->FindClass(env, "com/omarmesqq/grunfeld/utils/StatResult");
    if (statResultClass == NULL) {
        LOGE("statResultClass is NULL");
        return NULL;
    }
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }

    jmethodID ctor = (*env)->GetMethodID(env, statResultClass, "<init>",
                                         "(JJJJJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");

    if (ctor == NULL) {
        LOGE("ctor is NULL");
        return NULL;
    }


    unsigned long dev = (unsigned long)statbuf.st_dev;
    unsigned long ino = (unsigned long)statbuf.st_ino;
    long size = (long)statbuf.st_size;
    long blocks = statbuf.st_blocks;
    long blkSiz = statbuf.st_blksize;

    // Timestamps
    char access_time_str[64] = {0};
    char modify_time_str[64] = {0};
    char change_time_str[64] = {0};
    struct tm tm_info;

    localtime_r(&statbuf.st_atim.tv_sec, &tm_info);
    strftime(access_time_str, sizeof(access_time_str), "%Y-%m-%d %H:%M:%S", &tm_info);
    localtime_r(&statbuf.st_mtim.tv_sec, &tm_info);
    strftime(modify_time_str, sizeof(modify_time_str), "%Y-%m-%d %H:%M:%S", &tm_info);
    localtime_r(&statbuf.st_ctim.tv_sec, &tm_info);
    strftime(change_time_str, sizeof(change_time_str), "%Y-%m-%d %H:%M:%S", &tm_info);


    char accessTime[128] = {0};
    char modTime[128] = {0};
    char statusChTime[128] = {0};

    snprintf(accessTime, sizeof(accessTime), "%s.%09ld\n", access_time_str, statbuf.st_atim.tv_nsec);
    snprintf(modTime, sizeof(modTime), "%s.%09ld\n", modify_time_str, statbuf.st_mtim.tv_nsec);
    snprintf(statusChTime, sizeof(statusChTime), "%s.%09ld\n", change_time_str, statbuf.st_ctim.tv_nsec);


    jstring jAccessTime = (*env)->NewStringUTF(env, accessTime);
    jstring jModTime = (*env)->NewStringUTF(env, modTime);
    jstring jStatusChTime = (*env)->NewStringUTF(env, statusChTime);

    jobject result = (*env)->NewObject(env, statResultClass, ctor,
                                       (jlong) dev,
                                       (jlong) ino,
                                       (jlong) size,
                                       (jlong) blkSiz,
                                       (jlong) blocks,
                                       jAccessTime,
                                       jModTime,
                                       jStatusChTime
    );

    close(fd);
    return result;
}


JNIEXPORT jobject JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testNewfstatat(JNIEnv *env, jobject thiz, jstring filename) {
    const char* filePath = (*env)->GetStringUTFChars(env, filename, NULL);
    if (filePath == NULL) {
        LOGE("filePath NULL");
        return NULL;
    }

    struct stat statbuf = {0};
    // if path is a symbolic link, do not dereference it: instead return information about the link itself
    int flags = AT_SYMLINK_NOFOLLOW;

    long ret = arm64_raw_syscall(__NR_newfstatat, (long)AT_FDCWD, (long)filePath, (long)&statbuf, flags, 0, 0);
    if (ret != 0) {
        LOGE("ret != 0");
        return NULL;
    }

    jclass statResultClass = (*env)->FindClass(env, "com/omarmesqq/grunfeld/utils/StatResult");
    if (statResultClass == NULL) {
        LOGE("statResultClass is NULL");
        return NULL;
    }
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }

    jmethodID ctor = (*env)->GetMethodID(env, statResultClass, "<init>",
                                         "(JJJJJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");

    if (ctor == NULL) {
        LOGE("ctor is NULL");
        return NULL;
    }


    unsigned long dev = (unsigned long)statbuf.st_dev;
    unsigned long ino = (unsigned long)statbuf.st_ino;
    long size = (long)statbuf.st_size;
    long blocks = statbuf.st_blocks;
    long blkSiz = statbuf.st_blksize;

    // Timestamps
    char access_time_str[64] = {0};
    char modify_time_str[64] = {0};
    char change_time_str[64] = {0};
    struct tm tm_info;

    localtime_r(&statbuf.st_atim.tv_sec, &tm_info);
    strftime(access_time_str, sizeof(access_time_str), "%Y-%m-%d %H:%M:%S", &tm_info);
    localtime_r(&statbuf.st_mtim.tv_sec, &tm_info);
    strftime(modify_time_str, sizeof(modify_time_str), "%Y-%m-%d %H:%M:%S", &tm_info);
    localtime_r(&statbuf.st_ctim.tv_sec, &tm_info);
    strftime(change_time_str, sizeof(change_time_str), "%Y-%m-%d %H:%M:%S", &tm_info);


    char accessTime[128] = {0};
    char modTime[128] = {0};
    char statusChTime[128] = {0};

    snprintf(accessTime, sizeof(accessTime), "%s.%09ld\n", access_time_str, statbuf.st_atim.tv_nsec);
    snprintf(modTime, sizeof(modTime), "%s.%09ld\n", modify_time_str, statbuf.st_mtim.tv_nsec);
    snprintf(statusChTime, sizeof(statusChTime), "%s.%09ld\n", change_time_str, statbuf.st_ctim.tv_nsec);


    jstring jAccessTime = (*env)->NewStringUTF(env, accessTime);
    jstring jModTime = (*env)->NewStringUTF(env, modTime);
    jstring jStatusChTime = (*env)->NewStringUTF(env, statusChTime);

    jobject result = (*env)->NewObject(env, statResultClass, ctor,
                                       (jlong) dev,
                                       (jlong) ino,
                                       (jlong) size,
                                       (jlong) blkSiz,
                                       (jlong) blocks,
                                       jAccessTime,
                                       jModTime,
                                       jStatusChTime
                                       );

    return result;
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testStatx(JNIEnv *env, jobject thiz) {
    char report[128] = {0};
    const char* ARBITRARY_PATH = "/system/lib64";

    long ret = -1;

    struct statx statxbuf = {0};
    int flags = AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW;
    unsigned int mask = STATX_ALL;

    // int statx(int dirfd,const char *_Nullable restrict path,int flags,unsigned int mask,struct statx *restrict statxbuf)
    ret = arm64_raw_syscall(__NR_statx, 0 , (long) ARBITRARY_PATH, (long) flags, mask, (long) &statxbuf, 0);

    if (ret == 0) {
        snprintf(report, sizeof(report), "statx worked");
    } else {
        snprintf(report, sizeof(report), "%s", RAW_SYSCALL_TO_ERRNO(ret));
    }

    return (*env)->NewStringUTF(env, report);
}


JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_scanProcSelfMaps(JNIEnv *env, jobject thiz) {
    char report[20000] = {0};
    char entry[PATH_MAX + 100] = {0};
    unsigned char linesLogged = 0;

    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        snprintf(entry, sizeof(entry), "Couldn't open /proc/self/maps (errno: %s)\n", strerror(errno));
        strcat(report, entry);
        return (*env)->NewStringUTF(env, report);
    }

    char buf[PATH_MAX] = {0};
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        char start[11] = {0};
        char end[11] = {0};
        char perms[5] = {0};
        char offset[9] = {0};
        char devMajor[3] = {0};
        char devMinor[3] = {0};
        size_t libInode = 0;
        char libName[PATH_MAX] = {0};

        int ret = sscanf(buf,
                         "%10[^-]-%10s %4s %8s %2[^:]:%2s %zu %s",
                         start, end, perms, offset, devMajor, devMinor, &libInode, libName);
        if (ret != 8) {
            if (FIND_BIPAN_TRACES(libName)) {
                snprintf(entry, sizeof(entry), "Something wrong. Matched args: %d | Culprit line: %s\n", ret, buf);
                strcat(report, entry);
                return (*env)->NewStringUTF(env, report);
            }
            // ignore problematic lines
        }
        if (FIND_BIPAN_TRACES(libName) && linesLogged < 2) {
            snprintf(entry, sizeof(entry), "%s", buf);
            strcat(report, entry);
            linesLogged++;
        }
    }

    fclose(fp);
    return (*env)->NewStringUTF(env, report);
}


JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_scanProcSelfSmaps(JNIEnv *env, jobject thiz) {
    size_t reportCap = 65536;
    size_t reportLen = 0;
    char* report = malloc(reportCap);
    unsigned char linesLogged = 0;
    if (!report) {
        return (*env)->NewStringUTF(env, "Allocation failed");
    }
    report[0] = '\0';

    char entry[PATH_MAX + 100] = {0};

    FILE* fp = fopen("/proc/self/smaps", "r");
    if (!fp) {
        snprintf(entry, sizeof(entry), "Couldn't open /proc/self/smaps (errno: %s)\n", strerror(errno));
        size_t entryLen = strlen(entry);
        if (reportLen + entryLen + 1 > reportCap) {
            reportCap = reportLen + entryLen + 1;
            report = realloc(report, reportCap);
        }
        memcpy(report + reportLen, entry, entryLen + 1);
        jstring result = (*env)->NewStringUTF(env, report);
        free(report);
        return result;
    }

    char buf[PATH_MAX] = {0};
    int matchedCurrentRegion = 0;

#define APPEND(str) do { \
        size_t _len = strlen(str); \
        if (reportLen + _len + 1 > reportCap) { \
            while (reportLen + _len + 1 > reportCap) reportCap *= 2; \
            char* _tmp = realloc(report, reportCap); \
            if (!_tmp) { free(report); fclose(fp); return (*env)->NewStringUTF(env, "OOM"); } \
            report = _tmp; \
        } \
        memcpy(report + reportLen, (str), _len + 1); \
        reportLen += _len; \
    } while (0)

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        char start[11] = {0};
        char end[11] = {0};
        char perms[5] = {0};
        char offset[9] = {0};
        char devMajor[3] = {0};
        char devMinor[3] = {0};
        size_t libInode = 0;
        char libName[PATH_MAX] = {0};

        int ret = sscanf(buf,
                         "%10[^-]-%10s %4s %8s %2[^:]:%2s %zu %s",
                         start, end, perms, offset, devMajor, devMinor, &libInode, libName);

        if (ret == 8) {
            matchedCurrentRegion = (FIND_BIPAN_TRACES(libName)) != 0;

            if (matchedCurrentRegion && linesLogged < 2) {
                APPEND(buf);
                linesLogged++;
            }
        } else {
            if (matchedCurrentRegion && linesLogged < 2) {
                APPEND(buf);
                linesLogged++;
            }
        }
    }

#undef APPEND
    fclose(fp);
    jstring result = (*env)->NewStringUTF(env, report);
    free(report);
    return result;
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testForkExec(JNIEnv *env, jobject thiz, jstring progname) {
    int pipefd[2];
    char errBuf[128] = {0};

    if (pipe(pipefd) == -1) {
        snprintf(errBuf, sizeof(errBuf), "pipe failed: %s", strerror(errno));
        return (*env)->NewStringUTF(env, errBuf);
    }

    pid_t pid = fork();
    if (pid == -1) {
        snprintf(errBuf, sizeof(errBuf), "fork failed: %s", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        return (*env)->NewStringUTF(env, errBuf);
    }

    if (pid == 0) {
        // Child Process
        close(pipefd[0]);          // Close reading end in child
        dup2(pipefd[1], STDOUT_FILENO); // Redirect stdout to pipe
        dup2(pipefd[1], STDERR_FILENO); // Redirect stderr to pipe
        close(pipefd[1]);

        const char* path = "/system/bin/uname";
        char* const argv[] = {"uname", "-a", NULL};
        execve(path, argv, environ);

        // If execve fails
        _exit(127);
    }

    // Parent Process
    close(pipefd[1]); // Close writing end in parent

    char outputBuffer[1024] = {0};
    size_t totalRead = 0;

    // Read output from child
    ssize_t n = -1;
    while ((n = read(pipefd[0], outputBuffer + totalRead, sizeof(outputBuffer) - totalRead - 1)) > 0) {
        // here inside its definitely positive, gonna cast
        totalRead += (size_t) n;
        if (totalRead >= sizeof(outputBuffer) - 1) {
            break;
        }
    }
    close(pipefd[0]);

    int wstatus = 0;
    // Wait properly without WNOHANG so the child finishes execution
    pid_t waitRes = waitpid(pid, &wstatus, 0);

    char finalReport[2048] = {0};
    if (waitRes == -1) {
        snprintf(finalReport, sizeof(finalReport), "waitpid failed: %s", strerror(errno));
        return (*env)->NewStringUTF(env, finalReport);
    }

    int exitCode = WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1;
    if (exitCode != 0) {
        snprintf(finalReport, sizeof(finalReport), "child exit code != 0. actually: %d", exitCode);
        return (*env)->NewStringUTF(env, finalReport);
    }

    snprintf(finalReport, sizeof(finalReport), "%s", outputBuffer);

    return (*env)->NewStringUTF(env, finalReport);
}


JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_dlIteratePhdrTest(JNIEnv *env, jobject thiz) {
    char *report = (char *) calloc(50000, sizeof(char));
    if (!report) {
        return (*env)->NewStringUTF(env, "Failed to allocate mem for report!");
    }

    dl_iterate_phdr(dl_iterate_phdr_cb, report);

    jstring result = (*env)->NewStringUTF(env, report);
    free(report);
    return result;
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_sysPropsGet(JNIEnv *env, jobject thiz, jstring propName) {
    char errBuf[128] = {0};

    const char* propNameCstr = (*env)->GetStringUTFChars(env, propName, NULL);
    if (propNameCstr == NULL) {
        snprintf(errBuf, sizeof(errBuf), "C-string from JNI String in array is NULL!");
        (*env)->DeleteLocalRef(env, propName);
        return (*env)->NewStringUTF(env, errBuf);
    }

    char report[PATH_MAX] = {0};
    char entry[512] = {0};
    int len = -1;
    char outBuf[PROP_VALUE_MAX] = {0};

    len = sys_prop_get(propNameCstr, outBuf);
    if (len <= 0) {
        snprintf(entry, sizeof(entry), "(empty)");
    } else {
        snprintf(entry, sizeof(entry), "%s\n", outBuf);
    }
    strcat(report, entry);

    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_sysPropsReadWithNullName(JNIEnv *env, jobject thiz, jstring propName) {
    char errBuf[128] = {0};

    const char* propNameCstr = (*env)->GetStringUTFChars(env, propName, NULL);
    if (propNameCstr == NULL) {
        snprintf(errBuf, sizeof(errBuf), "C-string from JNI String in array is NULL!");
        (*env)->DeleteLocalRef(env, propName);
        return (*env)->NewStringUTF(env, errBuf);
    }

    char report[PATH_MAX] = {0};
    char entry[512] = {0};
    int len = -1;
    char outBuf[PROP_VALUE_MAX] = {0};

    const prop_info* pi = sys_prop_find(propNameCstr);

    if (pi == NULL) {
        snprintf(entry, sizeof(entry), "prop_info* is NULL");
    } else {
        len = sys_prop_read(pi, NULL, outBuf);
        if (len <= 0) {
            snprintf(entry, sizeof(entry), "(empty)");
        } else {
            snprintf(entry, sizeof(entry), "%s", outBuf);
        }
    }
    strcat(report, entry);

    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_sysPropsRead(JNIEnv *env, jobject thiz, jstring propName) {
    char errBuf[128] = {0};

    const char* propNameCstr = (*env)->GetStringUTFChars(env, propName, NULL);
    if (propNameCstr == NULL) {
        snprintf(errBuf, sizeof(errBuf), "C-string from JNI String in array is NULL!");
        (*env)->DeleteLocalRef(env, propName);
        return (*env)->NewStringUTF(env, errBuf);
    }

    char report[PATH_MAX] = {0};
    char entry[512] = {0};
    int len = -1;
    char outBuf[PROP_VALUE_MAX] = {0};

    const prop_info* pi = sys_prop_find(propNameCstr);

    if (pi == NULL) {
        snprintf(entry, sizeof(entry), "prop_info* is NULL");
    } else {
        char propNameBuf[PROP_NAME_MAX] = {0};
        len = sys_prop_read(pi, propNameBuf, outBuf);
        if (len <= 0) {
            snprintf(entry, sizeof(entry), "(empty)");
        } else {
            snprintf(entry, sizeof(entry), "%s", outBuf);
        }
    }
    strcat(report, entry);

    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_sysPropsReadCb(JNIEnv *env, jobject thiz, jstring propName) {
    char errBuf[128] = {0};

    const char* propNameCstr = (*env)->GetStringUTFChars(env, propName, NULL);
    if (propNameCstr == NULL) {
        snprintf(errBuf, sizeof(errBuf), "C-string from JNI String in array is NULL!");
        (*env)->DeleteLocalRef(env, propName);
        return (*env)->NewStringUTF(env, errBuf);
    }


    char report[PATH_MAX] = {0};
    char entry[512] = {0};
    int len = -1;
    char outBuf[PROP_VALUE_MAX] = {0};

    const prop_info* pi = sys_prop_find(propNameCstr);

    if (pi == NULL) {
        snprintf(entry, sizeof(entry), "prop_info* is NULL");
    } else {
        sys_prop_read_cb(pi, sys_prop_read_cbFn, outBuf);
        if (outBuf[0] == '\0') {
            snprintf(entry, sizeof(entry), "(empty)");
        } else {
            snprintf(entry, sizeof(entry), "%s", outBuf);
        }
    }
    strcat(report, entry);

    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testGetsockname(JNIEnv *env, jobject thiz) {
    long ret = -1;
    char report[512] = {0};
    char entry[256] = {0};

    const int port_dns = 53;
    const char* cloudflareDnsIp4 = "1.1.1.1";
    SockFactoryRes* res = CreateSocket(IPv4, UDP, cloudflareDnsIp4, port_dns, 0, 0);
    if (!res) {
        return (*env)->NewStringUTF(env, "Failed to create socket!\n");
    }

    // 1. `connect` to WAN w/ a regular socket
    if (connect(res->sock, (struct sockaddr*)&res->sas.sas4, sizeof(res->sas.sas4)) == -1) {
        snprintf(entry, sizeof(entry), "connect failed \n");
        strcat(report, entry);

        close(res->sock);
        free(res);
        return (*env)->NewStringUTF(env, report);
    }

    // 2. `getsockname` of this socket to get the device's local IP
    struct sockaddr_in local_addr;
    socklen_t len = sizeof(local_addr);
    ret = arm64_raw_syscall(__NR_getsockname, res->sock, (long)&local_addr, (long)&len, 0, 0, 0);

    if (ret == 0) {
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &local_addr.sin_addr, ip, INET_ADDRSTRLEN);
        snprintf(entry, sizeof(entry), "%s", ip);
    } else {
        snprintf(entry, sizeof(entry), "Test failed. errno: %s\n", RAW_SYSCALL_TO_ERRNO(ret));
    }

    strcat(report, entry);
    close(res->sock);
    free(res);
    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_unameInlineAsm(JNIEnv *env, jobject thiz) {
    struct utsname buffer = {0};
    long ret = -1;
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

    char result_str[128] = {0};
    snprintf(result_str, sizeof(result_str), "%s", buffer.release);

    return (*env)->NewStringUTF(env, result_str);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_unameRawAsmSyscall(JNIEnv *env, jobject thiz) {
    struct utsname buffer = {0};
    long ret = arm64_raw_syscall(__NR_uname, (long) &buffer, 0, 0, 0, 0, 0);

    if (ret < 0) {
        return (*env)->NewStringUTF(env, "Error: uname syscall failed");
    }

    char result_str[128] = {0};
    snprintf(result_str, sizeof(result_str), "%s", buffer.release);

    return (*env)->NewStringUTF(env, result_str);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_unameSyscallLibcWrapper(JNIEnv *env, jobject thiz) {
    struct utsname buffer = {0};
    long ret = syscall(__NR_uname, &buffer);

    if (ret < 0) {
        return (*env)->NewStringUTF(env, "Error: uname syscall failed");
    }

    char result_str[128] = {0};
    snprintf(result_str, sizeof(result_str), "%s", buffer.release);

    return (*env)->NewStringUTF(env, result_str);
}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_unameBionic(JNIEnv *env, jobject thiz) {
    struct utsname buffer = {0};
    long ret = uname(&buffer);

    if (ret < 0) {
        return (*env)->NewStringUTF(env, "Error: uname syscall failed");
    }

    char result_str[128] = {0};
    snprintf(result_str, sizeof(result_str), "%s", buffer.release);

    return (*env)->NewStringUTF(env, result_str);
}

// TODO: maybe try with our kernel struct to bypass ART
static char g_altstack[SIGSTKSZ * 4];
JNIEXPORT jboolean JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_installSigsysHandler(JNIEnv* env, jobject thiz) {
    long ret = -1;

    // Altstack setup
    stack_t ss = {0};
    ss.ss_sp = g_altstack;
    ss.ss_size = sizeof(g_altstack);
    ss.ss_flags = 0;
    ret = sigaltstack(&ss, NULL);
    if (ret != 0) {
        LOGE("sigaltstack failed (errno: %s)", strerror(errno));
        return JNI_FALSE;
    }

    struct sigaction sigsysAct = {0};
    sigsysAct.sa_sigaction = grunfeld_sigsys_handler;
    sigsysAct.sa_flags = SA_SIGINFO | SA_ONSTACK;

    // Act "cleansing"
    ret = sigemptyset(&sigsysAct.sa_mask);
    if (ret != 0) {
        LOGE("sigemptyset failed (errno: %s)", strerror(errno));
        return JNI_FALSE;
    }
    // Actual SIGSYS registration
    ret = arm64_raw_syscall(__NR_rt_sigaction, SIGSYS, (long)&sigsysAct, 0, 8, 0, 0);
    if (ret != 0) {
        LOGE("sigaction(SIGSYS) failed (errno: %s)", RAW_SYSCALL_TO_ERRNO(ret));
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
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testSensors(JNIEnv *env, jobject thiz) {
    char result_buffer[PATH_MAX] = {0};
    char entry[512] = {0};

    // On API >= 26 we get the sensor sensorManager for our specific package
    ASensorManager* sensorManager = ASensorManager_getInstanceForPackage(PACKAGE_NAME);

    if (sensorManager != NULL) {
        snprintf(entry, sizeof(entry), "ASensorManager_getInstanceForPackage: Sensor Manager is NOT null\n");
        strcat(result_buffer, entry);
    }

    // Enumerate all sensors
    ASensorList list = {0};
    int sensorListCount = ASensorManager_getSensorList(sensorManager, &list);

    if (sensorListCount != 0) {
        snprintf(entry, sizeof(entry), "ASensorManager_getSensorList: %d sensors detected\n", sensorListCount);
        strcat(result_buffer, entry);
        for (int i = 0; i < sensorListCount; i++) {
            const char* name = ASensor_getName(list[i]);
            const char* vendor = ASensor_getVendor(list[i]);
            int type = ASensor_getType(list[i]);
            LOGI("Sensor name: %s, Vendor: %s, Type: %d", name, vendor, type);
        }
    }

    // Get some famous sensors
    const ASensor* accel = ASensorManager_getDefaultSensor(sensorManager, ASENSOR_TYPE_ACCELEROMETER);
    const ASensor* gyro = ASensorManager_getDefaultSensor(sensorManager, ASENSOR_TYPE_GYROSCOPE);
    if (accel != NULL) {
        snprintf(entry, sizeof(entry), "ASensorManager_getDefaultSensor(ACCELEROMETER): NOT null\n");
        strcat(result_buffer, entry);
    }
    if (gyro != NULL) {
        snprintf(entry, sizeof(entry), "ASensorManager_getDefaultSensor(GYROSCOPE): NOT null\n");
        strcat(result_buffer, entry);
    }

    // Get a looper for the current thread
    ALooper* looper = ALooper_prepare(ALOOPER_PREPARE_ALLOW_NON_CALLBACKS);
    if (!looper) {
        snprintf(entry, sizeof(entry), "testSensors: Failed to get ALooper for current thread!\n");
        strcat(result_buffer, entry);
    }

    // Create an event queue get streamed sensor data
    ASensorEventQueue* queue = ASensorManager_createEventQueue(sensorManager, looper, LOOPER_ID_USER, NULL, NULL);
    if (queue != NULL) {
        snprintf(entry, sizeof(entry), "ASensorManager_createEventQueue: created!\n");
        strcat(result_buffer, entry);

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

    return (*env)->NewStringUTF(env, result_buffer);
}

JNIEXPORT jboolean JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_triggerSigsysViolation(JNIEnv *env, jobject thiz) {
    long ret = 0;

    // attempt with inline asm first
    ret = arm64_raw_syscall(BOGUS_SYSCALL, 0, 0, 0, 0, 0, 0);
    if (ret != BOGUS_SYSCALL_EXPECTED_RET) {
        return JNI_FALSE;
    }

    // fallback to bionic wrapper
    ret = syscall(BOGUS_SYSCALL, 0, 0, 0, 0, 0, 0);
    if (ret != BOGUS_SYSCALL_EXPECTED_RET) {
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

static void grunfeld_sigsys_handler(int sig, siginfo_t* info, void* void_context) {
    ucontext_t* ctx = (ucontext_t*)void_context;
    int nr = info->si_syscall;

    if (nr == BOGUS_SYSCALL) {
        ctx->uc_mcontext.regs[0] = BOGUS_SYSCALL_EXPECTED_RET;
    }
    ctx->uc_mcontext.regs[0] = (__u64) -1;
}

static int dl_iterate_phdr_cb(struct dl_phdr_info *info, size_t size, void *data) {
    char* report = (char *) data;

    char line[512] ={0};

    if (strstr(info->dlpi_name, "memfd") || strstr(info->dlpi_name, "zygisk")) {
        snprintf(line, sizeof(line),"%s\n",info->dlpi_name);
    }

    // Bounds check
    size_t currentLen = strlen(report);
    size_t lineLen = strlen(line);
    size_t capacity = 50000;

    if (currentLen + lineLen + 1 < capacity) {
        strcat(report, line);
    }

    return 0;
}

static void bytes_to_hex(const uint8_t *in, size_t len, char *out, size_t out_cap) {
    static const char *hex = "0123456789abcdef";
    size_t i, o = 0;
    for (i = 0; i < len && o + 2 < out_cap; i++) {
        out[o++] = hex[(in[i] >> 4) & 0xf];
        out[o++] = hex[in[i] & 0xf];
    }
    out[o] = '\0';
}

static int sys_prop_get(const char* propName, char* outBuf) {
    int len = __system_property_get(propName, outBuf);
    return len;
}

static int sys_prop_read(const prop_info* pi, char* propName, char* outBuf) {
    int len = __system_property_read(pi, propName, outBuf);
    return len;
}

static void sys_prop_read_cbFn(void* cookie, const char* name, const char* value, uint32_t serial) {
    char* out_buf = (char*)cookie;
    strncpy(out_buf, value, PROP_VALUE_MAX - 1);
    out_buf[PROP_VALUE_MAX - 1] = '\0';
}

static void sys_prop_read_cb(const prop_info* pi,
                             void (*cb)(void *, const char *, const char *, uint32_t),
                             void* cookie) {
    __system_property_read_callback(pi, cb, cookie);
}

static const prop_info* sys_prop_find(const char* propName) {
    return __system_property_find(propName);
}


JNIEXPORT void JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_raiseSegv(JNIEnv *env, jobject thiz) {
    raise(SIGSEGV);
}

JNIEXPORT void JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_raiseAbrt(JNIEnv *env, jobject thiz) {
    raise(SIGABRT);
}

JNIEXPORT void JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_raiseTrap(JNIEnv *env, jobject thiz) {
    raise(SIGTRAP);
}

JNIEXPORT void JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_raiseQuit(JNIEnv *env, jobject thiz) {
    raise(SIGQUIT);
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
