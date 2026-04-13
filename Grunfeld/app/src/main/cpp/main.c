#include <android/log.h>
#include <android/sensor.h>
#include <errno.h>
#include <jni.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <sys/utsname.h>
#include <linux/fcntl.h>


#define TAG "GrunfeldNative"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static void sigsys_log_handler(int sig, siginfo_t* info, void* void_context);
static inline long arm64_raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5);
static void test_ndk_layer();

JNIEXPORT void JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testFileSystemProbes(JNIEnv *env, jobject thiz) {
    const char* paths[] =
            {"/proc/self/maps",
             "/proc/self/smaps",
             "/proc/self/mounts",
             "/proc/mounts",
             "/etc/hosts",
             "/system/etc/hosts",
             "/proc/version",
             "/proc/meminfo",
             "/proc/meminfo_extra",
             "/proc/cpuinfo",
             "/proc/sys/kernel/perf_event_paranoid",
             "/proc/zoneinfo",
             "/proc/vmstat",
             "/data/misc/user/0/cacerts-added",
             "/etc/security/otacerts.zip",
             "/dev/mali",
             "/dev/binder",
             "/dev/hwbinder",
             "/system/bin/app_process"
            };
    char buffer[20];

    for (int i = 0; i < 19; i++) {
        long fd = arm64_raw_syscall(__NR_openat, AT_FDCWD, (long)paths[i], O_RDONLY, 0, 0, 0);

        if (fd < 0) {
            LOGD("[Filesystem Probe] Failed to open %s (Error: %ld)", paths[i], fd);
        } else {
            long bytes = arm64_raw_syscall(__NR_read, fd, (long)buffer, sizeof(buffer) - 1, 0, 0, 0);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                LOGD("[Filesystem Probe] Contents of %s: %s...", paths[i], buffer);
            } else {
                LOGD("[Filesystem Probe] Failed to show bytes of %s", paths[i]);
            }
            arm64_raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
        }
    }
}

JNIEXPORT void JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testNetworkIdentity(JNIEnv *env, jobject thiz) {
    // 1. Test IPv4 LAN Bind (Port 0 - Client behavior)
    int sock4 = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr4 = {
            .sin_family = AF_INET,
            .sin_port = htons(0),
            .sin_addr.s_addr = inet_addr("192.168.1.50") // Simulated LAN IP
    };
    long ret = arm64_raw_syscall(__NR_bind, sock4, (long)&addr4, sizeof(addr4), 0, 0, 0);
    LOGD("[NET] IPv4 LAN Bind (Port 0) result: %ld (Expect -EADDRNOTAVAIL)", ret);

    // 2. Test IPv6 Server Bind (Port 8080 - Server behavior)
    int sock6 = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 addr6 = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(8080),
            .sin6_addr = IN6ADDR_ANY_INIT
    };
    ret = arm64_raw_syscall(__NR_bind, sock6, (long)&addr6, sizeof(addr6), 0, 0, 0);
    LOGD("[NET] IPv6 Server Bind (Port 8080) result: %ld (Expect 0/Spoofed success)", ret);

    // 3. Test Listen (Network Socket)
    ret = arm64_raw_syscall(__NR_listen, sock6, 5, 0, 0, 0, 0);
    LOGD("[NET] Listen on socket result: %ld (Expect 0/Spoofed success)", ret);

    close(sock4);
    close(sock6);
}

JNIEXPORT void JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testNetworkLeaks(JNIEnv *env, jobject thiz) {
    // sendto (Multicast / LAN Discovery)
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in target = {
            .sin_family = AF_INET,
            .sin_port = htons(1900), // SSDP Port
            .sin_addr.s_addr = inet_addr("239.255.255.250") // Multicast
    };
    const char* msg = "M-SEARCH * HTTP/1.1";

    long ret = arm64_raw_syscall(__NR_sendto, sock, (long)msg, strlen(msg), 0, (long)&target, sizeof(target));
    LOGD("[NET] sendto LAN result: %ld (Expect spoofed byte count: %zu)", ret, strlen(msg));

    // getsockname (LAN IP Leak Prevention)
    // As Bipan blocks binds to local IPs, we connect to a WAN IP and then check the
    // socket to see if it leaks the local IP
    struct sockaddr_in cf_dns = {
            .sin_family = AF_INET,
            .sin_port = htons(53),
            .sin_addr.s_addr = inet_addr("1.1.1.1")
    };

    // use standard connect (Bipan allows public internet)
    connect(sock, (struct sockaddr*)&cf_dns, sizeof(cf_dns));

    // getsockname
    struct sockaddr_in leaked_addr;
    socklen_t len = sizeof(leaked_addr);

    // The kernel WILL return the real LAN IP here.
    // Bipan should catch it, log the violation, and scrub it to 0.0.0.0.
    ret = arm64_raw_syscall(__NR_getsockname, sock, (long)&leaked_addr, (long)&len, 0, 0, 0);

    if (ret == 0) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &leaked_addr.sin_addr, ip, INET_ADDRSTRLEN);
        LOGD("[NET] getsockname result: %s (If 0.0.0.0, Bipan successfully scrubbed a REAL leak)", ip);
    }

    close(sock);
}

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    test_ndk_layer();
    return JNI_VERSION_1_6;
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
             "System: %s\nNode: %s\nRelease: %s\nVersion: %s\nMachine: %s",
             buffer.sysname,
             buffer.nodename,
             buffer.release,
             buffer.version,
             buffer.machine);

    return (*env)->NewStringUTF(env, result_str);
}


JNIEXPORT jboolean JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_installSigsysHandler(JNIEnv* env, jobject thiz) {
  struct sigaction sa = {0};
  sa.sa_sigaction = sigsys_log_handler;
  sa.sa_flags = SA_SIGINFO;

  long ret = arm64_raw_syscall(__NR_rt_sigaction, SIGSYS, (long)&sa, 0, 8, 0, 0);
  if (ret != 0) {
      LOGE("Failed to install SIGSYS handler (return: %ld)", ret);
      return JNI_FALSE;
  }

  LOGD("Installed SIGSYS handler successfully!");
  return JNI_TRUE;
}

/**
 * TODO:
 * this is passing. should fail
 */
static void test_ndk_layer() {
    // Get the manager instance
    ASensorManager* manager = ASensorManager_getInstanceForPackage("com.instagram.android");
    if (!manager) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "[NDK] ASensorManager is NULL (Hook successful or system error)");
        return;
    }

    // Test Sensor Enumeration
    ASensorList list;
    int count = ASensorManager_getSensorList(manager, &list);
    __android_log_print(ANDROID_LOG_INFO, TAG, "[NDK] Found %d sensors. (Expected 0 if blocked)", count);

    // Test Event Queue Creation (The Data Pipe)
    ASensorEventQueue* queue = ASensorManager_createEventQueue(manager, NULL, 0, NULL, NULL);
    if (queue == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "[NDK] Event Queue creation BLOCKED (Hook successful)");
    } else {
        __android_log_print(ANDROID_LOG_WARN, TAG, "[NDK] Event Queue created! LEAK DETECTED.");
    }
}

static void sigsys_log_handler(int sig, siginfo_t* info, void* void_context) {
  LOGE("Should never reach here...");
  _exit(-1);
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
