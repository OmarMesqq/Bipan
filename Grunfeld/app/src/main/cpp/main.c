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
#define MAX_REPORT_SIZE 8192

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)


static int is_noise(const char* path) {
    if (!path || strlen(path) == 0) return 0;
    const char* filters[] = {
            "/apex/",
            "/system/",
            "/vendor/",
            "/product/",
            "/dev/",
            "/data/misc/"
    };
    for (int i = 0; i < 6; i++) {
        if (strstr(path, filters[i])) return 1;
    }
    return 0;
}

static void sigsys_log_handler(int sig, siginfo_t* info, void* void_context);
static inline long arm64_raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5);

JNIEXPORT void JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testFileSystemProbes(JNIEnv *env, jobject thiz) {
    const char* paths[] =
            {
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
             "/sys/devices/system/cpu/present",
             "/sys/devices/system/cpu/possible",
             "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq",
            };
    char buffer[20];

    for (int i = 0; i < 16; i++) {
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

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_scanMaps(JNIEnv *env, jobject thiz) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return (*env)->NewStringUTF(env, "Error: Could not open maps");

    char line[1024];
    char report[MAX_REPORT_SIZE] = "--- Bipan Stealth Report ---\n";
    int found_any = 0;

    while (fgets(line, sizeof(line), fp)) {
        char addr[128], perms[16], offset[16], dev[16], inode[16], path[256] = "";
        int count = sscanf(line, "%s %s %s %s %s %s", addr, perms, offset, dev, inode, path);

        if (is_noise(path)) continue;

        // Focus on Executable regions
        if (strstr(perms, "x")) {
            found_any = 1;
            uintptr_t start_addr;
            sscanf(addr, "%lx-", &start_addr);

            char* elf_status = "Unknown";
            unsigned char* ptr = (unsigned char*)start_addr;

            // Diagnostic check
            if (ptr[0] == 0x7f && ptr[1] == 'E' && ptr[2] == 'L' && ptr[3] == 'F') {
                elf_status = "!! ELF HEADER DETECTED !!";
            } else if (ptr[0] == 0x00 && ptr[1] == 0x00) {
                elf_status = "Scrubbed (Safe)";
            }

            // Append to our Kotlin-bound report
            char entry[512];
            snprintf(entry, sizeof(entry), "\n[Region]: %s\n[Perms]: %s\n[Path]: %s\n[Status]: %s\n",
                     addr, perms, (count < 6 ? "Anonymous" : path), elf_status);

            if (strlen(report) + strlen(entry) < MAX_REPORT_SIZE - 1) {
                strcat(report, entry);
            }
        }
    }

    if (!found_any) {
        strcat(report, "\nNo suspicious executable regions found.\nStealth level: HIGH");
    }

    fclose(fp);
    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT void JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_removeBipan(JNIEnv *env, jobject thiz) {
    // TODO
}

JNIEXPORT void JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testBind(JNIEnv *env, jobject thiz) {
    long ret = 0;

    // Client behavior: IPv4, TCP, LAN addr, random port (0): Should fail
    int sock4tcp = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr4tcp = {
            .sin_family = AF_INET,
            .sin_port = htons(0),
            .sin_addr.s_addr = inet_addr("192.168.1.1")
    };
    ret = arm64_raw_syscall(__NR_bind, sock4tcp, (long)&addr4tcp, sizeof(addr4tcp), 0, 0, 0);

    // Client behavior: IPv4, UDP, LAN addr, random port (0): Should fail
    int sock6udp = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr6udp = {
            .sin_family = AF_INET,
            .sin_port = htons(0),
            .sin_addr.s_addr = inet_addr("127.0.0.1")
    };
    ret = arm64_raw_syscall(__NR_bind, sock6udp, (long)&addr6udp, sizeof(addr6udp), 0, 0, 0);

    // Client behavior: IPv6, TCP, LAN addr, random port (0): Should fail
    int sock6tcp = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 addr6tcp = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(0),
            .sin6_addr.s_addr = inet_pton(AF_INET6, "::1", &addr6tcp)
    };
    ret = arm64_raw_syscall(__NR_bind, sock6tcp, (long)&addr6tcp, sizeof(addr6tcp), 0, 0, 0);

    // Client behavior: IPv6, UDP, LAN addr, random port (0): Should fail
    int sock6udp = socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_in6 addr6udp = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(0),
            .sin6_addr.s_addr = inet_pton(AF_INET6, "fe80::10b4:f5ff:fecc:ee2a", &addr6tcp
    };
    ret = arm64_raw_syscall(__NR_bind, sock6udp, (long)&addr6udp, sizeof(addr6udp), 0, 0, 0);

    // Server behavior: IPv6, UDP, LAN addr, arbitrary port : Should fail
    int sock6udpServer = socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_in6 addr6udpServer = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(49321),
            .sin6_addr.s_addr = inet_pton(AF_INET6, "fe80::10b4:f5ff:fecc:ee2a", &addr6tcp
    };
    ret = arm64_raw_syscall(__NR_bind, sock6udpServer, (long)&addr6udpServer, sizeof(addr6udpServer), 0, 0, 0);

    // "Legitimate" use: local/UNIX TCP domain sockets on random port for IPC (example)
    int sockUnix = socket(AF_LOCAL, SOCK_STREAM, 0);
    struct sockaddr_in addrUnix = {
            .sin_family = AF_INET,
            .sin_port = htons(0),
            .sin_addr.s_addr = inet_addr("127.0.0.1")
    };
    ret = arm64_raw_syscall(__NR_bind, sockUnix, (long)&addrUnix, sizeof(addrUnix), 0, 0, 0);


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

    long ret = arm64_raw_syscall(__NR_sendto, sock, (long)msg, (long)strlen(msg), 0, (long)&target, sizeof(target));
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
      LOGE("Failed to install SIGSYS handler (return: %ld)", ret);
      return JNI_FALSE;
  }

  LOGD("Installed SIGSYS handler successfully!");
  return JNI_TRUE;
}

/**
 * TODO: this is passing. should fail
 */
JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testSensors(JNIEnv *env, jobject thiz) {
    char result_buffer[512];
    char* status_msg;
    char* queue_msg;

    // 1. Get the manager instance
    // Note: In a real app, you'd use the actual package name or NULL
    ASensorManager* manager = ASensorManager_getInstanceForPackage("com.instagram.android");

    if (!manager) {
        return (*env)->NewStringUTF(env, "Sensor Status: Manager is NULL\n(Hook Active)");
    }

    // 2. Test Sensor Enumeration
    ASensorList list;
    int count = ASensorManager_getSensorList(manager, &list);

    if (count == 0) {
        status_msg = "SUCCESS: 0 Sensors found (Blocked)";
    } else {
        status_msg = "LEAK: Sensors detected";
    }

    // 3. Test Event Queue Creation
    ASensorEventQueue* queue = ASensorManager_createEventQueue(manager, NULL, 0, NULL, NULL);
    if (queue == NULL) {
        queue_msg = "SUCCESS: Event Queue Blocked";
    } else {
        queue_msg = "LEAK: Event Queue Created";
        // Clean up if it actually leaked
        ASensorManager_destroyEventQueue(manager, queue);
    }

    // Format the final on-screen report
    snprintf(result_buffer, sizeof(result_buffer),
             "Sensor Count: %d\n%s\n%s",
             count, status_msg, queue_msg);

    return (*env)->NewStringUTF(env, result_buffer);
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
