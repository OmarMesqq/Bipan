#include <android/log.h>
#include <android/sensor.h>
#include <android/looper.h>
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
#include <time.h>
#include <sys/un.h>
#include "atomic_cat.h"
#include "socket_helper.h"


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

__attribute__((constructor))
void grunfeld_early_init() {
    write_to_logcat_async(ANDROID_LOG_WARN, TAG, "Grunfeld early init");
}


static int is_noise(const char* path);
static void hashTextSection();
static void sigsys_log_handler(int sig, siginfo_t* info, void* void_context);
static inline long arm64_raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5);

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    return JNI_VERSION_1_6;
}


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
    // TODO: sigprocmask

}

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testBind(JNIEnv *env, jobject thiz) {
    char report[2048] = {0};
    char entry[256] = {0};
    long ret = 0;

    // 1. Client behavior: IPv4, TCP, random ephemeral port (0): Should fail
    #define LAN_ADDR_1 "192.168.1.1"
    SockFactoryRes res1 = CreateSocket(IPv4, TCP, LAN_ADDR_1, RANDOM_EPHEMERAL_PORT, 0);
    ret = arm64_raw_syscall(
            __NR_bind,
            res1.sock,
            (long) &res1.sas.sas4,
            sizeof(res1.sas.sas4),
            0, 0, 0
    );
    snprintf(entry, sizeof(entry), "IPv4 TCP LAN (Random/Ephemeral Port 0): %s\n", (ret == -EADDRNOTAVAIL ? "BLOCKED ✅" : "LEAK ❌"));
    strcat(report, entry);

    // 2. Client behavior: IPv4, UDP, LAN addr, random ephemeral port (0): Should fail
    #define LAN_ADDR_2 "192.168.1.50"
    SockFactoryRes res2 = CreateSocket(IPv4, UDP, LAN_ADDR_2, RANDOM_EPHEMERAL_PORT, 0);
    ret = arm64_raw_syscall(
            __NR_bind,
            res2.sock,
            (long) &res2.sas.sas4,
            sizeof(res2.sas.sas4),
            0, 0, 0
    );
    snprintf(entry, sizeof(entry), "IPv4 UDP LAN (Random/Ephemeral Port 0): %s\n", (ret == -EADDRNOTAVAIL ? "BLOCKED ✅" : "LEAK ❌"));
    strcat(report, entry);

    // 3. Client behavior: IPv6, TCP, LAN addr, random ephemeral port (0): should fail
    #define LAN_ADDR_3 "fe80::10b4:f5ff:fecc:ee2a"
    SockFactoryRes res3 = CreateSocket(IPv6, TCP, LAN_ADDR_3, RANDOM_EPHEMERAL_PORT, 0);
    ret = arm64_raw_syscall(
            __NR_bind,
            res3.sock,
            (long) &res3.sas.sas6,
            sizeof(res3.sas.sas6),
            0, 0, 0
    );
    snprintf(entry, sizeof(entry), "IPv6 TCP LAN (Random/Ephemeral Port 0): %s\n", (ret == -EADDRNOTAVAIL ? "BLOCKED ✅" : "LEAK ❌"));
    strcat(report, entry);

    // 4. Client behavior: IPv6, UDP, LAN addr, random ephemeral port (0): should fail
    #define LAN_ADDR_4 "fe80::10b4:f5ff:fecc:ee2a"
    SockFactoryRes res4 = CreateSocket(IPv6, UDP, LAN_ADDR_4, RANDOM_EPHEMERAL_PORT, 0);
    ret = arm64_raw_syscall(
            __NR_bind,
            res4.sock,
            (long) &res4.sas.sas6,
            sizeof(res4.sas.sas6),
            0, 0, 0
    );
    snprintf(entry, sizeof(entry), "IPv6 UDP LAN (Port 0): %s\n", (ret == -EADDRNOTAVAIL ? "BLOCKED ✅" : "LEAK ❌"));
    strcat(report, entry);

    // 5. Server behavior: IPv4, TCP, listening on arbitrary port (8080): should fail
    SockFactoryRes res5 = CreateSocket(IPv4, TCP, "0.0.0.0", ARBITRARY_PORT, 0);
    ret = arm64_raw_syscall(
            __NR_bind,
            res5.sock,
            (long) &res5.sas.sas4,
            sizeof(res5.sas.sas4),
            0, 0, 0
    );

    // Bipan spoofs `bind`s success (return 0) but don't actually let it happen
    snprintf(entry, sizeof(entry), "Server Bind (Port %d): %s\n", ARBITRARY_PORT, (ret == 0 ? "SPOOFED ✅" : "FAILED ❌"));
    strcat(report, entry);


    // 6. "Legitimate" use: local/UNIX TCP for IPC for example: should pass
    SockFactoryRes res6 = CreateSocket(Unix, TCP, 0, 0, LOCAL_SOCKET);
    ret = arm64_raw_syscall(
            __NR_bind,
            res6.sock,
            (long) &res6.sas.sasUn,
            sizeof(res6.sas.sasUn),
            0, 0, 0
    );
    snprintf(entry, sizeof(entry), "Unix Domain IPC: %s\n", (ret == 0 ? "ALLOWED ✅" : "BLOCKED ❌"));
    strcat(report, entry);


    // 7. Loopback binding IPv4 TCP
    #define LAN_ADDR_5 "127.0.0.1"
    SockFactoryRes res7 = CreateSocket(IPv4, TCP, LAN_ADDR_5, RANDOM_EPHEMERAL_PORT, 0);
    ret = arm64_raw_syscall(
            __NR_bind,
            res7.sock,
            (long) &res7.sas.sas4,
            sizeof(res7.sas.sas4),
            0, 0, 0
    );
    snprintf(entry, sizeof(entry), "IPv4 TCP Loopback (Port 0): %s\n", (ret == -EADDRNOTAVAIL ? "BLOCKED ✅" : "LEAK ❌"));
    strcat(report, entry);

    // 8. Loopback binding IPv6 TCP
    #define LAN_ADDR_6 "::1"
    SockFactoryRes res8 = CreateSocket(IPv6, TCP, LAN_ADDR_6, RANDOM_EPHEMERAL_PORT, 0);
    ret = arm64_raw_syscall(
            __NR_bind,
            res8.sock,
            (long) &res8.sas.sas6,
            sizeof(res8.sas.sas6),
            0, 0, 0
    );

    snprintf(entry, sizeof(entry), "IPv6 TCP Loopback (Port 0): %s\n", (ret == -EADDRNOTAVAIL ? "BLOCKED ✅" : "LEAK ❌"));
    strcat(report, entry);


    // 9. Loopback binding IPv4 UDP
    #define LAN_ADDR_7 "127.0.0.1"
    SockFactoryRes res9 = CreateSocket(IPv4, UDP, LAN_ADDR_7, RANDOM_EPHEMERAL_PORT, 0);
    ret = arm64_raw_syscall(
            __NR_bind,
            res9.sock,
            (long) &res9.sas.sas4,
            sizeof(res9.sas.sas4),
            0, 0, 0
    );
    snprintf(entry, sizeof(entry), "IPv4 UDP Loopback (Port 0): %s\n", (ret == -EADDRNOTAVAIL ? "BLOCKED ✅" : "LEAK ❌"));
    strcat(report, entry);

    // 10. Loopback binding IPv6 UDP
    #define LAN_ADDR_8 "::1"
    SockFactoryRes res10 = CreateSocket(IPv6, UDP, LAN_ADDR_8, RANDOM_EPHEMERAL_PORT, 0);
    ret = arm64_raw_syscall(
            __NR_bind,
            res10.sock,
            (long) &res10.sas.sas6,
            sizeof(res10.sas.sas6),
            0, 0, 0
    );
    snprintf(entry, sizeof(entry), "IPv6 UDP Loopback (Port 0): %s\n", (ret == -EADDRNOTAVAIL ? "BLOCKED ✅" : "LEAK ❌"));
    strcat(report, entry);


    close(res1.sock);
    close(res2.sock);
    close(res3.sock);
    close(res4.sock);
    close(res5.sock);
    unlink(res6.sas.sasUn.sun_path);
    close(res6.sock);
    close(res7.sock);
    close(res8.sock);
    close(res9.sock);
    close(res10.sock);

    return (*env)->NewStringUTF(env, report);
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

JNIEXPORT jstring JNICALL
Java_com_omarmesqq_grunfeld_utils_NativeLibWrapper_testSensors(JNIEnv *env, jobject thiz) {
    char result_buffer[512];
    char* status_msg;
    char* queue_msg;

    // On API >= 26 we get the sensor sensorManager for our specific package
    ASensorManager* sensorManager = ASensorManager_getInstanceForPackage(PACKAGE_NAME);

    if (!sensorManager) {
        return (*env)->NewStringUTF(env, "Sensor Manager is NULL (Hook Active?)");
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

static int is_noise(const char* path) {
    if (!path || strlen(path) == 0) return 0;
    const char* filters[] = {
            "/apex/",
            "/system/",
            "/vendor/",
            "/product/",
            "/dev/",
            "/data/"
    };
    for (int i = 0; i < 6; i++) {
        if (strstr(path, filters[i])) return 1;
    }
    return 0;
}

static void hashTextSection() {

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
