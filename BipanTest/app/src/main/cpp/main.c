#include <android/log.h>
#include <jni.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <stdio.h>
#include <stdbool.h>

#define TAG "Grunfeld"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)


static int scanProcSelfMaps();
static int getNativeInfo();

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGD("Native C bridge initialized. Dumping system info...");
    int ret = 0;

    // ret = scanProcSelfMaps();
    // if (ret == -1) {
    //    LOGE("Failed to scan /proc/self/maps");
    // }
    ret = getNativeInfo();

    if (ret == 0) {
        LOGD("Dump successful");
    } else if (ret == -1) {
        LOGE("Failed to dump info!");
    } else {
        LOGE("Unknown error when dumping info!");
    }

    return JNI_VERSION_1_6;
}

static int getNativeInfo() {
    // uname syscall
    struct utsname buffer = {0};
    long ret;
    asm volatile (
            "mov x0, %[buf] \n\t"  // place `buffer`'s address in x0
            "mov x8, #160   \n\t"  // 160 is the syscall number for uname
            "svc #0         \n\t"  // Supervisor Call
            "mov %[res], x0 \n\t"  // Store return value in ret
            : [res] "=r" (ret)     // Output operand
    : [buf] "r" (&buffer)  // Input operand
    : "x0", "x8", "memory" // Clobbered registers
    );

    if (ret < 0) {
        if (ret == -EPERM || errno == EPERM) {
            LOGE("uname failed due to Permission Denied (EPERM)");
        } else {
            LOGE("uname failed due to unknown reason (status code: %ld)", ret);
        }
        return -1;
    } else {
        if (ret == 0) {
            LOGD("uname was SUCCESSFUL (status code: %ld)", ret);
        } else {
            LOGD("uname was SUCCESSFUL but returned non-zero (status code: %ld)", ret);
        }

        LOGD("System Name: %s\n", buffer.sysname);
        LOGD("Node Name:   %s\n", buffer.nodename);
        LOGD("Release:     %s\n", buffer.release);
        LOGD("Version:     %s\n", buffer.version);
        LOGD("Machine:     %s\n", buffer.machine);
        LOGD("Domain Name:     %s\n", buffer.domainname);
        return 0;
    }


    pid_t pid = fork();
    if (pid == 0) {
        sleep(1);
        LOGD("Child: becoming '/sytem/bin/echo'...\n");
        sleep(1);

        char *args[] = {"/system/bin/echo", "Hello", NULL};
        char *env[] = { NULL };

        // execve/execveat syscall
        if (execve("/system/bin/echo", args, env) == -1) {
            if (errno == EPERM) { // Sandbox worked?
                LOGE("Child: received permission denied (EPERM)");
                _exit(13);
            }
        }
        LOGE("Child: 'execve' failed due to UNKNOWN reason");
        _exit(1);
    } else {
        int status;
        LOGD("Parent: Waiting for child (PID %d) to finish...", pid);

        if (waitpid(pid, &status, 0) == -1) {
            LOGE("Parent: waitpid failed: %s", strerror(errno));
            return -1;
        } else {
            if (WIFSIGNALED(status)) { // The process was terminated by a signal
                int sig = WTERMSIG(status);
                LOGE("Parent: Child terminated by SIGNAL %d (%s)", sig, strsignal(sig));
                return -1;
            } else if (WIFEXITED(status)) { // The process exited normally by itself
                int exit_code = WEXITSTATUS(status);
                if (exit_code == 0) {
                    LOGD("Parent: Child exited normally (status code %d)", exit_code);
                    return 0;
                } else {
                    LOGE("Parent: Child exited with FAILURE (status code %d)", exit_code);
                    return -1;
                }
            } else {
                LOGE("Parent: Child failed by UNKNOWN cause (status code: %d)", status);
                return -1;
            }
        }
    }
}

static int scanProcSelfMaps() {
    FILE *fp;
    char line[1024];

    // open/openat syscall
    fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) {
        LOGE("Error opening /proc/self/maps");
        return -1;
    }

    printf("Memory map BELOW:\n");
    printf("--------------------------------------------------\n");

    while (fgets(line, sizeof(line), fp)) {
        // Here you can use sscanf to extract specific fields
        // For now, we'll just print the raw line
        LOGD("%s", line);
    }

    long long start, end;
    char perms[5];
    long long offset;
    int dev_major, dev_minor;
    long inode;
    char path[1024];

    if (sscanf(line, "%llx-%llx %4s %llx %x:%x %ld %s",
               &start, &end, perms, &offset, &dev_major, &dev_minor, &inode, path) >= 7) {
        LOGD("Range: %llx to %llx | Perms: %s | Path: %s\n", start, end, perms, path);
    } else {
        LOGE("sscanf failed to read all fields of /proc/self/maps");
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}
