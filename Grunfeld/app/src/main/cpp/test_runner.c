#include "test_runner.h"
#include "socket_helper.h"
#include <assert.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <errno.h>
#include <android/log.h>
#include <fcntl.h>

#define TAG "GrunfeldNative"
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static void test_uname(void);
static void test_execve(void);
static void test_openat_denied_and_spoofed(void);
static void test_openat_faked(void);


void run_all_tests(void) {
    test_uname();
    test_execve();
    test_openat_denied_and_spoofed();
    test_openat_faked();
}

static void test_uname(void) {
    struct utsname buffer = {0};
    long ret;
    asm volatile(
            "mov x0, %[buf] \n\t"
            "mov x8, #160   \n\t"
            "svc #0         \n\t"
            "mov %[res], x0 \n\t"
            : [res] "=r"(ret)
    : [buf] "r"(&buffer)
    : "x0", "x8", "memory"
    );

    assert(ret >= 0);
    assert(strcmp(buffer.sysname, "Linux") == 0);
    assert(strcmp(buffer.nodename, "localhost") == 0);
    assert(strcmp(buffer.release, "6.6.56-android16-11-g8a3e2b1c4d5f") == 0);
    assert(strcmp(buffer.version, "#1 SMP PREEMPT Fri Dec 05 12:00:00 UTC 2025") == 0);
    assert(strcmp(buffer.machine, "aarch64") == 0);
    assert(strcmp(buffer.domainname, "(none)") == 0);
}

static void test_execve(void) {
    pid_t pid = fork();
    assert(pid != -1);

    if (pid == 0) {
        char *const argv[] = {"/system/bin/sh", NULL};
        char *const envp[] = {NULL};

        syscall(SYS_execve, "/system/bin/sh", argv, envp);

        _exit(errno);
    } else {
        int status;
        waitpid(pid, &status, 0);
        assert(WEXITSTATUS(status) == 0);
    }
}

static void test_openat_denied_and_spoofed(void) {
    int fd = -1;
    const char* deniedPaths[] = {
            "/dev/socket",
            "/sys/class/thermal",
            "/sys/class/power_supply",
            "/sys/devices/platform",
            "/sys/bus/platform",
            "/sys/module",
            "/proc/zoneinfo",
            "/proc/vmstat"
    };
    for (int i = 0; i < 8; i++) {
        fd = open(deniedPaths[i], O_RDONLY);
        assert(fd == -1);
    }

    const char* spoofedPaths[] = {
            "/data/misc/user/0/cacerts-added",
            "/system/bin/su",
            "/system/xbin/su",
            "/product/bin/su",
            "/debug_ramdisk/su",
            "/proc/net/arp",
    };

    for (int i = 0; i < 6; i++) {
        fd = open(spoofedPaths[i], O_RDONLY);
        assert(fd == -1);
    }
}

static void test_openat_faked(void) {
    int fd = -1;
    char buf[10000];
    const char* fakedPaths[] = {
            "/etc/hosts",
            "/system/etc/hosts",
            "/proc/version",
            "/proc/cpuinfo",
            "/proc/meminfo",
            "/proc/meminfo_extra",
            "/proc/sys/kernel/perf_event_paranoid",
            "/dev/__properties__/fingerprint_prop",
            "/proc/mounts"
    };
    for (int i = 0; i < 9; i++) {
        fd = open(fakedPaths[i], O_RDONLY);
        assert(fd != -1);

        ssize_t bytesRead = read(fd, buf, sizeof(buf) - 1);
        assert(bytesRead >= 0);

        buf[bytesRead] = '\0';
        LOGW("Contents of %s:\n%s", fakedPaths[i], buf);

        close(fd);
    }
}
