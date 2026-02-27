#include "sigsys_handler.hpp"

#include <dlfcn.h>
#include <linux/memfd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>

#include "shared.hpp"
#include "spoofer.hpp"
#include "synchronization.hpp"

static volatile int ipc_lock_state = 0;
static inline long arm64_bypassed_syscall(long sysno, long a0, long a1, long a2, long a3, long a4);
static bool is_system_thread();
static void get_library_from_addr(const char* label, uintptr_t addr);

// Async-signal-safe lock
inline void lock_ipc() {
  // __sync_lock_test_and_set writes 1 and returns the old value.
  // If it returns 1, it was already locked, so we sleep on the futex.
  while (__sync_lock_test_and_set(&ipc_lock_state, 1)) {
    futex_wait(&ipc_lock_state, 1);
  }
}

// Async-signal-safe unlock
inline void unlock_ipc() {
  __sync_lock_release(&ipc_lock_state);  // sets back to 0 securely
  futex_wake(&ipc_lock_state);           // wakes up the next waiting thread
}

static void log_address_info(const char* label, uintptr_t addr);
static void get_library_from_addr(char* label, uintptr_t addr);
static void sigsys_log_handler(int sig, siginfo_t* info, void* void_context);

void registerSigSysHandler() {
  struct sigaction sa{};
  sa.sa_sigaction = sigsys_log_handler;
  sa.sa_flags = SA_SIGINFO;
  // sigemptyset(&sa.sa_mask);
  if (sigaction(SIGSYS, &sa, nullptr) == -1) {
    LOGE("applySeccompFilter: Failed to set SIGSYS handler (errno: %d)", errno);
    _exit(1);
  }
}

static void sigsys_log_handler(int sig, siginfo_t* info, void* void_context) {
  ucontext_t* ctx = (ucontext_t*)void_context;
  uintptr_t pc = ctx->uc_mcontext.pc;
  uintptr_t lr = ctx->uc_mcontext.regs[30];
  int nr = info->si_syscall;  // or ctx->uc_mcontext.regs[8];

  // Don't block legitimate system threads
  if (is_system_thread()) {
    long result = arm64_bypassed_syscall(
        nr,
        ctx->uc_mcontext.regs[0],
        ctx->uc_mcontext.regs[1],
        ctx->uc_mcontext.regs[2],
        ctx->uc_mcontext.regs[3],
        ctx->uc_mcontext.regs[4]);
    ctx->uc_mcontext.regs[0] = result;
    return;
  }

  long arg0 = ctx->uc_mcontext.regs[0];
  long arg1 = ctx->uc_mcontext.regs[1];
  long arg2 = ctx->uc_mcontext.regs[2];
  long arg3 = ctx->uc_mcontext.regs[3];
  long arg4 = ctx->uc_mcontext.regs[4];
  long arg5 = ctx->uc_mcontext.regs[5];

  switch (nr) {
    case __NR_execve:
    case __NR_execveat: {
      const char* path = (const char*)ctx->uc_mcontext.regs[0];

      LOGE("Violation: execve/execvat (\"%s\")", path);

      ctx->uc_mcontext.regs[0] = -EACCES;
      break;
    }
    case __NR_uname: {
      LOGE("Violation: uname");
      struct utsname* buf = (struct utsname*)ctx->uc_mcontext.regs[0];
      if (!buf) return;

      memset(buf, 0, sizeof(struct utsname));
      strncpy(buf->sysname, "Linux", 64);
      strncpy(buf->nodename, "localhost", 64);
      strncpy(buf->release, "6.6.56-android16-11-g8a3e2b1c4d5f", 64);
      strncpy(buf->version, "#1 SMP PREEMPT Fri Dec 05 12:00:00 UTC 2025", 64);
      strncpy(buf->machine, "aarch64", 64);
      strncpy(buf->domainname, "(none)", 64);

      ctx->uc_mcontext.regs[0] = 0;  // "success"
      break;
    }

    case __NR_faccessat:
    case __NR_newfstatat:
    case __NR_openat: {
      int dirfd = (int)ctx->uc_mcontext.regs[0];
      const char* pathname = (const char*)ctx->uc_mcontext.regs[1];
      int flags = (int)ctx->uc_mcontext.regs[2];
      mode_t mode = (mode_t)ctx->uc_mcontext.regs[3];

      // 1. INVISIBLE TRACES (-ENOENT)
      if (strstr(pathname, "81c450f1.0") != nullptr ||
          strstr(pathname, "894c9e9f.0") != nullptr ||
          strstr(pathname, "9a5ba575.0") != nullptr ||
          strstr(pathname, "c7981ca8.0") != nullptr ||
          starts_with(pathname, "/data/misc/user/0/cacerts-added") ||
          strstr(pathname, "libzygisk.so") != nullptr ||
          strstr(pathname, "magisk") != nullptr ||
          strstr(pathname, "magiskpolicy") != nullptr ||
          strstr(pathname, "resetprop") != nullptr ||
          strstr(pathname, "supolicy") != nullptr ||
          starts_with(pathname, "/system/xbin") ||
          starts_with(pathname, "/system/bin/su") ||
          starts_with(pathname, "/product/bin/su") ||
          starts_with(pathname, "/system/bin/getprop") ||
          starts_with(pathname, "/system/bin/dumpsys") ||
          starts_with(pathname, "/system/bin/dumpstate") ||
          starts_with(pathname, "/system/bin/uptime") ||
          starts_with(pathname, "/system/bin/toolbox") ||
          starts_with(pathname, "/system/bin/toybox") ||
          starts_with(pathname, "/system/bin/sh") ||
          starts_with(pathname, "/system/bin/mount") ||
          starts_with(pathname, "/system/bin/modprobe") ||
          starts_with(pathname, "/system/bin/vmstat") ||
          starts_with(pathname, "/system/bin/df") ||
          (strstr(pathname, "lineageos") != nullptr) ||
          (strstr(pathname, "Lineage") != nullptr)) {
        LOGW("App attempted faccessat/newfstatat/openat(%s)", pathname);
        ctx->uc_mcontext.regs[0] = -ENOENT;
        return;
      }

      // 2. SELINUX MIMICRY (-EACCES)
      if (starts_with(pathname, "/dev/__properties__/u:object_r:vendor_default_prop:s") ||
          starts_with(pathname, "/dev/__properties__/u:object_r:binder_cache_telephony_server_prop:s0") ||
          starts_with(pathname, "/dev/__properties__/u:object_r:telephony_config_prop:s0") ||
          starts_with(pathname, "/dev/__properties__/u:object_r:telephony_status_prop:s0") ||
          starts_with(pathname, "/dev/__properties__/u:object_r:serialno_prop:s0") ||
          starts_with(pathname, "/dev/__properties__/u:object_r:build_bootimage_prop:s0") ||
          starts_with(pathname, "/dev/__properties__/u:object_r:userdebug_or_eng_prop:s0") ||
          starts_with(pathname, "/dev/__properties__/u:object_r:radio_control_prop:s0") ||
          starts_with(pathname, "/mnt/vendor/efs") ||
          starts_with(pathname, "/mnt/vendor/cpefs") ||
          starts_with(pathname, "/mnt/pass_through") ||
          starts_with(pathname, "/sys/devices/system/cpu") ||
          starts_with(pathname, "/sys/class/thermal")) {
        LOGW("App attempted faccessat/newfstatat/openat(%s)", pathname);
        ctx->uc_mcontext.regs[0] = -EACCES;
        return;
      }

      if (strcmp(pathname, "/proc/meminfo") == 0 ||
          strcmp(pathname, "/proc/meminfo_extra") == 0 ||
          strcmp(pathname, "/proc/zoneinfo") == 0 ||
          strcmp(pathname, "/proc/vmstat") == 0) {
        LOGW("Blocked memory query: %s", pathname);
        ctx->uc_mcontext.regs[0] = -EACCES;
        return;
      }

      // 3. MAPS SCRUBBING (Native, No Broker Needed!)
      bool reading_maps = (strcmp(pathname, "/proc/self/maps") == 0) ||
                          ((safe_proc_pid_path[0] != '\0') && starts_with(pathname, safe_proc_pid_path) && strstr(pathname, "/maps") != nullptr);

      if (reading_maps) {
        LOGW("Intercepted memory maps read natively: %s", pathname);

        // 1. Open the real maps file natively using the bypassed syscall (6 args)
        long real_fd = arm64_bypassed_syscall(__NR_openat, dirfd, (long)pathname, flags, mode, 0);
        if (real_fd < 0) {
          ctx->uc_mcontext.regs[0] = real_fd;
          return;
        }

        // 2. Create a fake in-memory file to hold the scrubbed data (6 args)
        long fake_fd = arm64_bypassed_syscall(__NR_memfd_create, (long)"spoofed_maps", MFD_CLOEXEC, 0, 0, 0);
        if (fake_fd < 0) {
          arm64_bypassed_syscall(__NR_close, real_fd, 0, 0, 0, 0);
          ctx->uc_mcontext.regs[0] = real_fd;
          return;
        }

        // 3. Read the real file line-by-line and scrub it
        char buf[4096];
        long bytes_read;
        char line[4096];
        int line_pos = 0;

        // Read natively (6 args)
        while ((bytes_read = arm64_bypassed_syscall(__NR_read, real_fd, (long)buf, sizeof(buf), 0, 0)) > 0) {
          for (int i = 0; i < bytes_read; i++) {
            if (line_pos < sizeof(line) - 1) {
              line[line_pos++] = buf[i];
            }

            if (buf[i] == '\n') {
              line[line_pos] = '\0';  // Null-terminate the line

              // Check for forbidden keywords
              if (strstr(line, "magisk") == nullptr &&
                  strstr(line, "zygisk") == nullptr &&
                  strstr(line, "bipan") == nullptr &&
                  strstr(line, "riru") == nullptr &&
                  strstr(line, "ksud") == nullptr &&
                  !(strstr(line, "rw-s") != nullptr && strstr(line, "/dev/zero (deleted)") != nullptr) &&
                  !(strstr(line, "r-xp") != nullptr && (strstr(line, "[anon:") != nullptr || strchr(line, '/') == nullptr))) {
                // Line is clean, write it to the fake file natively (6 args)
                arm64_bypassed_syscall(__NR_write, fake_fd, (long)line, line_pos, 0, 0);
              }
              line_pos = 0;  // Reset for the next line
            }
          }
        }

        // 4. Clean up and return the fake file descriptor natively (6 args)
        arm64_bypassed_syscall(__NR_close, real_fd, 0, 0, 0, 0);
        arm64_bypassed_syscall(__NR_lseek, fake_fd, 0, SEEK_SET, 0, 0);  // Rewind

        ctx->uc_mcontext.regs[0] = fake_fd;
        return;
      }

      if (strcmp(pathname, "/proc/cpuinfo") == 0) {
        const char* fake_cpu = "Processor\t: AArch64 Processor rev 0 (aarch64)\nmodel name\t: ARMv8 Processor rev 0 (v8l)\nHardware\t: Google Tensor G3\n";
        ctx->uc_mcontext.regs[0] = create_spoofed_file(fake_cpu);
        LOGW("App attempted faccessat/newfstatat/openat(/proc/cpuinfo)");
        return;
      }
      if (strcmp(pathname, "/proc/version") == 0) {
        const char* fake_version = "Linux version 6.6.56-android16-11-g8a3e2b1c4d5f (build-user@build-host) (Android clang version 17.0.2) #1 SMP PREEMPT Fri Dec 05 12:00:00 UTC 2025\n";
        ctx->uc_mcontext.regs[0] = create_spoofed_file(fake_version);
        LOGW("App attempted faccessat/newfstatat/openat(/proc/version)");
        return;
      }
      if (strcmp(pathname, "/etc/hosts") == 0 || strcmp(pathname, "/system/etc/hosts") == 0) {
        const char* fake_hosts = "127.0.0.1       localhost\n::1             ip6-localhost\n";
        ctx->uc_mcontext.regs[0] = create_spoofed_file(fake_hosts);
        LOGW("App attempted faccessat/newfstatat/openat(%s)", pathname);
        return;
      }

      if (strcmp(pathname, "/proc/mounts") == 0) {
        const char* fake_mounts = "rootfs / rootfs ro,seclabel 0 0\ntmpfs /dev tmpfs rw,seclabel 0 0\nproc /proc proc rw,relatime 0 0\nsysfs /sys sysfs rw,seclabel,relatime 0 0\nselinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0\n/dev/block/mapper/system /system ext4 ro,seclabel,relatime 0 0\n/dev/block/mapper/vendor /vendor ext4 ro,seclabel,relatime 0 0\n/dev/block/by-name/userdata /data f2fs rw,seclabel,nosuid,nodev,noatime 0 0\n";
        ctx->uc_mcontext.regs[0] = create_spoofed_file(fake_mounts);
        LOGW("App attempted faccessat/newfstatat/openat(/proc/mounts)");
        return;
      }

      if (strstr(pathname, "build.prop") != nullptr &&
          (starts_with(pathname, "/system") || starts_with(pathname, "/vendor") ||
           starts_with(pathname, "/product") || starts_with(pathname, "/odm") || starts_with(pathname, "/system_ext"))) {
        const char* fake_prop = "ro.build.product=husky\nro.product.device=husky\nro.product.model=Pixel 8 Pro\nro.product.brand=google\nro.product.name=husky\nro.product.manufacturer=Google\nro.build.tags=release-keys\nro.build.type=user\nro.secure=1\nro.debuggable=0\n";
        ctx->uc_mcontext.regs[0] = create_spoofed_file(fake_prop);
        LOGW("App attempted faccessat/newfstatat/openat to build.prop");
        return;
      }

      // Native passthrough
      if (!starts_with(pathname, "/data") &&
          !starts_with(pathname, "/dev/ashmem") &&
          !starts_with(pathname, "/dev/mali") &&
          !starts_with(pathname, "/product/app/webview") &&
          !starts_with(pathname, "/apex/com.android") &&
          !starts_with(pathname, "/storage/emulated/0") &&
          // TODO
          !starts_with(pathname, "/proc") &&
          !starts_with(pathname, "/dev/random") &&
          !starts_with(pathname, "/system") &&
          !starts_with(pathname, "/product/fonts") &&
          !starts_with(pathname, "/dev/random") &&
          !starts_with(pathname, "/dev/urandom") &&
          !starts_with(pathname, "/mnt/expand") &&
          !starts_with(pathname, "/vendor/lib64") &&
          !starts_with(pathname, "/odm/lib64/hw") &&
          !starts_with(pathname, "/dev/null")) {
        LOGD("faccessat/newfstatat/openat to %s. Allowing natively", pathname);
        get_library_from_addr("PC", pc);
        get_library_from_addr("LR", lr);
      }

      ctx->uc_mcontext.regs[0] = arm64_bypassed_syscall(nr, arg0, arg1, arg2, arg3, arg4);
      return;
    }
    default: {
      LOGE("Violation: syscall number %d", nr);
      ctx->uc_mcontext.regs[0] = 0;  // "success"
      break;
    }
  }
}

static void log_address_info(const char* label, uintptr_t addr) {
  Dl_info dlinfo;
  if (dladdr((void*)addr, &dlinfo) && dlinfo.dli_fname) {
    LOGD("%s: %p | Library: %s | Symbol: %s",
         label,
         (void*)addr,
         dlinfo.dli_fname,
         dlinfo.dli_sname ? dlinfo.dli_sname : "N/A");
  } else {
    LOGE("%s: %p (Could not resolve)", label, (void*)addr);
  }
}

static void get_library_from_addr(const char* label, uintptr_t addr) {
  Dl_info dlinfo;
  if (dladdr((void*)addr, &dlinfo) && dlinfo.dli_fname) {
    const char* path = dlinfo.dli_fname;

    bool is_system = (strncmp(path, "/system/", 8) == 0);
    bool is_apex = (strncmp(path, "/apex/", 6) == 0);

    if (!is_system && !is_apex) {
      LOGD("%s resolves to library %s", label, path);
    }
  } else {
    LOGE("Could not resolve library at %p", (void*)addr);
  }
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wregister"
static inline long arm64_bypassed_syscall(long sysno, long a0, long a1, long a2, long a3, long a4) {
  register long x8 __asm__("x8") = sysno;
  register long x0 __asm__("x0") = a0;
  register long x1 __asm__("x1") = a1;
  register long x2 __asm__("x2") = a2;
  register long x3 __asm__("x3") = a3;
  register long x4 __asm__("x4") = a4;
  register long x5 __asm__("x5") = 0xBADB01;  // The Magic Number!

  __asm__ volatile(
      "svc #0\n"
      : "+r"(x0)
      : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
      : "memory", "cc");

  return x0;
}
#pragma clang diagnostic pop

static bool is_system_thread() {
  char thread_name[16] = {0};
  if (prctl(PR_GET_NAME, thread_name, 0, 0, 0) != 0) {
    return false;
  }

  if (strncmp(thread_name, "RenderThread", 12) == 0 ||
      strncmp(thread_name, "hwuiTask", 8) == 0 ||
      strncmp(thread_name, "Binder:", 7) == 0 ||
      strncmp(thread_name, "Jit thread pool", 15) == 0 ||
      strncmp(thread_name, "Profile Saver", 13) == 0 ||
      strncmp(thread_name, "mali-", 5) == 0 ||
      strncmp(thread_name, "kgsl-", 5) == 0 ||
      strncmp(thread_name, "ReferenceQueueD", 15) == 0 ||
      strncmp(thread_name, "FinalizerDaemon", 15) == 0 ||
      strncmp(thread_name, "HeapTaskDaemon", 14) == 0) {
    return true;
  }
  return false;
}