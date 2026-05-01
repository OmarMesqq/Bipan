#include "blocker.hpp"

#include <sys/mman.h>
#include <syscall.h>

#include <atomic>
#include <string>

#include "logger.hpp"
#include "shared.hpp"
#include "sigsys_handler.hpp"
#include "spoofer.hpp"
#include "unwinder.hpp"
#include "utils.hpp"

inline static bool shouldLog(const char* pathname);
inline static bool shouldSpoofExistence(const char* pathname);
inline static bool shouldDenyAccess(const char* pathname);
inline static const char* shouldFakeFile(const char* pathname);
void patchInstruction(uintptr_t address, int return_value);

/**
 * Blocks, lies about the existence or
 * provides a fake `memfd`'d FD for senstive
 * files. Otherwise, executes a raw syscall
 * to fetch FD to the file.
 */
int filterPathname(long sysno, long a0, long a1, long a2, long a3, long a4, long a5) {
  const char* pathname = (const char*)a1;
  if (pathname == nullptr) {
    return -EFAULT;
  }

  const bool isCallerTrusted = is_trusted_system_caller(pathname, nullptr, false);
  if (isCallerTrusted) {
    return arm64_raw_syscall(sysno, a0, a1, a2, a3, a4, a5);
  }

  if (shouldSpoofExistence(pathname)) {
    write_to_logcat_async(ANDROID_LOG_WARN, TAG, "Spoofing existence of %s", pathname);
    log_violation_trace(pathname);
    return -ENOENT;
  }

  const char* fakeFileContent = shouldFakeFile(pathname);
  if (fakeFileContent != nullptr) {
    int fake_fd = create_spoofed_file(fakeFileContent);
    if (fake_fd >= 0) {
      storeSpoofedFD(fake_fd, pathname);
      return fake_fd;
    }
  }

  if (shouldDenyAccess(pathname)) {
    write_to_logcat_async(ANDROID_LOG_WARN, TAG, "Denying access to %s", pathname);
    log_violation_trace(pathname);
    return -EACCES;
  }

  // TODO: too noisy! bionic kills us. Should find an async-signal safe logging solution
  // if (shouldLog(pathname) && !isCallerTrusted) {
  //   write_to_logcat_async(ANDROID_LOG_WARN, TAG, "Allowing access to: %s", pathname);
  // }
  return arm64_raw_syscall(sysno, a0, a1, a2, a3, a4, a5);
}

static std::atomic<uintptr_t> last_neutralized_pc{0};
/**
 * We patch the call site with a `nop`.
 * Bipan logs the violation as the PC at bottommost frame,
 * and every instruction in ARM64 is 4 bytes we just do:
 * PC_call = PC_logged - 4
 * and do nop(PC_call)
 */
void patchInstruction(uintptr_t address, int return_value) {
  if (last_neutralized_pc.exchange(address) == address) {
    return;
  }
  // Find the start of the page (4KB align)
  uintptr_t page_start = address & ~0xFFF;

  // Make it writable
  long ret = arm64_raw_syscall(__NR_mprotect, (long)page_start, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, 0, 0, 0);
  if (ret != 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "mprotect (W) failed natively: %ld", ret);
    return;
  }

  // Let's default to NOP
  uint32_t opcode = 0xd503201f;

  if (return_value >= 0 && return_value <= 65535) {
    // DYNAMIC ASSEMBLER: Generate 'MOV x0, #return_value' on the fly!
    // Base opcode for MOV x0 is 0xD2800000. We shift the value by 5 bits to place it in the 'imm16' field.
    opcode = 0xD2800000 | ((uint32_t)return_value << 5);
  } else if (return_value == -13) {  // -EACCES
    opcode = 0x92800180;             // MOVN x0, #12 (~12 = -13)
  } else if (return_value == -99) {  // -EADDRNOTAVAIL
    opcode = 0x92800C40;             // MOVN x0, #98 (~98 = -99)
  } else if (return_value == -11) {  // -EAGAIN
    opcode = 0x92800140;             // MOVN x0, #10 (~10 = -11)
  } else if (return_value == -2) {   // -ENOENT
    opcode = 0x92800040;             // MOVN x0, #1 (~1 = -2)
  }

  *(uint32_t*)address = opcode;

  __builtin___clear_cache((char*)address, (char*)(address + 4));

  // 5. Restore original permissions page permissions: probably (RX)
  arm64_raw_syscall(__NR_mprotect, (long)page_start, 4096, PROT_READ | PROT_EXEC, 0, 0, 0);

  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Patch succeeded: PC %p now returns %d.", (void*)address, return_value);
}

inline static bool shouldLog(const char* pathname) {
  return (
      !starts_with(pathname, "/data") &&
      !starts_with(pathname, "/product/app/webview") &&
      !starts_with(pathname, "/apex/com.android") &&
      !starts_with(pathname, "/storage/emulated/0") &&
      !starts_with(pathname, "/dev/ashmem") &&
      !starts_with(pathname, "/dev/urandom") &&
      !starts_with(pathname, "/dev/random") &&
      !starts_with(pathname, "/dev/zero") &&
      !starts_with(pathname, "/dev/null") &&
      !starts_with(pathname, "/mnt/expand") &&
      !([&]() {
        // Grouped Proc Checks
        if (starts_with(pathname, "/proc/")) {
          if (strstr(pathname, "/cmdline") ||
              strstr(pathname, "/task") ||
              strstr(pathname, "/cgroup") ||
              strstr(pathname, "/oom") ||
              strstr(pathname, "/comm") ||
              strstr(pathname, "/stat")) {
            return true;
          }
        }
        return false;
      }()));
}

inline static bool shouldSpoofExistence(const char* pathname) {
  return ((  // CAs
      strstr(pathname, "c7981ca8.0") != nullptr ||
      starts_with(pathname, "/data/misc/user/0/cacerts-added") ||
      // Root
      strstr(pathname, "zygisk") != nullptr ||
      strstr(pathname, "magisk") != nullptr ||
      strstr(pathname, "resetprop") != nullptr ||
      strstr(pathname, "supolicy") != nullptr ||
      // Weird ahh binaries
      starts_with(pathname, "/system/xbin") ||
      starts_with(pathname, "/system/bin/su") ||
      starts_with(pathname, "/product/bin/su") ||
      starts_with(pathname, "/bin/getprop") ||
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
      strstr(pathname, "otacerts") != nullptr));
}

inline static bool shouldDenyAccess(const char* pathname) {
  return ((starts_with(pathname, "/dev/socket") ||
           // Phone's EFS
           starts_with(pathname, "/mnt/vendor/efs") ||
           starts_with(pathname, "/mnt/vendor/cpefs") ||
           starts_with(pathname, "/mnt/pass_through") ||
           // CPU, temperature and platform info
           starts_with(pathname, "/sys/class/thermal") ||
           starts_with(pathname, "/sys/class/power_supply") ||
           starts_with(pathname, "/sys/devices/platform") ||
           starts_with(pathname, "/sys/bus/platform") ||
           starts_with(pathname, "/sys/module")) ||
          (strcmp(pathname, "/proc/zoneinfo") == 0 ||
           strcmp(pathname, "/proc/vmstat") == 0));
}

inline static const char* shouldFakeFile(const char* pathname) {
  if (strstr(pathname, "build.prop") != nullptr) {
    return "ro.build.product=husky\nro.product.device=husky\nro.product.model=Pixel 8 Pro\nro.product.brand=google\nro.product.name=husky\nro.product.manufacturer=Google\nro.build.tags=release-keys\nro.build.type=user\nro.secure=1\nro.debuggable=0\n";
  }
  if (strcmp(pathname, "/etc/hosts") == 0 || strcmp(pathname, "/system/etc/hosts") == 0) {
    return "127.0.0.1       localhost\n::1       localhost\n";
  }
  if (strcmp(pathname, "/proc/version") == 0) {
    return "Linux version 6.6.56-android16-11-g8a3e2b1c4d5f (build-user@build-host) (Android clang version 17.0.2) #1 SMP PREEMPT Fri Dec 05 12:00:00 UTC 2025\n";
  }
  if (strcmp(pathname, "/proc/cpuinfo") == 0) {
    return "Processor\t: AArch64 Processor rev 0 (aarch64)\nmodel name\t: ARMv8 Processor rev 0 (v8l)\nHardware\t: Google Tensor G3\n";
  }
  if (strcmp(pathname, "/proc/meminfo") == 0 ||
      strcmp(pathname, "/proc/meminfo_extra") == 0) {
    return "MemTotal:       11654320 kB\n"  // 12GB Pixel 8 Pro
           "MemFree:         1204164 kB\n"
           "MemAvailable:    4526384 kB\n"  // Higher available = "Healthy" system
           "Buffers:            4256 kB\n"
           "Cached:          3100192 kB\n"
           "SwapCached:          248 kB\n"
           "Active:          3475584 kB\n"
           "Inactive:        2658376 kB\n"
           "SwapTotal:       3145724 kB\n"  // Typical ZRAM size
           "SwapFree:        3140000 kB\n"
           "VmallocTotal:   263061440 kB\n"  // Standard for AArch64
           "CmaTotal:         163840 kB\n";
  }
  if (strcmp(pathname, "/proc/sys/kernel/perf_event_paranoid") == 0) {
    return "2\n";
  }
  // Stuff SELinux doesn't protect from
  if (
      local_strstr(pathname, "vendor_default_prop") ||
      local_strstr(pathname, "binder_cache_telephony_server_prop") ||
      local_strstr(pathname, "telephony_config_prop") ||
      local_strstr(pathname, "telephony_status_prop") ||
      local_strstr(pathname, "userdebug_or_eng_prop") ||
      local_strstr(pathname, "radio_control_prop") ||
      local_strstr(pathname, "fingerprint_prop") ||
      local_strstr(pathname, "bootloader_prop")) {
    // Dummy binary blob for the property service
    return "\1\0\0\0\0\0\0\0";
  }
  return nullptr;
}
