#include "blocker.hpp"

#include <sys/mman.h>

#include <string>

#include "assembly.hpp"
#include "shared.hpp"
#include "spoofer.hpp"
#include "unwinder.hpp"

inline static bool shouldLog(const char* pathname);
inline static bool shouldSpoofExistence(const char* pathname);
inline static bool shouldDenyAccess(const char* pathname);
inline static const char* shouldFakeFile(const char* pathname);
void patchInstructionWithNop(uintptr_t address);

/**
 * Blocks, lies about the existence or
 * provides a fake `memfd`'d FD for senstive
 * files. Otherwise, executes a bypassed syscall
 * to fetch FD to the file.
 */
int filterPathname(long sysno, long a0, long a1, long a2, long a3, long a4) {
  const char* pathname = (const char*)a1;
  if (pathname == nullptr) {
    return -EFAULT;
  }

  const bool isCallerTrusted = is_trusted_system_caller(pathname, false);
  if (isCallerTrusted) {
    return arm64_bypassed_syscall(sysno, a0, a1, a2, a3, a4);
  }

  if (shouldSpoofExistence(pathname)) {
    LOGW("Spoofing existence of %s", pathname);
    log_violation_trace(pathname);
    return -ENOENT;
  }

  const char* fakeFileContent = shouldFakeFile(pathname);
  if (fakeFileContent != nullptr) {
    LOGW("Spoofing %s", pathname);
    log_violation_trace(pathname);
    return create_spoofed_file(fakeFileContent);
  }

  if (shouldDenyAccess(pathname)) {
    LOGW("Denying access to %s", pathname);
    log_violation_trace(pathname);
    return -EACCES;
  }

  if (shouldLog(pathname) && !isCallerTrusted) {
    LOGW("Untrusted caller: allowing access to %s", pathname);
  }
  return arm64_bypassed_syscall(sysno, a0, a1, a2, a3, a4);
}

void patchInstructionWithNop(uintptr_t address) {
  // 1. Find the start of the page (4KB align)
  uintptr_t page_start = address & ~0xFFF;

  // 2. Make page writable
  if (mprotect((void*)page_start, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    LOGE("mprotect failed: %s", strerror(errno));
    return;
  }

  // 3. Write NOP (0x1f2003d5 in ARM64 Little Endian)
  *(uint32_t*)address = 0xd503201f;

  // 4. Clear CPU Cache
  __builtin___clear_cache((char*)address, (char*)(address + 4));

  // 5. Restore original permissions (R-X)
  mprotect((void*)page_start, 4096, PROT_READ | PROT_EXEC);

  LOGW("Proactive Patch: Offset %p is now a NOP.", (void*)address);
}

/**
 * Returns `true` if IP address
 * `ip4` is in any of
 * the IPv4 LAN ranges. `false` otherwise
 */
bool filterIPv4LanAccess(uint32_t ip4) {
  if ((ip4 & 0xFF000000) == 0x0A000000) {
    // 10.0.0.0/8 (Class A Private)
    return true;
  } else if ((ip4 & 0xFFF00000) == 0xAC100000) {
    // 172.16.0.0/12 (Class B Private)
    return true;
  } else if ((ip4 & 0xFFFF0000) == 0xC0A80000) {
    // 192.168.0.0/16 (Class C Private)
    return true;
  } else if ((ip4 & 0xF0000000) == 0xE0000000) {
    // 224.0.0.0/4 (Multicast)
    return true;
  } else if (ip4 == 0xFFFFFFFF) {
    // 255.255.255.255 (Broadcast)
    return true;
  }
  return false;
}

/**
 * Returns `true` if IP address
 * pointed by `ip6` is in any of
 * the IPv6 LAN ranges. `false` otherwise
 */
bool filterIPv6LanAccess(uint8_t* ip6) {
  if (!ip6) {
    LOGE("filterIPv6LanAccess: IPv6 pointer is null!");
    return false;
  }

  if (ip6[0] == 0xFE && (ip6[1] & 0xC0) == 0x80) {
    // fe80::/10 (Link-Local)
    return true;
  } else if ((ip6[0] & 0xFE) == 0xFC) {
    // fc00::/7 (Unique Local)
    return true;
  } else if (ip6[0] == 0xFF) {
    // ff00::/8 (Multicast)
    return true;
  }
  return false;
}

inline static bool shouldLog(const char* pathname) {
  return (
      !starts_with(pathname, "/data") &&
      !starts_with(pathname, "/product/app/webview") &&
      !starts_with(pathname, "/apex/com.android") &&
      !starts_with(pathname, "/storage/emulated/0") &&
      !starts_with(pathname, "/product/fonts") &&
      !starts_with(pathname, "/system/fonts") &&
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
              strstr(pathname, "libzygisk.so") != nullptr ||
              strstr(pathname, "magisk") != nullptr ||
              strstr(pathname, "magiskpolicy") != nullptr ||
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
              // Custom ROM
              (strstr(pathname, "lineage") != nullptr) ||
              (strstr(pathname, "Lineage") != nullptr) ||
              starts_with(pathname, "/etc/security/otacerts.zip")) ||
          (starts_with(pathname, "/dev/mali") ||
           starts_with(pathname, "/dev/kgsl-3d0") ||
           starts_with(pathname, "/dev/binder") ||
           starts_with(pathname, "/dev/hwbinder") ||
           starts_with(pathname, "/vendor/lib64") ||
           starts_with(pathname, "/system_ext/bin/hwservicemanager") ||
           starts_with(pathname, "/system/bin/app_process") ||
           starts_with(pathname, "/odm/lib64/hw") ||
           starts_with(pathname, "/dev/vndbinder")));
}

inline static bool shouldDenyAccess(const char* pathname) {
  return ((starts_with(pathname, "/dev/__properties__/u:object_r:vendor_default_prop:s") ||
           starts_with(pathname, "/dev/__properties__/u:object_r:binder_cache_telephony_server_prop:s0") ||
           starts_with(pathname, "/dev/__properties__/u:object_r:telephony_config_prop:s0") ||
           starts_with(pathname, "/dev/__properties__/u:object_r:telephony_status_prop:s0") ||
           starts_with(pathname, "/dev/__properties__/u:object_r:serialno_prop:s0") ||
           starts_with(pathname, "/dev/__properties__/u:object_r:build_bootimage_prop:s0") ||
           starts_with(pathname, "/dev/__properties__/u:object_r:userdebug_or_eng_prop:s0") ||
           starts_with(pathname, "/dev/__properties__/u:object_r:radio_control_prop:s0") ||
           starts_with(pathname, "/dev/__properties__/u:object_r:custom_version_prop:s0") ||
           starts_with(pathname, "/dev/__properties__/u:object_r:fingerprint_prop:s0") ||
           starts_with(pathname, "/dev/__properties__/u:object_r:bootloader_prop:s0") ||
           // Phone's EFS
           starts_with(pathname, "/mnt/vendor/efs") ||
           starts_with(pathname, "/mnt/vendor/cpefs") ||
           starts_with(pathname, "/mnt/pass_through") ||
           // CPU, temperature and platform info
           starts_with(pathname, "/sys/devices/system/cpu") ||
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
    return "127.0.0.1       localhost\n::1\n";
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
  return nullptr;
}
