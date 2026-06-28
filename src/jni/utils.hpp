#ifndef UTILS_HPP
#define UTILS_HPP

#include <arpa/inet.h>
#include <sys/mman.h>
#include <syscall.h>

#include <atomic>
#include <string>

#include "shared.hpp"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wregister"

/**
 * Executes a raw system call on ARM64
 */
__attribute__((always_inline)) inline long arm64_raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5) {
  register long x8 __asm__("x8") = sysno;
  register long x0 __asm__("x0") = a0;
  register long x1 __asm__("x1") = a1;
  register long x2 __asm__("x2") = a2;
  register long x3 __asm__("x3") = a3;
  register long x4 __asm__("x4") = a4;
  register long x5 __asm__("x5") = a5;

  __asm__ volatile(
      "svc #0\n"
      : "+r"(x0)                                              // Output: x0 will contain the return value
      : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)  // Inputs
      : "memory", "cc"                                        // Clobbers: memory and condition codes might change
  );

  return x0;
}

#pragma clang diagnostic pop

inline bool starts_with(const char* str, const char* prefix) {
  return strncmp(str, prefix, strlen(prefix)) == 0;
}

inline void write_to_char_buf(char* dest, const char* src, size_t len) {
  for (size_t i = 0; i < len; i++) {
    dest[i] = src[i];
  }
}

inline size_t local_strlen(const char* s) {
  size_t len = 0;
  while (s[len]) len++;
  return len;
}

inline const char* local_strstr(const char* haystack, const char* needle) {
  if (!*needle) return haystack;
  for (; *haystack; haystack++) {
    if (*haystack == *needle) {
      const char *h = haystack, *n = needle;
      while (*h && *n && *h == *n) {
        h++;
        n++;
      }
      if (!*n) return haystack;
    }
  }
  return nullptr;
}

inline const char* local_strchr(const char* s, int c) {
  while (*s) {
    if (*s == (char)c) return s;
    s++;
  }
  return nullptr;
}

// Verifies if a segment of a string is purely numbers (a PID)
__attribute__((always_inline)) inline bool is_pure_numeric(const char* str, size_t len) {
  if (len == 0) return false;
  for (size_t i = 0; i < len; i++) {
    if (str[i] < '0' || str[i] > '9') return false;
  }
  return true;
}

// Validates any /proc/<PID>/target_file layout
__attribute__((always_inline)) inline bool is_dynamic_proc_file(const char* pathname, const char* suffix) {
  // 1. Must start with "/proc/"
  if (strncmp(pathname, "/proc/", 6) != 0) return false;

  // 2. Locate the next slash after "/proc/"
  const char* pid_start = pathname + 6;
  const char* next_slash = strchr(pid_start, '/');
  if (!next_slash) return false;

  // 3. Ensure the characters between the slashes are a valid PID number
  size_t pid_len = next_slash - pid_start;
  if (!is_pure_numeric(pid_start, pid_len)) return false;

  // 4. Check if the remaining suffix matches exactly (e.g., "/maps" or "/smaps")
  return strcmp(next_slash, suffix) == 0;
}

inline bool is_maps(const char* pathname) {
  return (strcmp(pathname, "/proc/self/maps") == 0) ||
         is_dynamic_proc_file(pathname, "/maps");
}

inline bool is_smaps(const char* pathname) {
  return (strcmp(pathname, "/proc/self/smaps") == 0) ||
         is_dynamic_proc_file(pathname, "/smaps");
}

inline bool is_mounts(const char* pathname) {
  return (strcmp(pathname, "/proc/mounts") == 0) ||
         (strcmp(pathname, "/proc/self/mounts") == 0) ||
         (strcmp(pathname, "/proc/self/mountinfo") == 0) ||
         is_dynamic_proc_file(pathname, "/mountinfo") ||
         is_dynamic_proc_file(pathname, "/mounts");
}

inline size_t get_msghdr_len(const struct msghdr* msg) {
  size_t total = 0;
  if (msg && msg->msg_iov) {
    for (size_t i = 0; i < (size_t)msg->msg_iovlen; ++i) {
      total += msg->msg_iov[i].iov_len;
    }
  }
  return total;
}

/**
 * Returns `true` if IP address
 * `ip4` is in any of
 * the IPv4 LAN ranges. `false` otherwise
 */
inline bool filterIPv4LanAccess(uint32_t ip4) {
  // Unspecified address (0.0.0.0)
  if (ip4 == 0x00000000) {
    return true;
  }

  // Loopback (127.0.0.0/8)
  if ((ip4 & 0xFF000000) == 0x7F000000) {
    return true;
  }

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
  } else if ((ip4 & 0xFFFF0000) == 0xA9FE0000) {
    // 169.254.0.0/16 (Link-Local/ APIPA (Automatic Private IP Addressing))
    return true;
  }
  return false;
}

/**
 * Returns `true` if IP address
 * pointed by `ip6` is in any of
 * the IPv6 LAN ranges. `false` otherwise
 */
inline bool filterIPv6LanAccess(uint8_t* ip6) {
  if (!ip6) {
    return false;
  }

  // Handle IPv4-mapped IPv6 addresses
  bool is_v4_mapped = true;
  for (int i = 0; i < 10; i++) {
    if (ip6[i] != 0) {
      is_v4_mapped = false;
      break;
    }
  }

  if (is_v4_mapped && ip6[10] == 0xFF && ip6[11] == 0xFF) {
    // Reconstruct the 32-bit IPv4 address in host byte order
    uint32_t ipv4 = (ip6[12] << 24) | (ip6[13] << 16) | (ip6[14] << 8) | ip6[15];

    // Apply IPv4 policies
    return filterIPv4LanAccess(ipv4);
  }

  // Unspecified (::)
  bool is_unspecified = true;
  for (int i = 0; i < 16; i++) {
    if (ip6[i] != 0) is_unspecified = false;
  }
  if (is_unspecified) {
    return true;
  }

  // Loopback (::1)
  bool is_loopback = (ip6[15] == 1);
  for (int i = 0; i < 15; i++) {
    if (ip6[i] != 0) is_loopback = false;
  }
  if (is_loopback) {
    return true;
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

/**
 * Returns `true` if `sa_family` of given socket struct `addr`
 * is either IPv4 (`AF_INET`) or IPv6 (`AF_INET6`) **AND**
 * its address falls within LAN IP ranges defined by RFCs
 */
inline bool is_lan_address(struct sockaddr* addr) {
  if (addr == nullptr) return false;
  if (addr->sa_family == AF_INET) {
    return filterIPv4LanAccess(ntohl(((struct sockaddr_in*)addr)->sin_addr.s_addr));
  }
  if (addr->sa_family == AF_INET6) {
    return filterIPv6LanAccess(((struct sockaddr_in6*)addr)->sin6_addr.s6_addr);
  }
  return false;
}

__attribute__((always_inline)) static inline size_t my_strlen(const char* s) {
  size_t len = 0;
  while (s[len]) len++;
  return len;
}

__attribute__((always_inline)) static inline void* my_memset(void* s, int c, size_t n) {
  unsigned char* p = (unsigned char*)s;
  while (n--) *p++ = (unsigned char)c;
  return s;
}

__attribute__((always_inline)) static inline char* my_strncpy(char* dest, const char* src, size_t n) {
  size_t i;
  for (i = 0; i < n && src[i] != '\0'; i++) dest[i] = src[i];
  for (; i < n; i++) dest[i] = '\0';
  return dest;
}

__attribute__((always_inline)) static inline void* my_memcpy(void* dest, const void* src, size_t n) {
  unsigned char* d = (unsigned char*)dest;
  const unsigned char* s = (const unsigned char*)src;
  while (n--) *d++ = *s++;
  return dest;
}

__attribute__((always_inline)) inline bool is_exact_dir(const char* path, const char* target_dir) {
  size_t len = strlen(target_dir);
  if (strncmp(path, target_dir, len) == 0) {
    // Return true if it ends exactly at the dir name, or has a trailing slash
    return path[len] == '\0' || (path[len] == '/' && path[len + 1] == '\0');
  }
  return false;
}

__attribute__((always_inline)) inline bool shouldLog(const char* pathname) {
  // Ignore spammy app/system areas
  if (starts_with(pathname, "/data/data") ||
      starts_with(pathname, "/data/dalvik-cache") ||
      starts_with(pathname, "/data/app") ||
      starts_with(pathname, "/system/framework") ||
      starts_with(pathname, "/system_ext/framework") ||
      starts_with(pathname, "/data/misc/apexdata/com.android.art") ||
      starts_with(pathname, "/data/user/0") ||
      starts_with(pathname, "/data/user_de/0/") ||
      starts_with(pathname, "/storage/emulated/0/Android/media") ||
      starts_with(pathname, "/storage/emulated/0/Android/data") ||
      starts_with(pathname, "/data/misc/profiles") ||
      starts_with(pathname, "/data/misc/shared_relro") ||
      starts_with(pathname, "/product/app/webview") ||
      starts_with(pathname, "/apex/com.android") ||
      starts_with(pathname, "/mnt/expand")) {
    return false;
  }

  // Ignore noisy special file stats
  if (starts_with(pathname, "/dev/ashmem") ||
      starts_with(pathname, "/dev/urandom") ||
      starts_with(pathname, "/dev/random") ||
      starts_with(pathname, "/dev/zero") ||
      starts_with(pathname, "/dev/null")) {
    return false;
  }

  // Ignore some /proc stats
  if (starts_with(pathname, "/proc/")) {
    if (strstr(pathname, "/cmdline") ||
        strstr(pathname, "/task") ||
        strstr(pathname, "/cgroup") ||
        strstr(pathname, "/oom") ||
        strstr(pathname, "/comm") ||
        strstr(pathname, "/stat")) {
      return false;
    }
  }

  // Ignore EXACT directory opens (directory scans)
  if (is_exact_dir(pathname, "/data") ||
      is_exact_dir(pathname, "/data/user") ||
      is_exact_dir(pathname, "/storage/emulated/0") ||
      is_exact_dir(pathname, "/system") ||
      is_exact_dir(pathname, "/system_ext") ||
      is_exact_dir(pathname, "/system/framework") ||
      is_exact_dir(pathname, "/system_ext/framework") ||
      is_exact_dir(pathname, "/system/lib64") ||
      is_exact_dir(pathname, "/system_ext/lib64") ||
      is_exact_dir(pathname, "/product/lib64") ||
      is_exact_dir(pathname, "/system/product/lib64") ||
      is_exact_dir(pathname, "/vendor/lib64")) {
    return false;
  }

  return true;
}

__attribute__((always_inline)) inline bool shouldSpoofExistence(const char* pathname) {
  return ((  // CAs
      strstr(pathname, "c7981ca8.0") != nullptr ||
      starts_with(pathname, "/data/misc/user/0/cacerts-") ||
      // VPN tunnel
      starts_with(pathname, "/sys/class/net/tun") ||
      // Crash reports
      starts_with(pathname, "/data/anr") ||
      starts_with(pathname, "/proc/meminfo_extra") ||
      // Root
      strstr(pathname, "zygisk") != nullptr ||
      strstr(pathname, "magisk") != nullptr ||
      strstr(pathname, "resetprop") != nullptr ||
      strstr(pathname, "supolicy") != nullptr ||
      starts_with(pathname, "/system/bin") ||
      starts_with(pathname, "/system/xbin") ||
      starts_with(pathname, "/bin") ||
      starts_with(pathname, "/product/bin") ||
      // strstr(pathname, "Screenshots") != nullptr ||
      // strstr(pathname, "Camera") != nullptr ||
      starts_with(pathname, "/debug_ramdisk")));
}

__attribute__((always_inline)) inline bool shouldDenyAccess(const char* pathname) {
  return ((starts_with(pathname, "/dev/socket") ||
           starts_with(pathname, "/dev/tty") ||
           starts_with(pathname, "/dev/__properties__") ||
           // CPU, temperature and platform info
           starts_with(pathname, "/sys/class/thermal") ||
           starts_with(pathname, "/sys/class/power_supply") ||
           starts_with(pathname, "/sys/devices/platform") ||
           starts_with(pathname, "/sys/bus/platform") ||
           starts_with(pathname, "/sys/module")) ||
          (strcmp(pathname, "/proc/zoneinfo") == 0 ||
           strcmp(pathname, "/proc/vmstat") == 0));
}

__attribute__((always_inline)) inline bool shouldAllowDevProps(const char* pathname) {
  return (
      strcmp(pathname, "/dev/__properties__/u:object_r:vendor_persist_camera_prop:s0") == 0 ||
      strcmp(pathname, "/dev/__properties__/u:object_r:timezone_prop:s0") == 0 ||
      strcmp(pathname, "/dev/__properties__/u:object_r:binder_cache_telephony_server_prop:s0") == 0 ||
      strcmp(pathname, "/dev/__properties__/u:object_r:hwservicemanager_prop:s0") == 0);
}

/**
 * TODO: cache most used ones in a pool
 */
__attribute__((always_inline)) inline const char* shouldFakeFile(const char* pathname) {
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
    return "processor\t: 0\nBogoMIPS\t: 40.00\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics\nCPU implementer\t: 0x41\n"
           "processor\t: 1\nBogoMIPS\t: 40.00\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics\nCPU implementer\t: 0x41\n"
           "processor\t: 2\nBogoMIPS\t: 40.00\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics\nCPU implementer\t: 0x41\n"
           "processor\t: 3\nBogoMIPS\t: 40.00\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics\nCPU implementer\t: 0x41\n"
           "Hardware\t: Qualcomm Technologies, Inc MSM8953\n";
  }

  if (strcmp(pathname, "/proc/meminfo") == 0) {
    return "MemTotal:        3901140 kB\n"
           "MemFree:          258600 kB\n"
           "MemAvailable:    1234768 kB\n"
           "Buffers:            2048 kB\n"
           "Cached:           894172 kB\n"
           "SwapCached:            0 kB\n"
           "Active:          1291692 kB\n"
           "Inactive:         614884 kB\n"
           "SwapTotal:             0 kB\n"
           "SwapFree:              0 kB\n"
           "VmallocTotal:   263061440 kB\n"
           "CmaTotal:         159744 kB\n";
  }
  if (strcmp(pathname, "/proc/sys/kernel/perf_event_paranoid") == 0) {
    return "2\n";
  }
  if (
      starts_with(pathname, "/sys/devices/system/cpu/possible") ||
      starts_with(pathname, "/sys/devices/system/cpu/online") ||
      starts_with(pathname, "/sys/devices/system/cpu/present")) {
    return "0-3\n";
  }
  if (starts_with(pathname, "/sys/devices/system/cpu/kernel_max")) {
    return "4\n";
  }
  if (starts_with(pathname, "/sys/devices/system/cpu") &&
      strstr(pathname, "/cpufreq/cpuinfo_max_freq")) {
    if (strstr(pathname, "cpu0") || strstr(pathname, "cpu1")) {
      return "1590000\n";
    }
    if (strstr(pathname, "cpu2") || strstr(pathname, "cpu3")) {
      return "1900000\n";
    }
  }
  if (starts_with(pathname, "/sys/devices/system/cpu/cpu") &&
      strstr(pathname, "/topology/physical_package_id")) {
    return "0\n";
  }

  if (starts_with(pathname, "/sys/devices/system/cpu/cpu") &&
      strstr(pathname, "/topology/core_siblings_list")) {
    return "0-3\n";
  }

  if (starts_with(pathname, "/sys/devices/system/cpu/cpu") &&
      strstr(pathname, "/topology/cluster_cpus_list")) {
    return "0-3\n";
  }

  return nullptr;
}

#endif