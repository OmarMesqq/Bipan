#include "policies.hpp"

#include <arpa/inet.h>
#include <linux/limits.h>
#include <sys/socket.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "common_utils.hpp"
#include "logger/logger.hpp"

#define TAG "BipanPolicies"

static inline bool is_ipv4_lan_addr(uint32_t ip4);
static inline bool is_ipv6_lan_addr(uint8_t* ip6);
static inline bool is_exact_dir(const char* path, const char* target_dir);
static inline bool is_pure_numeric(const char* str, size_t len);
static inline bool is_dynamic_proc_file(const char* pathname, const char* suffix);

/**
 * Returns `true` if `sa_family` of given socket struct `addr`
 * is either IPv4 (`AF_INET`) or IPv6 (`AF_INET6`) **AND**
 * its address falls within LAN IP ranges defined by RFCs
 */
bool isLanAddress(struct sockaddr* addr) {
  if (addr == nullptr) return false;
  if (addr->sa_family == AF_INET) {
    return is_ipv4_lan_addr(ntohl(((struct sockaddr_in*)addr)->sin_addr.s_addr));
  }
  if (addr->sa_family == AF_INET6) {
    return is_ipv6_lan_addr(((struct sockaddr_in6*)addr)->sin6_addr.s6_addr);
  }
  return false;
}

bool shouldLog(const char* pathname) {
  // Ignore spammy app/system areas
  if (starts_with(pathname, "/data/data") ||
      starts_with(pathname, "/data/resource-cache") ||
      starts_with(pathname, "/data/dalvik-cache") ||
      starts_with(pathname, "/data/app") ||
      starts_with(pathname, "/system/framework") ||
      starts_with(pathname, "/system_ext/framework") ||
      starts_with(pathname, "/system_ext/bin/hwservicemanager") ||
      starts_with(pathname, "/data/misc/apexdata/com.android.art") ||
      starts_with(pathname, "/data/user/0") ||
      starts_with(pathname, "/data/user_de/0/") ||
      starts_with(pathname, "/storage/emulated/0/Android/media") ||
      starts_with(pathname, "/storage/emulated/0/Android/data") ||
      starts_with(pathname, "/data/misc/profiles/") ||
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
      starts_with(pathname, "/dev/hwbinder") ||
      starts_with(pathname, "/dev/zero") ||
      starts_with(pathname, "/dev/null")) {
    return false;
  }

  // Ignore some /proc stats
  if (starts_with(pathname, "/proc/")) {
    if (strstr(pathname, "/cmdline") ||
        strstr(pathname, "/oom") ||
        strstr(pathname, "/comm")) {
      return false;
    }
  }

  // Ignore EXACT directory opens (directory scans)
  if (is_exact_dir(pathname, "/data") ||
      is_exact_dir(pathname, "/system/lib/") ||
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

bool shouldSpoofExistence(const char* pathname) {
  return ((  // CAs
      strstr(pathname, "c7981ca8.0") != nullptr ||
      starts_with(pathname, "/data/misc/user/0/cacerts-removed") ||
      starts_with(pathname, "/proc/meminfo_extra") ||
      strstr(pathname, "lineage") != nullptr ||
      strstr(pathname, "Lineage") != nullptr));
}

bool shouldReportEmptyDir(const char* pathname) {
  return ((
      // CAs
      starts_with(pathname, "/data/misc/user/0/cacerts-added") ||
      // Crash reports
      starts_with(pathname, "/data/anr")));
}

SuNodeHandlerResponse handleSuRelatedNode(const char* pathname) {
  if (!pathname) return OK;

  if (starts_with(pathname, "/cache") &&
      strstr(pathname, "magisk")) {
    return DENY;
  }

  if (starts_with(pathname, "/data/adb/modules")) {
    return DENY;
  }

  if (starts_with(pathname, "/vendor/bin/install-recovery.sh")) {
    return DENY;
  }

  if (starts_with(pathname, "/data") &&
      strstr(pathname, "magisk")) {
    return DENY;
  }

  if (starts_with(pathname, "/system/lib") &&
      strstr(pathname, "zygisk")) {
    return SPOOF;
  }

  if (starts_with(pathname, "/system/xbin")) {
    return SPOOF;
  }

  if (starts_with(pathname, "/product/bin")) {
    return SPOOF;
  }

  if (starts_with(pathname, "/debug_ramdisk")) {
    return SPOOF;
  }

  return OK;
}

bool shouldDenyOpen(const char* pathname) {
  return ((starts_with(pathname, "/dev/socket") ||
           starts_with(pathname, "/dev/tty") ||
           starts_with(pathname, "/sys/class/thermal") ||
           starts_with(pathname, "/sys/class/power_supply") ||
           starts_with(pathname, "/sys/devices/platform") ||
           starts_with(pathname, "/sys/bus/platform") ||
           starts_with(pathname, "/sys/module")));
}

bool shouldDenyStat(const char* pathname) {
  return (
      (strcmp(pathname, "/proc/version") == 0) ||
      (strcmp(pathname, "/proc/sys/kernel/version") == 0) ||
      (strcmp(pathname, "/proc/sys/kernel/osrelease") == 0) ||
      (strcmp(pathname, "/proc/asound/version") == 0));
}

const char* shouldFakeFile(const char* pathname) {
  if (strstr(pathname, "build.prop") != nullptr) {
    return "ro.build.product=husky\nro.product.device=husky\nro.product.model=Pixel 8 Pro\nro.product.brand=google\nro.product.name=husky\nro.product.manufacturer=Google\nro.build.tags=release-keys\nro.build.type=user\nro.secure=1\nro.debuggable=0\n";
  }
  if (strcmp(pathname, "/etc/hosts") == 0 || strcmp(pathname, "/system/etc/hosts") == 0) {
    return "127.0.0.1       localhost\n::1       localhost\n";
  }
  if (strcmp(pathname, "/proc/version") == 0) {
    return "Linux version 6.6.56-android16-11-g8a3e2b1c4d5f (build-user@build-host) (Android clang version 17.0.2) #1 SMP PREEMPT Fri Dec 05 12:00:00 UTC 2025\n";
  }

  if (strcmp(pathname, "/proc/sys/kernel/version") == 0) {
    return "#1 SMP PREEMPT Fri Dec 05 12:00:00 UTC 2025\n";
  }

  if (strcmp(pathname, "/proc/sys/kernel/osrelease") == 0) {
    return "6.6.56-android16-11-g8a3e2b1c4d5f\n";
  }

  if (strcmp(pathname, "/proc/asound/version") == 0) {
    return "Advanced Linux Sound Architecture Driver Version k6.6.56-android16-11-g8a3e2b1c4d5f.\n";
  }

  return nullptr;
}

bool is_maps(const char* pathname) {
  return (strcmp(pathname, "/proc/self/maps") == 0) ||
         is_dynamic_proc_file(pathname, "/maps");
}

bool is_proc_status(const char* pathname) {
  return (strcmp(pathname, "/proc/self/status") == 0) ||
         is_dynamic_proc_file(pathname, "/status");
}

bool is_smaps(const char* pathname) {
  return (strcmp(pathname, "/proc/self/smaps") == 0) ||
         is_dynamic_proc_file(pathname, "/smaps");
}

bool is_mounts(const char* pathname) {
  return (strcmp(pathname, "/proc/mounts") == 0) ||
         (strcmp(pathname, "/proc/self/mounts") == 0) ||
         (strcmp(pathname, "/proc/self/mountstats") == 0) ||
         (strcmp(pathname, "/proc/self/mountinfo") == 0) ||
         is_dynamic_proc_file(pathname, "/mountstats") ||
         is_dynamic_proc_file(pathname, "/mountinfo") ||
         is_dynamic_proc_file(pathname, "/mounts");
}

char* fixMemfdSymlink(const char* resolvedPath, pid_t pid) {
  char* fixed = (char*)calloc(PATH_MAX, sizeof(char));
  if (!fixed) {
    return nullptr;
  }

  if (
      strstr(resolvedPath, "mountstats") ||
      strstr(resolvedPath, "version") ||
      strstr(resolvedPath, "osrelease")) {
    strcpy(fixed, "ENOENT");
    return fixed;
  }

  if (strstr(resolvedPath, "hosts")) {
    strcpy(fixed, "/system/etc/hosts");
    return fixed;
  }

  if (strstr(resolvedPath, "mountinfo")) {
    char proc_pid_mountinfo[PATH_MAX] = {0};
    snprintf(proc_pid_mountinfo, sizeof(proc_pid_mountinfo), "/proc/%d/mountinfo", pid);
    strcpy(fixed, proc_pid_mountinfo);
    return fixed;
  }

  if (strstr(resolvedPath, "mounts")) {
    char proc_pid_mounts[PATH_MAX] = {0};
    snprintf(proc_pid_mounts, sizeof(proc_pid_mounts), "/proc/%d/mounts", pid);
    strcpy(fixed, proc_pid_mounts);
    return fixed;
  }

  if (strstr(resolvedPath, "smaps")) {
    char proc_pid_mounts[PATH_MAX] = {0};
    snprintf(proc_pid_mounts, sizeof(proc_pid_mounts), "/proc/%d/smaps", pid);
    strcpy(fixed, proc_pid_mounts);
    return fixed;
  }

  if (strstr(resolvedPath, "maps")) {
    char proc_pid_mounts[PATH_MAX] = {0};
    snprintf(proc_pid_mounts, sizeof(proc_pid_mounts), "/proc/%d/maps", pid);
    strcpy(fixed, proc_pid_mounts);
    return fixed;
  }

  if (strstr(resolvedPath, "status")) {
    char proc_pid_mounts[PATH_MAX] = {0};
    snprintf(proc_pid_mounts, sizeof(proc_pid_mounts), "/proc/%d/status", pid);
    strcpy(fixed, proc_pid_mounts);
    return fixed;
  }

  if (strstr(resolvedPath, "build.prop")) {
    strcpy(fixed, resolvedPath);
    return fixed;
  }

  write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Got unexpected path when correcting symlink: %s", resolvedPath);
  return nullptr;
}

struct stat* fixHostsFileStat(const char* pathname, int flags) {
  if (!pathname) return nullptr;

  if (strcmp(pathname, "/etc/hosts") == 0) {
    struct stat statbufHosts;
    int ret = fstatat(0, pathname, &statbufHosts, flags);
    if (ret == -1) {
      return nullptr;
    }

    struct stat statbufEtc;
    ret = fstatat(0, "/etc", &statbufEtc, flags);
    if (ret == -1) {
      return nullptr;
    }

    statbufHosts.st_size = 46;
    statbufHosts.st_dev = statbufEtc.st_dev;
    statbufHosts.st_ino = statbufEtc.st_ino;
    statbufHosts.st_mode = S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    statbufHosts.st_atim = statbufEtc.st_atim;
    statbufHosts.st_mtim = statbufEtc.st_mtim;
    statbufHosts.st_ctim = statbufEtc.st_ctim;

    struct stat* fixed = (struct stat*)calloc(sizeof(struct stat), 1);
    if (!fixed) {
      return nullptr;
    }
    memcpy(fixed, &statbufHosts, sizeof(struct stat));
    return fixed;
  }

  if (strcmp(pathname, "/system/etc/hosts") == 0) {
    struct stat statbufHosts;
    int ret = fstatat(0, pathname, &statbufHosts, flags);
    if (ret == -1) {
      return nullptr;
    }

    struct stat statbufSystemEtc;
    ret = fstatat(0, "/system/etc", &statbufSystemEtc, flags);
    if (ret == -1) {
      return nullptr;
    }

    statbufHosts.st_size = 46;
    statbufHosts.st_dev = statbufSystemEtc.st_dev;
    statbufHosts.st_ino = statbufSystemEtc.st_ino;
    statbufHosts.st_mode = S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    statbufHosts.st_atim = statbufSystemEtc.st_atim;
    statbufHosts.st_mtim = statbufSystemEtc.st_mtim;
    statbufHosts.st_ctim = statbufSystemEtc.st_ctim;

    struct stat* fixed = (struct stat*)calloc(sizeof(struct stat), 1);
    if (!fixed) {
      return nullptr;
    }
    memcpy(fixed, &statbufHosts, sizeof(struct stat));
    return fixed;
  }

  return nullptr;
}

/**
 * Returns `true` if IP address
 * `ip4` is in any of
 * the IPv4 LAN ranges. `false` otherwise
 */
static inline bool is_ipv4_lan_addr(uint32_t ip4) {
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
static inline bool is_ipv6_lan_addr(uint8_t* ip6) {
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
    return is_ipv4_lan_addr(ipv4);
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

static inline bool is_exact_dir(const char* path, const char* target_dir) {
  size_t len = strlen(target_dir);
  if (strncmp(path, target_dir, len) == 0) {
    // Return true if it ends exactly at the dir name, or has a trailing slash
    return path[len] == '\0' || (path[len] == '/' && path[len + 1] == '\0');
  }
  return false;
}

// Verifies if a segment of a string is purely numbers (a PID)
static inline bool is_pure_numeric(const char* str, size_t len) {
  if (len == 0) {
    return false;
  }
  for (size_t i = 0; i < len; i++) {
    if (str[i] < '0' || str[i] > '9') {
      return false;
    }
  }
  return true;
}

// Validates any /proc/<PID>/target_file layout
static inline bool is_dynamic_proc_file(const char* pathname, const char* suffix) {
  // 1. Must start with "/proc/"
  if (strncmp(pathname, "/proc/", 6) != 0) {
    return false;
  }

  // 2. Locate the next slash after "/proc/"
  const char* pid_start = pathname + 6;
  const char* next_slash = strchr(pid_start, '/');
  if (!next_slash) {
    return false;
  }

  // 3. Ensure the characters between the slashes are a valid PID number
  size_t pid_len = next_slash - pid_start;
  if (!is_pure_numeric(pid_start, pid_len)) {
    return false;
  }

  // 4. Check if the remaining suffix matches exactly (e.g., "/maps" or "/smaps")
  return strcmp(next_slash, suffix) == 0;
}
