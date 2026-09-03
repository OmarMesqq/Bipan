#include "getifaddrs.hpp"

#include <dlfcn.h>
#include <ifaddrs.h>

#include "../../../logger/logger.hpp"
#include "common_utils.hpp"
#include "deps/dobby.h"
#include "in-app/globals.hpp"

// Original functions
static int (*orig_getifaddrs)(struct ifaddrs**) = nullptr;
static void (*orig_freeifaddrs)(struct ifaddrs*) = nullptr;

// Data structures
static struct ifaddrs* g_cached_ifaddrs = nullptr;
static bool g_ifaddrs_cached = false;

// Helpers
static void preCacheIfaddrs();
// Hooks
static void my_freeifaddrs(struct ifaddrs* ifa);
static int my_getifaddrs(struct ifaddrs** ifap);

void registerGetifaddrsHook(void) {
  preCacheIfaddrs();
  void* sym = dlsym(RTLD_DEFAULT, "getifaddrs");
  if (!sym) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "registerGetifaddrsHook error: symbol not found (getifaddrs)");
    return;
  }

  int r1 = DobbyHook(sym, reinterpret_cast<void*>(my_getifaddrs), reinterpret_cast<void**>(&orig_getifaddrs));
  if (r1 != 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "registerGetifaddrsHook error: failed to hook getifaddrs");
    return;
  }

  void* freeSym = dlsym(RTLD_DEFAULT, "freeifaddrs");
  if (!freeSym) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "registerGetifaddrsHook error: symbol not found (freeifaddrs)");
    return;
  }

  int r2 = DobbyHook(freeSym, reinterpret_cast<void*>(my_freeifaddrs), reinterpret_cast<void**>(&orig_freeifaddrs));
  if (r2 != 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "registerGetifaddrsHook error: failed to hook freeifaddrs");
    return;
  }
}

// Hooks below
static void my_freeifaddrs(struct ifaddrs* ifa) {
  if (ifa == g_cached_ifaddrs) {
    return;
  }
  write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "my_freeifaddrs: Got cached struct. Calling original freeifdaddrs");
  orig_freeifaddrs(ifa);
}

static int my_getifaddrs(struct ifaddrs** ifap) {
  if (!g_ifaddrs_cached || g_cached_ifaddrs == nullptr) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "my_getifaddrs error: cache miss. Call preCacheIfaddrs() before");
    *ifap = nullptr;
    return -1;
  }

  *ifap = g_cached_ifaddrs;
  return 0;
}

// Helpers below
static void preCacheIfaddrs() {
  if (g_ifaddrs_cached) {
    return;
  }

  if (getifaddrs(&g_cached_ifaddrs) != 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "preCacheIfaddrs: failed to pre-cache ifaddrs. error: %d", errno);
    BIPAN_PANIC();
  }
  g_ifaddrs_cached = true;

  struct ifaddrs* prev = nullptr;
  struct ifaddrs* ifa = g_cached_ifaddrs;

  while (ifa != nullptr) {
    struct ifaddrs* next = ifa->ifa_next;

    // won't scrub loopback
    if (ifa->ifa_name != nullptr && strcmp(ifa->ifa_name, "lo") == 0) {
      prev = ifa;
      ifa = next;
      continue;
    }

    // Remove VPN
    // Keep primary cellular iface, discard others
    bool shouldRemove = false;
    if (ifa->ifa_name != nullptr) {
      bool isRmnet = strncmp(ifa->ifa_name, "rmnet", 5) == 0;
      bool isPrimaryRmnet = strcmp(ifa->ifa_name, "rmnet0") == 0;

      shouldRemove =
          strncmp(ifa->ifa_name, "tun", 3) == 0 ||
          (isRmnet && !isPrimaryRmnet);
    }

    if (shouldRemove) {
      // Unlink from list
      if (prev == nullptr) {
        g_cached_ifaddrs = next;
      } else {
        prev->ifa_next = next;
      }
      // Note: don't free — freeifaddrs owns all nodes
      // Unlinked nodes will leak but that's acceptable (?)
      ifa = next;
      continue;
    }

    // Drop IPv6 on the active interface
    if (ifa->ifa_addr != nullptr && ifa->ifa_addr->sa_family == AF_INET6) {
      if (prev == nullptr) {
        g_cached_ifaddrs = next;
      } else {
        prev->ifa_next = next;
      }
      ifa = next;
      continue;
    }

    if (ifa->ifa_addr != nullptr && ifa->ifa_addr->sa_family == AF_INET) {
      // Spoof IP: 10.111.222.1
      reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr)->sin_addr.s_addr = 0x01DE6F0A;

      // Spoof broadcast: 10.111.222.255
      if (ifa->ifa_broadaddr != nullptr && ifa->ifa_broadaddr->sa_family == AF_INET) {
        reinterpret_cast<struct sockaddr_in*>(ifa->ifa_broadaddr)->sin_addr.s_addr = 0xFFDE6F0A;
      }

      // Spoof netmask: /24 = 255.255.255.0
      if (ifa->ifa_netmask != nullptr && ifa->ifa_netmask->sa_family == AF_INET) {
        reinterpret_cast<struct sockaddr_in*>(ifa->ifa_netmask)->sin_addr.s_addr = 0x00FFFFFF;
      }
    }

    prev = ifa;
    ifa = next;
  }
}
