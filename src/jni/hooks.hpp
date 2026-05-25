#ifndef HOOKS_HPP
#define HOOKS_HPP

#include <ifaddrs.h>
#include <stdint.h>
#include <string.h>
#include <sys/system_properties.h>

#include <unordered_map>

#include "filter.hpp"
#include "logger.hpp"
#include "shared.hpp"
#include "zygisk.hpp"

using zygisk::Api;

static bool linker_hooked = false;
static bool seccomp_applied = false;

// ==========================================
// Original function pointers
// ==========================================

void (*orig_clampGrowthLimit)(JNIEnv*, jobject) = nullptr;
static void (*orig_clearGrowthLimit)(JNIEnv*, jobject) = nullptr;

static void* (*orig_dlopen)(const char* filename, int flag) = nullptr;
static void* (*orig_android_dlopen_ext)(const char* filename, int flag, const android_dlextinfo* extinfo) = nullptr;

static ASensorManager* (*orig_ASensorManager_getInstance)();
static ASensorManager* (*orig_ASensorManager_getInstanceForPackage)(const char*);
static int (*orig_ASensorManager_getSensorList)(ASensorManager*, ASensorList**);
static ASensor* (*orig_ASensorManager_getDefaultSensor)(ASensorManager*, int);
static ASensorEventQueue* (*orig_ASensorManager_createEventQueue)(ASensorManager*, ALooper*, int, ALooper_callbackFunc, void*);

static int (*orig___system_property_get)(const char* key, char* value) = nullptr;

// ==========================================
// Linker hooks
// ==========================================

static void* my_dlopen(const char* filename, int flag) {
  if (filename != nullptr) {
    // write_to_logcat_async(ANDROID_LOG_WARN, TAG, "Hook (dlopen): app is loading: %s", filename);
  }
  return orig_dlopen(filename, flag);
}

static void* my_android_dlopen_ext(const char* filename, int flag, const android_dlextinfo* extinfo) {
  if (filename != nullptr) {
    // write_to_logcat_async(ANDROID_LOG_WARN, TAG, "Hook (android_dlopen_ext): app is loading: %s", filename);
  }

  return orig_android_dlopen_ext(filename, flag, extinfo);
}

// ==========================================
// Java Sensors hooks
// ==========================================

jboolean my_nativeGetSensorAtIndex(JNIEnv* env, jclass clazz, jlong nativeInstance, jobject sensor, jint index) {
  (void)env;
  (void)clazz;
  (void)nativeInstance;
  (void)sensor;
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Java Sensors) App attempted SensorManager enumeration (index %d). Neutering...", index);
  return JNI_FALSE;
}

jint my_nativeEnableSensor(JNIEnv* env, jclass clazz, jlong eventQueuePtr, jint handle, jint rateUs, jint maxBatchReportLatencyUs) {
  (void)env;
  (void)clazz;
  (void)eventQueuePtr;
  (void)handle;
  (void)rateUs;
  (void)maxBatchReportLatencyUs;
  write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "(Java Sensors) Blocked nativeEnableSensor");
  return -1;
}

jint my_nativeCreateDirectChannel(JNIEnv* env, jclass clazz, jlong nativeInstance, jint size, jint type, jint fd, jobject resource) {
  (void)env;
  (void)clazz;
  (void)nativeInstance;
  (void)size;
  (void)type;
  (void)fd;
  (void)resource;
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Java Sensors) App attempted nativeCreateDirectChannel. Neutering...");
  return -1;
}

jlong my_nativeCreate(JNIEnv* env, jclass clazz, jstring opPackageName) {
  (void)env;
  (void)clazz;
  (void)opPackageName;
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Java Sensors) App attempted nativeCreate. Neutering...");
  return 0;
}

// ==========================================
// Native Sensors hooks
// ==========================================

#define NATIVE_SENSORS_FUNCTIONS_COUNT 5

ASensorManager* hook_ASensorManager_getInstance() {
  write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "(Native Sensors) Blocked ASensorManager_getInstance");
  return nullptr;
}

ASensorManager* hook_ASensorManager_getInstanceForPackage(const char* packageName) {
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Native Sensors) App attempted ASensorManager_getInstanceForPackage(%s). Neutering....", packageName);
  return nullptr;
}

ASensorEventQueue* hook_ASensorManager_createEventQueue(ASensorManager* manager, ALooper* loper, int ident, ALooper_callbackFunc cb, void* data) {
  (void)manager;
  (void)loper;
  (void)ident;
  (void)cb;
  (void)data;
  write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "(Native Sensors) Blocked Native createEventQueue");
  return nullptr;
}

int hook_ASensorManager_getSensorList(ASensorManager* manager, ASensorList** list) {
  (void)manager;
  if (list != nullptr) {
    *list = nullptr;
  }
  write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "(Native Sensors) Blocked Native getSensorList");
  return 0;
}

ASensor* hook_ASensorManager_getDefaultSensor(ASensorManager* manager, int type) {
  (void)manager;
  (void)type;
  write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "(Native Sensors) Blocked Native getDefaultSensor");
  return nullptr;
}

// ==========================================
// libc hooks (getprop)
// ==========================================

static int hook___system_property_get(const char* key, char* value) {
  static const std::unordered_map<std::string, std::string> safe_spoof_map = {
      {"ro.product.model", "Pixel 8 Pro"},
      {"ro.product.manufacturer", "google"},
      {"ro.product.brand", "google"},
      {"ro.product.device", "husky"},
      {"ro.build.version.sdk", "36"},
      {"ro.build.version.codename", "REL"},
      {"ro.product.name", "husky"},
      {"ro.build.fingerprint", "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"},
      {"ro.build.tags", "release-keys"},
      {"ro.build.type", "user"},
      {"ro.build.id", "BP4A.251205.006"},
      {"ro.build.user", "android-build"},
      {"ro.build.host", "abfarm-20038"},
      {"ro.bootimage.build.fingerprint", "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"},
      {"ro.vendor.build.fingerprint", "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"}};

  static const std::unordered_map<std::string, std::string> dg_only_spoof_map = {
      {"ro.hardware", "zuma"},
      {"ro.board.platform", "husky"},
      {"ro.product.board", "husky"}};

  // 1. Check Global Map
  auto it = safe_spoof_map.find(key);
  if (it != safe_spoof_map.end()) {
    strcpy(value, it->second.c_str());
    return strlen(value);
  }

  bool is_integrity_process = (strcmp(package_name, "com.google.ccc.abuse.droidguard") == 0 ||
                               strcmp(package_name, "com.android.vending") == 0);

  if (is_integrity_process) {
    auto it_dg = dg_only_spoof_map.find(key);
    if (it_dg != dg_only_spoof_map.end()) {
      strcpy(value, it_dg->second.c_str());
      return strlen(value);
    }
  }

  if (strncmp(key, "ro.", 3) == 0) {
    write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(getprop hook): unspoofed .ro prop accessed: %s", key);
  }

  return orig___system_property_get(key, value);
}

// ==========================================
// JNI tripwires for Seccomp
// ==========================================

void my_clampGrowthLimit(JNIEnv* env, jobject obj) {
  if (!seccomp_applied) {
    // Bipan's global bounds
    if (g_bipan_lib_start != 0 && g_bipan_lib_end != 0) {
      applySeccomp(g_bipan_lib_start, g_bipan_lib_end);
      write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Seccomp applied at clampGrowthLimit.");
    } else {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Cannot apply seccomp: Library bounds are 0!");
    }
    seccomp_applied = true;
  }
  if (orig_clampGrowthLimit) {
    orig_clampGrowthLimit(env, obj);
  }
}

void my_clearGrowthLimit(JNIEnv* env, jobject obj) {
  if (!seccomp_applied) {
    if (g_bipan_lib_start != 0 && g_bipan_lib_end != 0) {
      applySeccomp(g_bipan_lib_start, g_bipan_lib_end);
      write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Seccomp applied at clearGrowthLimit.");
    } else {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Cannot apply seccomp: Library bounds are 0!");
    }
    seccomp_applied = true;
  }
  if (orig_clearGrowthLimit) {
    orig_clearGrowthLimit(env, obj);
  }
}

void registerDobbySensorsHooks() {
  void* handle = dlopen("libandroid.so", RTLD_NOLOAD);
  if (!handle) handle = dlopen("libandroid.so", RTLD_NOW);

  if (!handle) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Failed to get handle to libandroid.so. Aborting for safety!");
    _exit(-1);
  }

  const char* symbols[] = {
      "ASensorManager_getInstance",
      "ASensorManager_getInstanceForPackage",
      "ASensorManager_getSensorList",
      "ASensorManager_getDefaultSensor",
      "ASensorManager_createEventQueue"};

  void* hooks[] = {
      (void*)hook_ASensorManager_getInstance,
      (void*)hook_ASensorManager_getInstanceForPackage,
      (void*)hook_ASensorManager_getSensorList,
      (void*)hook_ASensorManager_getDefaultSensor,
      (void*)hook_ASensorManager_createEventQueue};

  void** originals[] = {
      (void**)&orig_ASensorManager_getInstance,
      (void**)&orig_ASensorManager_getInstanceForPackage,
      (void**)&orig_ASensorManager_getSensorList,
      (void**)&orig_ASensorManager_getDefaultSensor,
      (void**)&orig_ASensorManager_createEventQueue};

  for (int i = 0; i < NATIVE_SENSORS_FUNCTIONS_COUNT; i++) {
    void* addr = dlsym(handle, symbols[i]);
    if (addr) {
      if (DobbyHook(addr, hooks[i], originals[i]) == 0) {
        __builtin___clear_cache((char*)addr, (char*)addr + 32);
        write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "(Dobby Native Sensors) Hooked %s", symbols[i]);
      }
    }
  }
  dlclose(handle);
}

void registerDobbyLinkerHooks() {
  if (linker_hooked) {
    return;
  }
  write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Registering Dobby linker hooks...");
  void* dlopen_addr = dlsym(RTLD_DEFAULT, "dlopen");
  void* android_dlopen_ext_addr = dlsym(RTLD_DEFAULT, "android_dlopen_ext");

  if (dlopen_addr && android_dlopen_ext_addr) {
    int dlopenHookRes = DobbyHook(dlopen_addr, (void*)my_dlopen, (void**)&orig_dlopen);
    int android_dlopen_extHookRes = DobbyHook(android_dlopen_ext_addr, (void*)my_android_dlopen_ext, (void**)&orig_android_dlopen_ext);
    if (dlopenHookRes == 0 && android_dlopen_extHookRes == 0) {
      write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Linker hooks active.");
      linker_hooked = true;
    } else {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Failed to setup Dobby hooks!");
    }
  }
}

void registerDobbyPropertyHooks() {
  write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Registering Dobby Property hooks...");

  void* addr = dlsym(RTLD_DEFAULT, "__system_property_get");

  if (addr) {
    if (DobbyHook(addr, (void*)hook___system_property_get, (void**)&orig___system_property_get) == 0) {
      __builtin___clear_cache((char*)addr, (char*)addr + 32);
      write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Dobby) Successfully hooked __system_property_get");
    } else {
      write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Failed to hook __system_property_get");
    }
  } else {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Failed to find __system_property_get in memory");
  }
}

#endif
