#ifndef HOOKS_HPP
#define HOOKS_HPP

#include <ifaddrs.h>
#include <stdint.h>
#include <string.h>

#include <unordered_map>

#include "filter.hpp"
#include "logger.hpp"
#include "shared.hpp"
#include "zygisk.hpp"

using zygisk::Api;

// type for spoofing bionic's __system_property_read_callback
struct PropCallbackCtx {
  void (*user_cb)(void* cookie, const char* name, const char* value, uint32_t serial);
  void* user_cookie;
};

// sysprop overrides equivalent to `spoofBuildFields` ART fields
static const std::unordered_map<std::string, std::string> g_prop_overrides = {
    {"ro.product.board", "husky"},
    {"ro.product.brand", "google"},
    {"ro.product.device", "husky"},
    {"ro.product.manufacturer", "google"},
    {"ro.product.model", "Pixel 8 Pro"},
    {"ro.product.name", "husky"},
    {"ro.hardware", "zuma"},
    {"ro.soc.manufacturer", "Google"},
    {"ro.soc.model", "Tensor G3"},

    {"ro.product.odm.brand", "google"},
    {"ro.product.odm.device", "husky"},
    {"ro.product.odm.manufacturer", "google"},
    {"ro.product.odm.model", "Pixel 8 Pro"},
    {"ro.product.odm.name", "husky"},
    {"ro.product.product.brand", "google"},
    {"ro.product.product.device", "husky"},
    {"ro.product.product.manufacturer", "google"},
    {"ro.product.product.model", "Pixel 8 Pro"},
    {"ro.product.product.name", "husky"},
    {"ro.build.product", "husky"},
    {"ro.product.system.brand", "google"},
    {"ro.product.system.device", "husky"},
    {"ro.product.system.manufacturer", "google"},
    {"ro.product.system.model", "Pixel 8 Pro"},
    {"ro.product.system.name", "husky"},
    {"ro.product.system_ext.brand", "google"},
    {"ro.product.system_ext.device", "husky"},
    {"ro.product.system_ext.manufacturer", "google"},
    {"ro.product.system_ext.model", "Pixel 8 Pro"},
    {"ro.product.system_ext.name", "husky"},
    {"ro.product.vendor.brand", "google"},
    {"ro.product.vendor.device", "husky"},
    {"ro.product.vendor.manufacturer", "google"},
    {"ro.product.vendor.model", "Pixel 8 Pro"},
    {"ro.product.vendor.name", "husky"},

    {"ro.bootloader", "ripcurrent-15.0-12455211"},
    {"ro.boot.bootloader", "ripcurrent-15.0-12455211"},
    {"ro.build.host", "abfarm-20038"},
    {"ro.build.id", "BP4A.251205.006"},
    {"ro.build.display.id", "BP4A.251205.006"},
    {"ro.build.tags", "release-keys"},
    {"ro.build.type", "user"},
    {"ro.build.user", "android-build"},
    {"ro.build.date.utc", "1764954000"},
    {"ro.build.description", "husky-user 16 BP4A.251205.006 release-keys"},
    {"ro.build.flavor", "husky-user"},
    {"ro.board.platform", "zuma"},

    {"ro.build.version.incremental", "14401865"},
    {"ro.build.version.release", "16"},
    {"ro.build.version.release_or_codename", "16"},
    {"ro.build.version.release_or_preview_display", "16"},
    {"ro.build.version.sdk", "36"},
    {"ro.build.version.security_patch", "2025-12-05"},
    // TODO: does this make sense? vendor tends to be outdated compared to platform patch
    // {"ro.vendor.build.security_patch", "2025-12-05"},
    {"ro.build.version.codename", "REL"},
    {"ro.build.version.base_os", ""},
    {"ro.build.version.preview_sdk", "0"},

    {"ro.product.cpu.abilist", "arm64-v8a,armeabi-v7a,armeabi"},
    {"ro.product.cpu.abilist32", "armeabi-v7a,armeabi"},
    {"ro.product.cpu.abilist64", "arm64-v8a"},

    {"ro.build.fingerprint", "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"},
    {"ro.odm.build.fingerprint", "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"},
    {"ro.product.build.fingerprint", "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"},
    {"ro.system.build.fingerprint", "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"},
    {"ro.system_ext.build.fingerprint", "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"},
    {"ro.vendor.build.fingerprint", "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"},
    {"ro.vendor_dlkm.build.fingerprint", "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"},
    {"ro.bootimage.build.fingerprint", "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys"},

    // TODO: make radio stuff match our native and Java spoofs
    {"gsm.version.baseband", "g5300g-251108-251202-B-12876551"},
    {"gsm.version.ril-impl", "com.google.android.telephony.modem"},
    {"ril.sw_ver", "g5300g-251108-251202-B-12876551"},
    {"ril.sw_ver2", "g5300g-251108-251202-B-12876551"},

    // TODO: per-app basis. Use TelephonyManager hook instead
    {"gsm.current.phone-type", "1"},
    {"gsm.network.type", "LTE"},
    {"gsm.operator.alpha", "Vivo"},
    {"gsm.operator.iso-country", "br"},
    {"gsm.operator.isroaming", "false"},
    {"gsm.operator.numeric", "72423"},
    {"gsm.sim.operator.iso-country", "br"},
    {"gsm.sim.operator.isroaming", "false"},
    {"gsm.sim.operator.numeric", "72423"},
    {"gsm.sim.operator.alpha", "Vivo"},
    {"gsm.sim.state", "LOADED"},
    {"ril.simoperator", "ETC"},
    {"persist.radio.multisim.config", "ss"},
    {"ro.vendor.multisim.simslotcount", "1"},
    {"ro.telephony.sim_slots.count", "1"},
    {"ro.telephony.default_network", "9"},
    {"ro.vendor.radio.default_network", "9"},

    // AVB
    {"ro.boot.verifiedbootstate", "green"},
    {"ro.com.google.clientidbase", "android-google"},
    {"ro.boot.veritymode", "enforcing"},
    {"ro.boot.vbmeta.device_state", "locked"},
    {"ro.boot.avb_version", "1.2"},
    {"ro.boot.slot_suffix", "_b"},
};

static bool linker_hooked = false;
static bool seccomp_applied = false;

static void intercept_prop_callback(void* cookie, const char* name, const char* value, uint32_t serial);

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

static int (*orig_system_property_get)(const char* name, char* value) = nullptr;
static void (*orig_system_property_read_callback)(const void* pi, void (*callback)(void* cookie, const char* name, const char* value, uint32_t serial), void* cookie) = nullptr;

// ==========================================
// Linker hooks
// ==========================================

static void* my_dlopen(const char* filename, int flag) {
  if (filename != nullptr) {
    write_to_logcat_async(ANDROID_LOG_WARN, TAG, "Hook (dlopen): app is loading: %s", filename);
  }
  return orig_dlopen(filename, flag);
}

static void* my_android_dlopen_ext(const char* filename, int flag, const android_dlextinfo* extinfo) {
  if (filename != nullptr) {
    write_to_logcat_async(ANDROID_LOG_WARN, TAG, "Hook (android_dlopen_ext): app is loading: %s", filename);
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
// JNI tripwires for seccomp and grabbing the very first `Context`
// ==========================================

void my_clampGrowthLimit(JNIEnv* env, jobject obj) {
  if (g_bipanJavaClass == nullptr) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clampGrowthLimit: BipanJava class is null!");
    BIPAN_PANIC();
  }

  jmethodID hookMethod = env->GetStaticMethodID(g_bipanJavaClass, "hookInstrumentationNow", "()V");
  if (hookMethod == nullptr) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clampGrowthLimit: hookInstrumentationNow fnPtr is null!");
    BIPAN_PANIC();
  }

  env->CallStaticVoidMethod(g_bipanJavaClass, hookMethod);
  if (env->ExceptionCheck()) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clampGrowthLimit: hookInstrumentationNow threw an exception!");
    BIPAN_PANIC();
  }

  if (!seccomp_applied) {
    if (g_bipan_lib_start == 0 || g_bipan_lib_end == 0) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clampGrowthLimit: can't apply seccomp: lib bounds are 0!");
      BIPAN_PANIC();
    }

    applySeccomp(g_bipan_lib_start, g_bipan_lib_end);
    write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Seccomp applied at clampGrowthLimit");
    seccomp_applied = true;
  }

  if (orig_clampGrowthLimit) {
    orig_clampGrowthLimit(env, obj);
  }
}

void my_clearGrowthLimit(JNIEnv* env, jobject obj) {
  if (g_bipanJavaClass == nullptr) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clearGrowthLimit: BipanJava class is null!");
    BIPAN_PANIC();
  }

  jmethodID hookMethod = env->GetStaticMethodID(g_bipanJavaClass, "hookInstrumentationNow", "()V");
  if (hookMethod == nullptr) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clearGrowthLimit: hookInstrumentationNow fnPtr is null!");
    BIPAN_PANIC();
  }

  env->CallStaticVoidMethod(g_bipanJavaClass, hookMethod);
  if (env->ExceptionCheck()) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clearGrowthLimit: hookInstrumentationNow threw an exception!");
    BIPAN_PANIC();
  }

  if (!seccomp_applied) {
    if (g_bipan_lib_start == 0 || g_bipan_lib_end == 0) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clearGrowthLimit: can't apply seccomp: lib bounds are 0!");
      BIPAN_PANIC();
    }

    applySeccomp(g_bipan_lib_start, g_bipan_lib_end);
    write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Seccomp applied at clearGrowthLimit");
    seccomp_applied = true;
  }

  if (orig_clearGrowthLimit) {
    orig_clearGrowthLimit(env, obj);
  }
}

// ==========================================
// SystemProperties hooks
// ==========================================

// Legacy: __system_property_get
static int hook_system_property_get(const char* name, char* value) {
  if (name != nullptr) {
    auto it = g_prop_overrides.find(name);
    if (it != g_prop_overrides.end()) {
      strncpy(value, it->second.c_str(), 91);
      value[91] = '\0';
      return (int)strlen(value);
    }
  }
  return orig_system_property_get(name, value);
}

// Modern: __system_property_read_callback
static void hook_system_property_read_callback(const void* pi, void (*callback)(void* cookie, const char* name, const char* value, uint32_t serial), void* cookie) {
  orig_system_property_read_callback(pi, intercept_prop_callback, new PropCallbackCtx{callback, cookie});
}

void registerNativeSensorsHooks() {
  void* handle = dlopen("libandroid.so", RTLD_NOLOAD);
  if (!handle) handle = dlopen("libandroid.so", RTLD_NOW);

  if (!handle) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Failed to get handle to libandroid.so. Aborting for safety!");
    BIPAN_PANIC();
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
      }
    }
  }
  dlclose(handle);
}

void registerDobbyLinkerHooks() {
  if (linker_hooked) {
    return;
  }

  void* dlopen_addr = dlsym(RTLD_DEFAULT, "dlopen");
  void* android_dlopen_ext_addr = dlsym(RTLD_DEFAULT, "android_dlopen_ext");

  if (dlopen_addr && android_dlopen_ext_addr) {
    int dlopenHookRes = DobbyHook(dlopen_addr, (void*)my_dlopen, (void**)&orig_dlopen);
    int android_dlopen_extHookRes = DobbyHook(android_dlopen_ext_addr, (void*)my_android_dlopen_ext, (void**)&orig_android_dlopen_ext);
    if (dlopenHookRes == 0 && android_dlopen_extHookRes == 0) {
      linker_hooked = true;
    } else {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Failed to setup Dobby hooks!");
    }
  }
}

void registerNativeSystemPropertiesHook() {
  void* addr_get = dlsym(RTLD_DEFAULT, "__system_property_get");
  void* addr_readcb = dlsym(RTLD_DEFAULT, "__system_property_read_callback");
  if (!addr_get || !addr_readcb) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to resolve address(es) of sysprop function(s)");
    return;
  }

  int getHook = DobbyHook(addr_get, (void*)hook_system_property_get, (void**)&orig_system_property_get);
  int readcbHook = DobbyHook(addr_readcb, (void*)hook_system_property_read_callback, (void**)&orig_system_property_read_callback);

  if ((getHook != 0) || (readcbHook != 0)) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to hook sysprop functions");
  }
}

// =======
// Helpers
// =======

static void intercept_prop_callback(void* cookie, const char* name, const char* value, uint32_t serial) {
  auto* ctx = static_cast<PropCallbackCtx*>(cookie);
  const char* effective = value;
  std::string override_buf;
  if (name != nullptr) {
    auto it = g_prop_overrides.find(name);
    if (it != g_prop_overrides.end()) {
      override_buf = it->second;
      effective = override_buf.c_str();
    }
  }
  ctx->user_cb(ctx->user_cookie, name, effective, serial);
  delete ctx;
}

#endif
