#ifndef HOOKS_HPP
#define HOOKS_HPP

#include "filter.hpp"
#include "shared.hpp"
#include "zygisk.hpp"
#include <stdint.h>
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

// ==========================================
// Linker hooks
// ==========================================

static void* my_dlopen(const char* filename, int flag) {
  if (filename != nullptr) {
    LOGW("Hook (dlopen): app is loading: %s", filename);
  }
  return orig_dlopen(filename, flag);
}

static void* my_android_dlopen_ext(const char* filename, int flag, const android_dlextinfo* extinfo) {
  if (filename != nullptr) {
    LOGW("Hook (android_dlopen_ext): app is loading: %s", filename);
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
  LOGE("(Sensors) Blocked Java SensorManager enumeration (index %d)!", index);
  return JNI_FALSE;
}

jint my_nativeEnableSensor(JNIEnv* env, jclass clazz, jlong eventQueuePtr, jint handle, jint rateUs, jint maxBatchReportLatencyUs) {
  (void)env;
  (void)clazz;
  (void)eventQueuePtr;
  (void)handle;
  (void)rateUs;
  (void)maxBatchReportLatencyUs;
  LOGE("(Sensors) Blocked Java nativeEnableSensor! Data stream is dead.");
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
  LOGE("(Sensors) Blocked nativeCreateDirectChannel! High-speed tracking denied.");
  return -1;
}

jlong my_nativeCreate(JNIEnv* env, jclass clazz, jstring opPackageName) {
  (void)env;
  (void)clazz;
  (void)opPackageName;
  LOGE("(Sensors) Blocked Java SystemSensorManager nativeCreate!");
  return 0;
}

// ==========================================
// Native Sensors hooks
// ==========================================

#define NATIVE_SENSORS_FUNCTIONS_COUNT 5

ASensorManager* hook_ASensorManager_getInstance() {
  LOGE("(Sensors) Blocked ASensorManager_getInstance!");
  return nullptr;
}

ASensorManager* hook_ASensorManager_getInstanceForPackage(const char* packageName) {
  LOGE("(Sensors) Blocked ASensorManager_getInstanceForPackage for: %s", packageName);
  return nullptr;
}

ASensorEventQueue* hook_ASensorManager_createEventQueue(ASensorManager* manager, ALooper* loper, int ident, ALooper_callbackFunc cb, void* data) {
  (void)manager;
  (void)loper;
  (void)ident;
  (void)cb;
  (void)data;
  LOGE("(Sensors) Blocked Native createEventQueue! NDK app is now blind.");
  return nullptr;
}

int hook_ASensorManager_getSensorList(ASensorManager* manager, ASensorList** list) {
  (void)manager;
  if (list != nullptr) *list = nullptr;
  return 0;
}

ASensor* hook_ASensorManager_getDefaultSensor(ASensorManager* manager, int type) {
  (void)manager;
  (void)type;
  return nullptr;
}

// ==========================================
// JNI tripwires for Seccomp
// ==========================================

void my_clampGrowthLimit(JNIEnv* env, jobject obj) {
  if (!seccomp_applied) {
    // Pass the global bounds into the filter installer
    if (g_bipan_lib_start != 0 && g_bipan_lib_end != 0) {
      applySeccomp(g_bipan_lib_start, g_bipan_lib_end);
      LOGD("Seccomp applied at clampGrowthLimit.");
    } else {
      LOGE("Cannot apply seccomp: Library bounds are 0!");
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
      LOGD("Seccomp applied at clearGrowthLimit.");
    } else {
      LOGE("Cannot apply seccomp: Library bounds are 0!");
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
    LOGE("Failed to get handle to libandroid.so. Aborting for safety!");
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
        LOGD("(Sensors) Hooked %s at %p", symbols[i], addr);
      }
    }
  }
  dlclose(handle);
}

void registerDobbyLinkerHooks() {
  if (linker_hooked) {
    return;
  }
  LOGD("Registering Dobby linker hooks...");
  void* dlopen_addr = dlsym(RTLD_DEFAULT, "dlopen");
  void* android_dlopen_ext_addr = dlsym(RTLD_DEFAULT, "android_dlopen_ext");

  if (dlopen_addr && android_dlopen_ext_addr) {
    int dlopenHookRes = DobbyHook(dlopen_addr, (void*)my_dlopen, (void**)&orig_dlopen);
    int android_dlopen_extHookRes = DobbyHook(android_dlopen_ext_addr, (void*)my_android_dlopen_ext, (void**)&orig_android_dlopen_ext);
    if (dlopenHookRes == 0 && android_dlopen_extHookRes == 0) {
      LOGD("Linker hooks active.");
      linker_hooked = true;
    } else {
      LOGE("Failed to setup Dobby hooks!");
    }
  }
}

#endif
