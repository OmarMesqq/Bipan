#ifndef HOOKS_HPP
#define HOOKS_HPP

#include "filter.hpp"
#include "shared.hpp"
#include "zygisk.hpp"

using zygisk::Api;

static bool linker_hooked = false;
static bool seccomp_applied = false;

void registerDobbySensorsHooks();

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

    if (strstr(filename, "libwebviewchromium.so") != nullptr) {
      // TODO:
      LOGW("WebView Detected! Re-applying sensor blocks...");
      registerDobbySensorsHooks();
    } else if (strstr(filename, "libloader.so") != nullptr) {
      LOGE("Attach GDB: gdb -p %d", getpid());
      volatile int wait_for_gdb = 1;
      while (wait_for_gdb) {
        asm volatile("yield");
      }
    }
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

// ==========================================
// Native Sensors hooks
// ==========================================

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

ASensorManager* hook_ASensorManager_getInstance() {
  LOGE("(Sensors) Blocked ASensorManager_getInstance!");
  return nullptr;
}

ASensorManager* hook_ASensorManager_getInstanceForPackage(const char* packageName) {
  LOGE("(Sensors) Blocked ASensorManager_getInstanceForPackage for: %s", packageName);
  return nullptr;
}

// ==========================================
// JNI tripwires for Seccomp
// ==========================================

void my_clampGrowthLimit(JNIEnv* env, jobject obj) {
  if (!seccomp_applied) {
    applySeccomp();
    seccomp_applied = true;
    LOGD("Seccomp applied at clampGrowthLimit.");
  }
  if (orig_clampGrowthLimit) {
    orig_clampGrowthLimit(env, obj);
  }
}

void my_clearGrowthLimit(JNIEnv* env, jobject obj) {
  if (!seccomp_applied) {
    applySeccomp();
    seccomp_applied = true;
    LOGD("Seccomp applied at clearGrowthLimit.");
  }
  if (orig_clearGrowthLimit) {
    orig_clearGrowthLimit(env, obj);
  }
}

void registerDobbySensorsHooks() {
  // RTLD_NOLOAD = "Don't load, just find if it's there"
  void* handle = dlopen("libandroid.so", RTLD_NOLOAD);
  if (!handle) {
    // 2. If NOLOAD fails, it's a namespace issue. Try a hard dlopen.
    handle = dlopen("libandroid.so", RTLD_NOW);
  }

  void* getInstPkg = dlsym(handle, "ASensorManager_getInstanceForPackage");

  if (getInstPkg) {
    LOGD("Bipan hooking getInstanceForPackage at: %p", getInstPkg);
    int res = DobbyHook(getInstPkg, (void*)hook_ASensorManager_getInstanceForPackage, (void**)&orig_ASensorManager_getInstanceForPackage);
    if (res != 0) {
      LOGE("Dobby FAILED to hook getInstanceForPackage!");
    } else {
      __builtin___clear_cache((char*)getInstPkg, (char*)getInstPkg + 32);
      LOGD("Dobby SUCCESS at %p", getInstPkg);
  }
  } else {
    LOGE("Failed to find getInstanceForPackage!");
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
