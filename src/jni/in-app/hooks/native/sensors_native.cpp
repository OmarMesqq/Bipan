#include "sensors_native.hpp"

#include <android/sensor.h>
#include <dlfcn.h>

#include "../../../logger/logger.hpp"
#include "common_utils.hpp"
#include "deps/dobby.h"
#include "in-app/globals.hpp"

// Original functions
static ASensorManager* (*orig_ASensorManager_getInstance)();
static ASensorManager* (*orig_ASensorManager_getInstanceForPackage)(const char*);
static int (*orig_ASensorManager_getSensorList)(ASensorManager*, ASensorList**);
static ASensor* (*orig_ASensorManager_getDefaultSensor)(ASensorManager*, int);
static ASensorEventQueue* (*orig_ASensorManager_createEventQueue)(ASensorManager*, ALooper*, int, ALooper_callbackFunc, void*);

// Hooks
static ASensorManager* hook_ASensorManager_getInstance();
static ASensorManager* hook_ASensorManager_getInstanceForPackage(const char* packageName);
static ASensorEventQueue* hook_ASensorManager_createEventQueue(ASensorManager* manager, ALooper* loper, int ident, ALooper_callbackFunc cb, void* data);
static int hook_ASensorManager_getSensorList(ASensorManager* manager, ASensorList** list);
static ASensor* hook_ASensorManager_getDefaultSensor(ASensorManager* manager, int type);

#define NATIVE_SENSOR_SYM_1 "ASensorManager_getInstance"
#define NATIVE_SENSOR_SYM_2 "ASensorManager_getInstanceForPackage"
#define NATIVE_SENSOR_SYM_3 "ASensorManager_getSensorList"
#define NATIVE_SENSOR_SYM_4 "ASensorManager_getDefaultSensor"
#define NATIVE_SENSOR_SYM_5 "ASensorManager_createEventQueue"
#define NATIVE_SENSOR_METHOD_COUNT 5

void registerDobbyNativeSensorsHooks(void) {
  void* handle = dlopen("libandroid.so", RTLD_NOLOAD);
  if (!handle) {
    handle = dlopen("libandroid.so", RTLD_NOW);
  }

  if (!handle) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "(Native Sensors): failed to get handle to libandroid.so!");
    BIPAN_PANIC();
  }

  const char* symbols[] = {
      NATIVE_SENSOR_SYM_1,
      NATIVE_SENSOR_SYM_2,
      NATIVE_SENSOR_SYM_3,
      NATIVE_SENSOR_SYM_4,
      NATIVE_SENSOR_SYM_5,
  };

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

  for (int i = 0; i < NATIVE_SENSOR_METHOD_COUNT; i++) {
    void* addr = dlsym(handle, symbols[i]);
    if (!addr) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to resolve: %s", symbols[i]);
      BIPAN_PANIC();
    }

    int rc = DobbyHook(addr, hooks[i], originals[i]);
    if (rc != 0) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to hook: %s", symbols[i]);
      BIPAN_PANIC();
    }

    __builtin___clear_cache((char*)addr, (char*)addr + 32);
#ifdef IN_APP_DEBUG_LOGGING
    write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Dobby hooked: %s", symbols[i]);
#endif
  }
  dlclose(handle);
}

// Hooks below
static ASensorManager* hook_ASensorManager_getInstance() {
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Native Sensors) Blocked ASensorManager_getInstance");
  return nullptr;
}

static ASensorManager* hook_ASensorManager_getInstanceForPackage(const char* packageName) {
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Native Sensors) App attempted ASensorManager_getInstanceForPackage(%s). Neutering....", packageName);
  return nullptr;
}

static ASensorEventQueue* hook_ASensorManager_createEventQueue(ASensorManager* manager, ALooper* loper, int ident, ALooper_callbackFunc cb, void* data) {
  (void)manager;
  (void)loper;
  (void)ident;
  (void)cb;
  (void)data;
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Native Sensors) Blocked Native createEventQueue");
  return nullptr;
}

static int hook_ASensorManager_getSensorList(ASensorManager* manager, ASensorList** list) {
  (void)manager;
  if (list != nullptr) {
    *list = nullptr;
  }
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Native Sensors) Blocked Native getSensorList");
  return 0;
}

static ASensor* hook_ASensorManager_getDefaultSensor(ASensorManager* manager, int type) {
  (void)manager;
  (void)type;
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Native Sensors) Blocked Native getDefaultSensor");
  return nullptr;
}
