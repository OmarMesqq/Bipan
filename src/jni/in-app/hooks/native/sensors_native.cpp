#include "sensors_native.hpp"

#include <android/sensor.h>
#include <dlfcn.h>

#include "common_utils.hpp"
#include "deps/dobby.h"
#include "in-app/globals.hpp"
#include "../../../logger/logger.hpp"

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

void registerDobbyNativeSensorsHooks(void) {
  void* handle = dlopen("libandroid.so", RTLD_NOLOAD);
  if (!handle) {
    handle = dlopen("libandroid.so", RTLD_NOW);
  }

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

  const int nativeSensorsMethodsCount = 5;
  for (int i = 0; i < nativeSensorsMethodsCount; i++) {
    void* addr = dlsym(handle, symbols[i]);
    if (addr) {
      if (DobbyHook(addr, hooks[i], originals[i]) == 0) {
        __builtin___clear_cache((char*)addr, (char*)addr + 32);
      }
    }
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
