#include "bionic_signals.hpp"

#include <dlfcn.h>

#include <cstring>

#include "../../../logger/logger.hpp"
#include "common_utils.hpp"
#include "deps/dobby.h"
#include "in-app/globals.hpp"

void registerDobbyBionicSignalHooks(void) {
  const int bionicSignalMethodsCount = 7;
  const char* symbols[] = {
      "sigaction",
      "signal",
      "bsd_signal",
      "sigprocmask",
      "pthread_sigmask",
      "sigsuspend",
      "signalfd",
  };

  // void* hooks[] = {
  //     (void*)hook_ASensorManager_getInstance,
  //     (void*)hook_ASensorManager_getInstanceForPackage,
  //     (void*)hook_ASensorManager_getSensorList,
  //     (void*)hook_ASensorManager_getDefaultSensor,
  //     (void*)hook_ASensorManager_createEventQueue};

  // void** originals[] = {
  //     (void**)&orig_ASensorManager_getInstance,
  //     (void**)&orig_ASensorManager_getInstanceForPackage,
  //     (void**)&orig_ASensorManager_getSensorList,
  //     (void**)&orig_ASensorManager_getDefaultSensor,
  //     (void**)&orig_ASensorManager_createEventQueue};

  // for (int i = 0; i < bionicSignalMethodsCount; i++) {
  //   void* addr = dlsym(RTLD_DEFAULT, symbols[i]);
  //   if (!addr) {
  //     write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to resolve: %s", symbols[i]);
  //     BIPAN_PANIC();
  //   }

  //   if (DobbyHook(addr, hooks[i], originals[i]) != 0) {
  //     write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to hook: %s", symbols[i]);
  //     BIPAN_PANIC();
  //   }

  //   __builtin___clear_cache((char*)addr, (char*)addr + 32);
  // }
}