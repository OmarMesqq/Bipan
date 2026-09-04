#include "drm_native.hpp"

#include <dlfcn.h>
#include <media/NdkMediaDrm.h>

#include <cstring>

#include "../../../logger/logger.hpp"
#include "../common/drm_common.hpp"
#include "common_utils.hpp"
#include "deps/dobby.h"
#include "in-app/globals.hpp"

// Original functions
// https://android.googlesource.com/platform/frameworks/av/+/master/media/ndk/include/media/NdkMediaDrm.h#593
static media_status_t (*orig_AMediaDrm_getPropertyByteArray)(AMediaDrm* drm, const char* propertyName, AMediaDrmByteArray* propertyValue) = nullptr;

// Data structures
static uint8_t gSpoofedPropBuf[DRM_ID_BUF_SIZE];
static AMediaDrmByteArray gSpoofedProp;

// Hooks
static media_status_t my_AMediaDrm_getPropertyByteArray(AMediaDrm* drm, const char* propertyName, AMediaDrmByteArray* propertyValue);

// Symbol names
#define NATIVE_GET_PROP_BYTE_ARRAY_SYM "AMediaDrm_getPropertyByteArray"

void registerDobbyDrmNativeHook(void) {
  void* addr = dlsym(RTLD_DEFAULT, NATIVE_GET_PROP_BYTE_ARRAY_SYM);
  if (!addr) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to resolve: %s", NATIVE_GET_PROP_BYTE_ARRAY_SYM);
    BIPAN_PANIC();
  }

  int rc = DobbyHook(addr, (void*)my_AMediaDrm_getPropertyByteArray, (void**)&orig_AMediaDrm_getPropertyByteArray);
  if (rc != 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to hook: %s", NATIVE_GET_PROP_BYTE_ARRAY_SYM);
    BIPAN_PANIC();
  }
  __builtin___clear_cache((char*)addr, (char*)addr + 32);
#ifdef IN_APP_DEBUG_LOGGING
  write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Dobby hooked: %s", NATIVE_GET_PROP_BYTE_ARRAY_SYM);
#endif
}

// Hooks below
static media_status_t my_AMediaDrm_getPropertyByteArray(AMediaDrm* drm, const char* propertyName, AMediaDrmByteArray* propertyValue) {
  if (propertyName != nullptr &&
      strcmp(propertyName, "deviceUniqueId") == 0 &&
      propertyValue != nullptr) {
    ensureFakeId();
    memcpy(gSpoofedPropBuf, kFakeId, sizeof(kFakeId));
    gSpoofedProp.ptr = gSpoofedPropBuf;
    gSpoofedProp.length = sizeof(gSpoofedPropBuf);
    *propertyValue = gSpoofedProp;

    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Native DRM) Spoofed AMediaDrm_getPropertyByteArray(deviceUniqueId)");
    return AMEDIA_OK;
  }

  return orig_AMediaDrm_getPropertyByteArray(drm, propertyName, propertyValue);
}

// Helpers below