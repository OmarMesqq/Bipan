#include "drm_native.hpp"

#include <dlfcn.h>
#include <media/NdkMediaDrm.h>

#include <cstring>

#include "../../../logger/logger.hpp"
#include "../common/drm_common.hpp"
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

void registerDobbyDrmHook(void) {
  void* sym = dlsym(RTLD_DEFAULT, "AMediaDrm_getPropertyByteArray");
  if (!sym) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to resolve AMediaDrm_getPropertyByteArray!");
    return;
  }

  int rc = DobbyHook(sym, (void*)my_AMediaDrm_getPropertyByteArray, (void**)&orig_AMediaDrm_getPropertyByteArray);
  if (rc != 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to hook AMediaDrm_getPropertyByteArray!");
    return;
  }
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