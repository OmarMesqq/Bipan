#ifndef DRM_JNI_HPP
#define DRM_JNI_HPP

#include <jni.h>

#include <cstring>

#include "../../../logger/logger.hpp"
#include "../common/drm_common.hpp"
#include "in-app/globals.hpp"

// Original functions
jbyteArray (*orig_getPropertyByteArray)(JNIEnv* env, jobject thiz, jstring property) = nullptr;

// Hooks
jbyteArray my_getPropertyByteArray(JNIEnv* env, jobject thiz, jstring property) {
  if (property != nullptr) {
    const char* name = env->GetStringUTFChars(property, nullptr);

    bool match = name != nullptr && strcmp(name, "deviceUniqueId") == 0;

    if (name != nullptr) {
      env->ReleaseStringUTFChars(property, name);
    }

    if (match) {
      ensureFakeId();
      jbyteArray result = env->NewByteArray(DRM_ID_BUF_SIZE);
      if (result != nullptr) {
        write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Java DRM) Spoofed getPropertyByteArray(deviceUniqueId)");
        env->SetByteArrayRegion(result, 0, DRM_ID_BUF_SIZE, reinterpret_cast<const jbyte*>(kFakeId));
      }
      return result;
    }
  }

  return orig_getPropertyByteArray(env, thiz, property);
}

#endif
