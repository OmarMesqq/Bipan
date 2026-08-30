/**
 * Hooks for JNI functions
 * using Zygisk's built-in `hookJniNativeMethods`
 */

#ifndef JNI_HOOKS_HPP
#define JNI_HOOKS_HPP

#include "deps/zygisk.hpp"
#include "drm/fake_id.hpp"
#include "globals.hpp"
#include "logger/logger.hpp"

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

jboolean my_nativeGetSensorAtIndex(JNIEnv* env, jclass clazz, jlong nativeInstance, jobject sensor, jint index) {
  (void)env;
  (void)clazz;
  (void)nativeInstance;
  (void)sensor;
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(Java Sensors) App attempted SensorManager enumeration (index %d). Neutering...", index);
  return JNI_FALSE;
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

static jbyteArray (*orig_getPropertyByteArray)(JNIEnv* env, jobject thiz, jstring property) = nullptr;

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