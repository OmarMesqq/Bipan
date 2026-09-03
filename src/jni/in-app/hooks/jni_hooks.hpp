/**
 * Hooks for JNI functions
 * using Zygisk's built-in `hookJniNativeMethods`
 */

#ifndef JNI_HOOKS_HPP
#define JNI_HOOKS_HPP

#include "../filter.hpp"
#include "../globals.hpp"
#include "deps/zygisk.hpp"
#include "drm_hook.hpp"
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

// ----------- TODO: organize ts -----------

// Original functions
void (*orig_clampGrowthLimit)(JNIEnv*, jobject) = nullptr;
static void (*orig_clearGrowthLimit)(JNIEnv*, jobject) = nullptr;

// Data structures
static bool seccomp_applied = false;

// Hooks
void my_clampGrowthLimit(JNIEnv* env, jobject obj);
void my_clearGrowthLimit(JNIEnv* env, jobject obj);

// Hooks below

void my_clampGrowthLimit(JNIEnv* env, jobject obj) {
  if (g_bipan_java_class == nullptr) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clampGrowthLimit: BipanJava class is null!");
    BIPAN_PANIC();
  }

  // Call hookInstrumentation from Java
  jmethodID hookMethod = env->GetStaticMethodID(g_bipan_java_class, "h", "()V");
  if (hookMethod == nullptr) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clampGrowthLimit: hookInstrumentation fnPtr is null!");
    BIPAN_PANIC();
  }

  env->CallStaticVoidMethod(g_bipan_java_class, hookMethod);
  if (env->ExceptionCheck()) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clampGrowthLimit: hookInstrumentation threw an exception!");
    BIPAN_PANIC();
  }

  if (!seccomp_applied) {
    if (g_bipan_lib_start == 0 || g_bipan_lib_end == 0) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clampGrowthLimit: can't apply seccomp: lib bounds are 0!");
      BIPAN_PANIC();
    }

    applySeccomp(g_bipan_lib_start, g_bipan_lib_end);
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Seccomp applied at clampGrowthLimit");
    seccomp_applied = true;
  }

  if (orig_clampGrowthLimit) {
    orig_clampGrowthLimit(env, obj);
  }
}

void my_clearGrowthLimit(JNIEnv* env, jobject obj) {
  if (g_bipan_java_class == nullptr) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clearGrowthLimit: BipanJava class is null!");
    BIPAN_PANIC();
  }

  // Call hookInstrumentation from Java
  jmethodID hookMethod = env->GetStaticMethodID(g_bipan_java_class, "h", "()V");
  if (hookMethod == nullptr) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clearGrowthLimit: hookInstrumentation fnPtr is null!");
    BIPAN_PANIC();
  }

  env->CallStaticVoidMethod(g_bipan_java_class, hookMethod);
  if (env->ExceptionCheck()) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clearGrowthLimit: hookInstrumentation threw an exception!");
    BIPAN_PANIC();
  }

  if (!seccomp_applied) {
    if (g_bipan_lib_start == 0 || g_bipan_lib_end == 0) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] clearGrowthLimit: can't apply seccomp: lib bounds are 0!");
      BIPAN_PANIC();
    }

    applySeccomp(g_bipan_lib_start, g_bipan_lib_end);
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Seccomp applied at clearGrowthLimit");
    seccomp_applied = true;
  }

  if (orig_clearGrowthLimit) {
    orig_clearGrowthLimit(env, obj);
  }
}

// Helpers below

#endif