#ifndef INSTRUMENTATION_HPP
#define INSTRUMENTATION_HPP

#include <jni.h>

#include "../../../logger/logger.hpp"
#include "../../filter.hpp"
#include "common_utils.hpp"
#include "in-app/globals.hpp"

// Original functions
void (*orig_clampGrowthLimit)(JNIEnv*, jobject) = nullptr;
void (*orig_clearGrowthLimit)(JNIEnv*, jobject) = nullptr;

// Data structures
static bool seccomp_applied = false;

// Hooks
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

#endif
