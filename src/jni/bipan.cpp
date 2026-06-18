#include <android/dlext.h>
#include <android/looper.h>
#include <android/sensor.h>
#include <dlfcn.h>
#include <link.h>
#include <signal.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>
#include <unordered_set>
#include <vector>

#include "bipan_java.h"
#include "broker.hpp"
#include "dobby.h"
#include "hooks.hpp"
#include "shared.hpp"
#include "sigsys_handler.hpp"
#include "synchronization.hpp"
#include "zygisk.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

#define BIPAN_JAVA_PACKAGE_NAME "com.omarmesqq.bipan.BipanJava"

// Variables "owned" exclusively by the entrypoint (this module)
extern "C" char __executable_start;  // Thanks, linker
constexpr int JAVA_SENSORS_EVENT_QUEUE_METHODS_COUNT = 1;
constexpr int JAVA_SENSORS_MANAGER_METHODS_COUNT = 4;
// Variables shared across modules
char safe_proc_pid_path[64] = {0};
uintptr_t g_bipan_lib_start = 0;
uintptr_t g_bipan_lib_end = 0;
char package_name[256] = {0};
jclass g_bipanJavaClass = nullptr;
// Broker
SharedIPC* ipc_mem = nullptr;
int sv[2] = {0};
int g_broker_socket = -1;

struct LibBounds {
  uintptr_t start = 0;
  uintptr_t end = 0;
};

static int find_lib_bounds(struct dl_phdr_info* info, size_t size, void* data);

std::unordered_set<std::string> telephonySpoofingAllowlist = {
    "com.android.vending",
    "com.google.android.gms",
    "com.whatsapp",
    "com.instagram.android"};

class Bipan : public zygisk::ModuleBase {
 public:
  Bipan() : api(nullptr), env(nullptr), targetsSet(), isTargetApp(false) {}

  void onLoad(Api* api_ptr, JNIEnv* env_ptr) override {
    this->api = api_ptr;
    this->env = env_ptr;
  }

  void preAppSpecialize(AppSpecializeArgs* args) override {
    fetchTargetProcesses();

    const char* raw_process_name = env->GetStringUTFChars(args->nice_name, nullptr);
    if (!raw_process_name) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "preAppSpecialize: process name is nil. Aborting.");
      BIPAN_PANIC();
    }
    isTargetApp = isTarget(raw_process_name);

    // Not a target: remove ourselves...
    if (!isTargetApp) {
      env->ReleaseStringUTFChars(args->nice_name, raw_process_name);
      api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
      return;
    }

    write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "preAppSpecialize: will apply sandbox for %s", raw_process_name);
    snprintf(safe_proc_pid_path, sizeof(safe_proc_pid_path), "/proc/%d/", getpid());
    size_t i = 0;
    while (raw_process_name[i] && i < 255) {
      package_name[i] = raw_process_name[i];
      i++;
    }
    package_name[i] = '\0';

    g_broker_socket = api->connectCompanion();
    if (g_broker_socket < 0) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Failed to connect to Broker Companion. Aborting!");
      BIPAN_PANIC();
    }

    // Tell the companion daemon we want to start a Broker thread
    int cmd = CMD_START_BROKER;
    write(g_broker_socket, &cmd, sizeof(cmd));

    // Create the RAM-backed IPC memory
    int memfd = (int)arm64_raw_syscall(__NR_memfd_create, (long)"7EFE8wVJq686", MFD_CLOEXEC, 0, 0, 0, 0);
    if (memfd < 0) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Failed to memfd_create IPC mem! Aborting!");
      BIPAN_PANIC();
    }
    ftruncate(memfd, sizeof(SharedIPC));

    // Map it locally for the Target App
    ipc_mem = (SharedIPC*)mmap(NULL, sizeof(SharedIPC), PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
    if (ipc_mem == MAP_FAILED) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Failed to mmap shared memory for IPC! Aborting!");
      BIPAN_PANIC();
    }

    ipc_mem->status = IDLE;
    ipc_mem->lock = 0;

    // Teleport the FD to the Root Companion
    send_fd(g_broker_socket, memfd);

    // Close our local FD handle
    close(memfd);

    // Save the socket so sigsys_handler can recv_fd() openat results
    sv[1] = g_broker_socket;

    env->ReleaseStringUTFChars(args->nice_name, raw_process_name);
  }

  void postAppSpecialize(const AppSpecializeArgs* args) override {
    if (!isTargetApp) {
      return;
    }
#ifdef DEBUG
    registerDobbyLinkerHooks();
#endif
    // Native (C/C++ setup)
    registerNativeSensorsHooks();
    registerNativeSystemPropertiesHook();
    // -- TODO: this leaks local IP
    // preCacheIfaddrs();
    // registerGetifaddrsHook();
    // -- 

    // Get lib bounds in mappings for PC-relative seccomp
    LibBounds my_lib;
    dl_iterate_phdr(find_lib_bounds, &my_lib);
    g_bipan_lib_start = my_lib.start;
    g_bipan_lib_end = my_lib.end;

#ifdef DEBUG
    size_t lib_size = my_lib.end - my_lib.start;
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Library Bounds - Start: 0x%lx, End: 0x%lx, Size: %zu bytes", (unsigned long)my_lib.start, (unsigned long)my_lib.end, lib_size);
#endif
    // Install process-wide SIGSYS handler for seccomp
    registerSignalHandler();

    // Java-layer setup
    initBipanJava();
    hookJniFunctions();
  }

 private:
  Api* api;
  JNIEnv* env;
  std::unordered_set<std::string> targetsSet;
  bool isTargetApp;

  void initBipanJava() {
    // Map the .dex byte array into a Java DirectByteBuffer
    jobject byteBuffer = env->NewDirectByteBuffer(const_cast<unsigned char*>(classes_dex), classes_dex_len);
    if (byteBuffer == nullptr) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to create DirectByteBuffer!");
      return;
    }

    // Get the System ClassLoader
    jclass classLoaderClass = env->FindClass("java/lang/ClassLoader");
    jmethodID getSystemClassLoader = env->GetStaticMethodID(classLoaderClass, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    jobject systemClassLoader = env->CallStaticObjectMethod(classLoaderClass, getSystemClassLoader);

    // Instantiate InMemoryDexClassLoader using the system's ClassLoader
    jclass inMemoryDexClassLoaderClass = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    jmethodID constructor = env->GetMethodID(inMemoryDexClassLoaderClass, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    jobject dexClassLoader = env->NewObject(inMemoryDexClassLoaderClass, constructor, byteBuffer, systemClassLoader);

    if (env->ExceptionCheck()) {
      env->ExceptionClear();
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to instantiate InMemoryDexClassLoader! Maybe the .dex is invalid?");
      return;
    }

    // Ask the ClassLoader to load BipanJava's entrypoint
    jmethodID loadClassMethod = env->GetMethodID(classLoaderClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    jstring className = env->NewStringUTF(BIPAN_JAVA_PACKAGE_NAME);
    jobject payloadClassObj = env->CallObjectMethod(dexClassLoader, loadClassMethod, className);

    if (env->ExceptionCheck()) {
      env->ExceptionClear();
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to load BipanJava's class (%s)!", BIPAN_JAVA_PACKAGE_NAME);
    } else {
      jclass payloadClass = static_cast<jclass>(payloadClassObj);

      g_bipanJavaClass = static_cast<jclass>(env->NewGlobalRef(payloadClass));

      // install() BipanJava!
      jmethodID installMethod = env->GetStaticMethodID(payloadClass, "install", "()V");
      if (installMethod == nullptr) {
        write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] BipanJava's installMethod is NULL!");
        return;
      }

      env->CallStaticVoidMethod(payloadClass, installMethod);
      if (env->ExceptionCheck()) {
        env->ExceptionClear();
        write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Could not .install() BipanJava!");
      } else {
        write_to_logcat_async(ANDROID_LOG_INFO, TAG, "BipanJava DEX payload successfully injected.");
      }
    }

    env->DeleteLocalRef(className);
    env->DeleteLocalRef(dexClassLoader);
    env->DeleteLocalRef(systemClassLoader);
    env->DeleteLocalRef(inMemoryDexClassLoaderClass);
    env->DeleteLocalRef(classLoaderClass);
    env->DeleteLocalRef(byteBuffer);
  }

  bool isTarget(const char* process) {
    if (process == nullptr) {
      return false;
    }
    // Direct match
    if (targetsSet.find(process) != targetsSet.end()) {
      return true;
    }

    // Multi-process match (check if it's a sub-process i.e. com.some.app:subservice)
    std::string procStr(process);
    for (const auto& target : targetsSet) {
      if (procStr.compare(0, target.length(), target) == 0) {
        // Ensure we aren't matching "com.foo.app" by checking for the ':'
        if (procStr.length() > target.length() && procStr[target.length()] == ':') {
          return true;
        }
      }
    }
    return false;
  }

  void fetchTargetProcesses() {
    int fd = api->connectCompanion();
    if (fd < 0) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "fetchTargetProcesses: unexpected file descriptor %d", fd);
      BIPAN_PANIC();
    }

    // Tell the companion we want to fetch the targets list
    int cmd = CMD_FETCH_TARGETS;
    write(fd, &cmd, sizeof(cmd));

    uint32_t len;
    while (read(fd, &len, sizeof(len)) == sizeof(len)) {
      if (len == 0) {
        break;  // done
      }
      std::string target(len, '\0');
      if (read(fd, target.data(), len) == len) {
        targetsSet.insert(target);
      }
    }
    close(fd);
  }

  void setField(jclass clazz, const char* fieldName, const char* value) {
    jfieldID fieldId = env->GetStaticFieldID(clazz, fieldName, "Ljava/lang/String;");

    if (env->ExceptionCheck()) {
      env->ExceptionClear();
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "setField: failed to find field: %s", fieldName);
      return;
    }

    jstring newStr = env->NewStringUTF(value);
    if (newStr == nullptr) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "setField: failed create new Java String for value: %s", value);
      return;
    }

    env->SetStaticObjectField(clazz, fieldId, newStr);
    env->DeleteLocalRef(newStr);
  }

  void hookJniFunctions() {
    jclass buildClass = env->FindClass("android/os/Build");
    if (buildClass == nullptr) {
      env->ExceptionClear();
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Could not find android.os.Build!");
      return;
    }

    setField(buildClass, "BOARD", "husky");
    setField(buildClass, "BOOTLOADER", "ripcurrent-15.0-12455211");
    setField(buildClass, "BRAND", "google");
    setField(buildClass, "DEVICE", "husky");
    setField(buildClass, "DISPLAY", "BP4A.251205.006");
    setField(buildClass, "FINGERPRINT", "google/husky/husky:16/BP4A.251205.006/14401865:user/release-keys");
    setField(buildClass, "HARDWARE", "zuma");
    setField(buildClass, "HOST", "abfarm-20038");
    setField(buildClass, "ID", "BP4A.251205.006");
    setField(buildClass, "MANUFACTURER", "google");
    setField(buildClass, "MODEL", "Pixel 8 Pro");
    setField(buildClass, "PRODUCT", "husky");
    // RADIO needs native spoofing
    setField(buildClass, "SOC_MANUFACTURER", "Google");
    setField(buildClass, "SOC_MODEL", "Tensor G3");
    setField(buildClass, "TAGS", "release-keys");
    setField(buildClass, "TYPE", "user");
    setField(buildClass, "USER", "android-build");
    jfieldID timeId = env->GetStaticFieldID(buildClass, "TIME", "J");
    env->SetStaticLongField(buildClass, timeId, 1764954000000);

    // Some version fields are inside a nested class of android.os.Build
    jclass versionClass = env->FindClass("android/os/Build$VERSION");
    if (versionClass == nullptr) {
      env->ExceptionClear();
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "could not find android.os.Build.VERSION!");
      return;
    }

    setField(versionClass, "INCREMENTAL", "14401865");
    setField(versionClass, "SECURITY_PATCH", "2025-12-05");
    setField(versionClass, "SDK", "36");

    setField(versionClass, "CODENAME", "REL");
    setField(versionClass, "RELEASE", "16");
    // The two below should be the same value as `RELEASE` for final release builds
    setField(versionClass, "RELEASE_OR_CODENAME", "16");
    setField(versionClass, "RELEASE_OR_PREVIEW_DISPLAY", "16");

    jfieldID sdkIntId = env->GetStaticFieldID(versionClass, "SDK_INT", "I");
    env->SetStaticIntField(versionClass, sdkIntId, 36);

    jfieldID sdkIntFullId = env->GetStaticFieldID(versionClass, "SDK_INT_FULL", "I");
    env->SetStaticIntField(versionClass, sdkIntFullId, 3600001);

    jfieldID mpcId = env->GetStaticFieldID(versionClass, "MEDIA_PERFORMANCE_CLASS", "I");
    env->SetStaticIntField(versionClass, mpcId, 33);  // TIRAMISU/Android 13

    env->DeleteLocalRef(buildClass);
    if (versionClass) {
      env->DeleteLocalRef(versionClass);
    }

    // Java Layer Sensors hooking
    JNINativeMethod event_queue_methods[JAVA_SENSORS_EVENT_QUEUE_METHODS_COUNT] = {
        {"nativeEnableSensor", "(JIII)I", (void*)my_nativeEnableSensor}};
    api->hookJniNativeMethods(env, "android/hardware/SystemSensorManager$BaseEventQueue", event_queue_methods, JAVA_SENSORS_EVENT_QUEUE_METHODS_COUNT);
    JNINativeMethod manager_methods[JAVA_SENSORS_MANAGER_METHODS_COUNT] = {
        {"nativeGetSensorAtIndex", "(JLandroid/hardware/Sensor;I)Z", (void*)my_nativeGetSensorAtIndex},
        {"nativeGetDefaultDeviceSensorAtIndex", "(JLandroid/hardware/Sensor;I)Z", (void*)my_nativeGetSensorAtIndex},
        {"nativeCreate", "(Ljava/lang/String;)J", (void*)my_nativeCreate},
        {"nativeCreateDirectChannel", "(JIJIILandroid/hardware/HardwareBuffer;)I", (void*)my_nativeCreateDirectChannel}};
    api->hookJniNativeMethods(env, "android/hardware/SystemSensorManager", manager_methods, JAVA_SENSORS_MANAGER_METHODS_COUNT);

    // Setup JNI tripwires for activating seccomp and hooking Instrumentation.onCreate()
    JNINativeMethod runtime_methods[] = {
        {"clampGrowthLimit", "()V", (void*)my_clampGrowthLimit},
        {"clearGrowthLimit", "()V", (void*)my_clearGrowthLimit}};
    api->hookJniNativeMethods(env, "dalvik/system/VMRuntime", runtime_methods, 2);

    // Zygisk populates fnPtr with the original function pointer after hooking
    orig_clampGrowthLimit = reinterpret_cast<void (*)(JNIEnv*, jobject)>(runtime_methods[0].fnPtr);
    orig_clearGrowthLimit = reinterpret_cast<void (*)(JNIEnv*, jobject)>(runtime_methods[1].fnPtr);
  }
};

static int find_lib_bounds(struct dl_phdr_info* info, size_t size, void* data) {
  auto* bounds = reinterpret_cast<LibBounds*>(data);

  // Match our library base address with the loaded segment address
  extern char __executable_start;
  if (info->dlpi_addr == reinterpret_cast<uintptr_t>(&__executable_start)) {
    bounds->start = info->dlpi_addr;

    // Iterate through program headers to find the maximum memory span
    for (int i = 0; i < info->dlpi_phnum; i++) {
      uintptr_t seg_end = bounds->start + info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz;
      if (seg_end > bounds->end) {
        bounds->end = seg_end;
      }
    }
    return 1;  // Stop iteration
  }
  return 0;
}

// Register the module class
REGISTER_ZYGISK_MODULE(Bipan)
