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

#include "broker.hpp"
#include "dobby.h"
#include "hooks.hpp"
#include "settings_hook_payload.h"
#include "shared.hpp"
#include "sigsys_handler.hpp"
#include "zygisk.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

// Variables "owned" exclusively by the entrypoint (this module)
extern "C" char __executable_start;  // Thanks, linker
constexpr int JAVA_SENSORS_EVENT_QUEUE_METHODS_COUNT = 1;
constexpr int JAVA_SENSORS_MANAGER_METHODS_COUNT = 4;
// Variables shared across modules
char safe_proc_pid_path[64] = {0};
uintptr_t g_bipan_lib_start = 0;
uintptr_t g_bipan_lib_end = 0;
char package_name[256] = {0};

#ifdef BROKER_ARCH
SharedIPC* ipc_mem = nullptr;
int sv[2] = {0};
#endif

struct LibBounds {
  uintptr_t start = 0;
  uintptr_t end = 0;
};

static int find_lib_bounds(struct dl_phdr_info* info, size_t size, void* data);

class Bipan : public zygisk::ModuleBase {
 public:
  Bipan() : api(nullptr), env(nullptr), targetsSet(), isTargetApp(false) {}

  void onLoad(Api* api_ptr, JNIEnv* env_ptr) override {
    this->api = api_ptr;
    this->env = env_ptr;
    fetchTargetProcesses();
  }

  void preAppSpecialize(AppSpecializeArgs* args) override {
    // Filter the process: only spoof some packages
    const char* raw_process_name = env->GetStringUTFChars(args->nice_name, nullptr);
    if (!raw_process_name) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "preAppSpecialize: process name is nil. Aborting.");
      return;
    }
    isTargetApp = isTarget(raw_process_name);

    if (isTargetApp) {
      write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "preAppSpecialize: will apply sandbox for %s", raw_process_name);
      snprintf(safe_proc_pid_path, sizeof(safe_proc_pid_path), "/proc/%d/", getpid());
      size_t i = 0;
      while (raw_process_name[i] && i < 255) {
        package_name[i] = raw_process_name[i];
        i++;
      }
      package_name[i] = '\0';
    }

    env->ReleaseStringUTFChars(args->nice_name, raw_process_name);

    preSpecialize();
  }

  void postAppSpecialize(const AppSpecializeArgs* args) override {
    if (isTargetApp) {
      registerDobbyLinkerHooks();
      registerDobbySensorsHooks();
      LibBounds my_lib;
      dl_iterate_phdr(find_lib_bounds, &my_lib);

      // Save them to the globals
      g_bipan_lib_start = my_lib.start;
      g_bipan_lib_end = my_lib.end;

      // 2. Calculate size and log everything
      size_t lib_size = my_lib.end - my_lib.start;
      write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Bipan Library Bounds - Start: 0x%lx, End: 0x%lx, Size: %zu bytes",
           (unsigned long)my_lib.start, (unsigned long)my_lib.end, lib_size);

      spoofBuildFields();
      injectAndStartJavaPayload();

#ifdef BROKER_ARCH
      ipc_mem = (SharedIPC*)(mmap(
          NULL,
          sizeof(SharedIPC),
          PROT_READ | PROT_WRITE,
          MAP_SHARED | MAP_ANONYMOUS,
          -1, 0));

      if (ipc_mem == MAP_FAILED) {
        write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Failed to allocate shared memory for IPC!");
        _exit(1);
      }

      ipc_mem->status = IDLE;

      if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
        write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Failed to socketpair");
        _exit(1);
      }

      pid_t pid = fork();
      if (pid == 0) {
        close(sv[1]);        // Close target's end
        startBroker(sv[0]);  // Pass the socket to broker loop
        write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Broker loop stopped!");
        _exit(-1);
      }

      close(sv[0]);  // Close broker's end
#endif
      registerSignalHandler();

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

      // This will finally trigger Seccomp before app code runs
      JNINativeMethod runtime_methods[] = {
          {"clampGrowthLimit", "()V", (void*)my_clampGrowthLimit},
          {"clearGrowthLimit", "()V", (void*)my_clearGrowthLimit}};
      api->hookJniNativeMethods(env, "dalvik/system/VMRuntime", runtime_methods, 2);

      // Zygisk populates fnPtr with the original function pointer after hooking
      orig_clampGrowthLimit = reinterpret_cast<void (*)(JNIEnv*, jobject)>(runtime_methods[0].fnPtr);
      orig_clearGrowthLimit = reinterpret_cast<void (*)(JNIEnv*, jobject)>(runtime_methods[1].fnPtr);
    }
  }

 private:
  Api* api;
  JNIEnv* env;
  std::unordered_set<std::string> targetsSet;
  bool isTargetApp;

  void preSpecialize() {
    // Targets require us to on memory to catch SIGSYS
    if (!isTargetApp) {
      api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }
  }

  void injectAndStartJavaPayload() {
    // Map the byte array into a Java DirectByteBuffer
    jobject byteBuffer = env->NewDirectByteBuffer(const_cast<unsigned char*>(classes_dex), classes_dex_len);
    if (byteBuffer == nullptr) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "injectAndStartJavaPayload: failed to create DirectByteBuffer!");
      return;
    }

    // Get the System ClassLoader
    jclass classLoaderClass = env->FindClass("java/lang/ClassLoader");
    jmethodID getSystemClassLoader = env->GetStaticMethodID(classLoaderClass, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    jobject systemClassLoader = env->CallStaticObjectMethod(classLoaderClass, getSystemClassLoader);

    // Instantiate dalvik.system.InMemoryDexClassLoader using the system's ClassLoader
    jclass inMemoryDexClassLoaderClass = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    jmethodID constructor = env->GetMethodID(inMemoryDexClassLoaderClass, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    jobject dexClassLoader = env->NewObject(inMemoryDexClassLoaderClass, constructor, byteBuffer, systemClassLoader);

    if (env->ExceptionCheck()) {
      env->ExceptionClear();
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "injectAndStartJavaPayload: failed to instantiate InMemoryDexClassLoader! Maybe the .dex is invalid?");
      return;
    }

    // 4. Ask our new ClassLoader to find your SettingsHook class
    jmethodID loadClassMethod = env->GetMethodID(classLoaderClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    // TODO
    jstring className = env->NewStringUTF("com.omarmesqq.bipan.SettingsHook");
    jobject payloadClassObj = env->CallObjectMethod(dexClassLoader, loadClassMethod, className);

    if (env->ExceptionCheck()) {
      env->ExceptionClear();
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "inject: Failed to load class com.omarmesqq.bipan.SettingsHook");
    } else {
      jclass payloadClass = static_cast<jclass>(payloadClassObj);

      // 5. Execute the static install() method!
      if (payloadClass != nullptr) {
        jmethodID installMethod = env->GetStaticMethodID(payloadClass, "install", "()V");
        if (installMethod != nullptr) {
          env->CallStaticVoidMethod(payloadClass, installMethod);

          if (env->ExceptionCheck()) {
            env->ExceptionClear();
            write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "inject: Exception thrown inside SettingsHook.install()!");
          } else {
            write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Bipan: Fileless Java Payload successfully injected and executing!");
          }
        }
      }
    }

    // 6. Clean up JNI references to prevent memory leaks in the target process
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
      return;
    }

    while (true) {
      // Read length of the string first (4 bytes or less)
      uint32_t len;
      ssize_t pkgLenRet = read(fd, &len, sizeof(len));

      if (pkgLenRet <= 0) {
        if (pkgLenRet < 0) {
          write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "fetchTargetProcesses: error reading package name's length (errno %d)", errno);
        } else {
          write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "fetchTargetProcesses: fd %d returned EOF", fd);
        }
        break;
      }

      // Expected end of list signal from the companion
      if (len == 0) {
        break;
      }

      // Read the string
      std::string pkgName(len, '\0');
      ssize_t pkgNameRet = read(fd, &pkgName[0], len);
      if (pkgNameRet != (ssize_t)len) {
        write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "fetchTargetProcesses: failed to read complete package name. Expected: %zd. Got: %zd", (ssize_t)len, pkgNameRet);
        break;
      }
      targetsSet.insert(pkgName);
    }
    close(fd);
  }

  void setField(jclass clazz, const char* fieldName, const char* value) {
    jfieldID fieldId = env->GetStaticFieldID(clazz, fieldName, "Ljava/lang/String;");

    // Check for exceptions (e.g., field doesn't exist on this Android version)
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

    // Set new Java String and cleanup
    env->SetStaticObjectField(clazz, fieldId, newStr);
    env->DeleteLocalRef(newStr);
  }

  void spoofBuildFields() {
    // Find the offending class...
    jclass buildClass = env->FindClass("android/os/Build");
    if (buildClass == nullptr) {
      env->ExceptionClear();
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "spoofBuildFields: could not find android.os.Build class!");
      return;
    }

    // Spoof some fields to make it look like you're running a Google Pixel 8 Pro
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
    setField(buildClass, "RADIO", "g5300g-251108-251202-B-12876551");
    setField(buildClass, "SOC_MANUFACTURER", "Google");
    setField(buildClass, "SOC_MODEL", "Tensor G3");
    setField(buildClass, "TAGS", "release-keys");
    setField(buildClass, "TYPE", "user");
    setField(buildClass, "USER", "android-build");

    // Spoof some version fields of android.os.Build's nested class
    jclass versionClass = env->FindClass("android/os/Build$VERSION");
    if (versionClass == nullptr) {
      env->ExceptionClear();
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "spoofBuildFields: could not find android.os.Build.VERSION class!");
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

    // SDK_INT and SDK_INT_FULL are an 'int's
    jfieldID sdkIntId = env->GetStaticFieldID(versionClass, "SDK_INT", "I");
    env->SetStaticIntField(versionClass, sdkIntId, 36);

    jfieldID sdkIntFullId = env->GetStaticFieldID(versionClass, "SDK_INT_FULL", "I");
    env->SetStaticIntField(versionClass, sdkIntFullId, 3600001);

    // TIME is a long
    jfieldID timeId = env->GetStaticFieldID(buildClass, "TIME", "J");
    env->SetStaticLongField(buildClass, timeId, 1764954000000);

    // cleanup!
    env->DeleteLocalRef(buildClass);
    if (versionClass) {
      env->DeleteLocalRef(versionClass);
    }
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
