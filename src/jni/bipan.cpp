#include <android/dlext.h>
#include <android/looper.h>
#include <android/sensor.h>
#include <dlfcn.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>
#include <unordered_set>
#include <vector>

#include "broker.hpp"
#include "dobby.h"
#include "filter.hpp"
#include "settings_hook_payload.h"
#include "shared.hpp"
#include "sigsys_handler.hpp"
#include "zygisk.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

#ifdef BROKER_ARCH
SharedIPC* ipc_mem = nullptr;
int sv[2] = {0};
#endif
char safe_proc_pid_path[64] = {0};
static bool seccomp_applied = false;

/**
 * Original function pointers
 */
void (*orig_clampGrowthLimit)(JNIEnv*, jobject) = nullptr;
void (*orig_clearGrowthLimit)(JNIEnv*, jobject) = nullptr;
void* (*orig_dlopen)(const char* filename, int flag) = nullptr;
void* (*orig_android_dlopen_ext)(const char* filename, int flag, const android_dlextinfo* extinfo) = nullptr;
static int (*orig_ASensorManager_getSensorList)(ASensorManager*, ASensorList**);
static ASensor* (*orig_ASensorManager_getDefaultSensor)(ASensorManager*, int);
static ASensorEventQueue* (*orig_ASensorManager_createEventQueue)(ASensorManager*, ALooper*, int, ALooper_callbackFunc, void*);

// ==========================================
// Java and Native Sensor hooks
// ==========================================
jboolean my_nativeGetSensorAtIndex(JNIEnv* env, jclass clazz, jlong nativeInstance, jobject sensor, jint index) {
  (void)env;
  (void)clazz;
  (void)nativeInstance;
  (void)sensor;
  LOGE("(Sensors) Blocked Java SensorManager enumeration (index %d)!", index);
  return JNI_FALSE;
}

jint my_nativeEnableSensor(JNIEnv* env, jclass clazz, jlong eventQueuePtr, jint handle, jint rateUs, jint maxBatchReportLatencyUs) {
  (void)env;
  (void)clazz;
  (void)eventQueuePtr;
  (void)handle;
  (void)rateUs;
  (void)maxBatchReportLatencyUs;
  LOGE("(Sensors) Blocked Java nativeEnableSensor! Data stream is dead.");
  return -1;
}

jint my_nativeCreateDirectChannel(JNIEnv* env, jclass clazz, jlong nativeInstance, jint size, jint type, jint fd, jobject resource) {
  (void)env;
  (void)clazz;
  (void)nativeInstance;
  (void)size;
  (void)type;
  (void)fd;
  (void)resource;
  LOGE("(Sensors) Blocked nativeCreateDirectChannel! High-speed tracking denied.");
  return -1;
}

ASensorEventQueue* hook_ASensorManager_createEventQueue(ASensorManager* manager, ALooper* loper, int ident, ALooper_callbackFunc cb, void* data) {
  (void)manager;
  (void)loper;
  (void)ident;
  (void)cb;
  (void)data;
  LOGE("(Sensors) Blocked Native createEventQueue! NDK app is now blind.");
  return nullptr;
}

int hook_ASensorManager_getSensorList(ASensorManager* manager, ASensorList** list) {
  (void)manager;
  if (list != nullptr) *list = nullptr;
  return 0;
}

ASensor* hook_ASensorManager_getDefaultSensor(ASensorManager* manager, int type) {
  (void)manager;
  (void)type;
  return nullptr;
}

// ==========================================
// Sensor spoofing strategy
// ==========================================

void setupSensorsSpoofing() {
  void* getList_addr = dlsym(RTLD_DEFAULT, "ASensorManager_getSensorList");
  void* getDefault_addr = dlsym(RTLD_DEFAULT, "ASensorManager_getDefaultSensor");
  void* createQueue_addr = dlsym(RTLD_DEFAULT, "ASensorManager_createEventQueue");

  if (getList_addr) {
    DobbyHook(getList_addr, (void*)hook_ASensorManager_getSensorList, (void**)&orig_ASensorManager_getSensorList);
  }
  if (getDefault_addr) {
    DobbyHook(getDefault_addr, (void*)hook_ASensorManager_getDefaultSensor, (void**)&orig_ASensorManager_getDefaultSensor);
  }
  if (createQueue_addr) {
    DobbyHook(createQueue_addr, (void*)hook_ASensorManager_createEventQueue, (void**)&orig_ASensorManager_createEventQueue);
  }

  LOGD("Native sensor hooks applied");
}

// ==========================================
// Linker hooks
// ==========================================

void* my_dlopen(const char* filename, int flag) {
  if (filename != nullptr) {
    LOGW("Hook (dlopen): app is loading: %s", filename);
  }
  return orig_dlopen(filename, flag);
}

void* my_android_dlopen_ext(const char* filename, int flag, const android_dlextinfo* extinfo) {
  if (filename != nullptr) {
    LOGW("Hook (android_dlopen_ext): app is loading: %s", filename);

    if (strstr(filename, "libwebviewchromium.so") != nullptr) {
      LOGW("WebView Detected! Re-applying sensor blocks...");
      setupSensorsSpoofing();
    } else if (strstr(filename, "libloader.so") != nullptr) {
      LOGE("Attach GDB: gdb -p %d", getpid());
      volatile int wait_for_gdb = 1;
      while (wait_for_gdb) {
        asm volatile("yield");
      }
    }
  }

  return orig_android_dlopen_ext(filename, flag, extinfo);
}

// ==========================================
// JNI tripwires for Seccomp
// ==========================================

void my_clampGrowthLimit(JNIEnv* env, jobject obj) {
  if (!seccomp_applied) {
    applySeccomp();
    seccomp_applied = true;
    LOGW("Seccomp applied at clampGrowthLimit.");
  }
  if (orig_clampGrowthLimit) {
    orig_clampGrowthLimit(env, obj);
  }
}

void my_clearGrowthLimit(JNIEnv* env, jobject obj) {
  if (!seccomp_applied) {
    applySeccomp();
    seccomp_applied = true;
    LOGW("Seccomp applied at clearGrowthLimit.");
  }
  if (orig_clearGrowthLimit) {
    orig_clearGrowthLimit(env, obj);
  }
}

// ==========================================
// Dobby setup for inline hooks
// ==========================================

void registerDobbyLinkerHooks() {
  static bool dobby_initialized = false;
  if (dobby_initialized) {
    return;
  }

  LOGD("Registering Dobby Linker Hooks...");
  void* dlopen_addr = dlsym(RTLD_DEFAULT, "dlopen");
  void* android_dlopen_ext_addr = dlsym(RTLD_DEFAULT, "android_dlopen_ext");

  if (dlopen_addr && android_dlopen_ext_addr) {
    int dlopenHookRes = DobbyHook(dlopen_addr, (void*)my_dlopen, (void**)&orig_dlopen);
    int android_dlopen_extHookRes = DobbyHook(android_dlopen_ext_addr, (void*)my_android_dlopen_ext, (void**)&orig_android_dlopen_ext);
    if (dlopenHookRes == 0 && android_dlopen_extHookRes == 0) {
      LOGW("Linker hooks active.");
      dobby_initialized = true;
    } else {
      LOGE("Failed to setup Dobby hooks!");
    }
  }
}

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
      LOGE("preAppSpecialize: process name is nil. Aborting.");
      return;
    }
    isTargetApp = isTarget(raw_process_name);

    if (isTargetApp) {
      LOGW("preAppSpecialize: will apply sandbox for %s", raw_process_name);
      snprintf(safe_proc_pid_path, sizeof(safe_proc_pid_path), "/proc/%d/", getpid());
    }

    env->ReleaseStringUTFChars(args->nice_name, raw_process_name);

    preSpecialize();
  }

  void postAppSpecialize(const AppSpecializeArgs* args) override {
    if (isTargetApp) {
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
        LOGE("Failed to allocate shared memory for IPC!");
        _exit(1);
      }

      ipc_mem->status = IDLE;

      if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
        LOGE("Failed to socketpair");
        _exit(1);
      }

      pid_t pid = fork();
      if (pid == 0) {
        close(sv[1]);        // Close target's end
        startBroker(sv[0]);  // Pass the socket to broker loop
        LOGE("Broker loop stopped!");
        _exit(-1);
      }

      close(sv[0]);  // Close broker's end
#endif
      registerSigSysHandler();
      registerDobbyLinkerHooks();
      setupSensorsSpoofing();

      JNINativeMethod event_queue_methods[] = {
          {"nativeEnableSensor", "(JIII)I", (void*)my_nativeEnableSensor}};
      api->hookJniNativeMethods(env, "android/hardware/SystemSensorManager$BaseEventQueue", event_queue_methods, 1);

      JNINativeMethod manager_methods[] = {
          {"nativeGetSensorAtIndex", "(JLandroid/hardware/Sensor;I)Z", (void*)my_nativeGetSensorAtIndex},
          {"nativeCreateDirectChannel", "(JIJIILandroid/hardware/HardwareBuffer;)I", (void*)my_nativeCreateDirectChannel}};
      api->hookJniNativeMethods(env, "android/hardware/SystemSensorManager", manager_methods, 2);

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
    // 1. Map our C++ byte array into a Java DirectByteBuffer
    jobject byteBuffer = env->NewDirectByteBuffer(const_cast<unsigned char*>(classes_dex), classes_dex_len);
    if (byteBuffer == nullptr) {
      LOGE("inject: Failed to create DirectByteBuffer");
      return;
    }

    // 2. Get the System ClassLoader (we need this as a parent delegate)
    jclass classLoaderClass = env->FindClass("java/lang/ClassLoader");
    jmethodID getSystemClassLoader = env->GetStaticMethodID(classLoaderClass, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    jobject systemClassLoader = env->CallStaticObjectMethod(classLoaderClass, getSystemClassLoader);

    // 3. Instantiate dalvik.system.InMemoryDexClassLoader
    jclass inMemoryDexClassLoaderClass = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    jmethodID constructor = env->GetMethodID(inMemoryDexClassLoaderClass, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    jobject dexClassLoader = env->NewObject(inMemoryDexClassLoaderClass, constructor, byteBuffer, systemClassLoader);

    if (env->ExceptionCheck()) {
      env->ExceptionClear();
      LOGE("inject: Failed to instantiate InMemoryDexClassLoader. Is the payload valid?");
      return;
    }

    // 4. Ask our new ClassLoader to find your SettingsHook class
    jmethodID loadClassMethod = env->GetMethodID(classLoaderClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    jstring className = env->NewStringUTF("com.omarmesqq.bipan.SettingsHook");
    jobject payloadClassObj = env->CallObjectMethod(dexClassLoader, loadClassMethod, className);

    if (env->ExceptionCheck()) {
      env->ExceptionClear();
      LOGE("inject: Failed to load class com.omarmesqq.bipan.SettingsHook");
    } else {
      jclass payloadClass = static_cast<jclass>(payloadClassObj);

      // 5. Execute the static install() method!
      if (payloadClass != nullptr) {
        jmethodID installMethod = env->GetStaticMethodID(payloadClass, "install", "()V");
        if (installMethod != nullptr) {
          env->CallStaticVoidMethod(payloadClass, installMethod);

          if (env->ExceptionCheck()) {
            env->ExceptionClear();
            LOGE("inject: Exception thrown inside SettingsHook.install()!");
          } else {
            LOGW("Bipan: Fileless Java Payload successfully injected and executing!");
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
      LOGE("fetchTargetProcesses: unexpected file descriptor %d", fd);
      return;
    }

    while (true) {
      // Read length of the string first (4 bytes or less)
      uint32_t len;
      ssize_t pkgLenRet = read(fd, &len, sizeof(len));

      if (pkgLenRet <= 0) {
        if (pkgLenRet < 0) {
          LOGE("fetchTargetProcesses: error reading package name's length (errno %d)", errno);
        } else {
          LOGE("fetchTargetProcesses: fd %d returned EOF", fd);
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
        LOGE("fetchTargetProcesses: failed to read complete package name. Expected: %zd. Got: %zd", (ssize_t)len, pkgNameRet);
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
      LOGE("setField: failed to find field: %s", fieldName);
      return;
    }

    jstring newStr = env->NewStringUTF(value);
    if (newStr == nullptr) {
      LOGE("setField: failed create new Java String for value: %s", value);
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
      LOGE("spoofBuildFields: could not find android.os.Build class!");
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
      LOGE("spoofBuildFields: could not find android.os.Build.VERSION class!");
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

// Register the module class
REGISTER_ZYGISK_MODULE(Bipan)
