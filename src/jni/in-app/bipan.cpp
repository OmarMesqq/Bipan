#include <android/dlext.h>
#include <android/sensor.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>

#include "bipan_java.h"
#include "broker.hpp"
#include "common_utils.hpp"
#include "compile_time_flags.hpp"
#include "deps/dobby.h"
#include "deps/zygisk.hpp"
#include "hooks.hpp"
#include "ipc_communication.hpp"
#include "sigsys_handler.hpp"
#include "synchronization.hpp"
#include "tools/mem.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

#define BIPAN_JAVA_PACKAGE_NAME "b.J"

static inline ssize_t send_fd(int socket, int fd);

// Variables "owned" exclusively by the entrypoint (this module)
extern "C" char __executable_start;  // Thanks, linker
// Variables shared across modules
uintptr_t g_bipan_lib_start = 0;
uintptr_t g_bipan_lib_end = 0;
char g_package_name[256] = {0};
jclass g_bipan_java_class = nullptr;
// Broker
SharedIPC* ipc_mem = nullptr;
int sv[2] = {0};
int g_broker_socket = -1;

std::unordered_set<std::string> g_telephony_spoofing_allowlist = {
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
    initializeLogger();
    fetchTargetProcesses();

    if (!initializeLogger()) {
      BIPAN_PANIC();
    }

    const char* raw_process_name = env->GetStringUTFChars(args->nice_name, nullptr);
    if (!raw_process_name) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] preAppSpecialize: process name is nil. Aborting.");
      BIPAN_PANIC();
    }
    isTargetApp = isTarget(raw_process_name);

    // Not a target: remove ourselves
    if (!isTargetApp) {
      env->ReleaseStringUTFChars(args->nice_name, raw_process_name);
      api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
      return;
    }
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Will apply sandbox for %s", raw_process_name);

    // Get lib bounds in mappings for PC-relative seccomp
    LibBounds my_lib;
    dl_iterate_phdr(findBipansBounds, &my_lib);
    g_bipan_lib_start = my_lib.start;
    g_bipan_lib_end = my_lib.end;

#ifdef DEBUG_LOGGING
    write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Lib's header at preAppSpecialize (BEFORE scrubbing):");
    dumpBytes(reinterpret_cast<unsigned char*>(g_bipan_lib_start), 4);

    dl_iterate_phdr(dumpBipanLinkerInfo, nullptr);
    readAuxVector();

    size_t lib_size = my_lib.end - my_lib.start;
    write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Lib bounds: Start=0x%lx, End=0x%lx, Size=%zu bytes", (unsigned long)my_lib.start, (unsigned long)my_lib.end, lib_size);
#endif

    if (!scrubBipansElfHeader()) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to scrub lib's headers. Aborting!");
      BIPAN_PANIC();
    }

    strncpy(g_package_name, raw_process_name, 255);

    g_broker_socket = api->connectCompanion();
    if (g_broker_socket < 0) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Failed to connect to Broker Companion. Aborting!");
      BIPAN_PANIC();
    }
    write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "[*] In-app Broker socket: %d", g_broker_socket);

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
    write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "[*] Shared IPC mmap'ed at: %p", (void*)ipc_mem);

    ipc_mem->status = IDLE;
    ipc_mem->lock = 0;
    ipc_mem->target_pid = getpid();

    memset(ipc_mem->package_name, 0, sizeof(ipc_mem->package_name));
    strncpy(ipc_mem->package_name, g_package_name, 255);

    // Send the Broker sock to the companion
    if (send_fd(g_broker_socket, memfd) == -1) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] send_fd failed. sockfd: %d | fd: %d | errno: %s", g_broker_socket, memfd, strerror(errno));
      BIPAN_PANIC();
    }

    // Close our local FD handle
    close(memfd);

    // Save the our sockfd of the pair
    sv[1] = g_broker_socket;

    env->ReleaseStringUTFChars(args->nice_name, raw_process_name);
  }

  void postAppSpecialize(const AppSpecializeArgs* args) override {
    if (!isTargetApp) {
      return;
    }

    // Native (C/C++ setup)
    registerDobbyDlIteratePhdrHook();
    registerDobbyNativeSensorsHooks();

    // Unseal the VM
    initBipanJava();

    // Install application-wide SIGSYS handler
    registerSignalHandler();
    // Setup tripwires for seccomp
    hookJniFunctions();
    registerDobbyNativeSystemPropertiesHook();

#ifdef DEBUG_LOGGING
    write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Lib's header at end of postAppSpecialize:");
    dumpBytes(reinterpret_cast<unsigned char*>(g_bipan_lib_start), 4);
#endif

#ifdef IN_APP_EXPERIMENTS
    registerDobbyLinkerHooks();
#endif
  }

 private:
  Api* api;
  JNIEnv* env;
  std::unordered_set<std::string> targetsSet;
  bool isTargetApp;

  /**
   * Calls `BipanJava`'s `install` method:
   * Unseals the ART VM
   */
  void initBipanJava() {
    // Map the .dex byte array into a Java DirectByteBuffer
    jobject byteBuffer = env->NewDirectByteBuffer(const_cast<unsigned char*>(classes_dex), classes_dex_len);
    if (byteBuffer == nullptr) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to create DirectByteBuffer!");
      BIPAN_PANIC();
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
      BIPAN_PANIC();
    }

    // Ask the ClassLoader to load BipanJava's entrypoint
    jmethodID loadClassMethod = env->GetMethodID(classLoaderClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    jstring className = env->NewStringUTF(BIPAN_JAVA_PACKAGE_NAME);
    jobject payloadClassObj = env->CallObjectMethod(dexClassLoader, loadClassMethod, className);

    if (env->ExceptionCheck()) {
      env->ExceptionClear();
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to load BipanJava's class (%s)!", BIPAN_JAVA_PACKAGE_NAME);
      BIPAN_PANIC();
    } else {
      jclass payloadClass = static_cast<jclass>(payloadClassObj);

      g_bipan_java_class = static_cast<jclass>(env->NewGlobalRef(payloadClass));

      // Call install from Java-side
      jmethodID installMethod = env->GetStaticMethodID(payloadClass, "i", "()V");
      if (installMethod == nullptr) {
        write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] BipanJava's installMethod is NULL!");
        BIPAN_PANIC();
      }

      env->CallStaticVoidMethod(payloadClass, installMethod);
      if (env->ExceptionCheck()) {
        env->ExceptionClear();
        write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Could not .install() BipanJava!");
        BIPAN_PANIC();
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

  /**
   * 1. Spoofs `Build` fields
   * 2. Hooks JNI sensors functions
   * 3. Sets up the ART tripwires (`clampGrowthLimit`/`clearGrowthLimit`) for
   * applying seccomp and loading BipanJava modules
   */
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
    const int JAVA_SENSORS_EVENT_QUEUE_METHODS_COUNT = 1;
    JNINativeMethod event_queue_methods[JAVA_SENSORS_EVENT_QUEUE_METHODS_COUNT] = {
        {"nativeEnableSensor", "(JIII)I", (void*)my_nativeEnableSensor}};
    api->hookJniNativeMethods(env, "android/hardware/SystemSensorManager$BaseEventQueue", event_queue_methods, JAVA_SENSORS_EVENT_QUEUE_METHODS_COUNT);

    const int JAVA_SENSORS_MANAGER_METHODS_COUNT = 4;
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

/**
 * The app calls this to send an fd to the companion
 */
__attribute__((always_inline)) static inline ssize_t send_fd(int socket, int fd) {
  struct msghdr msg = {};
  char buf[CMSG_SPACE(sizeof(int))] = {0};
  char dummy = '!';
  struct iovec io = {.iov_base = &dummy, .iov_len = 1};

  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  *((int*)CMSG_DATA(cmsg)) = fd;

  ssize_t ret = sendmsg(socket, &msg, 0);
  return ret;
}

// Register the module class
REGISTER_ZYGISK_MODULE(Bipan)
