#include <android/dlext.h>
#include <android/sensor.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>

#include "bipan_java.h"
#include "broker.hpp"
#include "common_utils.hpp"
#include "deps/zygisk.hpp"
#include "feature_flags.hpp"
#include "hooks/native_hooks.hpp"
#include "hooks/jni_hooks.hpp"
#include "ipc_communication.hpp"

#include "sigsys_handler.hpp"
#include "synchronization.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

struct LibBounds {
  uintptr_t start = 0;
  uintptr_t end = 0;
};

#define BIPAN_JAVA_PACKAGE_NAME "b.J"

static inline ssize_t send_fd(int socket, int fd);
static inline int findBipansBounds(struct dl_phdr_info* info, size_t size, void* data);
static inline bool scrubBipansElfHeader();

extern "C" char __executable_start;  // Thanks, linker
static int sv[2] = {0};
static int g_broker_socket = -1;

uintptr_t g_bipan_lib_start = 0;
uintptr_t g_bipan_lib_end = 0;
char g_package_name[IPC_PACKAGE_NAME_BUF_SIZ] = {0};
jclass g_bipan_java_class = nullptr;
SharedIPC* ipc_mem = nullptr;

class Bipan : public zygisk::ModuleBase {
 public:
  Bipan() : api(nullptr), env(nullptr), targetsSet(), isTargetApp(false) {}

  void onLoad(Api* api_ptr, JNIEnv* env_ptr) override {
    this->api = api_ptr;
    this->env = env_ptr;
  }

  void preAppSpecialize(AppSpecializeArgs* args) override {
    if (!fetchTargetProcesses()) {
      api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
      return;
    }

    const char* raw_process_name = env->GetStringUTFChars(args->nice_name, nullptr);
    if (!raw_process_name) {
      env->ReleaseStringUTFChars(args->nice_name, raw_process_name);
      api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
      return;
    }
    isTargetApp = isTarget(raw_process_name);

    // Not a target: remove ourselves
    if (!isTargetApp) {
      env->ReleaseStringUTFChars(args->nice_name, raw_process_name);
      api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
      return;
    }

    if (!initializeLogger()) {
      BIPAN_PANIC();
    }

    api->setOption(zygisk::Option::FORCE_DENYLIST_UNMOUNT);

    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Will apply sandbox for %s", raw_process_name);
#ifdef IN_APP_DEBUG_LOGGING
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[*] In-app logcat fd: %d", getLogcatFd());
#endif

    // Get lib bounds in mappings for PC-relative seccomp
    LibBounds my_lib;
    dl_iterate_phdr(findBipansBounds, &my_lib);
    g_bipan_lib_start = my_lib.start;
    g_bipan_lib_end = my_lib.end;

#ifdef IN_APP_DEBUG_LOGGING
    size_t lib_size = my_lib.end - my_lib.start;
    write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Lib bounds: Start=0x%lx, End=0x%lx, Size=%zu bytes", (unsigned long)my_lib.start, (unsigned long)my_lib.end, lib_size);

    write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "__executable_start (.text section): %p", &__executable_start);
#endif

    if (!scrubBipansElfHeader()) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to scrub lib's headers. Aborting!");
      BIPAN_PANIC();
    }

    strncpy(g_package_name, raw_process_name, IPC_PACKAGE_NAME_BUF_SIZ - 1);

    g_broker_socket = api->connectCompanion();
    if (g_broker_socket < 0) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Failed to connect to Broker Companion. Aborting!");
      BIPAN_PANIC();
    }
#ifdef IN_APP_DEBUG_LOGGING
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[*] In-app Broker sockfd: %d", g_broker_socket);
#endif

    // Tell the companion daemon we want to start a Broker thread
    int cmd = CMD_START_BROKER;
    write(g_broker_socket, &cmd, sizeof(cmd));

    // Create the RAM-backed IPC memory
    int memfd = (int)raw_syscall(__NR_memfd_create, (long)"BipanSharedIPCMemfd", MFD_CLOEXEC, 0, 0, 0, 0);
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
#ifdef IN_APP_DEBUG_LOGGING
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[*] In-app shared IPC mem region at %p", (void*)ipc_mem);
#endif

    ipc_mem->status = IDLE;
    ipc_mem->lock = 0;
    ipc_mem->target_pid = getpid();
    strncpy(ipc_mem->package_name, g_package_name, IPC_PACKAGE_NAME_BUF_SIZ - 1);

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
    (void)args;

    if (!isTargetApp) {
      return;
    }

    // Native (C/C++ setup)
    registerDobbyDlIteratePhdrHook();
    registerDobbyNativeSensorsHooks();
    registerDobbyNativeSystemPropertiesHook();
    registerDobbyDrmHook();

    preCacheIfaddrs();
    registerGetifaddrsHook();

    // Unseal the VM
    initBipanJava();

    // Install application-wide SIGSYS handler
    registerSignalHandler();
    // Setup tripwires for seccomp
    hookJniFunctions();
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
        write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] BipanJava's install threw!");
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

  bool fetchTargetProcesses() {
    int fd = api->connectCompanion();
    if (fd < 0) {
      return false;
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
    return true;
  }

  void setField(jclass clazz, const char* fieldName, const char* value) {
    jfieldID fieldId = env->GetStaticFieldID(clazz, fieldName, "Ljava/lang/String;");

    if (env->ExceptionCheck()) {
      env->ExceptionClear();
      write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "setField: failed to find field: %s", fieldName);
      return;
    }

    jstring newStr = env->NewStringUTF(value);
    if (newStr == nullptr) {
      write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "setField: failed create new Java String for value: %s", value);
      return;
    }

    env->SetStaticObjectField(clazz, fieldId, newStr);
    env->DeleteLocalRef(newStr);
  }

  /**
   * 1. Spoofs `Build` fields
   * 2. Hooks sensors related functions and `MediaDrm`'s `getPropertyByteArray`
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

    spoofAbisAs64BitOnly();
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
    setField(buildClass, "SOC_MANUFACTURER", "Google");
    setField(buildClass, "SOC_MODEL", "Tensor G3");
    setField(buildClass, "TAGS", "release-keys");
    setField(buildClass, "TYPE", "user");
    setField(buildClass, "USER", "android-build");
    jfieldID timeId = env->GetStaticFieldID(buildClass, "TIME", "J");
    env->SetStaticLongField(buildClass, timeId, 1764954000000);

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

    // Sensors blinding
    const int eventQueueMethodsCount = 1;
    const int sensorManagerMethodsCount = 4;

    JNINativeMethod event_queue_methods[eventQueueMethodsCount] = {
        {"nativeEnableSensor", "(JIII)I", (void*)my_nativeEnableSensor}};
    api->hookJniNativeMethods(env, "android/hardware/SystemSensorManager$BaseEventQueue", event_queue_methods, eventQueueMethodsCount);

    JNINativeMethod sensor_manager_methods[sensorManagerMethodsCount] = {
        {"nativeGetSensorAtIndex", "(JLandroid/hardware/Sensor;I)Z", (void*)my_nativeGetSensorAtIndex},
        {"nativeGetDefaultDeviceSensorAtIndex", "(JLandroid/hardware/Sensor;I)Z", (void*)my_nativeGetSensorAtIndex},
        {"nativeCreate", "(Ljava/lang/String;)J", (void*)my_nativeCreate},
        {"nativeCreateDirectChannel", "(JIJIILandroid/hardware/HardwareBuffer;)I", (void*)my_nativeCreateDirectChannel}};
    api->hookJniNativeMethods(env, "android/hardware/SystemSensorManager", sensor_manager_methods, sensorManagerMethodsCount);

    // DRM ID spoofing
    JNINativeMethod methods[] = {
        {"getPropertyByteArray",
         "(Ljava/lang/String;)[B",
         (void*)my_getPropertyByteArray}};

    api->hookJniNativeMethods(
        env,
        "android/media/MediaDrm",
        methods,
        1);

    orig_getPropertyByteArray = reinterpret_cast<decltype(orig_getPropertyByteArray)>(methods[0].fnPtr);

    // Tripwires for installing seccomp and hooking Instrumentation.onCreate()
    JNINativeMethod runtime_methods[] = {
        {"clampGrowthLimit", "()V", (void*)my_clampGrowthLimit},
        {"clearGrowthLimit", "()V", (void*)my_clearGrowthLimit}};
    api->hookJniNativeMethods(env, "dalvik/system/VMRuntime", runtime_methods, 2);

    // Zygisk populates fnPtr with the original function pointer after hooking
    orig_clampGrowthLimit = reinterpret_cast<void (*)(JNIEnv*, jobject)>(runtime_methods[0].fnPtr);
    orig_clearGrowthLimit = reinterpret_cast<void (*)(JNIEnv*, jobject)>(runtime_methods[1].fnPtr);
  }

  jobjectArray makeStringArray(const char* const* strings, size_t count) {
    jclass stringClass = env->FindClass("java/lang/String");
    if (!stringClass) return nullptr;

    jobjectArray array = env->NewObjectArray((jsize)count, stringClass, nullptr);
    if (!array) {
      env->DeleteLocalRef(stringClass);
      return nullptr;
    }

    for (size_t i = 0; i < count; i++) {
      jstring str = env->NewStringUTF(strings[i]);
      env->SetObjectArrayElement(array, (jsize)i, str);
      env->DeleteLocalRef(str);
    }

    env->DeleteLocalRef(stringClass);
    return array;
  }

  // Sets a static final String[] field, bypassing `final`
  bool setStaticStringArrayField(jclass clazz, const char* fieldName, const char* const* values, size_t count) {
    jfieldID fieldId = env->GetStaticFieldID(clazz, fieldName, "[Ljava/lang/String;");
    if (!fieldId) {
      env->ExceptionClear();
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "Field %s not found or wrong type", fieldName);
      return false;
    }

    jobjectArray array = makeStringArray(values, count);
    if (!array) {
      return false;
    }

    env->SetStaticObjectField(clazz, fieldId, array);
    env->DeleteLocalRef(array);

    if (env->ExceptionCheck()) {
      env->ExceptionClear();
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "Failed to set static field %s", fieldName);
      return false;
    }
    return true;
  }

  void spoofAbisAs64BitOnly() {
    jclass buildClass = env->FindClass("android/os/Build");
    if (!buildClass) {
      env->ExceptionClear();
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Could not find android.os.Build!");
      return;
    }

    const char* abis64[] = {"arm64-v8a"};
    const char* empty[] = {};

    bool ok1 = setStaticStringArrayField(buildClass, "SUPPORTED_ABIS", abis64, 1);
    bool ok2 = setStaticStringArrayField(buildClass, "SUPPORTED_32_BIT_ABIS", empty, 0);

    if (!ok1 || !ok2) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Failed to set some CPU ABI JNI field");
    }

    env->DeleteLocalRef(buildClass);
  }
};

// `dl_iterate_phdr` callback for finding Bipan's start and end addresses
__attribute__((always_inline)) static inline int findBipansBounds(struct dl_phdr_info* info, size_t size, void* data) {
  (void)size;

  auto* bounds = reinterpret_cast<LibBounds*>(data);

  // Match our library base address with the loaded segment address
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

/**
 * Removes ELF headers from the lib:
 * 0x7f, 0x45, 0x4c, 0x46
 */
__attribute__((always_inline)) static inline bool scrubBipansElfHeader() {
  // system's page size: always positive for Love's sake
  size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
  // align our base address to beginning of a page
  uintptr_t page_start = g_bipan_lib_start & ~(page_size - 1);

  if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Failed to change perms of lib's page-aligned addr! errno: %s", strerror(errno));
    return false;
  }

  unsigned char* dest = reinterpret_cast<unsigned char*>(g_bipan_lib_start);
  const size_t bytesToPatch = 4;

  unsigned char new_data[4];
  ssize_t result = getrandom(new_data, sizeof(new_data), 0);
  if (result == -1) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Failed to getrandom!");
    return false;
  }

  for (size_t i = 0; i < bytesToPatch; ++i) {
    dest[i] = new_data[i];
  }

  mprotect((void*)page_start, page_size, PROT_READ | PROT_EXEC);

  char* begin = reinterpret_cast<char*>(g_bipan_lib_start);
  char* end = begin + bytesToPatch;
  __builtin___clear_cache(begin, end);

  return true;
}

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
