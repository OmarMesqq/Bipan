#include <vector>
#include <string>
#include <unistd.h>
#include <unordered_set>
#include <sys/mman.h>
#include <sys/socket.h>

#include "zygisk.hpp"
#include "shared.hpp"
#include "filter.hpp"
#include "sigsys_handler.hpp"
#include "broker.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

// Initialize shared components
SharedIPC* ipc_mem = nullptr;
int sv[2] = {0};
// Whitelist variables
char safe_path_user_0[256] = {0};
size_t safe_path_user_0_len = 0;
char safe_path_data_data[256] = {0};
size_t safe_path_data_data_len = 0;


// Globals to store the original JNI function pointers
void (*orig_clampGrowthLimit)(JNIEnv*, jobject) = nullptr;
void (*orig_clearGrowthLimit)(JNIEnv*, jobject) = nullptr;

// Ensure we only apply the seccomp filter once
bool seccomp_applied = false;

// Our hijacked clampGrowthLimit
void my_clampGrowthLimit(JNIEnv* env, jobject obj) {
    if (!seccomp_applied) {
        applySeccompFilter();
        seccomp_applied = true;
        LOGW("Seccomp filter safely applied at clampGrowthLimit");
    }
    if (orig_clampGrowthLimit) {
        orig_clampGrowthLimit(env, obj);
    }
}

// Our hijacked clearGrowthLimit
void my_clearGrowthLimit(JNIEnv* env, jobject obj) {
    if (!seccomp_applied) {
        applySeccompFilter();
        seccomp_applied = true;
        LOGW("Seccomp filter safely applied at clearGrowthLimit");
    }
    if (orig_clearGrowthLimit) {
        orig_clearGrowthLimit(env, obj);
    }
}



class Bipan : public zygisk::ModuleBase {
public:
    Bipan() : api(nullptr), env(nullptr), targetsSet(), isTargetApp(false) {}

    void onLoad(Api *api_ptr, JNIEnv *env_ptr) override {
        this->api = api_ptr;
        this->env = env_ptr;
        fetchTargetProcesses();
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        // Filter the process: only spoof some packages
        const char *raw_process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!raw_process_name) {
            LOGE("preAppSpecialize: process name is nil. Aborting.");
            return;
        }
        isTargetApp = isTarget(raw_process_name);

        if (isTargetApp) {
            LOGW("preAppSpecialize: will apply sandbox for %s", raw_process_name);
            
            std::string basePkg(raw_process_name);
            size_t colon_pos = basePkg.find(':');
            if (colon_pos != std::string::npos) {
                basePkg = basePkg.substr(0, colon_pos); // Strip ":sync" or ":service"
            }

            // Build the string safely in userland, BEFORE the signal handler is active
            snprintf(safe_path_user_0, sizeof(safe_path_user_0), "/data/user/0/%s", basePkg.c_str());
            safe_path_user_0_len = strlen(safe_path_user_0);

            snprintf(safe_path_data_data, sizeof(safe_path_data_data), "/data/data/%s", basePkg.c_str());
            safe_path_data_data_len = strlen(safe_path_data_data);
        }
        
        env->ReleaseStringUTFChars(args->nice_name, raw_process_name);

        preSpecialize();
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (isTargetApp) {
            spoofBuildFields();

            ipc_mem = (SharedIPC*)(mmap(
                NULL,
                sizeof(SharedIPC),
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS,
                -1, 0)
            );

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
              startBroker(sv[0]);  // Pass the socket to your broker loop
              LOGE("Broker loop stopped!");
              _exit(-1);
            }
            
            close(sv[0]);  // Close broker's end
            registerSigSysHandler();
            
            // Hook JNI methods that will trip app code as soon as they're done
            // Source: https://cs.android.com/android/platform/superproject/+/android-latest-release:frameworks/base/core/java/android/app/ActivityThread.java;l=8061?q=handleBindApplication&ss=android%2Fplatform%2Fsuperproject
            // Set up the tripwire to delay Seccomp until app execution
            JNINativeMethod methods[] = {
                {"clampGrowthLimit", "()V", (void*)my_clampGrowthLimit},
                {"clearGrowthLimit", "()V", (void*)my_clearGrowthLimit}
            };
            
            // Inject our functions into the VMRuntime class
            api->hookJniNativeMethods(env, "dalvik/system/VMRuntime", methods, 2);
            
            // Zygisk populates fnPtr with the original function pointer after hooking
            orig_clampGrowthLimit = reinterpret_cast<void(*)(JNIEnv*, jobject)>(methods[0].fnPtr);
            orig_clearGrowthLimit = reinterpret_cast<void(*)(JNIEnv*, jobject)>(methods[1].fnPtr);
        }
    }

private:
    Api *api;
    JNIEnv *env;
    std::unordered_set<std::string> targetsSet;
    bool isTargetApp;

    void preSpecialize() {
        // Targets require us to on memory to catch SIGSYS
        if (!isTargetApp) {
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }
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

    /**
     * Do some IPC with the companion handler
     * to get the list of target processes whose
     * fields should be spoofed. Yes, this runs on every app launch,
     * but hopefully it's O(1) as I'm using an ordered_set
     * to gather target apps.
     */
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
