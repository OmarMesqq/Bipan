#include <vector>
#include <string>
#include <unistd.h>
#include <dirent.h>
#include <unordered_set>

#include "zygisk.hpp"
#include "bipan_shared.hpp"
#include "bipan_filters.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;



#define TARGETS_DIR "/data/adb/modules/bipan/targets"

class Bipan : public zygisk::ModuleBase {
public:
    Bipan() : api(nullptr), env(nullptr) {}

    void onLoad(Api *api_ptr, JNIEnv *env_ptr) override {
        this->api = api_ptr;
        this->env = env_ptr;
        fetchTargetProcesses();
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        // Filter the process: only spoof some packages
        const char *raw_process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        bool should_spoof = isTarget(raw_process_name);


        if (should_spoof) {
            spoofBuildFields();
            block_syscalls();
            LOGD("Sanbox applied for %s", raw_process_name);
        }
        env->ReleaseStringUTFChars(args->nice_name, raw_process_name);
        preSpecialize(raw_process_name);
    }

    void preServerSpecialize(ServerSpecializeArgs *args) override {
        preSpecialize("system_server");
    }

private:
    Api *api;
    JNIEnv *env;
    std::unordered_set<std::string> targetsSet;

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

    void preSpecialize(const char *process) {
        // Since we do not hook any functions, we should let Zygisk dlclose ourselves
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

    /**
     * Sets a field `fieldName` in a Java class `clazz` obtained via JNI
     * to the value `value`.
     *
     * WARNING: This is a setter for String fields only!!!!
     */
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
        setField(buildClass, "RADIO", "1.0.0");
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
};


/**
 * The companion handler func runs as root.
 * It was deemed necessary in order to bypass
 * SELinux policies in the Magisk folder
 */
static void companion_handler(int fd) {
    DIR* dir = opendir(TARGETS_DIR);
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_name[0] == '.') {
                // Skip . and ..
                continue;
            }

            auto len = static_cast<uint32_t>(strlen(entry->d_name));
            write(fd, &len, sizeof(len));
            write(fd, entry->d_name, len);
        }
        closedir(dir);
    } else {
        LOGE("companion_handler: failed to read targets dir (%s)!", TARGETS_DIR);
        return;
    }
    
    uint32_t done = 0; // means we are finished
    write(fd, &done, sizeof(done));
}


// Register the module class
REGISTER_ZYGISK_MODULE(Bipan)
// Register the companion handler function
REGISTER_ZYGISK_COMPANION(companion_handler)
