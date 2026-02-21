#include <vector>
#include <string>
#include <unistd.h>
#include <dirent.h>
#include <unordered_set>
#include <thread>
#include <mutex>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <csignal>
#include <ucontext.h>

#include "zygisk.hpp"
#include "bipan_shared.hpp"
#include "bipan_filters.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

#define TARGETS_DIR "/data/adb/modules/bipan/targets"

constexpr BIPAN_FILTER filterMode = LOG;

std::mutex maps_mutex;
std::vector<std::pair<uintptr_t, uintptr_t>> target_memory_ranges;
static inline long arm64_raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5);

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
        if (!raw_process_name) {
            LOGE("preAppSpecialize: process name is nil. Aborting.");
            return;
        }
        bool should_spoof = isTarget(raw_process_name);

        if (should_spoof) {
            spoofBuildFields();
            applySeccompFilter(filterMode);   
            LOGD("Sandbox applied for %s (Mode: %s)", raw_process_name, (filterMode == LOG ? "LOG" : "BLOCK"));
        }

        // This is ugly, but `processNameCopy` is still in the stack when `preSpecialize` is called
        char processNameCopy[strlen(raw_process_name) + 1];
        strcpy(processNameCopy, raw_process_name);
        
        env->ReleaseStringUTFChars(args->nice_name, raw_process_name);

        const bool shouldClose = should_spoof ? (filterMode == BLOCK) : true;
        preSpecialize(processNameCopy, should_spoof, shouldClose);
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        const char *raw_process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (isTarget(raw_process_name)) {
            // 1. Register the SIGSYS Handler
            setupSigsysHandler();

            // 2. Start the Watcher thread safely after specialization
            std::thread watcher(memoryWatcherThread);
            watcher.detach(); // Let it run in the background
        }
        env->ReleaseStringUTFChars(args->nice_name, raw_process_name);
    }

private:
    Api *api;
    JNIEnv *env;
    std::unordered_set<std::string> targetsSet;

    static void setupSigsysHandler() {
        struct sigaction sa{};
        sa.sa_flags = SA_SIGINFO;
        sa.sa_sigaction = sigsysHandler;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGSYS, &sa, nullptr) != 0) {
            LOGE("Failed to register SIGSYS handler!");
        }
    }

    static void memoryWatcherThread() {
        while (true) {
            std::vector<std::pair<uintptr_t, uintptr_t>> new_ranges;
            std::ifstream maps("/proc/self/maps");
            std::string line;

            while (std::getline(maps, line)) {
                // Look for executable maps belonging to app data directories
                // Usually /data/app/ or /data/data/ containing .so
                if (line.find("r-xp") != std::string::npos && 
                   (line.find("/data/app/") != std::string::npos || line.find("/data/data/") != std::string::npos) &&
                   line.find(".so") != std::string::npos) {
                    
                    uintptr_t start, end;
                    if (sscanf(line.c_str(), "%lx-%lx", &start, &end) == 2) {
                        new_ranges.push_back({start, end});
                    }
                }
            }

            // Safely update the shared ranges
            {
                std::lock_guard<std::mutex> lock(maps_mutex);
                target_memory_ranges = new_ranges;
            }

            // Sleep to prevent CPU hogging. 
            // 1-2 seconds is usually enough to catch lazy-loaded libraries.
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }

    static void sigsysHandler(int signum, siginfo_t *info, void *ucontext) {
        if (signum != SIGSYS) return;

        ucontext_t *uc = static_cast<ucontext_t *>(ucontext);
        // Extract the Instruction Pointer (PC)
        uintptr_t caller_pc = uc->uc_mcontext.pc;

        // Extract Syscall Number
        int syscall_no = uc->uc_mcontext.regs[8];

        // Extract Arguments (x0 to x5)
        long arg0 = uc->uc_mcontext.regs[0];
        long arg1 = uc->uc_mcontext.regs[1];
        long arg2 = uc->uc_mcontext.regs[2];
        long arg3 = uc->uc_mcontext.regs[3];
        long arg4 = uc->uc_mcontext.regs[4];
        long arg5 = uc->uc_mcontext.regs[5];

        bool from_target_so = false;
        {
            std::lock_guard<std::mutex> lock(maps_mutex);
            for (const auto& range : target_memory_ranges) {
                if (caller_pc >= range.first && caller_pc < range.second) {
                    from_target_so = true;
                    break;
                }
            }
        }

        if (from_target_so) {
            // --- INTERCEPT & DUMP ---
            LOGD("[Seccomp] Blocked syscall %d from target .so at %lx", syscall_no, caller_pc);
            LOGD("          Args: [0]=%lx, [1]=%lx, [2]=%lx, [3]=%lx", arg0, arg1, arg2, arg3);

            uc->uc_mcontext.regs[0] = -13; // Permission denied

        } else {
            // --- PASSTHROUGH (Allowed) ---
            // Manually execute the syscall on behalf of libc/linker/apex
            long ret = arm64_raw_syscall(syscall_no, arg0, arg1, arg2, arg3, arg4, arg5);

            // Inject the return value back into the register context
            // so the original calling function receives it.
            uc->uc_mcontext.regs[0] = ret;
        }
        uc->uc_mcontext.pc += 4;
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

    void preSpecialize(const char* process, bool isTarget, bool shouldClose) {
        if (shouldClose) {
            if (isTarget) {
                LOGD("Dlclosing module for process %s", process);
            }
            // If we don't hook any functions, we can let Zygisk dlclose ourselves
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }
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

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wregister"
#pragma clang diagnostic ignored "-Wdeprecated-register"
/**
 * Executes a raw system call on ARM64.
 * Forces the compiler to map arguments to the correct x0-x5 and x8 registers.
 */
static inline long arm64_raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5) {
    register long x8 __asm__("x8") = sysno;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;

    __asm__ volatile(
        "svc #0\n"
        : "+r"(x0) // Output: x0 will contain the return value
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) // Inputs
        : "memory", "cc" // Clobbers: memory and condition codes might change
    );
    
    return x0;
}
#pragma clang diagnostic pop

// Register the module class
REGISTER_ZYGISK_MODULE(Bipan)
// Register the companion handler function
REGISTER_ZYGISK_COMPANION(companion_handler)
