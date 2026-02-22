#include <vector>
#include <string>
#include <unistd.h>
#include <unordered_set>
#include <mutex>
#include <fstream>
#include <sstream>
#include <csignal>
#include <ucontext.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <syscall.h>
#include <dlfcn.h>

#include "zygisk.hpp"
#include "bipan_shared.hpp"
#include "filter.hpp"
#include "broker.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

constexpr BIPAN_FILTER filterMode = LOG;

static std::mutex maps_mutex;
static std::vector<std::pair<uintptr_t, uintptr_t>> target_memory_ranges;
static pid_t broker_pid = -1;

void log_address_info(const char* label, uintptr_t addr);

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
            _exit(1);
        }
        bool should_spoof = isTarget(raw_process_name);

        if (should_spoof) {
            LOGW("Sandbox starting for %s...", raw_process_name);
            // Do the usual Java fields spoofing
            spoofBuildFields();

            // Setup IPC with the un-seccomped broker
            ipc_mem = static_cast<SharedIPC*>(mmap(
                nullptr, 
                sizeof(SharedIPC), 
                PROT_READ | PROT_WRITE, 
                MAP_SHARED | MAP_ANONYMOUS, 
                -1, 0
            ));
            LOGD("Bipan's shared mem at %p", ipc_mem);

            if (ipc_mem == MAP_FAILED) {
                LOGE("Failed to allocate shared memory for IPC!");
                _exit(1);
            }
            
            ipc_mem->state.store(IDLE);

            broker_pid = fork();
            if (broker_pid == 0) {
                brokerProcessLoop();

                // Should never reach here
                LOGE("Broker stopped executing!");
                _exit(1);
            }
            LOGD("Spawned bipan_broker with PID %d", broker_pid);

            // Register the SIGSYS handler before applying seccomp
            setupSigsysHandler();
            applySeccompFilter(filterMode);   
            LOGD("Sandbox applied for %s (Mode: %s)", raw_process_name, (filterMode == LOG ? "LOG" : "BLOCK"));
        }

        char processNameCopy[strlen(raw_process_name) + 1];
        strcpy(processNameCopy, raw_process_name);
        
        env->ReleaseStringUTFChars(args->nice_name, raw_process_name);

        const bool shouldClose = should_spoof ? (filterMode == BLOCK) : true;
        preSpecialize(processNameCopy, should_spoof, shouldClose);
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
            _exit(1);
        }
        LOGW("Sucessfuly set up SIGSYS handler");
    }

    static void sigsysHandler(int signum, siginfo_t *info, void *ucontext) {
        if (signum != SIGSYS) {
            LOGE("sigsysHandler: received unexpected signal: %d", signum);
            _exit(1);
        };
        LOGD("sigsysHandler got a signal.");

        ucontext_t* uc = static_cast<ucontext_t *>(ucontext);
        uintptr_t caller_pc = uc->uc_mcontext.pc;   // caller's program counter
        int syscall_no = uc->uc_mcontext.regs[8];   // syscall number (x8 in aarch64)
        uintptr_t lr = uc->uc_mcontext.regs[30];    // Link Return register

        log_address_info("PC (Actual Caller)", caller_pc);
        log_address_info("LR (Return Address)", lr);

        // extract arguments (x0 through x5)
        long arg0 = uc->uc_mcontext.regs[0];
        long arg1 = uc->uc_mcontext.regs[1];
        long arg2 = uc->uc_mcontext.regs[2];
        long arg3 = uc->uc_mcontext.regs[3];
        long arg4 = uc->uc_mcontext.regs[4];
        long arg5 = uc->uc_mcontext.regs[5];

        
        // LOGD("Evaluating if syscall is legit...");

        ipc_mem->pc.store(caller_pc, std::memory_order_release);
        ipc_mem->lr.store(lr, std::memory_order_release);
        ipc_mem->isTarget.store(false, std::memory_order_release);
        ipc_mem->state.store(REQUEST_SCAN, std::memory_order_release);

        LOGD("Main app is spinning waiting for BROKER_ANSWERED...");
        while (ipc_mem->state.load(std::memory_order_acquire) != BROKER_ANSWERED) {
            __asm__ volatile("yield" ::: "memory");
        }

        bool from_target_so = ipc_mem->isTarget.load(std::memory_order_acquire);
        LOGD("Broker answered");
        
        // Tell the broker we are done with the SCAN result
        ipc_mem->state.store(IDLE, std::memory_order_release);

        if (from_target_so) {
            if (syscall_no == __NR_uname) {
                struct utsname* buf = (struct utsname*)uc->uc_mcontext.regs[0];
                memset(buf, 0, sizeof(struct utsname));
                
                strncpy(buf->sysname, "Linux", 64);
                strncpy(buf->nodename, "localhost", 64);
                strncpy(buf->release, "6.6.56-android16-11-g8a3e2b1c4d5f", 64);
                strncpy(buf->version, "#1 SMP PREEMPT Fri Dec 05 12:00:00 UTC 2025", 64);
                strncpy(buf->machine, "aarch64", 64);
                strncpy(buf->domainname, "(none)", 64);

                uc->uc_mcontext.regs[0] = 0; // success
                LOGE("Target .so attempted uname. Falsified values");
            } else {
                LOGE("Blocked syscall %d from target .so at address %lx", syscall_no, caller_pc);
                LOGE("Args: [0]=%lx, [1]=%lx, [2]=%lx, [3]=%lx", arg0, arg1, arg2, arg3);

                uc->uc_mcontext.regs[0] = -13; // Permission denied
            }
        } else {
            // --- PASSTHROUGH VIA SHARED MEMORY SPINLOCK ---
            if (ipc_mem != nullptr && ipc_mem != MAP_FAILED) {
                LOGW("Syscall not from target. Allowing it via IPC");

                BROKER_STATUS expected = IDLE;
                while (!ipc_mem->state.compare_exchange_weak(
                    expected, REQUEST_SYSCALL, 
                    std::memory_order_release, 
                    std::memory_order_relaxed)) {
                    expected = IDLE; 
                    __asm__ volatile("yield" ::: "memory");
                }

                ipc_mem->syscall_no = syscall_no;
                ipc_mem->arg0 = arg0;
                ipc_mem->arg1 = arg1;
                ipc_mem->arg2 = arg2;
                ipc_mem->arg3 = arg3;
                ipc_mem->arg4 = arg4;
                ipc_mem->arg5 = arg5;

                // --- 1. POINTER MARSHALING (APP TO BROKER) ---
                if (syscall_no == __NR_execve) {
                    // Copy the path string into shared memory so the Broker can read it
                    // arg0 is the pointer to the filename
                    if (arg0 != 0) {
                        strncpy(ipc_mem->buffer, (const char*)arg0, sizeof(ipc_mem->buffer) - 1);
                    }
                }

                // 2. Signal Broker to go
                LOGW("[Main app] requesting syscall to broker...");
                ipc_mem->state.store(REQUEST_SYSCALL, std::memory_order_release);
                LOGW("[Main app] requested syscall to broker!");

                // 3. Spin wait for Broker response
                // (It's okay for the App to spin here with yield, because it only 
                // waits for the microsecond it takes the Broker to finish)
                while (ipc_mem->state.load(std::memory_order_acquire) != BROKER_ANSWERED) {
                    __asm__ volatile("yield" ::: "memory");
                }

                // --- 4. POINTER MARSHALING (BROKER TO APP) ---
                if (syscall_no == __NR_uname && ipc_mem->return_value == 0) { // uname success
                    // Copy the kernel's response from shared memory back into the App's original pointer
                    if (arg0 != 0) {
                        memcpy((void*)arg0, ipc_mem->buffer, sizeof(struct utsname));
                    }
                }

                // 5. Read result
                uc->uc_mcontext.regs[0] = ipc_mem->return_value;

                // 6. Release lock back to Idle
                LOGW("[Main app] setting IPC mem to IDLE!");
                ipc_mem->state.store(IDLE, std::memory_order_release);
            } else {
                LOGE("IPC shared region is nil");
                _exit(1);
            }
        }
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

    void preSpecialize(const char* process, bool isTarget, bool shouldClose) {
        if (shouldClose) {
            if (isTarget) {
                LOGW("Dlclosing module for process %s", process);
            }
            // If we don't hook any functions, we can let Zygisk dlclose ourselves
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }
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

void log_address_info(const char* label, uintptr_t addr) {
    Dl_info dlinfo;
    if (dladdr((void*)addr, &dlinfo) && dlinfo.dli_fname) {
        LOGD("%s: %p | Library: %s | Symbol: %s", 
             label, 
             (void*)addr, 
             dlinfo.dli_fname, 
             dlinfo.dli_sname ? dlinfo.dli_sname : "N/A");
    } else {
        LOGE("%s: %p (Could not resolve)", label, (void*)addr);
    }
}


// Register the module class
REGISTER_ZYGISK_MODULE(Bipan)
