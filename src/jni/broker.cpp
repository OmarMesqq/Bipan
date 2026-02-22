#include <sys/prctl.h>
#include <unistd.h>
#include <syscall.h>
#include <string>
#include <fstream>
#include <sstream>

#include "broker.hpp"
#include "bipan_shared.hpp"

static inline long arm64_raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5);

void brokerProcessLoop() {
    prctl(PR_SET_NAME, "bipan_broker", 0, 0, 0);
    LOGW("Starting broker loop...");

    while (true) {
        // Spin until the App sends a request
        while (ipc_mem->state.load(std::memory_order_acquire) == IDLE) {
            usleep(50);
        }

        BROKER_STATUS current_state = ipc_mem->state.load(std::memory_order_acquire);

        if (current_state == REQUEST_SCAN) {
            LOGW("[Broker]: app requested maps scan!");
            // set to false until we scan maps
            ipc_mem->isTarget.store(false, std::memory_order_release);

            std::ifstream maps("/proc/self/maps");
            std::string line;
            while (std::getline(maps, line)) {
                uintptr_t start, end;
                if (sscanf(line.c_str(), "%lx-%lx", &start, &end) == 2) {
                    if (
                        (ipc_mem->pc >= start && ipc_mem->pc < end) ||
                        (ipc_mem->lr >= start && ipc_mem->lr < end)
                    ) {
                        // We found exactly where the caller is. Is it a target .so?
                        if (line.find("/data/app/") != std::string::npos || line.find("/data/data/") != std::string::npos) {
                            ipc_mem->isTarget.store(true, std::memory_order_release);

                            // Dynamically add it to our cached ranges so we don't have to parse next time
                            // std::lock_guard<std::mutex> lock(maps_mutex);
                            // target_memory_ranges.push_back({start, end});
                        }
                        break; // Stop parsing, we found the memory block
                    }
                } else {
                    LOGE("brokerProcessLoop: sscanf failed to parse maps");
                    _exit(1);
                }
            }
        } else if (current_state == REQUEST_SYSCALL) {
            LOGW("[Broker]: app requested syscall. Doing it!");
            if (ipc_mem->syscall_no == __NR_uname) {
                ipc_mem->return_value = arm64_raw_syscall(__NR_uname, (long)ipc_mem->buffer, 0, 0, 0, 0, 0);
            }
            else if (ipc_mem->syscall_no == __NR_execve) {
                ipc_mem->return_value = arm64_raw_syscall(__NR_execve, (long)ipc_mem->buffer, ipc_mem->arg1, ipc_mem->arg2, 0, 0, 0);
            }
            else {
                // Standard integer syscalls (passthrough normally)
                ipc_mem->return_value = arm64_raw_syscall(
                    ipc_mem->syscall_no, ipc_mem->arg0, ipc_mem->arg1, 
                    ipc_mem->arg2, ipc_mem->arg3, ipc_mem->arg4, ipc_mem->arg5
                );
            }
        }
        LOGW("[Broker]: setting IPC mem to BROKER_ANSWERED");
        ipc_mem->state.store(BROKER_ANSWERED, std::memory_order_release);
        // --- NEW HANDSHAKE ---
        // Wait until the App acknowledges by setting state back to IDLE
        // This prevents the Broker from "double-processing" or 
        // seeing a stale request.
        while (ipc_mem->state.load(std::memory_order_acquire) == BROKER_ANSWERED) {
            __asm__ volatile("yield" ::: "memory");
        }
        LOGW("[Broker]: App acknowledged. Back to IDLE.");
    }
}


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wregister"
#pragma clang diagnostic ignored "-Wdeprecated-register"

/**
 * Executes a raw system call on ARM64.
 * Forces the compiler to map arguments to the correct x0-x5 and x8 registers.
 */
static inline long arm64_raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5) {
    std::string syscallName = "Unknown";
    switch (sysno) {
        case __NR_uname:    syscallName = "uname";    break;
        case __NR_execve:   syscallName = "execve";   break;
        case __NR_execveat: syscallName = "execveat"; break;
    }
    LOGW("Broker: running legit syscall %s", syscallName.c_str());

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
