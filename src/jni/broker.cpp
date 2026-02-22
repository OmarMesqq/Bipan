#include <sys/prctl.h>
#include <unistd.h>
#include <syscall.h>
#include <string>

#include "broker.hpp"
#include "bipan_shared.hpp"

static inline long arm64_raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5);

void brokerProcessLoop() {
    LOGW("Starting broker loop...");
    prctl(PR_SET_NAME, "bipan_broker", 0, 0, 0);

    while (true) {
        // Spin until the App sends a request (state == 1)
        while (ipc_mem->state.load(std::memory_order_acquire) != 1) {
            // Sleep for 50 microseconds. 
            // This drops CPU usage from 100% down to roughly 0.01%
            // while keeping syscall interception extremely fast.
            usleep(50); 
        }

        // Handle Syscalls that require Pointer Marshaling
        if (ipc_mem->syscall_no == __NR_uname) { // uname
            ipc_mem->return_value = arm64_raw_syscall(__NR_uname, (long)ipc_mem->buffer, 0, 0, 0, 0, 0);
        }
        else if (ipc_mem->syscall_no == __NR_execve) { // execve
            ipc_mem->return_value = arm64_raw_syscall(__NR_execve, (long)ipc_mem->buffer, ipc_mem->arg1, ipc_mem->arg2, 0, 0, 0);
        }
        else {
            // Standard integer syscalls (passthrough normally)
            ipc_mem->return_value = arm64_raw_syscall(
                ipc_mem->syscall_no, ipc_mem->arg0, ipc_mem->arg1, 
                ipc_mem->arg2, ipc_mem->arg3, ipc_mem->arg4, ipc_mem->arg5
            );
        }

        ipc_mem->state.store(2, std::memory_order_release);
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
