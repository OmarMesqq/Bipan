#ifndef BIPAN_SHARED_H
#define BIPAN_SHARED_H

#include <android/log.h>
#include <atomic>

#define TAG "Bipan"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Shared memory structure
struct SharedIPC {
    // 0 = Idle, 1 = App Requesting, 2 = Broker Responded
    std::atomic<int> state; 
    
    // Syscall data
    int syscall_no;
    long arg0, arg1, arg2, arg3, arg4, arg5;
    long return_value;

    // The Bridge: A dedicated buffer for moving pointer data across the boundary
    char buffer[8192]; 
};

/**
 * Pointer to our shared memory region
 * Thanks to C++17, I can mark this as
 * inline and (hopefully) all TUs 
 * get the same address
 */
inline SharedIPC* ipc_mem = nullptr;

#endif