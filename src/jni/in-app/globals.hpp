#ifndef IN_APP_GLOBALS_HPP
#define IN_APP_GLOBALS_HPP

#include <jni.h>

#include <cstdint>
#include <unordered_set>

#include "ipc_communication.hpp"

#define TAG "BipanInApp"
#define BIPAN_PANIC() arm64_raw_syscall(__NR_exit_group, -1, 0, 0, 0, 0, 0)

/**
 * The globals declared below are defined in Bipan's entrypoint
 * (bipan.cpp) and used accross `in-app` files
 */

extern uintptr_t g_bipan_lib_start;
extern uintptr_t g_bipan_lib_end;
extern char g_package_name[IPC_PACKAGE_NAME_BUF_SIZ];
extern jclass g_bipan_java_class;

// Shared IPC memory map between target app (injected code) and the Broker
extern SharedIPC* ipc_mem;

#endif