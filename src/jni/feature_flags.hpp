#ifndef COMPILE_TIME_FLAGS_HPP
#define COMPILE_TIME_FLAGS_HPP

// #define IN_APP_DEBUG_LOGGING

/**
 * Enables:
 * - Zygisk's `FORCE_DENYLIST_UNMOUNT` at `preAppSpecialize`
 */
#define IN_APP_EXPERIMENTS

// #define IN_APP_SPOOF_GETIFADDRS
// #define IN_APP_PERF_ANALYSIS
// #define IN_APP_SIGSEGV_HANDLER

/**
 * *For some reason, some crash reporters fail/bail out app execution
 * if this flag is off, might be something to do with the early registration
 * in bionic.*
 * 
 * If enabled, the SIGSYS handler registration is done in assembly,
 * bypassing `bionic`'s wrappers and `libsigchain.so`.
 *
 * Otherwise, it's done through the library provided `sigaction()`.
 *
 * Still studying whether this is a good idea. Turning it off is
 * definitely useful for debugging the lib as we don't overwrite
 * `tombstoned`/`debuggerd` built-in handlers that generate dumps.
 */
#define IN_APP_RAW_SIGNAL_REGISTRATION

// #define BROKER_DEBUG_LOGGING

// #define BROKER_DEBUG_BUILD

// Syscalls I am still trying to investigate severity and how "hot" they are
// #define TRAP_EXPERIMENTAL_SYSCALLS

#endif