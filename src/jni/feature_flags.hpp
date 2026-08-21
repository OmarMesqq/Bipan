#ifndef COMPILE_TIME_FLAGS_HPP
#define COMPILE_TIME_FLAGS_HPP

// #define IN_APP_DEBUG_LOGGING

/**
 * Logs time taken to get IPC mem lock and for Broker to answer.
 * This is will log a lot.
 */
// #define IN_APP_PERF_ANALYSIS

/**
 * For devtime only: install sig handlers for
 * useful signals in the injected side
 */
// #define IN_APP_ADDITIONAL_HANDLERS

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

/**
 * Logs all stats/accesses/opens Broker-side.
 * This may log a lot. 
 */
// #define BROKER_DEBUG_LOGGING

/**
 * Logs the stack unwinding iterations and lib search in
 * /proc/self/maps.
 * 
 * This will log a lot.
 */
// #define BROKER_UNWINDER_LOGGING

/**
 * Devtime only: installs BipanBrokerAssitant to handle bad programming
 * (sorry) I may leave out in the privileged Broker thread.
 */
// #define BROKER_DEBUG_BUILD

// Syscalls I am still trying to investigate severity and how "hot" they are
// #define TRAP_EXPERIMENTAL_SYSCALLS

#endif