#ifndef COMPILE_TIME_FLAGS_HPP
#define COMPILE_TIME_FLAGS_HPP

// #define IN_APP_DEBUG_LOGGING

// For now enables Dobby hooking of linker lib-loading functions
// #define IN_APP_EXPERIMENTS

/**
 * If enabled, the SIGSYS handler registration is done in assembly,
 * bypassing `bionic`'s wrappers.
 * 
 * Otherwise, it's done through the library provided `sigaction()`
 */
// #define IN_APP_RAW_SIGNAL_REGISTRATION

// #define BROKER_DEBUG_LOGGING
// #define BROKER_EXPERIMENTS

// Syscalls I am still trying to investigate severity and how "hot" they are
// #define TRAP_EXPERIMENTAL_SYSCALLS

#endif