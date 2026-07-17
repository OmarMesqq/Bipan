#ifndef COMPILE_TIME_FLAGS_HPP
#define COMPILE_TIME_FLAGS_HPP

// Enables debug logging for injected code and Broker
#define DEBUG_LOGGING

// ==========================================
// Seccomp flags
// ==========================================
#define TRAP_MMAP_MPROTECT
#define TRAP_EXPERIMENTAL_SYSCALLS

// Enables injected code experimental feats that may break stuff
#define IN_APP_EXPERIMENTS

#endif