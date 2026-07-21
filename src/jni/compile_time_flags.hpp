#ifndef COMPILE_TIME_FLAGS_HPP
#define COMPILE_TIME_FLAGS_HPP

// #define IN_APP_DEBUG_LOGGING

// For now enables Dobby hooking of linker lib-loading functions
#define IN_APP_EXPERIMENTS


#define BROKER_DEBUG_LOGGING
#define BROKER_EXPERIMENTS

// Syscalls I am still trying to investigate severity and how "hot" they are
#define TRAP_EXPERIMENTAL_SYSCALLS

#endif