#ifndef COMMON_UTILS_HPP
#define COMMON_UTILS_HPP

#include <cstring>

#include "as_safe_string.hpp"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wregister"

#if defined(__aarch64__)

/**
 * Executes a raw system call on ARM64 (AArch64 EABI: syscall# in x8, args in x0-x5)
 */
__attribute__((always_inline)) inline long raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5) {
  register long x8 __asm__("x8") = sysno;
  register long x0 __asm__("x0") = a0;
  register long x1 __asm__("x1") = a1;
  register long x2 __asm__("x2") = a2;
  register long x3 __asm__("x3") = a3;
  register long x4 __asm__("x4") = a4;
  register long x5 __asm__("x5") = a5;

  __asm__ volatile(
      "svc #0\n"
      : "+r"(x0)
      : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
      : "memory", "cc");

  return x0;
}

#elif defined(__arm__)

/**
 * Executes a raw system call on ARM32 (EABI: syscall# in r7, args in r0-r5)
 * Note: r7 is the Thumb frame-pointer register in debug builds, so it cannot
 * be bound directly via `register long r7 __asm__("r7")` — it must be loaded
 * inside the asm block and declared as a clobber instead.
 */
__attribute__((always_inline)) inline long raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5) {
  register long r0 __asm__("r0") = a0;
  register long r1 __asm__("r1") = a1;
  register long r2 __asm__("r2") = a2;
  register long r3 __asm__("r3") = a3;
  register long r4 __asm__("r4") = a4;
  register long r5 __asm__("r5") = a5;

  __asm__ volatile(
      "push {r7}\n"
      "mov r7, %[sysno]\n"
      "svc #0\n"
      "pop {r7}\n"
      : "+r"(r0)
      : [sysno] "r"(sysno), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5)
      : "memory", "cc");

  return r0;
}

#else
#error "raw_syscall: unsupported architecture"
#endif

#pragma clang diagnostic pop

inline bool isHostsFile(const char* pathname) {
  return (
      (local_strcmp(pathname, "/etc/hosts") == 0) ||
      (local_strcmp(pathname, "/system/etc/hosts") == 0));
}

/**
 * NOT async-signal safe function to check if first arg
 * (`str`) has the string `prefix` as its leading chars
 */
inline bool startsWith(const char* str, const char* prefix) {
  return strncmp(str, prefix, strlen(prefix)) == 0;
}

#endif