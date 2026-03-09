#ifndef ASSEMBLY_HPP
#define ASSEMBLY_HPP

#include "shared.hpp"
#include <syscall.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wregister"

/**
 * Executes a raw arm64 syscall that bypasses our seccomp filter
 */
static inline long arm64_bypassed_syscall(long sysno, long a0, long a1, long a2, long a3, long a4) {
  register long x8 __asm__("x8") = sysno;
  register long x0 __asm__("x0") = a0;
  register long x1 __asm__("x1") = a1;
  register long x2 __asm__("x2") = a2;
  register long x3 __asm__("x3") = a3;
  register long x4 __asm__("x4") = a4;
  register long x5 __asm__("x5") = SECCOMP_BYPASS;

  __asm__ volatile(
      "svc #0\n"
      : "+r"(x0)
      : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
      : "memory", "cc");

  return x0;
}

/**
 * Executes a raw system call on ARM64
 */
static inline long arm64_raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5) {
  register long x8 __asm__("x8") = sysno;
  register long x0 __asm__("x0") = a0;
  register long x1 __asm__("x1") = a1;
  register long x2 __asm__("x2") = a2;
  register long x3 __asm__("x3") = a3;
  register long x4 __asm__("x4") = a4;
  register long x5 __asm__("x5") = a5;

  __asm__ volatile(
      "svc #0\n"
      : "+r"(x0)                                              // Output: x0 will contain the return value
      : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)  // Inputs
      : "memory", "cc"                                        // Clobbers: memory and condition codes might change
  );

  return x0;
}

static inline long arm64_bypassed_mmap(long a0, long a1, long a2, long a3, long a4, long a5) {
  // a4 is the 'fd' (32-bit int). 
  // We pack 0xBADB into the top 32 bits and keep the real FD in the bottom 32 bits.
  long magic_a4 = (a4 & 0xFFFFFFFF) | 0x0000BADB00000000ULL;
  
  return arm64_raw_syscall(__NR_mmap, a0, a1, a2, a3, magic_a4, a5);
}


#pragma clang diagnostic pop

#endif
