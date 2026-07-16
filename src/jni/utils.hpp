#ifndef UTILS_HPP
#define UTILS_HPP

#include <arpa/inet.h>
#include <syscall.h>

/**
 * Collection of AS-safe clones
 * of string manipulation libc functions.
 *
 * This is necessary as a good chunk of Bipan is injected into the process
 * and seccomp needs a signal handler. Turns out there are tons of limitations
 * on what you can do inside one.
 *
 * Please read:
 * https://www.man7.org/linux/man-pages/man7/signal-safety.7.html
 */

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wregister"

/**
 * Executes a raw system call on ARM64
 */
__attribute__((always_inline)) inline long arm64_raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4, long a5) {
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

#pragma clang diagnostic pop

__attribute__((always_inline)) inline size_t local_strlen(const char* s) {
  size_t len = 0;
  while (s[len]) len++;
  return len;
}

__attribute__((always_inline)) inline size_t local_strnlen(const char* s, size_t maxlen) {
  size_t len = 0;
  while (len < maxlen && s[len]) len++;
  return len;
}

__attribute__((always_inline)) inline int local_strncmp(const char* a, const char* b, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (a[i] != b[i]) return (unsigned char)a[i] - (unsigned char)b[i];
    if (a[i] == '\0') return 0;
  }
  return 0;
}

__attribute__((always_inline)) inline int local_strcmp(const char* a, const char* b) {
  size_t i = 0;
  while (a[i] == b[i]) {
    if (a[i] == '\0') {
      return 0;
    }
    i++;
  }
  return (unsigned char)a[i] - (unsigned char)b[i];
}

__attribute__((always_inline)) inline bool starts_with(const char* str, const char* prefix) {
  return local_strncmp(str, prefix, local_strlen(prefix)) == 0;
}

__attribute__((always_inline)) inline const char* local_strstr(const char* haystack, const char* needle) {
  if (!*needle) return haystack;
  for (; *haystack; haystack++) {
    if (*haystack == *needle) {
      const char *h = haystack, *n = needle;
      while (*h && *n && *h == *n) {
        h++;
        n++;
      }
      if (!*n) return haystack;
    }
  }
  return nullptr;
}

__attribute__((always_inline)) inline const char* local_strchr(const char* s, int c) {
  while (*s) {
    if (*s == (char)c) return s;
    s++;
  }
  return nullptr;
}

__attribute__((always_inline)) static inline void* local_memset(void* s, int c, size_t n) {
  unsigned char* p = (unsigned char*)s;
  while (n--) *p++ = (unsigned char)c;
  return s;
}

__attribute__((always_inline)) static inline char* local_strncpy(char* dest, const char* src, size_t n) {
  size_t i;
  for (i = 0; i < n && src[i] != '\0'; i++) dest[i] = src[i];
  for (; i < n; i++) dest[i] = '\0';
  return dest;
}

__attribute__((always_inline)) static inline void* local_memcpy(void* dest, const void* src, size_t n) {
  unsigned char* d = (unsigned char*)dest;
  const unsigned char* s = (const unsigned char*)src;
  while (n--) *d++ = *s++;
  return dest;
}


#endif
