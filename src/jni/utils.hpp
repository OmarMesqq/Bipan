#ifndef UTILS_HPP
#define UTILS_HPP

#include <arpa/inet.h>
#include <syscall.h>

#include "shared.hpp"

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

inline bool starts_with(const char* str, const char* prefix) {
  return strncmp(str, prefix, strlen(prefix)) == 0;
}

inline void write_to_char_buf(char* dest, const char* src, size_t len) {
  for (size_t i = 0; i < len; i++) {
    dest[i] = src[i];
  }
}

inline size_t local_strlen(const char* s) {
  size_t len = 0;
  while (s[len]) len++;
  return len;
}

inline const char* local_strstr(const char* haystack, const char* needle) {
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

inline const char* local_strchr(const char* s, int c) {
  while (*s) {
    if (*s == (char)c) return s;
    s++;
  }
  return nullptr;
}

inline int local_atoi(const char* s) {
  if (!s) return 0;

  int res = 0;
  int sign = 1;

  // 1. Skip leading whitespace
  while (*s == ' ' || *s == '\t' || *s == '\n' ||
         *s == '\r' || *s == '\f' || *s == '\v') {
    s++;
  }

  // 2. Handle optional sign
  if (*s == '-') {
    sign = -1;
    s++;
  } else if (*s == '+') {
    s++;
  }

  // 3. Process digits and stop at the first non-digit
  while (*s >= '0' && *s <= '9') {
    res = res * 10 + (*s - '0');
    s++;
  }

  return res * sign;
}

inline bool is_smaps(const char* pathname) {
  return (strcmp(pathname, "/proc/self/smaps") == 0) ||
         ((safe_proc_pid_path[0] != '\0') &&
          starts_with(pathname, safe_proc_pid_path) &&
          local_strstr(pathname, "/smaps") != nullptr);
}

inline bool is_maps(const char* pathname) {
  return (strcmp(pathname, "/proc/self/maps") == 0) ||
         ((safe_proc_pid_path[0] != '\0') &&
          starts_with(pathname, safe_proc_pid_path) &&
          local_strstr(pathname, "/maps") != nullptr);
}

inline bool is_mounts(const char* pathname) {
  return (strcmp(pathname, "/proc/mounts") == 0) ||
         (strcmp(pathname, "/proc/self/mounts") == 0) ||
         ((safe_proc_pid_path[0] != '\0') &&
          starts_with(pathname, safe_proc_pid_path) &&
          local_strstr(pathname, "/mounts") != nullptr);
}

inline size_t get_msghdr_len(const struct msghdr* msg) {
  size_t total = 0;
  if (msg && msg->msg_iov) {
    for (size_t i = 0; i < (size_t)msg->msg_iovlen; ++i) {
      total += msg->msg_iov[i].iov_len;
    }
  }
  return total;
}

/**
 * Returns `true` if IP address
 * `ip4` is in any of
 * the IPv4 LAN ranges. `false` otherwise
 */
inline bool filterIPv4LanAccess(uint32_t ip4) {
  // Unspecified address (0.0.0.0)
  if (ip4 == 0x00000000) {
    return true;
  }

  // Loopback (127.0.0.0/8)
  if ((ip4 & 0xFF000000) == 0x7F000000) {
    // Stopping loopback will probably break a shit ton of apps
    return false;
  }

  if ((ip4 & 0xFF000000) == 0x0A000000) {
    // 10.0.0.0/8 (Class A Private)
    return true;
  } else if ((ip4 & 0xFFF00000) == 0xAC100000) {
    // 172.16.0.0/12 (Class B Private)
    return true;
  } else if ((ip4 & 0xFFFF0000) == 0xC0A80000) {
    // 192.168.0.0/16 (Class C Private)
    return true;
  } else if ((ip4 & 0xF0000000) == 0xE0000000) {
    // 224.0.0.0/4 (Multicast)
    return true;
  } else if (ip4 == 0xFFFFFFFF) {
    // 255.255.255.255 (Broadcast)
    return true;
  } else if ((ip4 & 0xFFFF0000) == 0xA9FE0000) {
    // 169.254.0.0/16 (Link-Local/ APIPA (Automatic Private IP Addressing))
    return true;
  }
  return false;
}

/**
 * Returns `true` if IP address
 * pointed by `ip6` is in any of
 * the IPv6 LAN ranges. `false` otherwise
 */
inline bool filterIPv6LanAccess(uint8_t* ip6) {
  if (!ip6) {
    return false;
  }

  // Unspecified (::)
  bool is_unspecified = true;
  for (int i = 0; i < 16; i++) {
    if (ip6[i] != 0) is_unspecified = false;
  }
  if (is_unspecified) {
    return true;
  }

  // Loopback (::1)
  bool is_loopback = (ip6[15] == 1);
  for (int i = 0; i < 15; i++) {
    if (ip6[i] != 0) is_loopback = false;
  }
  if (is_loopback) {
    // Stopping loopback will probably break a shit ton of apps
    return false;
  }

  if (ip6[0] == 0xFE && (ip6[1] & 0xC0) == 0x80) {
    // fe80::/10 (Link-Local)
    return true;
  } else if ((ip6[0] & 0xFE) == 0xFC) {
    // fc00::/7 (Unique Local)
    return true;
  } else if (ip6[0] == 0xFF) {
    // ff00::/8 (Multicast)
    return true;
  }
  return false;
}

/**
 * Returns `true` if `sa_family` of given socket struct `addr`
 * is either IPv4 (`AF_INET`) or IPv6 (`AF_INET6`) **AND**
 * its address falls within LAN IP ranges defined by RFCs
 */
inline bool is_lan_address(struct sockaddr* addr) {
  if (addr == nullptr) return false;
  if (addr->sa_family == AF_INET) {
    return filterIPv4LanAccess(ntohl(((struct sockaddr_in*)addr)->sin_addr.s_addr));
  }
  if (addr->sa_family == AF_INET6) {
    return filterIPv6LanAccess(((struct sockaddr_in6*)addr)->sin6_addr.s6_addr);
  }
  return false;
}

inline void get_socket_info(int sockfd,
                            struct sockaddr* sockAddrStruct,
                            char* protocol,
                            int* port,
                            char* ipAddr,
                            char* family) {
  if (sockAddrStruct == nullptr) {
    return;
  }
  int sock_type = 0;
  socklen_t optlen = sizeof(sock_type);

  long ret = arm64_raw_syscall(__NR_getsockopt,
                               sockfd, SOL_SOCKET,
                               SO_TYPE,
                               (long)&sock_type,
                               (long)&optlen,
                               0);

  if (ret != 0) {
    _exit(-1);
  }

  if (sock_type == SOCK_STREAM) {
    write_to_char_buf(protocol, "TCP", 4);
  } else if (sock_type == SOCK_DGRAM) {
    write_to_char_buf(protocol, "UDP", 4);
  } else {
    write_to_char_buf(protocol, "UNKNOWN", 8);
  }

  if (sockAddrStruct->sa_family == AF_INET) {
    struct sockaddr_in* ipv4 = (struct sockaddr_in*)sockAddrStruct;

    *port = ntohs(ipv4->sin_port);
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipAddr, INET_ADDRSTRLEN);
    write_to_char_buf(family, "IPv4", 5);
  } else if (sockAddrStruct->sa_family == AF_INET6) {
    struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)sockAddrStruct;

    *port = ntohs(ipv6->sin6_port);
    inet_ntop(AF_INET6, &(ipv6->sin6_addr), ipAddr, INET6_ADDRSTRLEN);
    write_to_char_buf(family, "IPv6", 5);
  } else {
    write_to_char_buf(family, "UNKNOWN", 8);
  }
}

inline bool is_network_socket(const char* family) {
  return (strcmp(family, "IPv4") == 0) ||
         (strcmp(family, "IPv6") == 0);
}

__attribute__((always_inline)) static inline size_t my_strlen(const char* s) {
  size_t len = 0;
  while (s[len]) len++;
  return len;
}

__attribute__((always_inline)) static inline void* my_memset(void* s, int c, size_t n) {
  unsigned char* p = (unsigned char*)s;
  while (n--) *p++ = (unsigned char)c;
  return s;
}

__attribute__((always_inline)) static inline char* my_strncpy(char* dest, const char* src, size_t n) {
  size_t i;
  for (i = 0; i < n && src[i] != '\0'; i++) dest[i] = src[i];
  for (; i < n; i++) dest[i] = '\0';
  return dest;
}

__attribute__((always_inline)) static inline void my_reverse(char* str, int len) {
  int i = 0, j = len - 1;
  while (i < j) {
    char t = str[i];
    str[i] = str[j];
    str[j] = t;
    i++;
    j--;
  }
}

#endif