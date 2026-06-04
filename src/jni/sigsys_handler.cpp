#include "sigsys_handler.hpp"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <syscall.h>
#include <unistd.h>

#include <atomic>

#include "logger.hpp"
#include "shared.hpp"
#include "spoofer.hpp"
#include "synchronization.hpp"
#include "utils.hpp"

struct kernel_sigaction {
  void (*sa_handler)(int, siginfo_t*, void*);
  unsigned long sa_flags;
  void (*sa_restorer)(void);
  uint64_t sa_mask;
};

static void sigsys_handler(int sig, siginfo_t* info, void* void_context);
static void scrub_socket(struct sockaddr* s);

void registerSignalHandler() {
  struct kernel_sigaction sa_SYS = {};
  sa_SYS.sa_handler = sigsys_handler;
  sa_SYS.sa_flags = SA_SIGINFO;
  long ret = 0;

  // Register signal directly with kernel to bypass libsigchain.so
  ret = arm64_raw_syscall(__NR_rt_sigaction, SIGSYS, (long)&sa_SYS, 0, 8, 0, 0);
  if (ret != 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Failed to set SIGSYS handler. Aborting for safety!");
    _exit(1);
  }
}

static thread_local bool in_sigsys_handler = false;
static void sigsys_handler(int sig, siginfo_t* info, void* void_context) {
  ucontext_t* ctx = (ucontext_t*)void_context;
  int nr = info->si_syscall;

  if (in_sigsys_handler) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Recursed signal handler. We're probably cooked. Aborting!");
    _exit(1);
  }
  in_sigsys_handler = true;

  if (nr == __NR_sendmmsg) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "Lying about sendmmsg existing...");
    ctx->uc_mcontext.regs[0] = -ENOSYS;
    in_sigsys_handler = false;
    return;
  }

  long arg0 = ctx->uc_mcontext.regs[0];
  long arg1 = ctx->uc_mcontext.regs[1];
  long arg2 = ctx->uc_mcontext.regs[2];
  long arg3 = ctx->uc_mcontext.regs[3];
  long arg4 = ctx->uc_mcontext.regs[4];
  long arg5 = ctx->uc_mcontext.regs[5];

  ipc_mem->stack_trace[0] = ctx->uc_mcontext.regs[30];
  ipc_mem->caller_pc = ctx->uc_mcontext.pc;
  ipc_mem->caller_fp = ctx->uc_mcontext.regs[29];
  ipc_mem->target_pid = (pid_t)arm64_raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
  ipc_mem->nr = nr;
  ipc_mem->arg0 = arg0;
  ipc_mem->arg1 = arg1;
  ipc_mem->arg2 = arg2;
  ipc_mem->arg3 = arg3;
  ipc_mem->arg4 = arg4;
  ipc_mem->arg5 = arg5;

  // Zero-out string payloads
  my_memset(ipc_mem->string_payload, 0, sizeof(ipc_mem->string_payload));
  my_memset(ipc_mem->struct_payload, 0, sizeof(ipc_mem->struct_payload));
  my_memset(ipc_mem->out_buffer, 0, sizeof(ipc_mem->out_buffer));

  __sync_synchronize();

  // app-side FD to be filled by Broker in relevant syscalls
  int pre_fd = -1;

  // Serialize Strings
  if (nr == __NR_openat) {
    pre_fd = (int)arm64_raw_syscall(__NR_memfd_create, (long)"8pten5k9K4Lx", MFD_CLOEXEC, 0, 0, 0, 0);
    // openat takes up to 4 args, so use arg5 as slot for the pre-FD
    ipc_mem->arg5 = pre_fd;
    my_strncpy(ipc_mem->string_payload, (const char*)arg1, 255);
  } else if (nr == __NR_faccessat ||
             nr == __NR_newfstatat ||
             nr == __NR_statx) {
    my_strncpy(ipc_mem->string_payload, (const char*)arg1, 255);
  } else if (nr == __NR_execve ||
             nr == __NR_execveat) {
    my_strncpy(ipc_mem->string_payload, (const char*)arg0, 255);
  }

  // Serialize binary structures with their exact lengths
  long sock_ptr = 0;
  long sock_len = 0;
  struct sockaddr_storage temp_addr;  // Used for the Pre-Flight check

  if (nr == __NR_bind || nr == __NR_connect) {
    sock_ptr = arg1;
    sock_len = arg2;
  } else if (nr == __NR_sendto || nr == __NR_sendmsg) {
    long sockfd = arg0;
    if (nr == __NR_sendto) {
      sock_ptr = arg4;
      sock_len = arg5;
    } else {
      struct msghdr* msg = (struct msghdr*)arg1;

      sock_ptr = (long)msg->msg_name;
      sock_len = msg->msg_namelen;

      // get message's length
      long total_len = 0;
      for (size_t i = 0; i < msg->msg_iovlen; i++) {
        total_len += msg->msg_iov[i].iov_len;
      }
      // sendmsg takes 3 so pass its size in this empty slot
      ipc_mem->arg3 = total_len;
    }

    /**
     * If msg_name inside msghdr (sendmsg) or
     * dest_addr (sendto) is empty, we are talking about
     * an already connected socket. Ask the kernel
     * its address to prevent LAN chatter
     */
    if (sock_ptr == 0) {
      long temp_len = sizeof(temp_addr);
      my_memset(&temp_addr, 0, sizeof(temp_addr));

      // getpeername gives us the destination IP of a connected socket
      if (arm64_raw_syscall(__NR_getpeername, sockfd, (long)&temp_addr, (long)&temp_len, 0, 0, 0) == 0) {
        sock_ptr = (long)&temp_addr;
        sock_len = temp_len;
      }
    }
  } else if (nr == __NR_listen || nr == __NR_getsockname) {
    long sockfd = arg0;
    // --- THE FIX: Pre-Flight Check ---
    // listen() doesn't give us a sockaddr, so we must extract it from the FD
    long temp_len = sizeof(temp_addr);
    my_memset(&temp_addr, 0, sizeof(temp_addr));

    if (arm64_raw_syscall(__NR_getsockname, sockfd, (long)&temp_addr, (long)&temp_len, 0, 0, 0) == 0) {
      sock_ptr = (long)&temp_addr;
      sock_len = temp_len;
    }
  }

  // getsockname populates the struct on return, no need to send it upfront
  if (sock_ptr != 0 && sock_len > 0) {
    size_t copy_len = (sock_len > 127) ? 127 : (size_t)sock_len;
    my_memcpy(ipc_mem->struct_payload, (const void*)sock_ptr, copy_len);
  }

  // Wake Broker & Wait
  ipc_mem->status = REQUEST_SYSCALL;
  futex_wake(&ipc_mem->status);

  while (ipc_mem->status != BROKER_ANSWERED) {
    futex_wait(&ipc_mem->status, REQUEST_SYSCALL);
  }


  long result = 0;
  int action = ipc_mem->action;

  if (action == ACTION_EXIT_PROCESS) {
    if (pre_fd >= 0) {
      arm64_raw_syscall(__NR_close, pre_fd, 0, 0, 0, 0, 0);
    }
    ipc_mem->status = IDLE;
    unlock_ipc();

    in_sigsys_handler = false;

    arm64_raw_syscall(__NR_exit, ipc_mem->ret, 0, 0, 0, 0, 0);
  } else if (action == ACTION_EXECUTE_NATIVE) {
    if (pre_fd >= 0) {
      // Cleanup unused ghost
      arm64_raw_syscall(__NR_close, pre_fd, 0, 0, 0, 0, 0);
    }

    result = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
  } else if (action == ACTION_USE_RET) {
    if (pre_fd >= 0 && ipc_mem->ret != pre_fd) {
      // Cleanup if Broker gave -EACCES
      arm64_raw_syscall(__NR_close, pre_fd, 0, 0, 0, 0, 0);
    }
    result = ipc_mem->ret;

    // Deserialize outputs with their exact lengths
    if (nr == __NR_uname && result == 0) {
      my_memcpy((void*)arg0, ipc_mem->out_buffer, sizeof(struct utsname));
    }
  } else if (action == ACTION_EXECUTE_AND_SCRUB_SOCK) {
    if (pre_fd >= 0) {
      arm64_raw_syscall(__NR_close, pre_fd, 0, 0, 0, 0, 0);
    }
    result = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);

    if (result == 0 && arg1 != 0) {
      struct sockaddr* s = (struct sockaddr*)arg1;
      scrub_socket(s);
      write_to_logcat_async(ANDROID_LOG_INFO, TAG, "(getsockname) scrubbed");
    } else {
      write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "sockaddr to scrub is null and/or native getsockname failed!");
    }
  }

  ipc_mem->status = IDLE;
  unlock_ipc();

  ctx->uc_mcontext.regs[0] = result;
  in_sigsys_handler = false;
}

static void scrub_socket(struct sockaddr* s) {
  if (!s) return;

  if (s->sa_family == AF_INET) {
    struct sockaddr_in* sin = (struct sockaddr_in*)s;

    sin->sin_addr.s_addr = 0x8001A8C0;  // 192.168.1.128
  } else if (s->sa_family == AF_INET6) {
    struct sockaddr_in6* sin6 = (struct sockaddr_in6*)s;

    // Unique Local Address (ULA) like fd00::1
    my_memset(&sin6->sin6_addr, 0, 16);
    sin6->sin6_addr.s6_addr[0] = 0xfd;
    sin6->sin6_addr.s6_addr[15] = 0x01;
  }
}
