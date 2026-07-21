#include "sigsys_handler.hpp"

#include <arpa/inet.h>
#include <linux/memfd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#include "as_safe_string.hpp"
#include "compile_time_flags.hpp"
#include "globals.hpp"
#include "in-app/ipc_lock.hpp"
#include "ipc_communication.hpp"
#include "logger/logger.hpp"

static void sigsys_handler(int sig, siginfo_t* info, void* void_context);
static void scrub_socket(struct sockaddr* s);

void registerSignalHandler() {
  struct sigaction act = {
      .sa_sigaction = &sigsys_handler,
      .sa_flags = SA_SIGINFO | SA_NODEFER};

  int ret = sigaction(SIGSYS, &act, nullptr);
  if (ret != 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] sigaction(SIGSYS) failed (errno: %s)", strerror(errno));
    BIPAN_PANIC();
  }
}

static thread_local bool in_sigsys_handler = false;
static void sigsys_handler(int sig, siginfo_t* info, void* void_context) {
  ucontext_t* ctx = (ucontext_t*)void_context;
  int nr = info->si_syscall;

  if (in_sigsys_handler) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Recursed signal handler. We're probably cooked. Aborting!");
    BIPAN_PANIC();
  }
  in_sigsys_handler = true;

  long arg0 = (long)ctx->uc_mcontext.regs[0];
  long arg1 = (long)ctx->uc_mcontext.regs[1];
  long arg2 = (long)ctx->uc_mcontext.regs[2];
  long arg3 = (long)ctx->uc_mcontext.regs[3];
  long arg4 = (long)ctx->uc_mcontext.regs[4];
  long arg5 = (long)ctx->uc_mcontext.regs[5];

  if (nr == __NR_sendmmsg) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Lying about sendmmsg existing...");
    ctx->uc_mcontext.regs[0] = (__u64)-ENOSYS;
    in_sigsys_handler = false;
    return;
  }

  if (nr == __NR_userfaultfd) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Lying about userfaultfd existing...");
    ctx->uc_mcontext.regs[0] = (__u64)-ENOSYS;
    in_sigsys_handler = false;
    return;
  }

  if (nr == __NR_listen) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Spoofing listen...");
    ctx->uc_mcontext.regs[0] = 0;
    in_sigsys_handler = false;
    return;
  }

  if (nr == __NR_getsockname) {
    long r = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);

    if (r != 0 || arg1 == 0) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "sockaddr to scrub is null and/or native getsockname failed!");
      BIPAN_PANIC();
    }

    struct sockaddr* s = (struct sockaddr*)arg1;
    scrub_socket(s);

    in_sigsys_handler = false;
    ctx->uc_mcontext.regs[0] = (__u64)r;
    return;
  }

  if (nr == __NR_socket) {
    // 1st arg is the "domain" of the socket
    if (arg0 == AF_NETLINK) {
      // write_to_logcat_async(ANDROID_LOG_INFO, TAG, " Blocked AF_NETLINK socket");
      ctx->uc_mcontext.regs[0] = (__u64)-EAFNOSUPPORT;
      in_sigsys_handler = false;
      return;
    }

    long ret = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
    ctx->uc_mcontext.regs[0] = (__u64)ret;
    in_sigsys_handler = false;
    return;
  }

  lock_ipc();

  ipc_mem->stack_trace[0] = ctx->uc_mcontext.regs[30];  // Link Register (x30)
  ipc_mem->caller_pc = ctx->uc_mcontext.pc;             // Program counter at time of trap
  ipc_mem->caller_fp = ctx->uc_mcontext.regs[29];       // Frame Pointer (x29)
  ipc_mem->target_pid = (pid_t)arm64_raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
  ipc_mem->nr = nr;
  ipc_mem->arg0 = arg0;
  ipc_mem->arg1 = arg1;
  ipc_mem->arg2 = arg2;
  ipc_mem->arg3 = arg3;
  ipc_mem->arg4 = arg4;
  ipc_mem->arg5 = arg5;
#ifdef TRAP_EXPERIMENTAL_SYSCALLS
  ipc_mem->vm_iov_count = 0;
#endif

  // Zero-out string payloads
  local_memset(ipc_mem->string_payload, 0, sizeof(ipc_mem->string_payload));
  local_memset(ipc_mem->struct_payload, 0, sizeof(ipc_mem->struct_payload));
  local_memset(ipc_mem->out_buffer, 0, sizeof(ipc_mem->out_buffer));
#ifdef TRAP_EXPERIMENTAL_SYSCALLS
  local_memset(ipc_mem->pipefd_payload, 0, sizeof(ipc_mem->pipefd_payload));
  local_memset(ipc_mem->vm_iov_addr, 0, sizeof(ipc_mem->vm_iov_addr));
  local_memset(ipc_mem->vm_iov_len, 0, sizeof(ipc_mem->vm_iov_len));
#endif
  __sync_synchronize();

  int pre_fd = -1;  // app-side fd to be filled by Broker open-like syscalls

  // Serialization of strings
  if (nr == __NR_openat) {
    pre_fd = (int)arm64_raw_syscall(__NR_memfd_create, (long)arg1, MFD_CLOEXEC, 0, 0, 0, 0);
    ipc_mem->arg5 = pre_fd;
    local_strncpy(ipc_mem->string_payload, (const char*)arg1, 255);
  } else if (nr == __NR_faccessat) {
    local_strncpy(ipc_mem->string_payload, (const char*)arg1, 255);
  } else if (nr == __NR_statfs) {
    local_strncpy(ipc_mem->string_payload, (const char*)arg0, 255);
  } else if (nr == __NR_newfstatat || nr == __NR_statx) {
    local_strncpy(ipc_mem->string_payload, (const char*)arg1, 255);
  } else if (nr == __NR_inotify_add_watch ||
             nr == __NR_readlinkat ||
             nr == __NR_mknodat) {
    local_strncpy(ipc_mem->string_payload, (const char*)arg1, 255);
  } else if (nr == __NR_execve ||
             nr == __NR_execveat) {
    local_strncpy(ipc_mem->string_payload, (const char*)arg0, 255);
  }
#ifdef TRAP_EXPERIMENTAL_SYSCALLS
  else if (nr == __NR_pipe2) {
    local_memcpy(ipc_mem->pipefd_payload, (int*)arg0, 2);
  }

  else if (nr == __NR_process_vm_readv || nr == __NR_process_vm_writev) {
    ipc_mem->arg0 = arg0;  // target pid

    const struct iovec* remote_iov = (const struct iovec*)arg3;
    unsigned long riovcnt = (unsigned long)arg4;

    // Capture up to 4 remote iovec entries for inspection
    for (unsigned long i = 0; i < riovcnt && i < 4; i++) {
      ipc_mem->vm_iov_addr[i] = (uintptr_t)remote_iov[i].iov_base;
      ipc_mem->vm_iov_len[i] = remote_iov[i].iov_len;
    }
    ipc_mem->vm_iov_count = (riovcnt < 4) ? riovcnt : 4;
  }
#endif

  // Serialization of structs
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
      local_memset(&temp_addr, 0, sizeof(temp_addr));

      // getpeername gives us the destination IP of a connected socket
      if (arm64_raw_syscall(__NR_getpeername, sockfd, (long)&temp_addr, (long)&temp_len, 0, 0, 0) == 0) {
        sock_ptr = (long)&temp_addr;
        sock_len = temp_len;
      }
    }
  }

  // getsockname populates the struct on return, no need to send it upfront
  if (sock_ptr != 0 && sock_len > 0) {
    size_t copy_len = (sock_len > 127) ? 127 : (size_t)sock_len;
    local_memcpy(ipc_mem->struct_payload, (const void*)sock_ptr, copy_len);
  }

  // Wake Broker
  ipc_mem->status = REQUEST_SYSCALL;
  futex_wake(&ipc_mem->status);
  // Spinlock
  while (ipc_mem->status != BROKER_ANSWERED) {
    futex_wait(&ipc_mem->status, REQUEST_SYSCALL);
  }

  long result = 0;
  int action = ipc_mem->action;

  // Route action based on Broker policy decision
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
      arm64_raw_syscall(__NR_close, pre_fd, 0, 0, 0, 0, 0);
    }

    // fork/exec family handling:
    // clear reentrancy flag and IPC lock before the exec'ing
    if (nr == __NR_execve || nr == __NR_execveat) {
      in_sigsys_handler = false;
      ipc_mem->status = IDLE;
      unlock_ipc();
    }

    result = arm64_raw_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);

    // if exec actually fails, we reach here,
    // so we restore the state so that the cleanup
    // code at the bottom doesn't double-unlock
    if (nr == __NR_execve || nr == __NR_execveat) {
      lock_ipc();
      in_sigsys_handler = true;
    }
  } else if (action == ACTION_USE_RET) {
    if (pre_fd >= 0 && ipc_mem->ret != pre_fd) {
      // Cleanup if Broker rejected
      arm64_raw_syscall(__NR_close, pre_fd, 0, 0, 0, 0, 0);
    }

    result = ipc_mem->ret;

    // Deserialize outputs
    if (nr == __NR_uname && result == 0) {
      local_memcpy((void*)arg0, ipc_mem->out_buffer, sizeof(struct utsname));
    }
    if (nr == __NR_readlinkat && result > 0) {
      char* buf = (char*)ipc_mem->arg2;
      size_t bufsiz = (size_t)ipc_mem->arg3;
      size_t copy_len = local_strnlen((char*)ipc_mem->out_buffer, bufsiz - 1);
      local_memcpy(buf, ipc_mem->out_buffer, copy_len);
    }
    if (nr == __NR_newfstatat && result == 0) {
      struct stat* buf = (struct stat*)ipc_mem->arg2;
      local_memcpy(buf, ipc_mem->out_buffer, sizeof(struct stat));
    }
    if (nr == __NR_fstat && result == 0) {
      struct stat* buf = (struct stat*)ipc_mem->arg1;
      local_memcpy(buf, ipc_mem->out_buffer, sizeof(struct stat));
    }
  }

  ipc_mem->status = IDLE;
  unlock_ipc();

  ctx->uc_mcontext.regs[0] = (__u64)result;
  in_sigsys_handler = false;
}

static void scrub_socket(struct sockaddr* s) {
  if (!s) return;

  if (s->sa_family == AF_INET) {
    struct sockaddr_in* sin = (struct sockaddr_in*)s;

    sin->sin_addr.s_addr = 0x01DE6F0A;  // 10.111.222.1

    // write_to_logcat_async(ANDROID_LOG_INFO, TAG, "IPv4 (getsockname) scrubbed");
  } else if (s->sa_family == AF_INET6) {
    struct sockaddr_in6* sin6 = (struct sockaddr_in6*)s;

    // Unique Local Address (ULA) like fd00::1
    local_memset(&sin6->sin6_addr, 0, 16);
    sin6->sin6_addr.s6_addr[0] = 0xfd;
    sin6->sin6_addr.s6_addr[15] = 0x01;

    // write_to_logcat_async(ANDROID_LOG_INFO, TAG, "IPv6 (getsockname) scrubbed");
  }
}
