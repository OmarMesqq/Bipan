#include <arpa/inet.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <string>

#include "broker.hpp"
#include "deps/zygisk.hpp"
#include "ipc_communication.hpp"
#include "logger/logger.hpp"

#define TAG "BipanRootCompanion"

#define TARGETS_DIR "/data/adb/modules/bipan/targets"

static void handle_fetch_targets(int sockfd);
static inline int recv_fd(int socket);

/**
 * Our root companion's request handler function. This function runs in
 * superuser daemon spawned by Zygisk.
 *
 * Paraphrasing the docs, this function will run concurrently
 * on multiple threads as [fact-check this] the root daemon will be unique
 * across multiple Bipan targeted apps.
 *
 * As the targeted app (running `Bipan`) can only "talk" to the companion
 * in pre[XXX]Specialize methods, we implement a multiplexer here so the "door"
 * to the companion remains open during tageted app's lifetime. The reason for this
 * is that Bipan leverages the superuser daemon for
 * two crucially distinct operations in `preAppSpecialize`:
 *
 * 1. Getting the target processes (`fetchTargetProcesses()`)
 * 2. Asking the companion to start our trusted `Broker` process and registering the `sockfd` for "later talk"
 */
static void companion_handler(int sock) {
  CompanionCommand cmd;
  if (!initializeLogger()) {
    return;
  }

  // Get the command ID from the client
  if (read(sock, &cmd, sizeof(cmd)) <= 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] companion_handler failed to read CMD from target!");
    return;
  }

  // Multiplexing: route the request
  if (cmd == CMD_FETCH_TARGETS) {
    handle_fetch_targets(sock);
  } else if (cmd == CMD_START_BROKER) {
    // Receive the Memory FD from the Target App
    int memfd = recv_fd(sock);
    if (memfd < 0) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] companion_handler failed to receive memfd from target!");
      return;
    }

    // Map the memory for THIS specific app's thread
    SharedIPC* local_ipc_mem = (SharedIPC*)mmap(NULL, sizeof(SharedIPC), PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
    close(memfd);
    if (local_ipc_mem == MAP_FAILED) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] companion_handler mmap failed!");
      return;
    }

    __sync_synchronize();
    startBroker(sock, local_ipc_mem);
    pid_t pid = getpid();
    pid_t tid = gettid();
    write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] Broker exited. Companion's PID: %d | TID: %d", tid, pid);
  }
}

// Register the root companion function
REGISTER_ZYGISK_COMPANION(companion_handler)

static void handle_fetch_targets(int sockfd) {
  DIR* dir = opendir(TARGETS_DIR);
  if (!dir) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "handle_fetch_targets: failed to read targets dir (%s)!", TARGETS_DIR);
    return;
  }

  struct dirent* entry;
  while ((entry = readdir(dir)) != nullptr) {
    if (entry->d_name[0] == '.') {
      // Skip . and ..
      continue;
    }

    auto len = static_cast<uint32_t>(strlen(entry->d_name));
    write(sockfd, &len, sizeof(len));
    write(sockfd, entry->d_name, len);
  }
  closedir(dir);

  uint32_t done = 0;  // means we are finished
  write(sockfd, &done, sizeof(done));
}

/**
 * "Captures" the sockfd of its end in the socketpair
 * crated by in-app Bipan
 */
static inline int recv_fd(int socket) {
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));

  struct cmsghdr* cmsg;
  char buf[CMSG_SPACE(sizeof(int))];
  memset(buf, 0, sizeof(buf));

  char dummy[1];
  struct iovec io = {.iov_base = dummy, .iov_len = sizeof(dummy)};

  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);

  if (recvmsg(socket, &msg, 0) <= 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] recvmsg failed! errno: %s", strerror(errno));
    return -1;
  }

  cmsg = CMSG_FIRSTHDR(&msg);
  if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) {
    return -1;
  }

  // The kernel has now placed a new fd into our table: extract it
  return *((int*)CMSG_DATA(cmsg));
}
