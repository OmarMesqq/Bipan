#include <arpa/inet.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>
#include <unordered_set>

#include "broker.hpp"
#include "deps/zygisk.hpp"
#include "ipc_communication.hpp"
#include "logger/logger.hpp"

#define TAG "BipanRootCompanion"
#define TARGETS_DIR "/data/adb/modules/bipan/targets"

static void handle_fetch_targets(int sockfd);
static inline int recv_fd(int socket);
static void close_unrelated_fds(const std::unordered_set<int>& keep);

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
  if (!initializeLogger()) {
    close(sock);
    return;
  }
  CompanionCommand cmd;

  // Get the command ID from the client
  if (read(sock, &cmd, sizeof(cmd)) <= 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] companion_handler: failed to read CMD from target!");
    destroyLogger();
    close(sock);
    return;
  }

  if (cmd == CMD_FETCH_TARGETS) {
    handle_fetch_targets(sock);
    destroyLogger();
    close(sock);
    return;
  }

  if (cmd != CMD_START_BROKER) {
    destroyLogger();
    close(sock);
    return;
  }

  /**
   * If we are asked to start a Broker, spin up a new process
   * so we don't block Zygisk's threads on the potentially long-lived Broker
   */
  pid_t mid_pid = fork();
  if (mid_pid < 0) {
    initializeLogger();
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] companion_handler: 1st fork() (intermediate/zygiskd's child) failed: %s", strerror(errno));
    destroyLogger();
    close(sock);
    return;
  }

  if (mid_pid == 0) {
    // Intermediate child (`zygiskd`'s child)

    // Double-fork idiom: fork again, then exit immediately so the
    // grandchild gets reparented to init(1), which auto-reaps it on exit.
    pid_t grandchild_pid = fork();
    if (grandchild_pid < 0) {
      initializeLogger();
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] companion_handler: 2nd fork() (reparented grandchild) failed: %s", strerror(errno));
      destroyLogger();
      close(sock);
      _exit(1);
    }

    if (grandchild_pid > 0) {
      // exit cleanly so actual `zygiskd` unblocks the `waitpid` outside this scope; below
      destroyLogger();
      close(sock);
      _exit(0);
    }

    // Grandchild: the actual Broker process
    initializeLogger();

    pid_t sessionId = setsid();
    if (sessionId == -1) {
      initializeLogger();
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] companion_handler: setsid failed %s", strerror(errno));
      destroyLogger();
      close(sock);
      _exit(1);
    }
    initializeLogger();

    int memfd = recv_fd(sock);
    if (memfd < 0) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] companion_handler: failed to receive memfd from target!");
      destroyLogger();
      close(sock);
      return;
    }

    close_unrelated_fds({sock, memfd, getLogcatFd(), STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO});
    initializeLogger();

    SharedIPC* local_ipc_mem = (SharedIPC*)mmap(NULL, sizeof(SharedIPC), PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
    close(memfd);
    if (local_ipc_mem == MAP_FAILED) {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] companion_handler: grandchild mmap failed!");
      destroyLogger();
      close(sock);
      _exit(1);
    }

    __sync_synchronize();
    startBroker(sock, local_ipc_mem);

    destroyLogger();
    close(sock);
    _exit(0);  // prevent fallthrough
  }

  // `zygiskd` resumes here
  initializeLogger();
  int status;
  // Block Zygisk's thread for a while till first child exits after 2nd fork
  waitpid(mid_pid, &status, 0);

  // Session now belongs entirely to the grandchild; this thread is done with it.
  destroyLogger();
  close(sock);
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

static void close_unrelated_fds(const std::unordered_set<int>& keep) {
  DIR* d = opendir("/proc/self/fd");
  if (!d) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "close_unrelated_fds: failed to open /proc/self/fd!");
    return;
  }
  struct dirent* entry;
  while ((entry = readdir(d)) != nullptr) {
    if (entry->d_name[0] == '.') {
      continue;
    }
    int fd = atoi(entry->d_name);
    if (fd >= 0 && !keep.count(fd) && fd != dirfd(d)) {
      close(fd);
    }
  }
  closedir(d);
}
