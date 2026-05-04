#include <dirent.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string>

#include "logger.hpp"
#include "shared.hpp"
#include "synchronization.hpp"
#include "broker.hpp"
#include "zygisk.hpp"

#define TARGETS_DIR "/data/adb/modules/bipan/targets"

static void handle_fetch_targets(int fd) {
  DIR* dir = opendir(TARGETS_DIR);
  if (dir) {
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
      if (entry->d_name[0] == '.') {
        // Skip . and ..
        continue;
      }

      auto len = static_cast<uint32_t>(strlen(entry->d_name));
      write(fd, &len, sizeof(len));
      write(fd, entry->d_name, len);
    }
    closedir(dir);
  } else {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "handle_fetch_targets: failed to read targets dir (%s)!", TARGETS_DIR);
    return;
  }

  uint32_t done = 0;  // means we are finished
  write(fd, &done, sizeof(done));
}

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

  // 1. Read the command ID from the client
  if (read(sock, &cmd, sizeof(cmd)) <= 0) {
    return;
  }

  // 2. Route the request
  if (cmd == CMD_FETCH_TARGETS) {
    handle_fetch_targets(sock);
  } else if (cmd == CMD_START_BROKER) {
    // Receive the Memory FD from the Target App
    int memfd = recv_fd(sock);
    if (memfd < 0) return;

    // Map the memory for THIS specific app's thread
    SharedIPC* local_ipc_mem = (SharedIPC*)mmap(NULL, sizeof(SharedIPC), PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
    close(memfd);

    if (local_ipc_mem != MAP_FAILED) {
      write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Starting Broker via root companion...\n");
      startBroker(sock, local_ipc_mem);
    } else {
      write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to start Broker via root companion!\n");
    }
  }
}

REGISTER_ZYGISK_COMPANION(companion_handler)
