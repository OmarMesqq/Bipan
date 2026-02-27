#include "broker.hpp"

#include <fcntl.h>
#include <linux/memfd.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <fstream>
#include <string>

#include "shared.hpp"
#include "spoofer.hpp"
#include "synchronization.hpp"
#include "assembly.hpp"

void startBroker(int sock) {
  prctl(PR_SET_NAME, "BipanBroker", 0, 0, 0);

  while (true) {
    while (ipc_mem->status != REQUEST_SYSCALL) {
      futex_wait(&ipc_mem->status, ipc_mem->status);
    }
    __sync_synchronize();

    long ret = arm64_raw_syscall(
        ipc_mem->nr,
        ipc_mem->arg0,
        (long)ipc_mem->path,
        ipc_mem->arg2,
        ipc_mem->arg3,
        ipc_mem->arg4,
        ipc_mem->arg5);

    ipc_mem->ret = ret;
    if (ret >= 0) {
      send_fd(sock, (int)ret);  // Teleport it
      close((int)ret);          // Close broker's local copy to prevent -24
      ipc_mem->ret = 0;         // Signal success to target
    } else {
      ipc_mem->ret = ret;  // Signal error to target
    }

    __sync_synchronize();
    ipc_mem->status = BROKER_ANSWERED;
    futex_wake(&ipc_mem->status);
  }
}

#pragma clang diagnostic pop
