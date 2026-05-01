#ifndef ATOMIC_CAT_H
#define ATOMIC_CAT_H

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <string.h>
#include <time.h>
#include <android/log.h>

void write_to_logcat_async(android_LogPriority prio, const char* tag, const char* msg);

#endif // ATOMIC_CAT_H
