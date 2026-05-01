#ifndef ATOMIC_CAT_H
#define ATOMIC_CAT_H

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <string.h>

void write_to_logcat_async(const char* tag, const char* msg);

#endif // ATOMIC_CAT_H
