#ifndef ATOMIC_CAT_H
#define ATOMIC_CAT_H

#include <android/log.h>

void write_to_logcat_async(android_LogPriority prio, const char* tag, const char* msg);

#endif // ATOMIC_CAT_H
