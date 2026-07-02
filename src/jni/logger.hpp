#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <fcntl.h>
#include "utils.hpp"
#include "shared.hpp"

bool initializeLogger();
int getLogcatFd();
void write_to_logcat_async(android_LogPriority prio, const char* tag, const char* fmt, ...);

#endif