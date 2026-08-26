#ifndef BROKER_ASSIST_HPP
#define BROKER_ASSIST_HPP

#include <sys/types.h>

extern thread_local pid_t g_current_client_pid;

bool registerAssistSigHandlers();

#endif