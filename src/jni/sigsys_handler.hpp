#ifndef SIGSYS_HANDLER_HPP
#define SIGSYS_HANDLER_HPP

void registerSignalHandler();
void storeSpoofedFD(int fd, const char* original_path);

#endif
