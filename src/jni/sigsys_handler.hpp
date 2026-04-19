#ifndef SIGSYS_HANDLER_HPP
#define SIGSYS_HANDLER_HPP

void registerSigSysHandler();
void register_spoofed_fd(int fd, const char* original_path);

#endif
