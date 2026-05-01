#ifndef LOGGER_HPP
#define LOGGER_HPP

/**
 * https://cs.android.com/android/platform/superproject/+/android-latest-release:bionic/libc/async_safe/async_safe_log.cpp;drc=b4e3e2b6b71d284a1731c3729576d793861089a8;l=533
 */

int async_safe_write_log(int priority, const char* tag, const char* msg) {
  int main_log_fd = open_log_socket();
  if (main_log_fd == -1) {
    // Try stderr instead.
    return write_stderr(tag, msg);
  }

  iovec vec[6];
  char log_id = (priority == ANDROID_LOG_FATAL) ? LOG_ID_CRASH : LOG_ID_MAIN;
  vec[0].iov_base = &log_id;
  vec[0].iov_len = sizeof(log_id);
  uint16_t tid = gettid();
  vec[1].iov_base = &tid;
  vec[1].iov_len = sizeof(tid);
  timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  log_time realtime_ts;
  realtime_ts.tv_sec = ts.tv_sec;
  realtime_ts.tv_nsec = ts.tv_nsec;
  vec[2].iov_base = &realtime_ts;
  vec[2].iov_len = sizeof(realtime_ts);

  vec[3].iov_base = &priority;
  vec[3].iov_len = 1;
  vec[4].iov_base = const_cast<char*>(tag);
  vec[4].iov_len = strlen(tag) + 1;
  vec[5].iov_base = const_cast<char*>(msg);
  vec[5].iov_len = strlen(msg) + 1;

  int result = TEMP_FAILURE_RETRY(writev(main_log_fd, vec, sizeof(vec) / sizeof(vec[0])));
  __close(main_log_fd);
  return result;
}

int async_safe_format_log_va_list(int priority, const char* tag, const char* format, va_list args) {
  ErrnoRestorer errno_restorer;
  char buffer[1024];
  BufferOutputStream os(buffer, sizeof(buffer));
  out_vformat(os, format, args);
  return async_safe_write_log(priority, tag, buffer);
}

int async_safe_format_log(int priority, const char* tag, const char* format, ...) {
  va_list args;
  va_start(args, format);
  int result = async_safe_format_log_va_list(priority, tag, format, args);
  va_end(args);
  return result;
}

#endif