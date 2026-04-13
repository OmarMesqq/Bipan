#ifndef UNWINDER_HPP
#define UNWINDER_HPP

#include <dlfcn.h>
#include <unwind.h>

#include <string>

#include "shared.hpp"

static constexpr int MAX_UNWIND_DEPTH = 10;

// State container passed through the unwinder callbacks
struct UnwindState {
  int current_depth;
  bool is_trusted;
  bool silent;  // log supression for WebView
  uintptr_t frames[MAX_UNWIND_DEPTH];
  const char* libs[MAX_UNWIND_DEPTH];
};

// Callback run for every frame in the stack
static _Unwind_Reason_Code unwind_callback(struct _Unwind_Context* context, void* arg) {
  UnwindState* state = static_cast<UnwindState*>(arg);

  if (state->current_depth >= MAX_UNWIND_DEPTH) {
    return _URC_END_OF_STACK;
  }

  uintptr_t pc = _Unwind_GetIP(context);
  if (pc == 0) {
    return _URC_NO_REASON;
  }

  // Record the frame
  state->frames[state->current_depth] = pc;

  Dl_info dlinfo;
  if (dladdr(reinterpret_cast<void*>(pc), &dlinfo) && dlinfo.dli_fname) {
    const char* lib_path = dlinfo.dli_fname;
    state->libs[state->current_depth] = lib_path;

    // Allow-list first system/hardware partitions
    if (strncmp(lib_path, "/system/", 8) == 0 ||
        strncmp(lib_path, "/vendor/", 8) == 0 ||
        strncmp(lib_path, "/apex/", 6) == 0 ||
        strncmp(lib_path, "/system_ext/", 12) == 0) {
      state->current_depth++;  // we are at a "trusted" OS component frame, keep on unwinding
      return _URC_NO_REASON;
    }

    // Block if in user partition or is a non-system APK
    if (strstr(lib_path, "/data/") != nullptr ||
        strstr(lib_path, ".apk") != nullptr) {
      state->is_trusted = false;

      if (strstr(lib_path, "webview") != nullptr) {
        state->silent = true;
      }

      state->current_depth++;
      return _URC_END_OF_STACK;
    }
  } else {
    // Anonymous memory trap
    state->libs[state->current_depth] = "[Anonymous / Unresolved Memory]";
    state->is_trusted = false;
    state->current_depth++;
    return _URC_END_OF_STACK;
  }

  state->current_depth++;
  return _URC_NO_REASON;
}

inline bool is_trusted_system_caller(const char* target_pathname, bool log_on_fail = true) {
  UnwindState state;
  state.current_depth = 0;
  state.is_trusted = true;
  state.silent = false;
  memset(state.frames, 0, sizeof(state.frames));
  memset(state.libs, 0, sizeof(state.libs));

  _Unwind_Backtrace(unwind_callback, &state);

  if (!state.is_trusted && !state.silent && log_on_fail) {
    LOGE("--- Caller-ID Violation ---");
    LOGE("%s", target_pathname);
    LOGE("Stacktrace:");
    for (int i = 0; i < state.current_depth; i++) {
      LOGE("  #%d pc %p  %s", i, (void*)state.frames[i], state.libs[i]);
    }
    LOGE("---------------------------");
  }

  return state.is_trusted;
}

// Runs the `is_trusted_system_caller` unwinder with logging on
inline void log_violation_trace(const char* label) {
  is_trusted_system_caller(label, true);
}

#endif