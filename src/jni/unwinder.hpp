#ifndef UNWINDER_HPP
#define UNWINDER_HPP

#include <dlfcn.h>
#include <unwind.h>

#include <string>

#include "shared.hpp"

static constexpr int MAX_UNWIND_DEPTH = 10;

// State container passed through the unwinder callbacks
static struct UnwindState {
  int current_depth;
  bool is_trusted;
  uintptr_t frames[MAX_UNWIND_DEPTH];
  const char* libs[MAX_UNWIND_DEPTH];
};

// The callback executed for every frame in the stack
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

    // Is this the App's memory space?
    if (strstr(lib_path, "/data/") != nullptr ||
        strstr(lib_path, ".apk") != nullptr) {
      state->is_trusted = false;
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

inline bool is_trusted_system_caller(const char* target_pathname) {
  UnwindState state = {0, true, {}, {}};

  _Unwind_Backtrace(unwind_callback, &state);

  if (!state.is_trusted) {
    LOGE("--- Caller-ID Violation Detected ---");
    LOGE("Target accessed: %s", target_pathname);
    LOGE("Stacktrace:");
    for (int i = 0; i < state.current_depth; i++) {
      LOGE("  #%d pc %p  %s", i, (void*)state.frames[i], state.libs[i]);
    }
    LOGE("------------------------------------");
  }

  return state.is_trusted;
}

#endif