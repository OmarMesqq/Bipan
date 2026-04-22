#ifndef UNWINDER_HPP
#define UNWINDER_HPP

#include <dlfcn.h>
#include <unwind.h>

#include <string>

#include "shared.hpp"

static constexpr int MAX_UNWIND_DEPTH = 20;

// State container passed through the unwinder callbacks
struct UnwindState {
  int current_depth;
  bool is_trusted;
  uintptr_t frames[MAX_UNWIND_DEPTH];
  const char* libs[MAX_UNWIND_DEPTH];
};
static const char* find_culprit(const UnwindState& state, uintptr_t* out_offset, uintptr_t* out_pc);

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
        strncmp(lib_path, "/product/", 9) == 0 ||
        strncmp(lib_path, "/apex/", 6) == 0 ||
        strncmp(lib_path, "/system_ext/", 12) == 0) {
      state->current_depth++;  // we are at a "trusted" OS component frame, keep on unwinding
      return _URC_NO_REASON;
    }

    // Block if in user partition or is a non-system APK
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

inline bool is_trusted_system_caller(const char* target_pathname, uintptr_t* out_patch_pc = nullptr, bool log_on_fail = true) {
  UnwindState state;
  state.current_depth = 0;
  state.is_trusted = true;
  memset(state.frames, 0, sizeof(state.frames));
  memset(state.libs, 0, sizeof(state.libs));

  _Unwind_Backtrace(unwind_callback, &state);

  // TODO: dladdr is not async-signal safe
  if (!state.is_trusted) {
    uintptr_t offset = 0;
    uintptr_t pc = 0;
    const char* culprit = find_culprit(state, &offset, &pc);

    if (out_patch_pc) {
      *out_patch_pc = pc;
    }

    if (log_on_fail) {
      LOGE("--- Bipan Violation ---");
      LOGE("Action:  %s", target_pathname);
      LOGE("Culprit: %s", culprit);
      LOGE("PC:      %p", (void*)pc);  // Absolute address in memory
      LOGE("Offset:  0x%lx", offset);  // Relative address for addr2line/objdump
      LOGE("-----------------------");
    }
  }

  return state.is_trusted;
}

// Runs the `is_trusted_system_caller` unwinder with logging on
inline void log_violation_trace(const char* label) {
  is_trusted_system_caller(label, 0, true);
}

static const char* find_culprit(const UnwindState& state, uintptr_t* out_offset, uintptr_t* out_pc) {
  for (int i = 0; i < state.current_depth; i++) {
    Dl_info info;
    uintptr_t pc = state.frames[i];

    if (dladdr((void*)pc, &info) && info.dli_fname) {
      const char* fname = info.dli_fname;
      if (strstr(fname, "jit-cache") || strstr(fname, "[vdso]") ||
          strncmp(fname, "/system/", 8) == 0 ||
          strncmp(fname, "/vendor/", 8) == 0 ||
          strncmp(fname, "/product/", 9) == 0 ||
          strncmp(fname, "/apex/", 6) == 0 ||
          strncmp(fname, "/system_ext/", 12) == 0) {
        continue;  // not what we look for: keep digging down the stack, my friend...
      }

      if (out_pc) *out_pc = pc;
      if (out_offset) *out_offset = pc - (uintptr_t)info.dli_fbase;
      return info.dli_fname;
    }
  }
  return "Unknown Source";
}

#endif