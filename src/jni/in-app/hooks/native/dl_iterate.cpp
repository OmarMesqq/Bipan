#include "dl_iterate.hpp"

#include <dlfcn.h>
#include <link.h>

#include <cstdint>

#include "../../../logger/logger.hpp"
#include "common_utils.hpp"
#include "deps/dobby.h"
#include "in-app/globals.hpp"

// Original functions
static int (*orig_dl_iterate_phdr)(int (*)(struct dl_phdr_info*, size_t, void*), void*) = nullptr;

// Helpers
static int filtered_iterate_callback(struct dl_phdr_info* info, size_t size, void* data);
// Hooks
static int my_dl_iterate_phdr(int (*cb)(struct dl_phdr_info*, size_t, void*), void* data);

// Symbol names
#define DL_ITERATE_SYM "__loader_dl_iterate_phdr"

void registerDobbyDlIteratePhdrHook(void) {
  void* addr = dlsym(RTLD_DEFAULT, DL_ITERATE_SYM);
  if (!addr) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to resolve: %s", DL_ITERATE_SYM);
    BIPAN_PANIC();
  }

  int hookRet = DobbyHook(addr, (void*)my_dl_iterate_phdr, (void**)&orig_dl_iterate_phdr);
  if (hookRet != 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to hook %s", DL_ITERATE_SYM);
    BIPAN_PANIC();
  }
  __builtin___clear_cache((char*)addr, (char*)addr + 32);
  write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Dobby hooked: %s", DL_ITERATE_SYM);
}

// Hooks below
struct FilteredCallback {
  int (*real_cb)(struct dl_phdr_info*, size_t, void*);
  void* real_data;
};

static int my_dl_iterate_phdr(int (*cb)(struct dl_phdr_info*, size_t, void*), void* data) {
  FilteredCallback ctx = {cb, data};
  return orig_dl_iterate_phdr(filtered_iterate_callback, &ctx);
}

// Helpers below
static int filtered_iterate_callback(struct dl_phdr_info* info, size_t size, void* data) {
  FilteredCallback* ctx = (FilteredCallback*)data;
  if (info->dlpi_addr == (ElfW(Addr))g_bipan_lib_start) return 0;
  return ctx->real_cb(info, size, ctx->real_data);
}