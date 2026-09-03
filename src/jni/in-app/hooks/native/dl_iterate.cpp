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

void registerDobbyDlIteratePhdrHook(void) {
  void* dl_iterate_phdr_addr = dlsym(RTLD_DEFAULT, "__loader_dl_iterate_phdr");
  if (!dl_iterate_phdr_addr) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to resolve dl_iterate_phdr!");
    BIPAN_PANIC();
  }
  int hookRet = DobbyHook(dl_iterate_phdr_addr, (void*)my_dl_iterate_phdr, (void**)&orig_dl_iterate_phdr);
  if (hookRet != 0) {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to hook dl_iterate_phdr!");
    BIPAN_PANIC();
  }
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