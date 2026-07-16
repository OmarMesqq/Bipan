#include "mem.hpp"

#include <dlfcn.h>
#include <link.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <unistd.h>

#include "logger/logger.hpp"
#include "in-app/globals.hpp"

/**
 * `dl_iterate_phdr` callback:
 * Purpose: find Bipan's start and end addresses
 */
int find_lib_bounds(struct dl_phdr_info* info, size_t size, void* data) {
  auto* bounds = reinterpret_cast<LibBounds*>(data);

  // Match our library base address with the loaded segment address
  extern char __executable_start; // TODO: use global in-app elf start
  if (info->dlpi_addr == reinterpret_cast<uintptr_t>(&__executable_start)) {
    bounds->start = info->dlpi_addr;

    // Iterate through program headers to find the maximum memory span
    for (int i = 0; i < info->dlpi_phnum; i++) {
      uintptr_t seg_end = bounds->start + info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz;
      if (seg_end > bounds->end) {
        bounds->end = seg_end;
      }
    }
    return 1;  // Stop iteration
  }
  return 0;
}

/**
 * `dl_iterate_phdr` callback:
 * Purpose: find all shared objects before app starts
 */
int find_loaded_shared_libs(struct dl_phdr_info* info, size_t size, void* data) {
  char entry[512];  // for each shared lib

  snprintf(entry, sizeof(entry), "%s\n", info->dlpi_name);
  strcat((char*)data, entry);

  return 0;
}

/**
 * `dl_iterate_phdr` callback:
 * Finds info on shared objects worthy studying
 */
int dump_phdr_callback(struct dl_phdr_info* info, size_t size, void* data) {
  DumpContext* ctx = (DumpContext*)data;

  if (info->dlpi_name == nullptr || !strstr(info->dlpi_name, ctx->target_soname)) {
    return 0;
  }

  write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[dump] found: %s base=0x%lx", info->dlpi_name, (uintptr_t)info->dlpi_addr);

  for (int i = 0; i < info->dlpi_phnum; i++) {
    const ElfW(Phdr)* phdr = &info->dlpi_phdr[i];

    if (phdr->p_type != PT_LOAD) {
      // interested only in sections to be eagerly loaded by the linker
      continue;
    }
    write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[phdr] flags=0x%x vaddr=0x%lx memsz=%zu filesz=%zu", phdr->p_flags, phdr->p_vaddr, phdr->p_memsz, phdr->p_filesz);

    uintptr_t start = info->dlpi_addr + phdr->p_vaddr;
    size_t len = phdr->p_memsz;

    char dumppath[128];
    snprintf(dumppath, sizeof(dumppath), "/data/data/%s/dump_%lx.bin", g_package_name, start);

    int out_fd = open(dumppath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[dump] failed to open %s: %s", dumppath, strerror(errno));
      continue;
    }

    uint8_t buf[4096];
    size_t remaining = len;
    uintptr_t cur = start;
    while (remaining > 0) {
      size_t to_read = remaining < sizeof(buf) ? remaining : sizeof(buf);
      memcpy(buf, (void*)cur, to_read);
      write(out_fd, buf, to_read);
      cur += to_read;
      remaining -= to_read;
    }
    close(out_fd);
    write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[dump] wrote 0x%lx len=%zu -> %s", start, len, dumppath);
  }
  return 0;
}

/**
 * `dl_iterate_phdr` callback:
 * Purpose: dump information on the lib provided by the linker
 */
int dump_lib_info_with_dlitphdr(struct dl_phdr_info* info, size_t size, void* data) {
  const char* type;
  int p_type;

  if (strstr(info->dlpi_name, "memfd")) {
      write_to_logcat_async(ANDROID_LOG_INFO, "BipanMemDump", "%s has %d segments:", info->dlpi_name, info->dlpi_phnum);
    }

  for (size_t j = 0; j < info->dlpi_phnum; j++) {
    if (!strstr(info->dlpi_name, "memfd")) {
      continue;
    }
    
    p_type = info->dlpi_phdr[j].p_type;
    type = (p_type == PT_LOAD) ? "PT_LOAD" : (p_type == PT_DYNAMIC)    ? "PT_DYNAMIC"
                                         : (p_type == PT_INTERP)       ? "PT_INTERP"
                                         : (p_type == PT_NOTE)         ? "PT_NOTE"
                                         : (p_type == PT_INTERP)       ? "PT_INTERP"
                                         : (p_type == PT_PHDR)         ? "PT_PHDR"
                                         : (p_type == PT_TLS)          ? "PT_TLS"
                                         : (p_type == PT_GNU_EH_FRAME) ? "PT_GNU_EH_FRAME"
                                         : (p_type == PT_GNU_STACK)    ? "PT_GNU_STACK"
                                         : (p_type == PT_GNU_RELRO)    ? "PT_GNU_RELRO"
                                                                       : nullptr;

    write_to_logcat_async(ANDROID_LOG_INFO, "BipanMemDump", "    %2zu: [%14p; memsz:%7jx] flags: %#jx; ", j,
                          (void*)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr),
                          (uintmax_t)info->dlpi_phdr[j].p_memsz,
                          (uintmax_t)info->dlpi_phdr[j].p_flags);

    if (type != nullptr) {
      write_to_logcat_async(ANDROID_LOG_INFO, "BipanMemDump", "%s\n", type);
    } else {
      write_to_logcat_async(ANDROID_LOG_INFO, "BipanMemDump", "[other (%#x)]\n", p_type);
    }
  }
  return 0;
}

/**
 * Removes ELF headers from the lib:
 * 0x7f, 0x45, 0x4c, 0x46
 */
bool scrub_elf_header() {
  // system's page size
  size_t page_size = sysconf(_SC_PAGESIZE);
  // align our base address to beginning of a page
  // TODO: should be independent of in-app
  uintptr_t page_start = g_bipan_lib_start & ~(page_size - 1);

  if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Failed to change perms of lib's page-aligned addr! errno: %s", strerror(errno));
    return false;
  }

  unsigned char* dest = reinterpret_cast<unsigned char*>(g_bipan_lib_start);
  const size_t bytesToPatch = 4;

  unsigned char new_data[4];
  ssize_t result = getrandom(new_data, sizeof(new_data), 0);
  if (result == -1) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Failed to getrandom!");
    return false;
  }

  for (size_t i = 0; i < bytesToPatch; ++i) {
    dest[i] = new_data[i];
  }

  mprotect((void*)page_start, page_size, PROT_READ | PROT_EXEC);

  char* begin = reinterpret_cast<char*>(g_bipan_lib_start);
  char* end = begin + bytesToPatch;
  __builtin___clear_cache(begin, end);

  return true;
}

/**
 * Dumps `bytes` at `addr`
 */
void dump_mem(void* addr, int bytes) {
  unsigned char* p = reinterpret_cast<unsigned char*>(addr);
  while (bytes--) {
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Dump: %02x (hex) | %c (char)", *p, *p);
    p++;
  }
}

void dump_lib_info_with_auxv() {
  const unsigned long types[] = {
      AT_PHDR, AT_PHNUM, AT_PAGESZ, AT_BASE, AT_ENTRY, AT_EXECFN, AT_PHENT, AT_SYSINFO_EHDR

  };

  for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
    unsigned long type = types[i];
    unsigned long val = getauxval(type);

    switch (type) {
      case AT_PHDR: {
        write_to_logcat_async(ANDROID_LOG_INFO, "BipanMemDump", "AT_PHDR: %#lx", val);
        break;
      }
      case AT_PHNUM: {
        write_to_logcat_async(ANDROID_LOG_INFO, "BipanMemDump", "AT_PHNUM: %lu", val);
        break;
      }
      case AT_PAGESZ: {
        write_to_logcat_async(ANDROID_LOG_INFO, "BipanMemDump", "AT_PAGESZ: %lu", val);
        break;
      }
      case AT_BASE: {
        write_to_logcat_async(ANDROID_LOG_INFO, "BipanMemDump", "AT_BASE: %#lx", val);
        break;
      }
      case AT_ENTRY: {
        write_to_logcat_async(ANDROID_LOG_INFO, "BipanMemDump", "AT_ENTRY: %#lx", val);
        break;
      }
      case AT_SYSINFO_EHDR: {
        write_to_logcat_async(ANDROID_LOG_INFO, "BipanMemDump", "AT_SYSINFO_EHDR: %#lx", val);
        break;
      }
      case AT_EXECFN: {
        write_to_logcat_async(ANDROID_LOG_INFO, "BipanMemDump", "AT_EXECFN: %s", (const char*)val);
        break;
      }
      case AT_PHENT: {
        write_to_logcat_async(ANDROID_LOG_INFO, "BipanMemDump", "AT_PHENT: %lu", val);
        break;
      }
    }
  }
}