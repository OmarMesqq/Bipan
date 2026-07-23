#include "mem.hpp"

#include <dlfcn.h>
#include <link.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <unistd.h>

#include "in-app/globals.hpp"
#include "logger/logger.hpp"

/**
 * `dl_iterate_phdr` callback:
 * Purpose: dump information on the lib provided by the linker
 */
int dumpBipanLinkerInfo(struct dl_phdr_info* info, size_t size, void* data) {
  // Mark unused
  (void)size; (void)data;

  const char* type;
  int p_type;

  if (strstr(info->dlpi_name, "memfd")) {
    write_to_logcat_async(ANDROID_LOG_DEBUG, "BipanMemDump", "%s has %d segments:", info->dlpi_name, info->dlpi_phnum);
  }

  for (size_t j = 0; j < info->dlpi_phnum; j++) {
    if (!strstr(info->dlpi_name, "memfd")) {
      continue;
    }

    // PT_* enum vals are small, should fit in `int`
    p_type = (int)info->dlpi_phdr[j].p_type;
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

    write_to_logcat_async(ANDROID_LOG_DEBUG, "BipanMemDump", "    %2zu: [%14p; memsz:%7jx] flags: %#jx; ", j,
                          (void*)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr),
                          (uintmax_t)info->dlpi_phdr[j].p_memsz,
                          (uintmax_t)info->dlpi_phdr[j].p_flags);

    if (type != nullptr) {
      write_to_logcat_async(ANDROID_LOG_DEBUG, "BipanMemDump", "%s\n", type);
    } else {
      write_to_logcat_async(ANDROID_LOG_DEBUG, "BipanMemDump", "[other (%#x)]\n", p_type);
    }
  }
  return 0;
}

/**
 * Dumps `bytes` at `addr`
 */
void dumpBytes(void* addr, int bytes) {
  unsigned char* p = reinterpret_cast<unsigned char*>(addr);
  while (bytes--) {
    write_to_logcat_async(ANDROID_LOG_DEBUG, "BipanMemDump", "%02x (hex) | %c (char)", *p, *p);
    p++;
  }
}

/**
 * Dumps info on the PROCESS using kernel-provided auxiliary vector
 */
void readAuxVector() {
  const unsigned long types[] = {
      AT_PHDR, AT_PHNUM, AT_PHENT,
      AT_BASE, AT_ENTRY, AT_SYSINFO_EHDR};

  for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
    unsigned long type = types[i];
    unsigned long val = getauxval(type);

    switch (type) {
      case AT_PHDR: {
        write_to_logcat_async(ANDROID_LOG_DEBUG, "BipanMemDump", "AT_PHDR (address of the program headers of the executable): %#lx", val);
        break;
      }
      case AT_PHNUM: {
        write_to_logcat_async(ANDROID_LOG_DEBUG, "BipanMemDump", "AT_PHNUM (number of program headers): %lu", val);
        break;
      }
      case AT_PHENT: {
        write_to_logcat_async(ANDROID_LOG_DEBUG, "BipanMemDump", "AT_PHENT (size of program header entry): %lu", val);
        break;
      }
      case AT_BASE: {
        write_to_logcat_async(ANDROID_LOG_DEBUG, "BipanMemDump", "AT_BASE (base addr of linker): %#lx", val);
        break;
      }
      case AT_ENTRY: {
        write_to_logcat_async(ANDROID_LOG_DEBUG, "BipanMemDump", "AT_ENTRY (entry address of the executable): %#lx", val);
        break;
      }
      case AT_SYSINFO_EHDR: {
        write_to_logcat_async(ANDROID_LOG_DEBUG, "BipanMemDump", "AT_SYSINFO_EHDR (address of page with the vDSO): %#lx", val);
        break;
      }
    }
  }
}
