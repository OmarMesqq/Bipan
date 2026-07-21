#include "unwinder.hpp"

#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <common_utils.hpp>
#include <cstdio>
#include <cstring>
#include <ipc_communication.hpp>

#include "logger/logger.hpp"

#define TAG "BipanUnwinder"

static void find_label_in_elf(const char* path, uintptr_t offset, char* out_name, size_t max_len);
static bool manual_dladdr(uintptr_t addr, ManualDlInfo* info, pid_t pid);
static inline bool is_trusted_lib(const char* lib_path);

bool unwinder(uintptr_t fp, uintptr_t lr, pid_t pid, int nr) {
  // Immediate caller is in LR (x30)
  lr &= 0x0000FFFFFFFFFFFFULL;  // Strip arm64 PAC auth bits

  char mem_path[64];
  snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
  // TODO: cache?
  int mem_fd = open(mem_path, O_RDONLY);
  if (mem_fd < 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "unwinder: Failed to open %s", mem_path);
    return false;  // fail closed, assuming untrusted
  }

  ManualDlInfo info;
  char sym_name[PATH_MAX] = "???";

  if (manual_dladdr(lr, &info, pid)) {
    find_label_in_elf(info.dli_fname, info.dli_offset, sym_name, sizeof(sym_name));

    if (!is_trusted_lib(info.dli_fname)) {
      write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Very first LR (%p) is a malicious lib: %s triggering nr %d. Unwinding over :)", (void*)lr, info.dli_fname, nr);
      close(mem_fd);
      return false;
    }

    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[Unwind start (nr: %d)] -> LR: %p | Sym: %s | Lib: %s | Offset: (+0x%lx)", nr, (void*)lr, sym_name, info.dli_fname, info.dli_offset);
  } else {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to resolve very first LR (%p)!", (void*)lr);
    close(mem_fd);
    return false;
  }

  // Walk the Frame Pointer chain (x29)
  for (unsigned int i = 0; i < MAX_STACK_TRACE; ++i) {
    if (!fp || (fp & 0x7)) {
      /**
       * Trying to take one more step, but
       * the value we'd use as the next FP isn't a valid pointer.
       * Typical in leaf functions.
       */
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[Unwind ending by exhaustion (%d passes)] -> Current FP isn't a valid pointer (null/misaligned)", i);
      close(mem_fd);
      return true;
    }

    /**
     * Read [x29] and [x29+8] from the target
     * On arm64, the return address is 8 bytes above the Frame Pointer
     */
    uintptr_t next_fp = 0, return_addr = 0;
    if (
        pread(mem_fd, &next_fp, sizeof(next_fp), fp) != sizeof(next_fp) ||
        pread(mem_fd, &return_addr, sizeof(return_addr), fp + 8) != sizeof(return_addr)) {
      /**
       * Address we're about to dereference isn't
       * backed by a readable page in the target's address space.
       * Could be garbage or we're at the edge of the stack region.
       */
      write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "[Unwind ending by exhaustion (%d passes)] -> Failed to pread current FP %p and next in chain (%p)", i, (void*)fp, (void*)(fp + 8));
      close(mem_fd);
      return true;
    }

    if (!return_addr) {
      /**
       * All 8 bytes at fp+8 are zero (nullptr).
       * We can have walked past the bottom of the frame chain
       */
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[Unwind ending by exhaustion (%d passes)] -> next return addr in frame chain is null", i);
      close(mem_fd);
      return true;
    }

    // Strip ARM64 PAC (Pointer Authentication) bits
    return_addr &= 0x0000FFFFFFFFFFFFULL;

    ManualDlInfo info;
    char sym_name[PATH_MAX] = "???";

    if (manual_dladdr(return_addr, &info, pid)) {
      find_label_in_elf(info.dli_fname, info.dli_offset, sym_name, sizeof(sym_name));
#ifdef BROKER_DEBUG_LOGGING
      write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "\tAncestor's addr: %p | Sym: %s | Lib: %s | Offset: (+0x%lx)\n", (void*)return_addr, sym_name, info.dli_fname, info.dli_offset);
#endif

      if (!is_trusted_lib(info.dli_fname)) {
        write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[Unwind good ending (%d passes)] -> Found malicious lib: %s at %p", i, info.dli_fname, (void*)return_addr);
        close(mem_fd);
        return false;
      }
    } else {
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "\tFailed to resolve ancestor addr: %p. Continuing...", (void*)return_addr);
    }

    if (next_fp <= fp) {
      /**
       * Sanity check for stack direction:
       * In this case, the Frame Pointer isn't increasing.
       * As the stack grows downward on arm64,
       * a legitimate frame chain should show monotonically
       * increasing addresses we walk towards the ultimate caller.
       * TLDR: each caller's frame sits at a higher address than the callee's.
       */
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[Unwind ending by exhaustion (%d passes)] -> FP not increasing", i);
      close(mem_fd);
      return true;
    }

    fp = next_fp;
  }

  close(mem_fd);
  write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[Unwind rare exhaustion ending] -> Walked %d frames and found only safe libs. Allowing syscall!", MAX_STACK_TRACE);
  return true;
}

/**
 * Parses the physical (in-disk ?) ELF file to find a name for a relative offset.
 * This sees STATIC labels that `dladdr` cannot. (really?)
 */
static void find_label_in_elf(const char* path, uintptr_t offset, char* out_name, size_t max_len) {
  if (!path) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "\tfind_label_in_elf: Passed empty `path`. Returning...");
    return;
  }

  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "\tfind_label_in_elf: Failed to open %s", path);
    return;
  }

  struct stat st;
  if (fstat(fd, &st) < 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "\tfind_label_in_elf: Failed to fstat fd %d associated with %s", fd, path);
    close(fd);
    return;
  }

  if (st.st_size < (off_t)sizeof(ElfHeader)) {
    write_to_logcat_async(ANDROID_LOG_WARN, TAG, "\tfind_label_in_elf: %s st_size's too small to be an ELF. Not searching symbols.", path);
    close(fd);
    strncpy(out_name, "[Too Small]", max_len - 1);
    return;
  }

  // TODO: can we cache this too?
  void* map = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);

  if (map == MAP_FAILED) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "\tfind_label_in_elf: mmap failed!");
    return;
  }

  ElfHeader* ehdr = (ElfHeader*)map;

  // TODO: If this is an APK (ZIP), it will fail this check and safely return
  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
    write_to_logcat_async(ANDROID_LOG_WARN, TAG, "\t%s header doesn't match ELF magic. Not searching symbols.", path);
    strncpy(out_name, "[APK/ZIP File]", max_len - 1);
    munmap(map, st.st_size);
    return;
  }

  ElfSection* shdr = (ElfSection*)((uintptr_t)map + ehdr->e_shoff);

  uintptr_t best_diff = (uintptr_t)-1;
  char* found_name = nullptr;

  // Search both SYMTAB (Static) and DYNSYM (Dynamic)
  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_DYNSYM) {
      ElfSymbol* syms = (ElfSymbol*)((uintptr_t)map + shdr[i].sh_offset);
      size_t count = shdr[i].sh_size / sizeof(ElfSymbol);

      // sh_link automatically points to the correct string table for this symbol table
      char* strings = (char*)((uintptr_t)map + shdr[shdr[i].sh_link].sh_offset);

      for (size_t j = 0; j < count; j++) {
        char* current_name = &strings[syms[j].st_name];

        // Skip empty names, mapping symbols ($x, $d),
        // and symbols that start after our offset.
        if (syms[j].st_name == 0 || syms[j].st_value > offset) {
          continue;
        }

        uintptr_t diff = offset - syms[j].st_value;
        if (diff < best_diff) {
          best_diff = diff;
          found_name = current_name;
        }
      }

      // If we found a perfect match (diff 0) in SYMTAB, we can stop early
      if (best_diff == 0 && shdr[i].sh_type == SHT_SYMTAB) {
        break;
      }
    }
  }

  if (found_name && strlen(found_name) > 0) {
    strncpy(out_name, found_name, max_len - 1);
  } else {
    strncpy(out_name, "???", max_len);
  }

  munmap(map, st.st_size);
}

/**
 * `dladdr` mimicking:
 * - opens /proc/<PID>/maps
 * - finds which region contains `addr`
 * - calculates the in-file offset of it
 */
static bool manual_dladdr(uintptr_t addr, ManualDlInfo* info, pid_t pid) {
  char proc_pid_maps_path[PATH_MAX] = {0};
  snprintf(proc_pid_maps_path, PATH_MAX, "/proc/%d/maps", pid);

  // TODO: cache this fd?
  FILE* f = fopen(proc_pid_maps_path, "r");
  if (!f) {
    write_to_logcat_async(ANDROID_LOG_WARN, TAG, "\tmanual_dladdr: Failed to open remote's %s", proc_pid_maps_path);
    return false;
  }

  char line[PATH_MAX] = {0};
  int found = false;

  while (fgets(line, sizeof(line), f)) {
    uintptr_t start, end, file_offset;
    char perms[5] = {0};
    // Standard `maps` format: start-end perms offset dev inode path
    if (sscanf(line, "%lx-%lx %4s %lx", &start, &end, perms, &file_offset) < 4) {
#ifdef BROKER_DEBUG_LOGGING
      write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "\t[*] manual_dladdr: Skipping malformed maps line: %s", line);
#endif
      continue;
    }

    if (addr >= start && addr < end) {
      info->dli_fbase = start;

      // Calculate offset: (Actual Addr - Map Start) + File Offset
      info->dli_offset = (addr - start) + file_offset;

      // Extract the path
      // Look for the first '/' or '[' (for [stack], [vdso], etc)
      char* path_start = strchr(line, '/');
      if (!path_start) {
        path_start = strchr(line, '[');
      }

      if (path_start) {
        char* newline = strchr(path_start, '\n');
        if (newline) {
          *newline = '\0';
        }
        strncpy(info->dli_fname, path_start, sizeof(info->dli_fname) - 1);
      } else {
        strcpy(info->dli_fname, "[anonymous memory]");
      }

      found = true;
      break;
    }
  }

  fclose(f);
  return found;
}

static inline bool is_trusted_lib(const char* lib_path) {
  return (
      starts_with(lib_path, "/apex") ||
      starts_with(lib_path, "/vendor") ||
      starts_with(lib_path, "/system") ||
      starts_with(lib_path, "/product") ||
      starts_with(lib_path, "/system_ext"));
}
