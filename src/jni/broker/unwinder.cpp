#include "unwinder.hpp"

#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <vector>

#include "common_utils.hpp"
#include "ipc_communication.hpp"
#include "logger/logger.hpp"

#define TAG "BipanUnwinder"
#define UNRESOLVED_SYMBOL_NAME "???"
#define UNKNOWN_LIB_FRAME_NAME "[Untrusted: anon/unknown memory]"

static std::vector<MapEntry> current_maps;

enum LIB_IN_MAPS_RET {
  FOUND,
  FAILED,
  NOT_FOUND
};

static void find_label_in_elf(const char* path, uintptr_t offset, char* out_name, size_t max_len);
static LIB_IN_MAPS_RET find_lib_name_in_maps(uintptr_t pc, ManualDlInfo* info, pid_t pid);
static inline bool is_trusted_lib(const char* lib_path);
static inline bool should_passthrough(const char* libPath);

UNWIND_DECISION unwinder(uintptr_t pc, uintptr_t fp, uintptr_t lr, pid_t pid) {
  char mem_path[64] = {0};
  snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

  int mem_fd = open(mem_path, O_RDONLY);
  if (mem_fd < 0) {
#ifdef BROKER_UNWINDER_LOGGING
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Failed to open %s", mem_path);
#endif
    return UNSAFE;  // fail closed, assuming untrusted
  }

  ManualDlInfo info;
  memset(&info, 0, sizeof(ManualDlInfo));
  char sym_name[PATH_MAX] = UNRESOLVED_SYMBOL_NAME;

  // Strip arm64 PAC auth bits
  pc &= 0x0000FFFFFFFFFFFFULL; 
  lr &= 0x0000FFFFFFFFFFFFULL;  

  // Try the actual PC first (like for inline asm)
  LIB_IN_MAPS_RET ret = find_lib_name_in_maps(pc, &info, pid);

  if (ret == FAILED || ret == NOT_FOUND) {
#ifdef BROKER_UNWINDER_LOGGING
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Couldn't establish trust for trapped PC. Treating as unsafe.", (void*)pc);
#endif
    close(mem_fd);
    return UNSAFE;
  }

  find_label_in_elf(info.dli_fname, info.dli_offset, sym_name, sizeof(sym_name));
  if (should_passthrough(info.dli_fname)) {
    close(mem_fd);
#ifdef BROKER_UNWINDER_LOGGING
    write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "PC is allowlisted -> Lib: %s | Sym: %s | Offset: (+0x%lx)\n", info.dli_fname, sym_name, info.dli_offset);
#endif
    return SAFE;
  }

  if (!is_trusted_lib(info.dli_fname)) {
#ifdef BROKER_UNWINDER_LOGGING
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Trapped PC (%p) is a malicious lib(%s)", (void*)pc, info.dli_fname);
#endif
    close(mem_fd);
    return UNSAFE;
  }

  // Here, pc is FOUND, so inclusive. Check its ancestors
  ret = find_lib_name_in_maps(lr, &info, pid);
  if (ret == FAILED || ret == NOT_FOUND) {
#ifdef BROKER_UNWINDER_LOGGING
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "[!] Failed to resolve very first LR (%p). Treating as unsafe", (void*)lr);
#endif
    close(mem_fd);
    return UNSAFE;
  }

  find_label_in_elf(info.dli_fname, info.dli_offset, sym_name, sizeof(sym_name));

  if (should_passthrough(info.dli_fname)) {
    close(mem_fd);
#ifdef BROKER_UNWINDER_LOGGING
    write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "LR is allowlisted -> Lib: %s | Sym: %s | Offset: (+0x%lx)\n", info.dli_fname, sym_name, info.dli_offset);
#endif
    return SAFE;
  }

  if (!is_trusted_lib(info.dli_fname)) {
#ifdef BROKER_UNWINDER_LOGGING
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Very first LR (%p) is a malicious lib(%s)", (void*)lr, info.dli_fname);
#endif
    close(mem_fd);
    return UNSAFE;
  }

#ifdef BROKER_UNWINDER_LOGGING
  write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[Unwind start] -> LR: %p | Sym: %s | Lib: %s | Offset: (+0x%lx)", (void*)lr, sym_name, info.dli_fname, info.dli_offset);
#endif
  /**
   * Actual unwinding logic:
   * we walk the frame records [fp/x29, x30/lr]:
   *
   * ```
   * stp x29, x30, [sp, #-16]!   ; push {old FP, LR} as a pair
   * mov x29, sp                 ; new FP points at this pair
   * ```
   */
  // Immediate caller is in LR (x30)

  for (unsigned int i = 0; i < MAX_STACK_TRACE; ++i) {
    if (!fp || (fp & 0x7)) {
/**
 * Trying to take one more step, but
 * the value we'd use as the next FP isn't a valid pointer.
 * Typical in leaf functions.
 */
#ifdef BROKER_UNWINDER_LOGGING
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[Unwind ending by exhaustion (%d passes)] -> Current FP isn't a valid pointer (null/misaligned)", i);
#endif
      close(mem_fd);
      return UNSAFE;
    }

    /**
     * Read [x29] and [x29+8] from the target
     *
     * On arm64, the return address is 8 bytes above the Frame Pointer
     *
     * On arm64, the return address is at lr (x30)
     */
    uintptr_t next_fp = 0;
    /**
     * Return address (lr) from current frame i.e.
     * the caller's PC
     */
    uintptr_t return_addr = 0;

    if (
        // Interpret uintptr_t (unsigned) as off_t (signed)
        // Both are 64-bit and fit in the data type, but I
        // shall cast only to reduce warnings
        pread(mem_fd, &next_fp, sizeof(next_fp), (off_t)fp) != sizeof(next_fp) ||
        pread(mem_fd, &return_addr, sizeof(return_addr), (off_t)(fp + 8)) != sizeof(return_addr)) {
/**
 * Address we're about to dereference isn't
 * backed by a readable page in the target's address space.
 * Could be garbage or we're at the edge of the stack region.
 */
#ifdef BROKER_UNWINDER_LOGGING
      write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "[Unwind ending by exhaustion (%d passes)] -> Failed to pread current FP and/or its ret addr (FP+8)(%p)", i);
#endif
      close(mem_fd);
      return UNSAFE;
    }

    if (!return_addr) {
/**
 * All 8 bytes at fp+8 are zero (nullptr).
 * We can have walked past the bottom of the frame chain
 */
#ifdef BROKER_UNWINDER_LOGGING
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[Unwind ending by exhaustion (%d passes)] -> next return addr in frame chain is null", i);
#endif
      close(mem_fd);
      return UNSAFE;
    }

    // Strip ARM64 PAC (Pointer Authentication) bits
    return_addr &= 0x0000FFFFFFFFFFFFULL;

    ret = find_lib_name_in_maps(return_addr, &info, pid);
    if (ret == FAILED || ret == NOT_FOUND) {
#ifdef BROKER_UNWINDER_LOGGING
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "\tFailed to find ancestor's PC (%p) in maps. Continuing...", (void*)return_addr);
#endif
      close(mem_fd);
      return UNSAFE;
    }

    find_label_in_elf(info.dli_fname, info.dli_offset, sym_name, sizeof(sym_name));

    if (should_passthrough(info.dli_fname)) {
      close(mem_fd);
#ifdef BROKER_UNWINDER_LOGGING
      write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "[Unwind absolute allowlist ending (%d passes)] -> Lib: %s | Sym: %s | Offset: (+0x%lx)\n", i, info.dli_fname, sym_name, info.dli_offset);
#endif
      return SAFE;
    }

    if (!is_trusted_lib(info.dli_fname)) {
#ifdef BROKER_UNWINDER_LOGGING
      write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "[Unwind good ending (%d passes)] -> Found malicious lib: %s | Sym: %s | Offset: (+0x%lx)\n", i, info.dli_fname, sym_name, info.dli_offset);
#endif
      close(mem_fd);
      return UNSAFE;
    }

#ifdef BROKER_UNWINDER_LOGGING
    write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "\tAncestor's PC: %p | Sym: %s | Lib: %s | Offset: (+0x%lx)\n", (void*)return_addr, sym_name, info.dli_fname, info.dli_offset);
#endif

    if (next_fp <= fp) {
/**
 * Sanity check for stack direction:
 * In this case, the Frame Pointer isn't increasing.
 * As the stack grows downward on arm64,
 * a legitimate frame chain should show monotonically
 * increasing addresses we walk towards the ultimate caller.
 * TLDR: each caller's frame sits at a higher address than the callee's.
 */
#ifdef BROKER_UNWINDER_LOGGING
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[Unwind ending by exhaustion (%d passes)] -> FP not increasing", i);
#endif
      close(mem_fd);
      return UNSAFE;
    }

    // Walk the linked list to next frame record
    fp = next_fp;
  }

  close(mem_fd);
#ifdef BROKER_UNWINDER_LOGGING
  write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[Unwind rare exhaustion ending] -> Walked %d frames and found only safe libs. Allowing syscall!", MAX_STACK_TRACE);
#endif
  return SAFE;
}

void prefetchMaps(pid_t pid) {
  if (!current_maps.empty()) {
    return;
  }

  char proc_pid_maps_path[PATH_MAX] = {0};
  snprintf(proc_pid_maps_path, sizeof(proc_pid_maps_path), "/proc/%d/maps", pid);

  FILE* f = fopen(proc_pid_maps_path, "re");
  if (!f) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "prefetchMaps: Failed to open remote's %s", proc_pid_maps_path);
    return;
  }

  char line[PATH_MAX] = {0};
  while (fgets(line, sizeof(line), f)) {
    if (!isxdigit(static_cast<unsigned char>(line[0]))) {
      continue;
    }

    uintptr_t start = 0, end = 0, offset = 0;
    char perms[5] = {0};
    unsigned dev_major = 0, dev_minor = 0;
    unsigned long inode = 0;

    int n = sscanf(line, "%lx-%lx %4s %lx %x:%x %lu",
                   &start, &end, perms, &offset, &dev_major, &dev_minor, &inode);
    if (n < 7 || start >= end) {
      continue;
    }

    char* path = line;
    for (int i = 0; i < 6; i++) {
      path = strchr(path, ' ');
      if (!path) {
        break;
      }
      while (*path == ' ') {
        path++;
      }
    }

    std::string lib_path;
    if (path && *path) {
      char* nl = strchr(path, '\n');
      if (nl) {
        *nl = '\0';
      }
      lib_path = path;
    } else {
      lib_path = UNKNOWN_LIB_FRAME_NAME;
    }

    // Always push every valid mapping
    current_maps.push_back({start, end, offset, lib_path});
  }

  if (ferror(f)) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "prefetchMaps: error while reading %s", proc_pid_maps_path);
  }
  fclose(f);

  if (current_maps.empty()) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "prefetchMaps: maps are still empty!");
  } else {
    write_to_logcat_async(ANDROID_LOG_INFO, TAG,
                          "maps successfully prefetched (size: %zu)", current_maps.size());
  }
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
  if (strstr(path, "/memfd") || strstr(path, "[")) {
    return;
  }

  if (fd < 0) {
#ifdef BROKER_UNWINDER_LOGGING
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "\tfind_label_in_elf: Failed to open %s", path);
#endif
    return;
  }

  struct stat st;
  if (fstat(fd, &st) < 0) {
#ifdef BROKER_UNWINDER_LOGGING
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "\tfind_label_in_elf: Failed to fstat fd %d associated with %s", fd, path);
#endif
    close(fd);
    return;
  }

  if (st.st_size < (off_t)sizeof(ElfHeader)) {
#ifdef BROKER_UNWINDER_LOGGING
    write_to_logcat_async(ANDROID_LOG_WARN, TAG, "\tfind_label_in_elf: %s st_size's too small to be an ELF. Not searching symbols.", path);
#endif
    close(fd);
    strncpy(out_name, "[Too Small]", max_len - 1);
    return;
  }

  void* map = mmap(nullptr, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);

  if (map == MAP_FAILED) {
#ifdef BROKER_UNWINDER_LOGGING
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "\tfind_label_in_elf: mmap failed!");
#endif
    return;
  }

  ElfHeader* ehdr = (ElfHeader*)map;

  // TODO: If this is an APK (ZIP), it will fail this check and safely return
  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
#ifdef BROKER_UNWINDER_LOGGING
    write_to_logcat_async(ANDROID_LOG_WARN, TAG, "\t%s header doesn't match ELF magic. Not searching symbols.", path);
#endif
    strncpy(out_name, "[APK/ZIP/JAR]", max_len - 1);
    munmap(map, (size_t)st.st_size);
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
    out_name[max_len - 1] = '\0';
  } else {
    strncpy(out_name, UNRESOLVED_SYMBOL_NAME, max_len);
  }

  munmap(map, (size_t)st.st_size);
}

/**
 * Tries to resolve PC in current `maps` snapshot
 * Otherwise, opens it and tries again
 */
static LIB_IN_MAPS_RET find_lib_name_in_maps(uintptr_t pc, ManualDlInfo* info, pid_t pid) {
  // 1. Happy path: PC in existing cache
  for (const auto& m : current_maps) {
    if (pc >= m.start && pc < m.end) {
      strncpy(info->dli_fname, m.libName.c_str(), sizeof(info->dli_fname) - 1);
      info->dli_fbase = m.start;
      info->dli_offset = (pc - m.start) + m.offset;
      return FOUND;
    }
  }

  // 2. Cache miss: rebuild full list
  current_maps.clear();

  char proc_pid_maps_path[PATH_MAX] = {0};
  snprintf(proc_pid_maps_path, sizeof(proc_pid_maps_path), "/proc/%d/maps", pid);

  FILE* f = fopen(proc_pid_maps_path, "re");
  if (!f) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "find_lib_name_in_maps: Failed to open %s", proc_pid_maps_path);
    return FAILED;
  }

  char line[PATH_MAX] = {0};
  while (fgets(line, sizeof(line), f)) {
    if (!isxdigit(static_cast<unsigned char>(line[0]))) {
      continue;
    }

    uintptr_t start = 0, end = 0, offset = 0;
    char perms[5] = {0};
    unsigned dev_major = 0, dev_minor = 0;
    unsigned long inode = 0;

    int n = sscanf(line, "%lx-%lx %4s %lx %x:%x %lu",
                   &start, &end, perms, &offset, &dev_major, &dev_minor, &inode);
    if (n < 7 || start >= end) {
      continue;
    }

    char* path = line;
    for (int i = 0; i < 6; i++) {
      path = strchr(path, ' ');
      if (!path) {
        break;
      }
      while (*path == ' ') {
        path++;
      }
    }

    std::string lib_path;
    if (path && *path) {
      char* nl = strchr(path, '\n');
      if (nl) {
        *nl = '\0';
      }
      lib_path = path;
    } else {
      lib_path = UNKNOWN_LIB_FRAME_NAME;
    }

    // Always push every valid mapping
    current_maps.push_back({start, end, offset, lib_path});
  }
  fclose(f);

  // 3. Search the full list
  for (const auto& m : current_maps) {
    if (pc >= m.start && pc < m.end) {
      strncpy(info->dli_fname, m.libName.c_str(), sizeof(info->dli_fname) - 1);
      info->dli_fbase = m.start;
      info->dli_offset = (pc - m.start) + m.offset;
      return FOUND;
    }
  }

  if (current_maps.empty()) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "find_lib_name_in_maps: could not parse any maps for PID %d", pid);
  } else {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG,
                          "find_lib_name_in_maps: PC %p not covered by any mapping (maps size %zu)",
                          (void*)pc, current_maps.size());
  }
  return NOT_FOUND;
}

static inline bool is_trusted_lib(const char* lib_path) {
  return (
      startsWith(lib_path, "/apex") ||
      startsWith(lib_path, "/vendor") ||
      startsWith(lib_path, "/system") ||
      startsWith(lib_path, "/product") ||
      startsWith(lib_path, "/data/resource-cache") ||
      startsWith(lib_path, "/dev") ||
      startsWith(lib_path, "/metadata") ||
      startsWith(lib_path, "[vdso]") ||
      startsWith(lib_path, "[vvar]") ||
      startsWith(lib_path, "[anon:dalvik-") ||
      startsWith(lib_path, "[anon:bionic") ||
      startsWith(lib_path, "[anon:cfi") ||
      startsWith(lib_path, "[stack]") ||
      startsWith(lib_path, "[anon:cfi") ||
      startsWith(lib_path, "[anon:linker_alloc]") ||
      startsWith(lib_path, "/system/lib64/libzygisk.so") ||
      startsWith(lib_path, "/memfd:jit-cache (deleted)")  // TODO: ourselves
  );
}

static inline bool should_passthrough(const char* libPath) {
  if (!libPath) {
    return false;
  }

  if (
      startsWith(libPath, "/system/lib64/libzygisk.so") ||
      startsWith(libPath, "/memfd:jit-cache (deleted)")) {
    return true;
  }
  return false;
}
