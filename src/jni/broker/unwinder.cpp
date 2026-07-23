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

// static thread_local std::vector<MapEntry> current_maps;
static std::vector<MapEntry> current_maps;

static void find_label_in_elf(const char* path, uintptr_t offset, char* out_name, size_t max_len);
static bool find_lib_name_in_maps(uintptr_t pc, ManualDlInfo* info, pid_t pid);
static inline bool is_trusted_lib(const char* lib_path);

bool unwinder(uintptr_t pc, uintptr_t fp, uintptr_t lr, pid_t pid, int nr) {
  char mem_path[64] = {0};
  snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

  int mem_fd = open(mem_path, O_RDONLY);
  if (mem_fd < 0) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "unwinder: Failed to open %s", mem_path);
    return false;  // fail closed, assuming untrusted
  }

  ManualDlInfo info;
  memset(&info, 0, sizeof(ManualDlInfo));
  // char sym_name[PATH_MAX] = "???";

  lr &= 0x0000FFFFFFFFFFFFULL;  // Strip arm64 PAC auth bits
  if (find_lib_name_in_maps(lr, &info, pid)) {
    // find_label_in_elf(info.dli_fname, info.dli_offset, sym_name, sizeof(sym_name));

    if (!is_trusted_lib(info.dli_fname)) {
      write_to_logcat_async(ANDROID_LOG_INFO, TAG, "Very first LR (%p) is a malicious lib(%s) triggering nr %d. Unwinding over :)", (void*)lr, info.dli_fname, nr);
      close(mem_fd);
      return false;
    }

    // write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[Unwind start (nr: %d)] -> LR: %p | Sym: %s | Lib: %s | Offset: (+0x%lx)", nr, (void*)pc, sym_name, info.dli_fname, info.dli_offset);
    write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[Unwind start (nr: %d)] -> PC: %p | Lib: %s", nr, (void*)pc, info.dli_fname);
  } else {
    write_to_logcat_async(ANDROID_LOG_FATAL, TAG, "[!] Failed to resolve very first LR (%p)!", (void*)lr);
    close(mem_fd);
    return false;
  }

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
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[Unwind ending by exhaustion (%d passes)] -> Current FP isn't a valid pointer (null/misaligned)", i);
      close(mem_fd);
      return true;
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
      write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "[Unwind ending by exhaustion (%d passes)] -> Failed to pread current FP and/or its ret addr (FP+8)(%p)", i);
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

    if (find_lib_name_in_maps(return_addr, &info, pid)) {
      // find_label_in_elf(info.dli_fname, info.dli_offset, sym_name, sizeof(sym_name));
      // write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "\tAncestor's addr: %p | Sym: %s | Lib: %s | Offset: (+0x%lx)\n", (void*)next_lr, sym_name, info.dli_fname, info.dli_offset);

      write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "\tAncestor's PC: %p | Lib: %s", (void*)return_addr, info.dli_fname);

      if (!is_trusted_lib(info.dli_fname)) {
        write_to_logcat_async(ANDROID_LOG_INFO, TAG, "[Unwind good ending (%d passes)] -> Found malicious lib: %s", i, info.dli_fname);
        close(mem_fd);
        return false;
      }
    } else {
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "\tFailed to find ancestor's PC (%p) in maps. Continuing...", (void*)return_addr);
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

    // Walk the linked list to next frame record
    fp = next_fp;
  }

  close(mem_fd);
  write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[Unwind rare exhaustion ending] -> Walked %d frames and found only safe libs. Allowing syscall!", MAX_STACK_TRACE);
  return true;
}

void initializeUnwinder(pid_t pid) {
  if (current_maps.empty()) {
    char proc_pid_maps_path[PATH_MAX] = {0};
    snprintf(proc_pid_maps_path, PATH_MAX, "/proc/%d/maps", pid);

    FILE* f = fopen(proc_pid_maps_path, "re");
    if (!f) {
      write_to_logcat_async(ANDROID_LOG_WARN, TAG, "initializeUnwinder: Failed to open remote's %s", proc_pid_maps_path);
      return;
    }
    char line[PATH_MAX] = {0};
    while (fgets(line, sizeof(line), f)) {
      if (!isxdigit(line[0])) {
        continue;
      }

      uintptr_t start = 0;
      uintptr_t end = 0;
      uintptr_t offset = 0;
      char perms[5] = {0};
      char devMajor[8] = {0};
      char devMinor[8] = {0};
      size_t libInode = 0;
      char libName[PATH_MAX] = {0};

      int ret = sscanf(line,
                       "%lx-%lx %4s %lx %7[^:]:%7s %zu %s",
                       &start, &end, perms, &offset, devMajor, devMinor, &libInode, libName);

      if (ret != 7 && ret != 8) {
        write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "\t[*] initializeUnwinder: Skipping malformed maps line: %s", line);
        continue;
      }

      if (start >= end) {
        write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "\t[*] initializeUnwinder: Error in maps line %s: start(%p) >= end(%p) ", line, (void*)start, (void*)end);
        continue;
      }

      std::string lib_path(libName);

      // Empty lib/malformed libname fallback 1
      if (lib_path.empty()) {
        lib_path = "[Anonymous Memory]";
        current_maps.push_back({start, end, offset, lib_path});
        break;
      }

      // Extract the path
      // 1st attempt: look for '/' or '[' (for [stack], [vdso], etc)
      char* path_start = strchr(line, '/');
      if (!path_start) {
        // 2nd attempt: '[' (for things like [stack], [vdso], etc)
        path_start = strchr(line, '[');
      }

      // Empty lib/malformed libname fallback 2
      if (!path_start) {
        lib_path = "[Anonymous Memory]";
        current_maps.push_back({start, end, offset, lib_path});
        break;
      }

      current_maps.push_back({start, end, offset, std::string(path_start)});
    }

    if (ferror(f)) {
      write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "initializeUnwinder: error while reading %s", proc_pid_maps_path);
    }
    fclose(f);

    if (current_maps.empty()) {
      write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "initializeUnwinder: maps are still empty!");
    } else {
      write_to_logcat_async(ANDROID_LOG_INFO, TAG, "maps successfully prefetched (size: %d)", current_maps.size());
    }
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

  void* map = mmap(nullptr, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
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
  } else {
    strncpy(out_name, "???", max_len);
  }

  munmap(map, (size_t)st.st_size);
}

/**
 * Tries to resolve PC in current `maps` snapshot
 * Otherwise, opens it and tries again
 */
static bool find_lib_name_in_maps(uintptr_t pc, ManualDlInfo* info, pid_t pid) {
  int found = false;

  // Step 1: Check if Program Counter is in currently cached maps
  for (const auto& m : current_maps) {
    if (pc >= m.start && pc < m.end) {
      strncpy(info->dli_fname, m.libName.c_str(), sizeof(m.libName.c_str()) - 1);
      found = true;
      return found;
    }
  }

  // Step 2 (expected): cache missed: something was loaded -> refresh maps and try again
  current_maps.clear();

  char proc_pid_maps_path[PATH_MAX] = {0};
  snprintf(proc_pid_maps_path, PATH_MAX, "/proc/%d/maps", pid);

  FILE* f = fopen(proc_pid_maps_path, "re");
  if (!f) {
    write_to_logcat_async(ANDROID_LOG_WARN, TAG, "\tfind_lib_name_in_maps: Failed to open remote's %s", proc_pid_maps_path);
    found = false;
    return found;
  }

  char line[PATH_MAX] = {0};
  while (fgets(line, sizeof(line), f)) {
    if (!isxdigit(line[0])) {
      write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "\t\t[*] find_lib_name_in_maps: Skipping malformed maps line: %s", line);
      continue;
    }

    uintptr_t start = 0;
    uintptr_t end = 0;
    uintptr_t offset = 0;
    char perms[5] = {0};
    char devMajor[8] = {0};
    char devMinor[8] = {0};
    size_t libInode = 0;
    char libName[PATH_MAX] = {0};

    // Standard `maps` format: start-end perms offset dev inode path
    int ret = sscanf(line,
                     "%lx-%lx %4s %lx %7[^:]:%7s %zu %s",
                     &start, &end, perms, &offset, devMajor, devMinor, &libInode, libName);

    if (ret != 7 && ret != 8) {
      write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "\t\t[*] find_lib_name_in_maps: Skipping malformed maps line: %s", line);
      continue;
    }

    if (start >= end) {
      write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "\t\t[*] find_lib_name_in_maps: Error in maps line %s: start(%p) >= end(%p) ", line, (void*)start, (void*)end);
      continue;
    }

    std::string lib_path(libName);

    // The PC is within this lib's range!
    if (pc >= start && pc < end) {
      // info->dli_fbase = start;
      // // Calculate offset: (Actual Addr - Map Start) + File Offset
      // info->dli_offset = (pc - start) + offset;

      // Empty lib/malformed libname fallback 1
      if (lib_path.empty()) {
        lib_path = "[Anonymous Memory]";
        strncpy(info->dli_fname, lib_path.c_str(), lib_path.size());
        found = true;

        // Update cache
        current_maps.push_back({start, end, offset, lib_path});
        break;
      }

      // Extract the path
      // 1st attempt: look for '/' or '[' (for [stack], [vdso], etc)
      char* path_start = strchr(line, '/');
      if (!path_start) {
        // 2nd attempt: '[' (for things like [stack], [vdso], etc)
        path_start = strchr(line, '[');
      }

      // Empty lib/malformed libname fallback 2
      if (!path_start) {
        strcpy(info->dli_fname, "[Anonymous Memory]");
        found = true;

        // Update cache
        current_maps.push_back({start, end, offset, std::string(info->dli_fname)});
        break;
      }

      strncpy(info->dli_fname, path_start, sizeof(info->dli_fname) - 1);
      found = true;

      // Update cache
      current_maps.push_back({start, end, offset, std::string(info->dli_fname)});
      break;
    }

    // If it's not, keep on looping...
  }

  if (ferror(f)) {
    write_to_logcat_async(ANDROID_LOG_ERROR, TAG, "Error while reading %s", proc_pid_maps_path);
  }
  fclose(f);

  if (current_maps.empty()) {
    write_to_logcat_async(ANDROID_LOG_WARN, TAG, "find_lib_name_in_maps: No maps found for PID %d", pid);
  }

  // Final step: Check PC again in fresh maps
  for (const auto& m : current_maps) {
    if (pc >= m.start && pc < m.end) {
      strncpy(info->dli_fname, m.libName.c_str(), sizeof(m.libName.c_str()) - 1);
      found = true;
      return found;
    }
  }

  write_to_logcat_async(ANDROID_LOG_WARN, TAG, "find_lib_name_in_maps: Ultimate fallthrough. found=%s", found == 0 ? "false" : "true");
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
