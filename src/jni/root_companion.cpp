#include <unistd.h>
#include <dirent.h>
#include <string>

#include "zygisk.hpp"
#include "shared.hpp"

#define TARGETS_DIR "/data/adb/modules/bipan/targets"

/**
 * The companion handler func runs as root.
 * It was deemed necessary in order to bypass
 * SELinux policies in the Magisk folder
 */
static void companion_handler(int fd) {
    DIR* dir = opendir(TARGETS_DIR);
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_name[0] == '.') {
                // Skip . and ..
                continue;
            }

            auto len = static_cast<uint32_t>(strlen(entry->d_name));
            write(fd, &len, sizeof(len));
            write(fd, entry->d_name, len);
        }
        closedir(dir);
    } else {
        LOGE("companion_handler: failed to read targets dir (%s)!", TARGETS_DIR);
        return;
    }
    
    uint32_t done = 0; // means we are finished
    write(fd, &done, sizeof(done));
}

// Register the companion handler function
REGISTER_ZYGISK_COMPANION(companion_handler)
