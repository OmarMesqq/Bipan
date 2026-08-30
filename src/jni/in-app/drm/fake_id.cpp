#include "fake_id.hpp"

#include <sys/random.h>

#include <cstring>

#include "../../logger/logger.hpp"
#include "../globals.hpp"

uint8_t kFakeId[DRM_ID_BUF_SIZE];
bool kFakeIdReady = false;

void ensureFakeId(void) {
  if (kFakeIdReady) {
    return;
  }

  ssize_t n = getrandom(kFakeId, sizeof(kFakeId), 0);
  if (n != (ssize_t)sizeof(kFakeId)) {
    // fallback to marking ready in case `getrandom` fails
    write_to_logcat_async(ANDROID_LOG_WARN, TAG, "(DRM) getrandom failed. Creating pre-determined fake ID");
    memset(kFakeId, 0xA5, sizeof(kFakeId));
  }
  kFakeIdReady = true;
}
