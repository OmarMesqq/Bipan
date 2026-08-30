#ifndef FAKE_ID_HPP
#define FAKE_ID_HPP

#include <cstddef>
#include <cstdint>

constexpr size_t DRM_ID_BUF_SIZE = 16;
// The actual byte array of our "PROPERTY_DEVICE_UNIQUE_ID"
extern uint8_t kFakeId[DRM_ID_BUF_SIZE];
// Whether the random bytes for the array are ready
extern bool kFakeIdReady;

void ensureFakeId(void);

#endif