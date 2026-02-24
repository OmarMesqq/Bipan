#ifndef BIPAN_SHARED_H
#define BIPAN_SHARED_H

#include <android/log.h>

#define TAG "Bipan"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#endif