LOCAL_PATH := $(call my-dir)

# Include Dobby's compiled static lib in the project
include $(CLEAR_VARS)
LOCAL_MODULE := dobby_static
LOCAL_SRC_FILES := libdobby.a
include $(PREBUILT_STATIC_LIBRARY)

# Build Bipan
include $(CLEAR_VARS)
LOCAL_MODULE := bipan
LOCAL_SRC_FILES := bipan.cpp \
	 									blocker.cpp \
										broker.cpp \
										filter.cpp \
										root_companion.cpp \
										sigsys_handler.cpp \
										spoofer.cpp


# Statically link Bipan to Dobby
LOCAL_STATIC_LIBRARIES := dobby_static

LOCAL_CPPFLAGS := -O3 -Wall -Wextra \
									-Wconversion -Wsign-conversion \
                  -Wdouble-promotion -Winline \
									-fno-exceptions -fno-rtti \
                  -fvisibility=hidden -fvisibility-inlines-hidden

# "Local Linker Libraries": dynamically link to liblog.so (for use of logcat)
LOCAL_LDLIBS := -llog 

include $(BUILD_SHARED_LIBRARY)
