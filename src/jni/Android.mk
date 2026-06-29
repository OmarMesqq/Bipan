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
										bipan_hash_table.cpp \
										broker.cpp \
										filter.cpp \
										root_companion.cpp \
										sigsys_handler.cpp \
										spoofer.cpp


# Statically link Bipan to Dobby
LOCAL_STATIC_LIBRARIES := dobby_static

ifeq ($(BIPAN_DEBUG), 1)
	LOCAL_CPPFLAGS := -O0 -g -Wall -Wextra -fno-exceptions -fno-rtti
	LOCAL_LDFLAGS := 
$(info Building DEBUG variant...)
else
	LOCAL_CPPFLAGS := -O3 -Wall -Wextra \
		-ffunction-sections -fdata-sections \
		-Wconversion -Wsign-conversion \
		-Wdouble-promotion -Winline \
		-fno-exceptions -fno-rtti \
		-fvisibility=hidden -fvisibility-inlines-hidden \
		-fomit-frame-pointer -flto \
		-Wno-unused-parameter

	LOCAL_LDFLAGS := -Wl,--gc-sections \
		-Wl,--exclude-libs,ALL \
		-Wl,--icf=all \
		-flto
$(info Building RELEASE variant...)
endif

include $(BUILD_SHARED_LIBRARY)
