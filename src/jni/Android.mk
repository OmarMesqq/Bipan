LOCAL_PATH := $(call my-dir)

# Forward declare prebuilt static Dobby (.a) to Make
include $(CLEAR_VARS)
LOCAL_MODULE := dobby_static
LOCAL_SRC_FILES := deps/libdobby.a
include $(PREBUILT_STATIC_LIBRARY)


# Logger
include $(CLEAR_VARS)
LOCAL_MODULE    := bipan-logger
LOCAL_SRC_FILES := $(subst $(LOCAL_PATH)/,,$(wildcard $(LOCAL_PATH)/logger/*.cpp))
LOCAL_CPPFLAGS := -O3 -Wall -Wextra \
		-ffunction-sections -fdata-sections \
		-Wconversion -Wsign-conversion \
		-Wdouble-promotion -Winline \
		-fno-exceptions -fno-rtti \
		-fvisibility=hidden -fvisibility-inlines-hidden \
		-fomit-frame-pointer -flto \
		-Wno-unused-parameter \
# 		-Rpass=inline -Rpass-missed=inline
include $(BUILD_STATIC_LIBRARY)

# Tools module
include $(CLEAR_VARS)
LOCAL_MODULE    := bipan-tools
LOCAL_SRC_FILES := $(subst $(LOCAL_PATH)/,,$(wildcard $(LOCAL_PATH)/tools/*.cpp))
LOCAL_CPPFLAGS := -O3 -Wall -Wextra \
		-ffunction-sections -fdata-sections \
		-Wconversion -Wsign-conversion \
		-Wdouble-promotion -Winline \
		-fno-exceptions -fno-rtti \
		-fvisibility=hidden -fvisibility-inlines-hidden \
		-fomit-frame-pointer -flto \
		-Wno-unused-parameter \
# 		-Rpass=inline -Rpass-missed=inline
include $(BUILD_STATIC_LIBRARY)

# In-app static lib (injected code)
include $(CLEAR_VARS)
LOCAL_MODULE    := bipan-inapp
LOCAL_SRC_FILES := $(subst $(LOCAL_PATH)/,,$(wildcard $(LOCAL_PATH)/in-app/*.cpp))
LOCAL_CPPFLAGS := -O3 -Wall -Wextra \
		-ffunction-sections -fdata-sections \
		-Wconversion -Wsign-conversion \
		-Wdouble-promotion -Winline \
		-fno-exceptions -fno-rtti \
		-fvisibility=hidden -fvisibility-inlines-hidden \
		-fomit-frame-pointer -flto \
		-Wno-unused-parameter \
# 		-Rpass=inline -Rpass-missed=inline

# Statically link injected portion to Dobby
LOCAL_STATIC_LIBRARIES := dobby_static
include $(BUILD_STATIC_LIBRARY)


# Broker process static lib
include $(CLEAR_VARS)
LOCAL_MODULE    := bipan-broker
LOCAL_SRC_FILES := $(subst $(LOCAL_PATH)/,,$(wildcard $(LOCAL_PATH)/broker/*.cpp))
LOCAL_CPPFLAGS := -O3 -Wall -Wextra \
		-ffunction-sections -fdata-sections \
		-Wconversion -Wsign-conversion \
		-Wdouble-promotion -Winline \
		-fno-exceptions -fno-rtti \
		-fvisibility=hidden -fvisibility-inlines-hidden \
		-fomit-frame-pointer -flto \
		-Wno-unused-parameter \
		-Rpass=inline -Rpass-missed=inline
include $(BUILD_STATIC_LIBRARY)


# Build final Bipan shared library
include $(CLEAR_VARS)
LOCAL_MODULE := bipan

# Nothing (or a thin glue .cpp) goes here if all real code lives in
# the two static libs. Add one if you need a JNI_OnLoad or entrypoint.
# LOCAL_SRC_FILES := bipan_entry.cpp

# Use WHOLE_STATIC here — you almost certainly want every object
# from both, since the in-app/broker code likely self-registers
# hooks (Dobby install points, broker IPC handlers) rather than
# being called directly from a small glue file the linker would
# otherwise see as "the reason to keep this".
LOCAL_WHOLE_STATIC_LIBRARIES := bipan-logger \
																bipan-tools \
																bipan-inapp \
																bipan-broker

LOCAL_LDFLAGS := -Wl,--gc-sections \
								 -Wl,--exclude-libs,ALL \
								 -Wl,--icf=all \
								 -Wl,-u,zygisk_module_entry \
                 -Wl,-u,zygisk_companion_entry \
                 -Wl,--version-script=$(LOCAL_PATH)/bipan_export.map \
								 -flto

include $(BUILD_SHARED_LIBRARY)
