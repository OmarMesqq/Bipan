LOCAL_PATH := $(call my-dir)

# Forward declare prebuilt static Dobby (.a) to Make
include $(CLEAR_VARS)
LOCAL_MODULE := dobby_static

ifeq ($(TARGET_ARCH_ABI),arm64-v8a)
    LOCAL_SRC_FILES := deps/libdobby-64.a
else ifeq ($(TARGET_ARCH_ABI),armeabi-v7a)
    LOCAL_SRC_FILES := deps/libdobby-32.a
endif
include $(PREBUILT_STATIC_LIBRARY)

ifeq ($(BIPAN_DEBUG), 1)
	BIPAN_CPPFLAGS := -Wall -Wextra \
		-Wconversion -Wsign-conversion \
		-Wdouble-promotion -Winline -Wshadow \
		-fno-exceptions -fno-rtti \
		-funwind-tables -fasynchronous-unwind-tables \
		-fno-omit-frame-pointer -fstrict-overflow \
		-fsanitize=undefined -fsanitize-trap=undefined
		-fsanitize=thread -g -O2
	
	BIPAN_LDFLAGS := 
	BIPAN_LDLIBS  := -lstdc++ -fsanitize=thread
$(info Building DEBUG variant...)
else
	BIPAN_CPPFLAGS := -O3 -Wall -Wextra \
		-ffunction-sections -fdata-sections \
		-Wconversion -Wsign-conversion \
		-Wdouble-promotion -Winline -Wshadow \
		-fno-exceptions -fno-rtti \
		-fvisibility=hidden -fvisibility-inlines-hidden \
		-fomit-frame-pointer \
		-fno-asynchronous-unwind-tables -fno-unwind-tables \
		-flto

	BIPAN_LDFLAGS := -Wl,--gc-sections \
								 	 -Wl,--exclude-libs,ALL \
								 	 -Wl,--icf=all \
								 	 -Wl,-u,zygisk_module_entry \
                 	 -Wl,-u,zygisk_companion_entry \
                 	 -Wl,--version-script=$(LOCAL_PATH)/bipan_export.map \
									 -Wl,--build-id=none \
									 -Wl,--no-eh-frame-hdr \
									 -Wl,--no-dynamic-linker \
									 -Wl,-z,nognustack \
									 -Wl,-z,relro \
									 -Wl,-z,now \
								 	 -flto
$(info Building RELEASE variant...)
endif


# Logger
include $(CLEAR_VARS)
LOCAL_MODULE    := bipan-logger
LOCAL_SRC_FILES := $(subst $(LOCAL_PATH)/,,$(wildcard $(LOCAL_PATH)/logger/*.cpp))
LOCAL_CPPFLAGS  := $(BIPAN_CPPFLAGS)
include $(BUILD_STATIC_LIBRARY)

# In-app static lib (injected code)
include $(CLEAR_VARS)
LOCAL_MODULE    := bipan-inapp
LOCAL_SRC_FILES := $(subst $(LOCAL_PATH)/,, \
  $(wildcard $(LOCAL_PATH)/in-app/*.cpp) \
  $(wildcard $(LOCAL_PATH)/in-app/*/*.cpp) \
  $(wildcard $(LOCAL_PATH)/in-app/*/*/*.cpp))
	
LOCAL_CPPFLAGS  := $(BIPAN_CPPFLAGS)
LOCAL_STATIC_LIBRARIES := dobby_static # link injected portion to Dobby
include $(BUILD_STATIC_LIBRARY)

# Broker process static lib
include $(CLEAR_VARS)
LOCAL_MODULE    := bipan-broker
LOCAL_SRC_FILES := $(subst $(LOCAL_PATH)/,,$(wildcard $(LOCAL_PATH)/broker/*.cpp))
LOCAL_CPPFLAGS  := $(BIPAN_CPPFLAGS)
include $(BUILD_STATIC_LIBRARY)

# Build final Bipan shared library
include $(CLEAR_VARS)
LOCAL_MODULE := bipan
LOCAL_WHOLE_STATIC_LIBRARIES := bipan-logger \
																bipan-inapp \
																bipan-broker
LOCAL_LDFLAGS := $(BIPAN_LDFLAGS)

include $(BUILD_SHARED_LIBRARY)
