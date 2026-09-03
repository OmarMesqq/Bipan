APP_ABI      := arm64-v8a armeabi-v7a
APP_PLATFORM := android-28

# TODO: add the following to ease debugging (requires battling with APP_STL)
# APP_CFLAGS 	 := -fsanitize=hwaddress
# APP_LDFLAGS  := -fsanitize=hwaddress
APP_STL      := c++_static

ifeq ($(BIPAN_DEBUG), 1)
  APP_OPTIM    := debug
  APP_CPPFLAGS := -std=c++17 \
    -fno-exceptions -fno-rtti \
    -fno-omit-frame-pointer
else
  APP_OPTIM    := release
  APP_CPPFLAGS := -std=c++17 \
    -fno-exceptions -fno-rtti \
    -fvisibility=hidden -fvisibility-inlines-hidden \
    -fomit-frame-pointer
endif
