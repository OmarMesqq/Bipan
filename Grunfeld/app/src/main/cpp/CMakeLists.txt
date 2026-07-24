cmake_minimum_required(VERSION 3.22.1)

project(GrunfeldProject)

# Define the library
add_library(grunfeld SHARED main.c socket_helper.c)

target_compile_options(grunfeld PRIVATE
    -O3
    -Wall
    -Wextra
    -Winline
    -Wpedantic
    -Wshadow
    -Wconversion
    -Wsign-conversion
    -Wdouble-promotion
    -fvisibility=hidden
    -Wno-unused-parameter
    -ffunction-sections
    -fdata-sections
    -fno-asynchronous-unwind-tables
    -fno-unwind-tables
    -fomit-frame-pointer
)

# Align the lib to 16KB (Android 15+ requirement)
target_link_options(grunfeld PRIVATE
        "-Wl,-z,max-page-size=16384"
        "-Wl,--gc-sections"
        "-Wl,--exclude-libs,ALL"
        "-Wl,--icf=all"
        "-Wl,--build-id=none"
        "-Wl,--no-eh-frame-hdr"
        "-Wl,--no-dynamic-linker"
        "-Wl,-z,nognustack"
        "-Wl,-z,relro"
        "-Wl,-z,now"
)


# Link dependencies
target_link_libraries(grunfeld log android)
