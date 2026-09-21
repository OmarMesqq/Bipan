cmake_minimum_required(VERSION 3.22.1)
project(NativeTemplate)

add_library(nativeTemplate SHARED main.cpp)

target_compile_options(nativeTemplate PRIVATE
        -Wall
        -Wextra
        -Winline
        -Wpedantic
        -Wshadow
        -Wconversion
        -Wsign-conversion
        -Wdouble-promotion
        #-Wno-unused-parameter
        -ffunction-sections
        -fdata-sections
)

target_link_options(nativeTemplate PRIVATE
        "-Wl,-z,max-page-size=16384"
        "-Wl,--gc-sections"
        "-Wl,-z,relro"
        "-Wl,-z,now"
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(nativeTemplate PRIVATE
            -O0
            -g
            -fno-omit-frame-pointer
            -funwind-tables
            -fasynchronous-unwind-tables
            -fstrict-overflow
            -fsanitize=undefined
            -fsanitize-trap=undefined
    )
else()
    target_compile_options(nativeTemplate PRIVATE
            -O3
            -fno-asynchronous-unwind-tables
            -fno-unwind-tables
            -fomit-frame-pointer
            -fvisibility=hidden
    )
    target_link_options(nativeTemplate PRIVATE
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
endif()

target_link_libraries(nativeTemplate log android)
