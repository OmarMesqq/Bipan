cmake_minimum_required(VERSION 3.22.1)

project(GrunfeldProject)

# Define the library
add_library(grunfeld SHARED main.c atomic_cat.c)

target_compile_options(grunfeld PRIVATE
    -O3
    -Wall
    -Wextra
    -Winline
    -Wshadow
    -Wconversion
    -Wsign-conversion
    -Wdouble-promotion
    -fvisibility=hidden
    -fomit-frame-pointer
    -Wno-unused-parameter
)

# Align the lib to 16KB (Android 15+ requirement)
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,max-page-size=16384")

# Link dependencies
target_link_libraries(grunfeld log android)
