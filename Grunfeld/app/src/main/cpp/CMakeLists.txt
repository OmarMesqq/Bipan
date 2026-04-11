cmake_minimum_required(VERSION 3.22.1)

# Build BipanTest's shared library (libgrunfeld.so)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror -Wextra -Wconversion -Wsign-conversion -Wdouble-promotion")

# Align it to. 16KB
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,max-page-size=16384")

add_library(grunfeld SHARED main.c)

# Link to its dependencies (only android log for now)
target_link_libraries(grunfeld log)