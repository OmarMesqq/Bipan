cmake_minimum_required(VERSION 3.22.1)

# Set C/C++ flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -Wall -Wextra -Winline -Wconversion -Wsign-conversion -Wdouble-promotion -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall -Wextra -Winline -Wconversion -Wsign-conversion -Wdouble-promotion -flto -fvisibility=hidden")

# Align the lib to 16KB (Android 15+ requirement)
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,max-page-size=16384")

# Define the library
add_library(grunfeld SHARED main.c)

# Link dependencies
target_link_libraries(grunfeld log)
