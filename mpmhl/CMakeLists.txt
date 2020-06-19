cmake_minimum_required(VERSION 3.17)
project(MPMHL_NOAS C)

set(CMAKE_C_STANDARD 11)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-parameter -Wno-unused-result -Wno-macro-redefined -Wno-format -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast")

find_package(OpenMP)
if (OPENMP_FOUND)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
endif(OPENMP_FOUND)

if(APPLE)
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -O3")
else()
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -O3 -Wno-clobbered")
endif()

# add extra include directories
set(INCLUDE /usr/local/include ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_BINARY_DIR}/include)
include_directories(${INCLUDE})

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/bin)

set(SIMUL "$ENV{SIMUL}" CACHE STRING "Path to call a simulator of the target platform.")
set(SIMAR "$ENV{SIMAR}" CACHE STRING "Arguments to call a simulator of the target platform.")
string(REPLACE " " ";" SIMAR "${SIMAR}")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/src)
file(GLOB includes "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")
