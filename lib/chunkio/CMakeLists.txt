cmake_minimum_required(VERSION 2.8)
project(chunk-io)

set(CIO_VERSION_MAJOR  1)
set(CIO_VERSION_MINOR  0)
set(CIO_VERSION_PATCH  4)
set(CIO_VERSION_STR "${CIO_VERSION_MAJOR}.${CIO_VERSION_MINOR}.${CIO_VERSION_PATCH}")

# CFLAGS
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(MSVC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4 ")
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall ")
endif()

# Set __FILENAME__
if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILENAME__='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILENAME__=__FILE__")
endif()

# ChunkIO options
option(CIO_DEV               "Enable dev/test mode"         Off)
option(CIO_LIB_STATIC        "Enable static library build"  On)
option(CIO_LIB_SHARED        "Enable shared library build"  Off)
option(CIO_SANITIZE_ADDRESS  "Enable address sanitizer"     Off)
option(CIO_TESTS             "Enable tests"                 Off)
option(CIO_BACKEND_FILESYSTEM "Enable filesystem backend"   On)

# Windows does not have file system backend support yet.
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(CIO_BACKEND_FILESYSTEM Off)
endif()

# Force Option value
macro(CIO_OPTION option value)
  set(${option} ${value} CACHE INTERNAL "" FORCE)
endmacro()

# Development/Test mode
if(CIO_DEV)
  CIO_OPTION(CMAKE_BUILD_TYPE      "Debug")
  CIO_OPTION(CIO_TESTS                  On)
  CIO_OPTION(CIO_LIB_STATIC             On)
endif()

# Macro to set definitions
macro(CIO_DEFINITION var)
  add_definitions(-D${var})
  set(CIO_BUILD_FLAGS "${CIO_BUILD_FLAGS}#ifndef ${var}\n#define ${var}\n#endif\n")
  set(CIO_INFO_FLAGS "${CIO_INFO_FLAGS} ${var}")
endmacro()

# Check if Address Sanitizer is enabled
if(CIO_SANITIZE_ADDRESS OR SANITIZE_ADDRESS)
  set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/sanitizers-cmake/cmake" ${CMAKE_MODULE_PATH})
  if(NOT SANITIZE_ADDRESS)
    add_definitions(-DSANITIZE_ADDRESS=On)
  endif()
  find_package(Sanitizers)

  # Note that this package don't define Sanitizers_FOUND:
  # https://github.com/arsenm/sanitizers-cmake/issues/16
  if (NOT DEFINED SANITIZE_LINK_STATIC)
    message(FATAL_ERROR "CMake Sanitizer not found")
  else()
    message(STATUS "Enabling address sanitizer")
  endif()
endif()

if(CIO_BACKEND_FILESYSTEM)
  CIO_DEFINITION(CIO_HAVE_BACKEND_FILESYSTEM)
endif()

include(CheckCSourceCompiles)

# fallocate support
check_c_source_compiles("
  #include <fcntl.h>
  int main() {
     fallocate(0,0,0);
     return 0;
  }" CIO_HAVE_FALLOCATE)

if(CIO_HAVE_FALLOCATE)
  CIO_DEFINITION(CIO_HAVE_FALLOCATE)
endif()

configure_file(
  "${PROJECT_SOURCE_DIR}/include/chunkio/cio_version.h.in"
  "${PROJECT_SOURCE_DIR}/include/chunkio/cio_version.h"
  )

include_directories(
  include
  deps/
  deps/monkey/include
  )

add_subdirectory(deps/crc32)
add_subdirectory(src)
add_subdirectory(tools)

if(CIO_TESTS)
  add_subdirectory(tests)
endif()
