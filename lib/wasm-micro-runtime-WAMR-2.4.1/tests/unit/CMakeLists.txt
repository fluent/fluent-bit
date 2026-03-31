# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)

project(unit-test)

# Yes. To solve the compatibility issue with CMAKE (>= 4.0), we need to update
# our `cmake_minimum_required()` to 3.5. However, there are CMakeLists.txt
# from 3rd parties that we should not alter. Therefore, in addition to
# changing the `cmake_minimum_required()`, we should also add a configuration
# here that is compatible with earlier versions.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

SET(CMAKE_BUILD_TYPE Debug)

# add_definitions (-m32)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}")

if(WAMR_BUILD_TARGET STREQUAL "X86_32")
  # 1) Force -m32
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32" CACHE STRING "" FORCE)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32" CACHE STRING "" FORCE)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m32" CACHE STRING "" FORCE)
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m32" CACHE STRING "" FORCE)

  # 2) Make CMake prefer i386 libraries
  set(CMAKE_SYSTEM_PROCESSOR i386 CACHE STRING "" FORCE)
  set(CMAKE_LIBRARY_ARCHITECTURE "i386-linux-gnu" CACHE STRING "" FORCE)
endif()

# Prevent overriding the parent project's compiler/linker
# settings on Windows
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

# Fetch Google test
include (FetchContent)

if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.24")
  FetchContent_Declare (
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
    DOWNLOAD_EXTRACT_TIMESTAMP ON
  )
else()
  FetchContent_Declare (
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
  )
endif()

FetchContent_MakeAvailable(googletest)

SET(GOOGLETEST_INCLUDED 1)

include(GoogleTest)
enable_testing()

add_subdirectory(wasm-vm)
add_subdirectory(interpreter)
add_subdirectory(wasm-c-api)
add_subdirectory(libc-builtin)
add_subdirectory(shared-utils)
add_subdirectory(linear-memory-wasm)
add_subdirectory(linear-memory-aot)
add_subdirectory(aot-stack-frame)
add_subdirectory(linux-perf)
add_subdirectory(gc)
add_subdirectory(tid-allocator)

if (NOT WAMR_BUILD_TARGET STREQUAL "X86_32")
  # should enable 32-bit llvm when X86_32
  add_subdirectory (aot)
  add_subdirectory (custom-section)
  add_subdirectory (compilation)

  # Fast-JIT or mem64 is not supported on X86_32
  add_subdirectory (running-modes)
  add_subdirectory (memory64)
  add_subdirectory (shared-heap)

  # HW_BOUND_CHECK is not supported on X86_32
  add_subdirectory (runtime-common)
endif ()
