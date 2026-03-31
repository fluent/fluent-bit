# Copyright (C) 2019 Intel Corporation.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
cmake_minimum_required(VERSION 3.14)

project(c_embed_test)

include(CheckPIESupported)

string (TOLOWER ${CMAKE_HOST_SYSTEM_NAME} WAMR_BUILD_PLATFORM)
if (APPLE)
  add_definitions(-DBH_PLATFORM_DARWIN)
endif ()

set (CMAKE_C_STANDARD 99)
set (CMAKE_CXX_STANDARD 17)

set(WAMR_BUILD_TARGET "X86_64")
set(WAMR_BUILD_INTERP 1)
set(WAMR_BUILD_FAST_INTERP 0)
set(WAMR_BUILD_AOT 0)
set(WAMR_BUILD_LIBC_BUILTIN 1)
set(WAMR_BUILD_LIBC_WASI 1)
set(WAMR_BUILD_SIMD 1)
set(WAMR_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../..)

if (NOT DEFINED WAMR_BUILD_REF_TYPES)
  # Enable reference types by default
  set (WAMR_BUILD_REF_TYPES 1)
endif ()

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")
if (NOT WAMR_BUILD_PLATFORM STREQUAL "darwin")
  set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections -pie -fPIE")
endif ()
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wformat -Wformat-security -Wshadow")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wformat -Wformat-security -Wno-unused")

# build out vmlib
include(${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)
add_library(vmlib ${WAMR_RUNTIME_LIB_SOURCE})

# application related
include(${SHARED_DIR}/utils/uncommon/shared_uncommon.cmake)
add_executable(c_embed_test src/main.c ${UNCOMMON_SHARED_SOURCE})

target_link_libraries(c_embed_test vmlib m ${LLVM_AVAILABLE_LIBS})

add_custom_command(TARGET c_embed_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_LIST_DIR}/../wasm-apps/mytest.wasm ${CMAKE_CURRENT_LIST_DIR}/../wasm-apps/hello.wasm
        ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Copy main.wasm and hello.wasm to the build directory"
        )
