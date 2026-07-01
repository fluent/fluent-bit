# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# Yes. To solve the compatibility issue with CMAKE (>= 4.0), we need to update
# our `cmake_minimum_required()` to 3.5. However, there are CMakeLists.txt
# from 3rd parties that we should not alter. Therefore, in addition to
# changing the `cmake_minimum_required()`, we should also add a configuration
# here that is compatible with earlier versions.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 FORCE)

set (IWASM_FAST_JIT_DIR ${CMAKE_CURRENT_LIST_DIR})
add_definitions(-DWASM_ENABLE_FAST_JIT=1)
if (WAMR_BUILD_FAST_JIT_DUMP EQUAL 1)
    add_definitions(-DWASM_ENABLE_FAST_JIT_DUMP=1)
endif ()

include_directories (${IWASM_FAST_JIT_DIR})
enable_language(CXX)

if (WAMR_BUILD_TARGET STREQUAL "X86_64" OR WAMR_BUILD_TARGET STREQUAL "AMD_64")
    include(FetchContent)
    if (NOT WAMR_BUILD_PLATFORM STREQUAL "linux-sgx")
        FetchContent_Declare(
            asmjit
            GIT_REPOSITORY https://github.com/asmjit/asmjit.git
            GIT_TAG c1019f1642a588107148f64ba54584b0ae3ec8d1
        )
    else ()
        FetchContent_Declare(
            asmjit
            GIT_REPOSITORY https://github.com/asmjit/asmjit.git
            GIT_TAG c1019f1642a588107148f64ba54584b0ae3ec8d1
            PATCH_COMMAND  git apply ${IWASM_FAST_JIT_DIR}/asmjit_sgx_patch.diff
        )
    endif ()
    FetchContent_GetProperties(asmjit)
    if (NOT asmjit_POPULATED)
        message ("-- Fetching asmjit ..")
        FetchContent_Populate(asmjit)
        add_definitions(-DASMJIT_STATIC)
        add_definitions(-DASMJIT_NO_DEPRECATED)
        add_definitions(-DASMJIT_NO_BUILDER)
        add_definitions(-DASMJIT_NO_COMPILER)
        add_definitions(-DASMJIT_NO_JIT)
        add_definitions(-DASMJIT_NO_LOGGING)
        add_definitions(-DASMJIT_NO_TEXT)
        add_definitions(-DASMJIT_NO_VALIDATION)
        add_definitions(-DASMJIT_NO_INTROSPECTION)
        add_definitions(-DASMJIT_NO_INTRINSICS)
        add_definitions(-DASMJIT_NO_AARCH64)
        add_definitions(-DASMJIT_NO_AARCH32)
        include_directories("${asmjit_SOURCE_DIR}/src")
        add_subdirectory(${asmjit_SOURCE_DIR} ${asmjit_BINARY_DIR} EXCLUDE_FROM_ALL)
        file (GLOB_RECURSE cpp_source_asmjit
            ${asmjit_SOURCE_DIR}/src/asmjit/core/*.cpp
            ${asmjit_SOURCE_DIR}/src/asmjit/x86/*.cpp
        )
    endif ()
    if (WAMR_BUILD_FAST_JIT_DUMP EQUAL 1)
        FetchContent_Declare(
            zycore
            GIT_REPOSITORY https://github.com/zyantific/zycore-c.git
        )
        FetchContent_GetProperties(zycore)
        if (NOT zycore_POPULATED)
            message ("-- Fetching zycore ..")
            FetchContent_Populate(zycore)
            option(ZYDIS_BUILD_TOOLS "" OFF)
            option(ZYDIS_BUILD_EXAMPLES "" OFF)
            include_directories("${zycore_SOURCE_DIR}/include")
            include_directories("${zycore_BINARY_DIR}")
            add_subdirectory(${zycore_SOURCE_DIR} ${zycore_BINARY_DIR} EXCLUDE_FROM_ALL)
            file (GLOB_RECURSE c_source_zycore ${zycore_SOURCE_DIR}/src/*.c)
        endif ()
        FetchContent_Declare(
            zydis
            GIT_REPOSITORY https://github.com/zyantific/zydis.git
            GIT_TAG e14a07895136182a5b53e181eec3b1c6e0b434de
        )
        FetchContent_GetProperties(zydis)
        if (NOT zydis_POPULATED)
            message ("-- Fetching zydis ..")
            FetchContent_Populate(zydis)
            option(ZYDIS_BUILD_TOOLS "" OFF)
            option(ZYDIS_BUILD_EXAMPLES "" OFF)
            include_directories("${zydis_BINARY_DIR}")
            include_directories("${zydis_SOURCE_DIR}/include")
            include_directories("${zydis_SOURCE_DIR}/src")
            add_subdirectory(${zydis_SOURCE_DIR} ${zydis_BINARY_DIR} EXCLUDE_FROM_ALL)
            file (GLOB_RECURSE c_source_zydis ${zydis_SOURCE_DIR}/src/*.c)
        endif ()
    endif ()
endif ()

file (GLOB c_source_jit ${IWASM_FAST_JIT_DIR}/*.c ${IWASM_FAST_JIT_DIR}/fe/*.c)

if (WAMR_BUILD_TARGET STREQUAL "X86_64" OR WAMR_BUILD_TARGET STREQUAL "AMD_64")
  file (GLOB_RECURSE cpp_source_jit_cg ${IWASM_FAST_JIT_DIR}/cg/x86-64/*.cpp)
else ()
  message (FATAL_ERROR "Fast JIT codegen for target ${WAMR_BUILD_TARGET} isn't implemented")
endif ()

set (IWASM_FAST_JIT_SOURCE ${c_source_jit} ${cpp_source_jit_cg}
                           ${cpp_source_asmjit} ${c_source_zycore} ${c_source_zydis})
