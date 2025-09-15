# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)

project (test-wasm-vm)

add_definitions (-DRUN_ON_LINUX)

add_definitions (-Dattr_container_malloc=malloc)
add_definitions (-Dattr_container_free=free)

set (WAMR_BUILD_APP_FRAMEWORK 1)
set (CMAKE_BUILD_TYPE Release)

include (../unit_common.cmake)

include_directories (${CMAKE_CURRENT_SOURCE_DIR})

file (GLOB_RECURSE source_all ${CMAKE_CURRENT_SOURCE_DIR}/*.cc)

set (UNIT_SOURCE ${source_all})

set (unit_test_sources
     ${UNIT_SOURCE}
     ${PLATFORM_SHARED_SOURCE}
     ${UTILS_SHARED_SOURCE}
     ${MEM_ALLOC_SHARED_SOURCE}
     ${LIB_HOST_AGENT_SOURCE}
     ${NATIVE_INTERFACE_SOURCE}
     ${LIBC_BUILTIN_SOURCE}
     ${LIBC_WASI_SOURCE}
     ${IWASM_COMMON_SOURCE}
     ${IWASM_INTERP_SOURCE}
     ${IWASM_AOT_SOURCE}
     ${IWASM_COMPL_SOURCE}
     ${WASM_APP_LIB_SOURCE_ALL}
     ${UNCOMMON_SHARED_SOURCE}
    )

# Now simply link against gtest or gtest_main as needed. Eg
add_executable(wasm_vm_test ${unit_test_sources})

target_link_libraries(wasm_vm_test ${LLVM_AVAILABLE_LIBS} gtest_main)

add_custom_command(TARGET wasm_vm_test POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_CURRENT_SOURCE_DIR}/wasm-apps/app4/*.wasm
                ${PROJECT_BINARY_DIR}/
    COMMENT "Copy wasm files to the output directory"
)

gtest_discover_tests(wasm_vm_test)
