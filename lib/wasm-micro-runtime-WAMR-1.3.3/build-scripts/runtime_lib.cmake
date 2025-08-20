# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

if (NOT DEFINED WAMR_ROOT_DIR)
    set (WAMR_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../)
endif ()
if (NOT DEFINED SHARED_DIR)
    set (SHARED_DIR ${WAMR_ROOT_DIR}/core/shared)
endif ()
if (NOT DEFINED IWASM_DIR)
    set (IWASM_DIR ${WAMR_ROOT_DIR}/core/iwasm)
endif ()
if (NOT DEFINED APP_MGR_DIR)
    set (APP_MGR_DIR ${WAMR_ROOT_DIR}/core/app-mgr)
endif ()
if (NOT DEFINED APP_FRAMEWORK_DIR)
    set (APP_FRAMEWORK_DIR ${WAMR_ROOT_DIR}/core/app-framework)
endif ()
if (NOT DEFINED DEPS_DIR)
    set (DEPS_DIR ${WAMR_ROOT_DIR}/core/deps)
endif ()
if (NOT DEFINED SHARED_PLATFORM_CONFIG)
    # CMake file for platform configuration. The PLATFORM_SHARED_SOURCE varable
    # should point to a list of platform-specfic source files to compile.
    set (SHARED_PLATFORM_CONFIG ${SHARED_DIR}/platform/${WAMR_BUILD_PLATFORM}/shared_platform.cmake)
endif ()

if (DEFINED EXTRA_SDK_INCLUDE_PATH)
    message(STATUS, "EXTRA_SDK_INCLUDE_PATH = ${EXTRA_SDK_INCLUDE_PATH} ")
    include_directories (
        ${EXTRA_SDK_INCLUDE_PATH}
    )
endif ()

# Set default options

# Set WAMR_BUILD_TARGET, currently values supported:
# "X86_64", "AMD_64", "X86_32", "AARCH64[sub]", "ARM[sub]", "THUMB[sub]",
# "MIPS", "XTENSA", "RISCV64[sub]", "RISCV32[sub]"
if (NOT DEFINED WAMR_BUILD_TARGET)
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)")
        set (WAMR_BUILD_TARGET "AARCH64")
    elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "riscv64")
        set (WAMR_BUILD_TARGET "RISCV64")
    elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)
        # Build as X86_64 by default in 64-bit platform
        set (WAMR_BUILD_TARGET "X86_64")
    elseif (CMAKE_SIZEOF_VOID_P EQUAL 4)
        # Build as X86_32 by default in 32-bit platform
        set (WAMR_BUILD_TARGET "X86_32")
    else ()
        message(SEND_ERROR "Unsupported build target platform!")
    endif ()
endif ()

################ optional according to settings ################
if (WAMR_BUILD_FAST_JIT EQUAL 1 OR WAMR_BUILD_JIT EQUAL 1)
    # Enable classic interpreter if Fast JIT or LLVM JIT is enabled
    set (WAMR_BUILD_INTERP 1)
    set (WAMR_BUILD_FAST_INTERP 0)
endif ()

if (WAMR_BUILD_INTERP EQUAL 1)
    include (${IWASM_DIR}/interpreter/iwasm_interp.cmake)
endif ()

if (WAMR_BUILD_FAST_JIT EQUAL 1)
    include (${IWASM_DIR}/fast-jit/iwasm_fast_jit.cmake)
endif ()

if (WAMR_BUILD_JIT EQUAL 1)
    # Enable AOT if LLVM JIT is enabled
    set (WAMR_BUILD_AOT 1)
    include (${IWASM_DIR}/compilation/iwasm_compl.cmake)
endif ()

if (WAMR_BUILD_AOT EQUAL 1)
    include (${IWASM_DIR}/aot/iwasm_aot.cmake)
endif ()

if (WAMR_BUILD_APP_FRAMEWORK EQUAL 1)
    include (${APP_FRAMEWORK_DIR}/app_framework.cmake)
    include (${SHARED_DIR}/coap/lib_coap.cmake)
    include (${APP_MGR_DIR}/app-manager/app_mgr.cmake)
    include (${APP_MGR_DIR}/app-mgr-shared/app_mgr_shared.cmake)
endif ()

if (WAMR_BUILD_LIBC_BUILTIN EQUAL 1)
    include (${IWASM_DIR}/libraries/libc-builtin/libc_builtin.cmake)
endif ()

if (WAMR_BUILD_LIBC_UVWASI EQUAL 1)
    include (${IWASM_DIR}/libraries/libc-uvwasi/libc_uvwasi.cmake)
    set (WAMR_BUILD_MODULE_INST_CONTEXT 1)
elseif (WAMR_BUILD_LIBC_WASI EQUAL 1)
    include (${IWASM_DIR}/libraries/libc-wasi/libc_wasi.cmake)
    set (WAMR_BUILD_MODULE_INST_CONTEXT 1)
endif ()

if (WAMR_BUILD_LIB_PTHREAD_SEMAPHORE EQUAL 1)
    # Enable the dependent feature if lib pthread semaphore is enabled
    set (WAMR_BUILD_LIB_PTHREAD 1)
endif ()

if (WAMR_BUILD_WASI_NN EQUAL 1)
    include (${IWASM_DIR}/libraries/wasi-nn/cmake/wasi_nn.cmake)
endif ()

if (WAMR_BUILD_LIB_PTHREAD EQUAL 1)
    include (${IWASM_DIR}/libraries/lib-pthread/lib_pthread.cmake)
    # Enable the dependent feature if lib pthread is enabled
    set (WAMR_BUILD_THREAD_MGR 1)
    set (WAMR_BUILD_BULK_MEMORY 1)
    set (WAMR_BUILD_SHARED_MEMORY 1)
endif ()

if (WAMR_BUILD_LIB_WASI_THREADS EQUAL 1)
    include (${IWASM_DIR}/libraries/lib-wasi-threads/lib_wasi_threads.cmake)
    # Enable the dependent feature if lib wasi threads is enabled
    set (WAMR_BUILD_THREAD_MGR 1)
    set (WAMR_BUILD_BULK_MEMORY 1)
    set (WAMR_BUILD_SHARED_MEMORY 1)
endif ()

if (WAMR_BUILD_DEBUG_INTERP EQUAL 1)
    set (WAMR_BUILD_THREAD_MGR 1)
    include (${IWASM_DIR}/libraries/debug-engine/debug_engine.cmake)

    if (WAMR_BUILD_FAST_INTERP EQUAL 1)
        set (WAMR_BUILD_FAST_INTERP 0)
        message(STATUS
                "Debugger doesn't work with fast interpreter, switch to classic interpreter")
    endif ()
endif ()

if (WAMR_BUILD_THREAD_MGR EQUAL 1)
    include (${IWASM_DIR}/libraries/thread-mgr/thread_mgr.cmake)
endif ()

if (WAMR_BUILD_LIBC_EMCC EQUAL 1)
    include (${IWASM_DIR}/libraries/libc-emcc/libc_emcc.cmake)
endif ()

if (WAMR_BUILD_LIB_RATS EQUAL 1)
    include (${IWASM_DIR}/libraries/lib-rats/lib_rats.cmake)
endif ()

if (WAMR_BUILD_WASM_CACHE EQUAL 1)
    include (${WAMR_ROOT_DIR}/build-scripts/involve_boringssl.cmake)
endif ()

####################### Common sources #######################
if (NOT MSVC)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -ffunction-sections -fdata-sections \
                                         -Wall -Wno-unused-parameter -Wno-pedantic")
endif ()

# include the build config template file
include (${CMAKE_CURRENT_LIST_DIR}/config_common.cmake)

include_directories (${IWASM_DIR}/include)

file (GLOB header
    ${IWASM_DIR}/include/*.h
)
LIST (APPEND RUNTIME_LIB_HEADER_LIST ${header})

if (WAMR_BUILD_PLATFORM STREQUAL "windows")
    enable_language (ASM_MASM)
else()
    enable_language (ASM)
endif()

include (${SHARED_PLATFORM_CONFIG})
include (${SHARED_DIR}/mem-alloc/mem_alloc.cmake)
include (${IWASM_DIR}/common/iwasm_common.cmake)
include (${SHARED_DIR}/utils/shared_utils.cmake)


set (source_all
    ${PLATFORM_SHARED_SOURCE}
    ${MEM_ALLOC_SHARED_SOURCE}
    ${UTILS_SHARED_SOURCE}
    ${LIBC_BUILTIN_SOURCE}
    ${LIBC_WASI_SOURCE}
    ${WASI_NN_SOURCES}
    ${IWASM_COMMON_SOURCE}
    ${IWASM_INTERP_SOURCE}
    ${IWASM_AOT_SOURCE}
    ${IWASM_COMPL_SOURCE}
    ${IWASM_FAST_JIT_SOURCE}
    ${WASM_APP_LIB_SOURCE_ALL}
    ${NATIVE_INTERFACE_SOURCE}
    ${APP_MGR_SOURCE}
    ${LIB_WASI_THREADS_SOURCE}
    ${LIB_PTHREAD_SOURCE}
    ${THREAD_MGR_SOURCE}
    ${LIBC_EMCC_SOURCE}
    ${LIB_RATS_SOURCE}
    ${DEBUG_ENGINE_SOURCE}
)

set (WAMR_RUNTIME_LIB_SOURCE ${source_all})
