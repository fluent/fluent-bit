# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 2.8)
project(app-framework)

SET (CMAKE_C_FLAGS "-O3")

if (NOT DEFINED WAMR_BUILD_SDK_PROFILE)
    set (WAMR_BUILD_SDK_PROFILE       "default")
endif ()

if (NOT DEFINED CONFIG_PATH)
    set (CONFIG_PATH       ${CMAKE_CURRENT_LIST_DIR}/../wamr_config_default.cmake)
    message(STATUS "CONFIG_PATH  set to ${CONFIG_PATH} ")
endif ()

if (NOT EXISTS "${CONFIG_PATH}")
    message (FATAL_ERROR "${CONFIG_PATH} not exist")
endif ()

include(${CONFIG_PATH})

if (NOT DEFINED OUT_DIR)
    set (OUT_DIR      "${CMAKE_CURRENT_LIST_DIR}/../out/${WAMR_BUILD_SDK_PROFILE}")
endif ()
set (APP_SDK_DIR  "${OUT_DIR}/app-sdk")

if (DEFINED EXTRA_SDK_INCLUDE_PATH)
    message(STATUS, "EXTRA_SDK_INCLUDE_PATH = ${EXTRA_SDK_INCLUDE_PATH} ")
    include_directories (
        ${EXTRA_SDK_INCLUDE_PATH}
    )
endif ()

if (WAMR_BUILD_LIBC_BUILTIN EQUAL 1)
    set (SYSROOT_DIR  "${APP_SDK_DIR}/libc-builtin-sysroot")
    execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory ${SYSROOT_DIR}/include)
    execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory ${SYSROOT_DIR}/share)
    execute_process(COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/libc-builtin-sysroot/share/defined-symbols.txt ${SYSROOT_DIR}/share)
    execute_process(COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/wamr_toolchain.cmake ${APP_SDK_DIR})
    execute_process(
        COMMAND ${CMAKE_COMMAND}
        -E copy_directory ${CMAKE_CURRENT_LIST_DIR}/libc-builtin-sysroot/include ${SYSROOT_DIR}/include
    )
else()
    if (WAMR_BUILD_LIBC_WASI EQUAL 1)
        set (SYSROOT_DIR  "${APP_SDK_DIR}/wasi-sysroot")
        message("sysroot: ${SYSROOT_DIR}")
        execute_process(COMMAND ln -s ${WASI_SDK_DIR}/share/wasi-sysroot ${SYSROOT_DIR})
        execute_process(COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/wasi_toolchain.cmake ${APP_SDK_DIR}/wamr_toolchain.cmake)
    endif ()
endif()

if (WAMR_BUILD_APP_FRAMEWORK EQUAL 1)
    message(WAMR_BUILD_APP_FRAMEWORK)
    set (APP_FRAMEWORK_INCLUDE_TYPE     "APP")
    set (WAMR_APP_OUT_DIR  "${APP_SDK_DIR}/wamr-app-framework")

    include(${CMAKE_CURRENT_LIST_DIR}/../../core/app-framework/app_framework.cmake)

    add_library(app_framework
        ${WASM_APP_SOURCE_ALL}
    )

    add_custom_command(
        TARGET app_framework POST_BUILD

        COMMAND ${CMAKE_COMMAND} -E make_directory ${WAMR_APP_OUT_DIR}/lib
        COMMAND ${CMAKE_COMMAND} -E make_directory ${WAMR_APP_OUT_DIR}/include/wa-inc
        COMMAND ${CMAKE_COMMAND} -E make_directory ${WAMR_APP_OUT_DIR}/share
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${WASM_APP_BI_INC_DIR} ${WAMR_APP_OUT_DIR}/include/bi-inc
        COMMAND ${CMAKE_COMMAND} -E copy ${WASM_APP_BASE_DIR}/bh_platform.h ${WAMR_APP_OUT_DIR}/include
        COMMAND ${CMAKE_COMMAND} -E copy ${WASM_APP_BASE_DIR}/wasm_app.h ${WAMR_APP_OUT_DIR}/include
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/*.a ${WAMR_APP_OUT_DIR}/lib

        # bi-inc folder should also copy into runtime-sdk
        COMMAND ${CMAKE_COMMAND} -E make_directory ${OUT_DIR}/runtime-sdk/include
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${WASM_APP_BI_INC_DIR} ${OUT_DIR}/runtime-sdk/include/bi-inc
    )

    # If app-framework is enabled, add the undefined-symbol list to the toolchain file
    if (WAMR_BUILD_LIBC_WASI EQUAL 1)
        file (APPEND
            ${APP_SDK_DIR}/wamr_toolchain.cmake
            "SET (CMAKE_EXE_LINKER_FLAGS \"\${CMAKE_EXE_LINKER_FLAGS},--allow-undefined-file=\${CMAKE_CURRENT_LIST_DIR}/wamr-app-framework/share/defined-symbols.txt\" CACHE INTERNAL \"\")"
        )
    endif ()

    FOREACH (dir IN LISTS WASM_APP_WA_INC_DIR_LIST)
        file (COPY ${dir} DESTINATION ${WAMR_APP_OUT_DIR}/include/)
    ENDFOREACH (dir)

    if (DEFINED EXTRA_SDK_INCLUDE_PATH)
        execute_process(COMMAND ${CMAKE_COMMAND} -E copy_directory ${EXTRA_SDK_INCLUDE_PATH} ${WAMR_APP_OUT_DIR}/include)
    endif ()

endif()
