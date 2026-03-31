# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (PLATFORM_SHARED_DIR ${CMAKE_CURRENT_LIST_DIR})

add_definitions(-DBH_PLATFORM_ESP_IDF)

include_directories(${PLATFORM_SHARED_DIR})
include_directories(${PLATFORM_SHARED_DIR}/../include)

file (GLOB_RECURSE source_all ${PLATFORM_SHARED_DIR}/*.c)

include (${CMAKE_CURRENT_LIST_DIR}/../common/libc-util/platform_common_libc_util.cmake)
set (source_all ${source_all} ${PLATFORM_COMMON_LIBC_UTIL_SOURCE})

set (PLATFORM_SHARED_SOURCE ${source_all} ${PLATFORM_COMMON_MATH_SOURCE})

# If enable PSRAM of ESP32-S3, it had better to put AOT into PSRAM, so that
# users can use SRAM to for Wi-Fi/BLE and peripheral driver.
if(CONFIG_ESP32S3_SPIRAM_SUPPORT)
    add_definitions(-DWASM_MEM_DUAL_BUS_MIRROR=1)
endif()
