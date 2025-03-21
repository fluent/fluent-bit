# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
INCLUDE(CMakeForceCompiler)

SET(CMAKE_SYSTEM_NAME Linux) # this one is important
SET(CMAKE_SYSTEM_VERSION 1) # this one not so much

message(STATUS "*** ARM A7 toolchain file ***")
set(CMAKE_VERBOSE_MAKEFILE ON) 

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GNU_SOURCE")


if (NOT $ENV{ARM_A7_COMPILER_DIR} STREQUAL "") 
    SET (toolchain_sdk_dir $ENV{ARM_A7_COMPILER_DIR}/)
endif ()

if (NOT $ENV{ARM_A7_SDKTARGETSYSROOT} STREQUAL "") 
    SET(SDKTARGETSYSROOT $ENV{ARM_A7_SDKTARGETSYSROOT})
    #SET(CMAKE_SYSROOT SDKTARGETSYSROOT)
endif ()    

message(STATUS "SDKTARGETSYSROOT=${SDKTARGETSYSROOT}")
message(STATUS "toolchain_sdk_dir=${toolchain_sdk_dir}")

SET(CMAKE_C_COMPILER ${toolchain_sdk_dir}arm-linux-gnueabihf-gcc)
SET(CMAKE_CXX_COMPILER ${toolchain_sdk_dir}arm-linux-gnueabihf-g++)


# this is the file system root of the target
SET(CMAKE_FIND_ROOT_PATH ${SDKTARGETSYSROOT})

# search for programs in the build host directories
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# for libraries and headers in the target directories
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

