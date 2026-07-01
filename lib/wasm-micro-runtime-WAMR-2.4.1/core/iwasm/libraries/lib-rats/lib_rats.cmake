# Copyright (c) 2022 Intel Corporation
# Copyright (c) 2020-2021 Alibaba Cloud
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# Yes. To solve the compatibility issue with CMAKE (>= 4.0), we need to update
# our `cmake_minimum_required()` to 3.5. However, there are CMakeLists.txt
# from 3rd parties that we should not alter. Therefore, in addition to
# changing the `cmake_minimum_required()`, we should also add a configuration
# here that is compatible with earlier versions.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 FORCE)

set (LIB_RATS_DIR ${CMAKE_CURRENT_LIST_DIR})

if ("$ENV{SGX_SSL_DIR}" STREQUAL "")
  set (SGX_SSL_DIR "/opt/intel/sgxssl")
else()
  set (SGX_SSL_DIR $ENV{SGX_SSL_DIR})
endif()

if (NOT EXISTS ${SGX_SSL_DIR})
    message(FATAL_ERROR "Can not find SGX_SSL, please install it first")
endif()

add_definitions (-DWASM_ENABLE_LIB_RATS=1)

include_directories(${LIB_RATS_DIR} ${SGX_SSL_DIR}/include)

include(FetchContent)

set(RATS_BUILD_MODE "sgx"
    CACHE INTERNAL "Select build mode for librats(host|occlum|sgx｜wasm)")
set(RATS_INSTALL_PATH  "${CMAKE_BINARY_DIR}/librats" CACHE INTERNAL "")
set(BUILD_SAMPLES OFF CACHE BOOL "Disable de compilation of the librats samples" FORCE)

FetchContent_Declare(
    librats
    GIT_REPOSITORY https://github.com/inclavare-containers/librats
    GIT_TAG master
)
FetchContent_GetProperties(librats)
if (NOT librats_POPULATED)
    message("-- Fetching librats ..")
    FetchContent_Populate(librats)
    include_directories("${librats_SOURCE_DIR}/include")
    
    # Prevent the propagation of the CMAKE_C_FLAGS of WAMR into librats
    set(SAVED_CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
    set(CMAKE_C_FLAGS "")

    # Import the building scripts of librats
    add_subdirectory(${librats_SOURCE_DIR} ${librats_BINARY_DIR} EXCLUDE_FROM_ALL)

    # Restore the CMAKE_C_FLAGS of WAMR
    set(CMAKE_C_FLAGS ${SAVED_CMAKE_C_FLAGS})

endif()

file (GLOB source_all ${LIB_RATS_DIR}/*.c)

set (LIB_RATS_SOURCE ${source_all})