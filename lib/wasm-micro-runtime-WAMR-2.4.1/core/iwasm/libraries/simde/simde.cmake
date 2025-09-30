# Copyright (C) 2024 Amazon Inc.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# simde is a header only library

# Yes. To solve the compatibility issue with CMAKE (>= 4.0), we need to update
# our `cmake_minimum_required()` to 3.5. However, there are CMakeLists.txt
# from 3rd parties that we should not alter. Therefore, in addition to
# changing the `cmake_minimum_required()`, we should also add a configuration
# here that is compatible with earlier versions.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 FORCE)

set (LIB_SIMDE_DIR ${CMAKE_CURRENT_LIST_DIR})

add_definitions (-DWASM_ENABLE_SIMDE=1)

include_directories(${LIB_SIMDE_DIR} ${LIB_SIMDE_DIR}/simde)

include(FetchContent)

FetchContent_Declare(
    simde
    GIT_REPOSITORY  https://github.com/simd-everywhere/simde
    GIT_TAG v0.8.2
)

message("-- Fetching simde ..")
FetchContent_MakeAvailable(simde)
include_directories("${simde_SOURCE_DIR}")
