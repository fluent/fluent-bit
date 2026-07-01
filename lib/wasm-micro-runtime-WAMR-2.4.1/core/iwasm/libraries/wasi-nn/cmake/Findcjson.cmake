# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# Yes. To solve the compatibility issue with CMAKE (>= 4.0), we need to update
# our `cmake_minimum_required()` to 3.5. However, there are CMakeLists.txt
# from 3rd parties that we should not alter. Therefore, in addition to
# changing the `cmake_minimum_required()`, we should also add a configuration
# here that is compatible with earlier versions.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 FORCE)

include(FetchContent)

set(CJSON_SOURCE_DIR "${WAMR_ROOT_DIR}/core/deps/cjson")
if(EXISTS ${CJSON_SOURCE_DIR})
  message("Use existed source code under ${CJSON_SOURCE_DIR}")
  FetchContent_Declare(
    cjson
    SOURCE_DIR     ${CJSON_SOURCE_DIR}
  )
else()
  message("download source code and store it at ${CJSON_SOURCE_DIR}")
  FetchContent_Declare(
    cjson
    GIT_REPOSITORY https://github.com/DaveGamble/cJSON.git
    GIT_TAG        v1.7.18
    SOURCE_DIR     ${CJSON_SOURCE_DIR}
  )
endif()

set(ENABLE_CJSON_TEST OFF CACHE INTERNAL "Turn off tests")
set(ENABLE_CJSON_UNINSTALL OFF CACHE INTERNAL "Turn off uninstall to avoid targets conflict")
FetchContent_MakeAvailable(cjson)
