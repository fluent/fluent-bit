# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# Yes. To solve the compatibility issue with CMAKE (>= 4.0), we need to update
# our `cmake_minimum_required()` to 3.5. However, there are CMakeLists.txt
# from 3rd parties that we should not alter. Therefore, in addition to
# changing the `cmake_minimum_required()`, we should also add a configuration
# here that is compatible with earlier versions.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 FORCE)

include(FetchContent)

set(LLAMA_SOURCE_DIR "${WAMR_ROOT_DIR}/core/deps/llama.cpp")
if(EXISTS ${LLAMA_SOURCE_DIR})
  message("Use existed source code under ${LLAMA_SOURCE_DIR}")
  FetchContent_Declare(
    llamacpp
    SOURCE_DIR     ${LLAMA_SOURCE_DIR}
  )
else()
  message("download source code and store it at ${LLAMA_SOURCE_DIR}")
  FetchContent_Declare(
    llamacpp
    GIT_REPOSITORY https://github.com/ggerganov/llama.cpp.git
    GIT_TAG        b3573
    SOURCE_DIR     ${LLAMA_SOURCE_DIR}
  )
endif()

set(LLAMA_BUILD_TESTS OFF)
set(LLAMA_BUILD_EXAMPLES OFF)
set(LLAMA_BUILD_SERVER OFF)
FetchContent_MakeAvailable(llamacpp)
