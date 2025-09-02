# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(FindPackageHandleStandardArgs)

find_path(EMSCRIPTEN_HOME
  NAMES upstream/emscripten
  PATHS /opt/emsdk
  NO_DEFAULT_PATH
  NO_CMAKE_PATH
  NO_CMAKE_SYSTEM_PATH
  NO_CMAKE_FIND_ROOT_PATH
  REQUIRED
)

find_file(EMSCRIPTEN_VERSION_FILE
  NAMES emscripten-version.txt
  PATHS ${EMSCRIPTEN_HOME}/upstream/emscripten
  NO_DEFAULT_PATH
  NO_CMAKE_PATH
  NO_CMAKE_SYSTEM_PATH
  NO_CMAKE_FIND_ROOT_PATH
  REQUIRED
)

file(READ ${EMSCRIPTEN_VERSION_FILE} EMSCRIPTEN_VERSION_FILE_CONTENT)

string(REGEX
    MATCH
    "[0-9]+\.[0-9]+(\.[0-9]+)*"
    EMSCRIPTEN_VERSION
    ${EMSCRIPTEN_VERSION_FILE_CONTENT}
)

find_package_handle_standard_args(EMSCRIPTEN
  REQUIRED_VARS EMSCRIPTEN_HOME
  VERSION_VAR EMSCRIPTEN_VERSION
  HANDLE_VERSION_RANGE
)

if(EMSCRIPTEN_FOUND)
  set(EMSCRIPTEN_TOOLCHAIN  ${EMSCRIPTEN_HOME}/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake)
  set(EMCC ${EMSCRIPTEN_HOME}/upstream/emscripten/emcc)
endif()
mark_as_advanced(EMSCRIPTEN_TOOLCHAIN EMCC)
