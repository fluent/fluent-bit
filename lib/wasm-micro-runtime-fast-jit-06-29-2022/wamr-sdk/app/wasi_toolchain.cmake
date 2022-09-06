# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

SET(CMAKE_SYSTEM_NAME Linux)

if (NOT DEFINED WASI_SDK_DIR)
    SET (WASI_SDK_DIR               "/opt/wasi-sdk")
endif ()

SET (CMAKE_C_COMPILER               "${WASI_SDK_DIR}/bin/clang")
SET (CMAKE_CXX_COMPILER             "${WASI_SDK_DIR}/bin/clang++")

SET (CMAKE_LINKER  "${WASI_SDK_DIR}/bin/wasm-ld"            CACHE INTERNAL "")
SET (CMAKE_AR      "${WASI_SDK_DIR}/bin/llvm-ar"            CACHE INTERNAL "")
SET (CMAKE_NM      "${WASI_SDK_DIR}/bin/llvm-nm"            CACHE INTERNAL "")
SET (CMAKE_OBJDUMP "${WASI_SDK_DIR}/bin/llvm-dwarfdump"     CACHE INTERNAL "")
SET (CMAKE_RANLIB  "${WASI_SDK_DIR}/bin/llvm-ranlib"        CACHE INTERNAL "")
