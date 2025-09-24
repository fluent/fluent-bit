# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)
project(wasm_modules)

if(NOT SOCKET_WASI_CMAKE)
  message(FATAL_ERROR "Require SOCKET_WASI_CMAKE")
endif()

option(WASM_TO_AOT "transfer wasm to aot" OFF)
if(WASM_TO_AOT AND NOT WAMRC_PATH)
  message(FATAL_ERROR "Require WAMRC_PATH when WASM_TO_AOT is ON")
endif()

#
# c -> wasm
include(${SOCKET_WASI_CMAKE})
add_executable(send_recv ${CMAKE_CURRENT_LIST_DIR}/send_recv.c)
set_target_properties(send_recv PROPERTIES SUFFIX .wasm)
target_include_directories(send_recv PUBLIC ${CMAKE_CURRENT_LIST_DIR}/inc)
target_link_libraries(send_recv socket_wasi_ext)
target_link_options(send_recv PRIVATE
  LINKER:--export=__heap_base
  LINKER:--export=__data_end
  LINKER:--shared-memory,--max-memory=196608
  LINKER:--no-check-features
  LINKER:--allow-undefined
)

if(WASM_TO_AOT)
  # wasm -> aot
  add_custom_target(send_recv_aot ALL
    COMMAND pwd && ${WAMRC_PATH} --invoke-c-api-import --enable-multi-thread -o ./send_recv.aot ./send_recv.wasm
    DEPENDS send_recv
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )
endif()

#
# install
if(WASM_TO_AOT)
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/send_recv.aot DESTINATION . )
else()
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/send_recv.wasm DESTINATION . )
endif()

