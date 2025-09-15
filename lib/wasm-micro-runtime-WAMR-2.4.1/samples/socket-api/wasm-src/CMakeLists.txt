# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)
project(socket_api_sample_wasm_app)

message(CHECK_START "Detecting WABT")
if(NOT (DEFINED WABT_DIR OR DEFINED CACHE{WABT_DIR}))
  find_path(WABT_DIR
    wabt
    PATHS /opt
    NO_DEFAULT_PATH
    NO_CMAKE_FIND_ROOT_PATH
  )
  if(DEFINED WABT_DIR)
    set(WABT_DIR ${WABT_DIR}/wabt)
  endif()
endif()
if(WABT_DIR)
  message(CHECK_PASS "found")
else()
  message(CHECK_FAIL "not found")
endif()

message(CHECK_START "Detecting WASM_OBJDUMP at ${WABT_DIR}")
find_program(WASM_OBJDUMP
  wasm-objdump
  PATHS "${WABT_DIR}/bin"
  NO_DEFAULT_PATH
  NO_CMAKE_FIND_ROOT_PATH
)
if(WASM_OBJDUMP)
  message(CHECK_PASS "found")
else()
  message(CHECK_FAIL "not found")
endif()

set(SRC ${CMAKE_CURRENT_SOURCE_DIR})

include(${CMAKE_CURRENT_SOURCE_DIR}/../../../core/iwasm/libraries/lib-socket/lib_socket_wasi.cmake)

function(COMPILE_WITH_CLANG SOURCE_FILE)
  get_filename_component(FILE_NAME ${SOURCE_FILE} NAME_WLE)

  set(WASM_MODULE ${FILE_NAME}.wasm)

  set(MAIN_TARGET_NAME MODULE_${FILE_NAME})

  add_executable(${MAIN_TARGET_NAME} ${SOURCE_FILE})
  set_target_properties(${MAIN_TARGET_NAME} PROPERTIES OUTPUT_NAME ${WASM_MODULE})
  target_include_directories(${MAIN_TARGET_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/inc)
  target_compile_options(${MAIN_TARGET_NAME} INTERFACE -pthread)
  target_link_libraries(${MAIN_TARGET_NAME} socket_wasi_ext)
  target_link_options(${MAIN_TARGET_NAME} PRIVATE
    LINKER:--export=__heap_base
    LINKER:--export=__data_end
    LINKER:--export=malloc
    LINKER:--export=free
    LINKER:--shared-memory,--max-memory=10485760
    LINKER:--no-check-features
    LINKER:--allow-undefined
  )

  if(EXISTS ${WASM_OBJDUMP})
    message(STATUS "Dumping ${WASM_MODULE}...")
    set(WASM_DUMP ${WASM_MODULE}.dump)
    set(DUMP_TARGET_NAME DUMP_${FILE_NAME})

    add_custom_command(OUTPUT ${WASM_DUMP}
      COMMAND ${WASM_OBJDUMP} -dx ${WASM_MODULE} > ${WASM_DUMP}
      COMMENT "Dumping ${WASM_MODULE}..."
      DEPENDS ${MAIN_TARGET_NAME}
    )

    add_custom_target(${DUMP_TARGET_NAME} ALL
      DEPENDS ${WASM_DUMP}
    )
  endif()
endfunction()

compile_with_clang(tcp_server.c)
compile_with_clang(tcp_client.c)
compile_with_clang(send_recv.c)
compile_with_clang(addr_resolve.c)
compile_with_clang(socket_opts.c)
compile_with_clang(udp_client.c)
compile_with_clang(udp_server.c)
compile_with_clang(multicast_client.c)
compile_with_clang(multicast_server.c)
compile_with_clang(timeout_client.c)
compile_with_clang(timeout_server.c)
