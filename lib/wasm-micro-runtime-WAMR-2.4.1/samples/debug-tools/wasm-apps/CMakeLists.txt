# Copyright (C) 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)

project (debut_tools_wasm)

set (CMAKE_BUILD_TYPE Debug)  # Otherwise no debug symbols (addr2line)

list (APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/../../cmake)
find_package (WAMRC REQUIRED)

option(SOURCE_MAP_DEMO "Enable source map demo" OFF)
if (SOURCE_MAP_DEMO)
  find_package(EMSCRIPTEN 3.1.50 REQUIRED)
endif ()

################ wasm and aot compilation ################
function (compile_sample SOURCE_FILE)
  get_filename_component (FILE_NAME ${SOURCE_FILE} NAME_WLE)

  ## wasm
  set (WASM_FILE ${FILE_NAME}.wasm)
  add_executable (${FILE_NAME} ${SOURCE_FILE})
  set_target_properties (${FILE_NAME} PROPERTIES SUFFIX .wasm)

  ## aot
  set (AOT_FILE ${FILE_NAME}.aot)
  add_custom_target (
    ${FILE_NAME}_aot
    ALL
    DEPENDS ${WAMRC_BIN} ${WASM_FILE}
    # Use --enable-dump-call-stack to generate stack trace (addr2line)
    COMMAND ${WAMRC_BIN} --size-level=0 --enable-dump-call-stack -o ${AOT_FILE} ${WASM_FILE}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )

  ## wasm + sourcemap
  if (DEFINED EMSCRIPTEN)
    add_custom_target(
      ${FILE_NAME}_w_sourcemap
      ALL
      DEPENDS ${SOURCE_FILE}
      COMMAND ${EMCC} -O0 -gsource-map -o ${FILE_NAME}.sourcemap.wasm ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_FILE}
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
  endif ()

  ## install both
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${WASM_FILE} DESTINATION wasm-apps)
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${AOT_FILE}  DESTINATION wasm-apps)
  if (DEFINED EMSCRIPTEN)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${FILE_NAME}.sourcemap.wasm DESTINATION wasm-apps)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${FILE_NAME}.sourcemap.wasm.map DESTINATION wasm-apps)
  endif ()
endfunction ()

compile_sample(trap.c)
