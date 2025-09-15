# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)
project(wasm-apps)

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

message(CHECK_START "Detecting WASM2WAT at ${WABT_DIR}")
find_program(WASM2WAT
  wasm2wat
  PATHS "${WABT_DIR}/bin"
  NO_DEFAULT_PATH
  NO_CMAKE_FIND_ROOT_PATH
)
if(WASM2WAT)
  message(CHECK_PASS "found")
else()
  message(CHECK_FAIL "not found")
endif()

function(COMPILE_WITH_CLANG SOURCE_FILE COMMAND)
  get_filename_component(FILE_NAME ${SOURCE_FILE} NAME_WLE)

  set(WASM_MODULE ${FILE_NAME}.wasm)

  set(MAIN_TARGET_NAME MODULE_${FILE_NAME})

  add_executable(${MAIN_TARGET_NAME} ${SOURCE_FILE})
  set_target_properties(${MAIN_TARGET_NAME} PROPERTIES OUTPUT_NAME ${WASM_MODULE})
  target_compile_options (${MAIN_TARGET_NAME} PRIVATE -fno-exceptions)

  if(${COMMAND})
    message(STATUS "Generating ${WASM_MODULE} as COMMAND...")
  else()
    message(STATUS "Generating ${WASM_MODULE} as REACTOR...")
    target_link_options(${MAIN_TARGET_NAME} PRIVATE -mexec-model=reactor)
  endif()

  if(EXISTS ${WASM2WAT})
    message(STATUS "Dumping ${WASM_MODULE}...")
    set(WASM_WAT ${FILE_NAME}.wat)
    set(DUMP_TARGET_NAME DUMP_${FILE_NAME})
    add_custom_command(OUTPUT ${WASM_WAT}
      COMMAND ${WASM2WAT} --enable-all -o ${WASM_WAT} ${WASM_MODULE}
      COMMENT "Dumping ${WASM_MODULE}..."
      DEPENDS ${MAIN_TARGET_NAME}
    )

    add_custom_target(${DUMP_TARGET_NAME} ALL
      DEPENDS ${WASM_WAT}
    )
  endif()
endfunction()

compile_with_clang(mA.c OFF)
compile_with_clang(mB.c OFF)
compile_with_clang(mC.c ON)
compile_with_clang(mD.cpp ON)
compile_with_clang(mE.cpp OFF)

