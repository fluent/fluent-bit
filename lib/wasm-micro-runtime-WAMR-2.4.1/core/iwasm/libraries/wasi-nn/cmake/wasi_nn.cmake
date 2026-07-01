# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR})

#
# wasi-nn general
set(WASI_NN_ROOT ${CMAKE_CURRENT_LIST_DIR}/..)
set(WASI_NN_SOURCES
  ${WASI_NN_ROOT}/src/wasi_nn.c
  ${WASI_NN_ROOT}/src/utils/wasi_nn_app_native.c
)
include_directories(${WASI_NN_ROOT}/include)
add_compile_definitions(
  $<$<CONFIG:Debug>:NN_LOG_LEVEL=0>
  $<$<CONFIG:Release>:NN_LOG_LEVEL=2>
)

#
# wasi-nn backends
#
# - tflite
if(WAMR_BUILD_WASI_NN_TFLITE EQUAL 1)
  find_package(tensorflow_lite REQUIRED)
  enable_language(CXX)

  add_library(
    wasi_nn_tflite
    SHARED
      ${WASI_NN_ROOT}/src/wasi_nn_tensorflowlite.cpp
  )

  target_include_directories(
    wasi_nn_tflite
    PUBLIC
      ${tensorflow_lite_SOURCE_DIR}
  )

  target_link_libraries(
    wasi_nn_tflite
    PUBLIC
      vmlib
      tensorflow-lite
  )

  install(TARGETS wasi_nn_tflite DESTINATION lib)
endif()

# - openvino
if(WAMR_BUILD_WASI_NN_OPENVINO EQUAL 1)
  if(NOT DEFINED ENV{OpenVINO_DIR})
    message(FATAL_ERROR
        "OpenVINO_DIR is not defined. "
        "Please follow https://docs.openvino.ai/2024/get-started/install-openvino.html,"
        "install openvino, and set environment variable OpenVINO_DIR."
        "Like OpenVINO_DIR=/usr/lib/openvino-2023.2/ cmake ..."
        "Or OpenVINO_DIR=/opt/intel/openvino/ cmake ..."
    )
  endif()

  list(APPEND CMAKE_MODULE_PATH $ENV{OpenVINO_DIR})
  # Find OpenVINO
  find_package(OpenVINO REQUIRED COMPONENTS Runtime)

  add_library(
    wasi_nn_openvino
    SHARED
      ${WASI_NN_ROOT}/src/wasi_nn_openvino.c
  )

  target_link_libraries(
    wasi_nn_openvino
    PUBLIC
      vmlib
      openvino::runtime
      openvino::runtime::c
  )

  install(TARGETS wasi_nn_openvino DESTINATION lib)
endif()

# - llamacpp

if(WAMR_BUILD_WASI_NN_LLAMACPP EQUAL 1)
  find_package(cjson REQUIRED)
  find_package(llamacpp REQUIRED)

  add_library(
    wasi_nn_llamacpp
    SHARED
      ${WASI_NN_ROOT}/src/wasi_nn_llamacpp.c
  )

  target_include_directories(
    wasi_nn_llamacpp
    PUBLIC
      ${cjson_SOURCE_DIR}
  )

  target_link_libraries(
    wasi_nn_llamacpp
    PUBLIC
      vmlib
      cjson
      common
      ggml
      llama
  )

  install(TARGETS wasi_nn_llamacpp DESTINATION lib)
endif()
