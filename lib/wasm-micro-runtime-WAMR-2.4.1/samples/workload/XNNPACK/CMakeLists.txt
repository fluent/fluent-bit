# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)

project(xnnpack_wasm)

################  EMCC ################
include(ExternalProject)

# grep xnnpack_benchmark -A 1 BUILD.bazel \
#   | grep "name =" \
#   | awk '{print $3}' \
#   | sed -e 's/\"//g; s/,//g; s/^/\"/g; s/$/\"/g'
list(APPEND NATIVE_BENCHMARKS
  "qs8_dwconv_bench"
  "qs8_f32_vcvt_bench"
  "qs8_gemm_bench"
  "qs8_requantization_bench"
  "qs8_vadd_bench"
  "qs8_vaddc_bench"
  "qs8_vcvt_bench"
  "qs16_qs8_vcvt_bench"
  "qs8_vlrelu_bench"
  "qs8_vmul_bench"
  "qs8_vmulc_bench"
  "qu8_f32_vcvt_bench"
  "qu8_gemm_bench"
  "qu8_requantization_bench"
  "qu8_vadd_bench"
  "qu8_vaddc_bench"
  "qu8_vcvt_bench"
  "qu8_vlrelu_bench"
  "qu8_vmul_bench"
  "qu8_vmulc_bench"
  "bf16_gemm_bench"
  "f16_f32acc_igemm_bench"
  "f16_igemm_bench"
  "f16_f32acc_gemm_bench"
  "f16_gemm_bench"
  "f16_raddstoreexpminusmax_bench"
  "f16_spmm_bench"
  "f16_vsigmoid_bench"
  "f16_vtanh_bench"
  "f16_f32_vcvt_bench"
  "f32_igemm_bench"
  "f32_conv_hwc_bench"
  "f16_conv_hwc2chw_bench"
  "f16_gavgpool_cw_bench"
  "f32_gavgpool_cw_bench"
  "f32_conv_hwc2chw_bench"
  "f16_dwconv_bench"
  "f32_dwconv_bench"
  "f32_dwconv2d_chw_bench"
  "f16_dwconv2d_chw_bench"
  "f32_f16_vcvt_bench"
  "xx_transpose_bench"
  "x8_transpose_bench"
  "x16_transpose_bench"
  "x24_transpose_bench"
  "x32_transpose_bench"
  "x64_transpose_bench"
  "f32_bgemm_bench"
  "f32_gemm_bench"
  "f32_qs8_vcvt_bench"
  "f32_qu8_vcvt_bench"
  "f32_raddexpminusmax_bench"
  "f32_raddextexp_bench"
  "f32_raddstoreexpminusmax_bench"
  "f32_rmax_bench"
  "f32_spmm_bench"
  "f32_softmax_bench"
  "f16_velu_bench"
  "f32_velu_bench"
  "f32_vhswish_bench"
  "f32_vlrelu_bench"
  "f32_vrelu_bench"
  "f32_vscaleexpminusmax_bench"
  "f32_vscaleextexp_bench"
  "f32_vsigmoid_bench"
  "f16_vsqrt_bench"
  "f32_vsqrt_bench"
  "f32_vtanh_bench"
  "f32_im2col_gemm_bench"
  "rounding_bench"
  "s16_rmaxabs_bench"
  "s16_window_bench"
  "u32_filterbank_accumulate_bench"
  "u32_filterbank_subtract_bench"
  "u32_vlog_bench"
  "u64_u32_vsqrtshift_bench"
  "i16_vlshift_bench"
  "cs16_vsquareabs_bench"
  "cs16_bfly4_bench"
  "cs16_fftr_bench"
  "x8_lut_bench"
  "x32_packw_bench"
  "x16_packw_bench"
  "abs_bench"
  "average_pooling_bench"
  "bankers_rounding_bench"
  "ceiling_bench"
  "channel_shuffle_bench"
  "convert_bench"
  "convolution_bench"
  "deconvolution_bench"
  "elu_bench"
  "floor_bench"
  "global_average_pooling_bench"
  "hardswish_bench"
  "leaky_relu_bench"
  "max_pooling_bench"
  "negate_bench"
  "prelu_bench"
  "sigmoid_bench"
  "softmax_bench"
  "square_bench"
  "square_root_bench"
  "tanh_bench"
  "truncation_bench"
  "f16_dwconv_e2e_bench"
  "f16_gemm_e2e_bench"
  "f32_dwconv_e2e_bench"
  "f32_gemm_e2e_bench"
  "qs8_dwconv_e2e_bench"
  "qs8_gemm_e2e_bench"
  "qu8_gemm_e2e_bench"
  "qu8_dwconv_e2e_bench"
  "end2end_bench"
  "f16_exp_ulp_eval"
  "f16_expminus_ulp_eval"
  "f16_expm1minus_ulp_eval"
  "f16_sigmoid_ulp_eval"
  "f16_sqrt_ulp_eval"
  "f16_tanh_ulp_eval"
  "f32_exp_ulp_eval"
  "f32_expminus_ulp_eval"
  "f32_expm1minus_ulp_eval"
  "f32_extexp_ulp_eval"
  "f32_sigmoid_ulp_eval"
  "f32_sqrt_ulp_eval"
  "f32_tanh_ulp_eval"
)

# Only Download
ExternalProject_Add(xnnpack-download
    PREFIX xnnpack
    GIT_REPOSITORY https://github.com/google/XNNPACK.git
    GIT_TAG        b9d4073a6913891ce9cbd8965c8d506075d2a45a
    GIT_PROGRESS   ON
    SOURCE_DIR     ${CMAKE_CURRENT_SOURCE_DIR}/xnnpack
    UPDATE_COMMAND ""
    PATCH_COMMAND git apply ${CMAKE_CURRENT_SOURCE_DIR}/xnnpack.patch
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
    TEST_COMMAND ""
)

set(WAMRC "${CMAKE_CURRENT_SOURCE_DIR}/../../../wamr-compiler/build/wamrc")
if(EXISTS ${WAMRC})
  message("-- Will generate .aot")
else()
  message("Will generate .wasm")
endif()

foreach(BENCHMARK IN LISTS NATIVE_BENCHMARKS)
  string(CONCAT WASM_BENCHMARK "//:" ${BENCHMARK} "-wasm")
  string(CONCAT WASM_OUTPUT ${BENCHMARK} ".wasm")

  add_custom_command(
    OUTPUT ${WASM_OUTPUT}
    COMMAND bazel --output_user_root=build-user-output build -c opt --config=wasm ${WASM_BENCHMARK}
              && ${CMAKE_COMMAND} -E copy_if_different ./bazel-bin/${WASM_OUTPUT} ${CMAKE_CURRENT_BINARY_DIR}/${WASM_OUTPUT}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/xnnpack
    DEPENDS xnnpack-download
    COMMENT "Generating ${WASM_OUTPUT} ..."
  )

  set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_CLEAN_FILES ${CMAKE_CURRENT_BINARY_DIR}/${WASM_OUTPUT})

  if(EXISTS ${WAMRC})
    string(CONCAT AOT_OUTPUT ${BENCHMARK} ".aot")

    add_custom_command(
      OUTPUT ${AOT_OUTPUT}
      COMMAND ${WAMRC} -o ${AOT_OUTPUT} ${WASM_OUTPUT}
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      DEPENDS ${WASM_OUTPUT}
      COMMENT "Generating ${AOT_OUTPUT} ..."
    )

    add_custom_target(${BENCHMARK} ALL DEPENDS ${AOT_OUTPUT})
  else()
    add_custom_target(${BENCHMARK} ALL DEPENDS ${WASM_OUTPUT})
  endif()
endforeach()

