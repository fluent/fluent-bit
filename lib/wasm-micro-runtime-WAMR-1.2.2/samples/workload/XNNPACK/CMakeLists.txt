# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.0)

project(xnnpack_wasm)

################  EMCC ################
include(ExternalProject)

ExternalProject_Add(xnnpack
    PREFIX xnnpack
    GIT_REPOSITORY https://github.com/google/XNNPACK.git
    GIT_TAG        4570a7151aa4f3e57eca14a575eeff6bb13e26be
    GIT_PROGRESS   ON
    SOURCE_DIR     ${CMAKE_CURRENT_SOURCE_DIR}/xnnpack
    UPDATE_COMMAND git restore .
                   && cmake -E copy ${CMAKE_CURRENT_SOURCE_DIR}/xnnpack/google3/third_party/XNNPACK/microkernels.bzl
                      ${CMAKE_CURRENT_SOURCE_DIR}/xnnpack/
                   && git apply ${CMAKE_CURRENT_SOURCE_DIR}/xnnpack.patch
    CONFIGURE_COMMAND ""
    # grep xnnpack_benchmark -A 1 BUILD.bazel \
    #   | grep "name =" \
    #   | awk '{print $3}' \
    #   | sed -e 's/\"//g' -e 's/,//g' -e 's/^/\/\/:/g'
    BUILD_COMMAND  cd ${CMAKE_CURRENT_SOURCE_DIR}/xnnpack
                   && bazel --output_user_root=build-user-output build -c opt --config=wasm
                       //:qs8_dwconv_bench.wasm
                       //:qs8_f32_vcvt_bench.wasm
                       //:qs8_gemm_bench.wasm
                       //:qs8_requantization_bench.wasm
                       //:qs8_vadd_bench.wasm
                       //:qs8_vaddc_bench.wasm
                       //:qs8_vcvt_bench.wasm
                       //:qs8_vlrelu_bench.wasm
                       //:qs8_vmul_bench.wasm
                       //:qs8_vmulc_bench.wasm
                       //:qu8_f32_vcvt_bench.wasm
                       //:qu8_gemm_bench.wasm
                       //:qu8_requantization_bench.wasm
                       //:qu8_vadd_bench.wasm
                       //:qu8_vaddc_bench.wasm
                       //:qu8_vcvt_bench.wasm
                       //:qu8_vlrelu_bench.wasm
                       //:qu8_vmul_bench.wasm
                       //:qu8_vmulc_bench.wasm
                       //:bf16_gemm_bench.wasm
                       //:f16_igemm_bench.wasm
                       //:f16_gemm_bench.wasm
                       //:f16_raddstoreexpminusmax_bench.wasm
                       //:f16_spmm_bench.wasm
                       //:f16_vsigmoid_bench.wasm
                       //:f16_f32_vcvt_bench.wasm
                       //:f32_igemm_bench.wasm
                       //:f32_conv_hwc_bench.wasm
                       //:f16_conv_hwc2chw_bench.wasm
                       //:f16_gavgpool_cw_bench.wasm
                       //:f32_gavgpool_cw_bench.wasm
                       //:f32_conv_hwc2chw_bench.wasm
                       //:f16_dwconv_bench.wasm
                       //:f32_dwconv_bench.wasm
                       //:f32_dwconv2d_chw_bench.wasm
                       //:f16_dwconv2d_chw_bench.wasm
                       //:f32_f16_vcvt_bench.wasm
                       //:xx_transpose_bench.wasm
                       //:x8_transpose_bench.wasm
                       //:x16_transpose_bench.wasm
                       //:x24_transpose_bench.wasm
                       //:x32_transpose_bench.wasm
                       //:x64_transpose_bench.wasm
                       //:f32_gemm_bench.wasm
                       //:f32_qs8_vcvt_bench.wasm
                       //:f32_qu8_vcvt_bench.wasm
                       //:f32_raddexpminusmax_bench.wasm
                       //:f32_raddextexp_bench.wasm
                       //:f32_raddstoreexpminusmax_bench.wasm
                       //:f32_rmax_bench.wasm
                       //:f32_spmm_bench.wasm
                       //:f32_softmax_bench.wasm
                       //:f16_velu_bench.wasm
                       //:f32_velu_bench.wasm
                       //:f32_vhswish_bench.wasm
                       //:f32_vlrelu_bench.wasm
                       //:f32_vrelu_bench.wasm
                       //:f32_vscaleexpminusmax_bench.wasm
                       //:f32_vscaleextexp_bench.wasm
                       //:f32_vsigmoid_bench.wasm
                       //:f16_vsqrt_bench.wasm
                       //:f32_vsqrt_bench.wasm
                       //:f32_im2col_gemm_bench.wasm
                       //:rounding_bench.wasm
                       //:s16_rmaxabs_bench.wasm
                       //:s16_window_bench.wasm
                       //:u32_filterbank_accumulate_bench.wasm
                       //:u32_filterbank_subtract_bench.wasm
                       //:u32_vlog_bench.wasm
                       //:u64_u32_vsqrtshift_bench.wasm
                       //:i16_vlshift_bench.wasm
                       //:cs16_vsquareabs_bench.wasm
                       //:cs16_bfly4_bench.wasm
                       //:cs16_fftr_bench.wasm
                       //:x8_lut_bench.wasm
                       //:abs_bench.wasm
                       //:average_pooling_bench.wasm
                       //:bankers_rounding_bench.wasm
                       //:ceiling_bench.wasm
                       //:channel_shuffle_bench.wasm
                       //:convert_bench.wasm
                       //:convolution_bench.wasm
                       //:deconvolution_bench.wasm
                       //:elu_bench.wasm
                       //:floor_bench.wasm
                       //:global_average_pooling_bench.wasm
                       //:hardswish_bench.wasm
                       //:leaky_relu_bench.wasm
                       //:max_pooling_bench.wasm
                       //:negate_bench.wasm
                       //:sigmoid_bench.wasm
                       //:prelu_bench.wasm
                       //:softmax_bench.wasm
                       //:square_bench.wasm
                       //:square_root_bench.wasm
                       //:truncation_bench.wasm
                       //:f16_gemm_e2e_bench.wasm
                       //:f32_dwconv_e2e_bench.wasm
                       //:f32_gemm_e2e_bench.wasm
                       //:qs8_dwconv_e2e_bench.wasm
                       //:qs8_gemm_e2e_bench.wasm
                       //:qu8_gemm_e2e_bench.wasm
                       //:qu8_dwconv_e2e_bench.wasm
                       //:end2end_bench.wasm
                       //:f16_exp_ulp_eval.wasm
                       //:f16_expminus_ulp_eval.wasm
                       //:f16_expm1minus_ulp_eval.wasm
                       //:f16_sigmoid_ulp_eval.wasm
                       //:f16_sqrt_ulp_eval.wasm
                       //:f32_exp_ulp_eval.wasm
                       //:f32_expminus_ulp_eval.wasm
                       //:f32_expm1minus_ulp_eval.wasm
                       //:f32_extexp_ulp_eval.wasm
                       //:f32_sigmoid_ulp_eval.wasm
                       //:f32_sqrt_ulp_eval.wasm
                       //:f32_tanh_ulp_eval.wasm
    INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory
                      ${CMAKE_CURRENT_SOURCE_DIR}/xnnpack/bazel-out/wasm-opt/bin/
                      ${CMAKE_BINARY_DIR}/wasm-opt
)
