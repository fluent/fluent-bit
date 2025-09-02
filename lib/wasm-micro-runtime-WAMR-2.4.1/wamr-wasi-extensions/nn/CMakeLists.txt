# Copyright (C) 2025 Midokura Japan KK.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

add_library(wamr-wasi-nn INTERFACE)

set(wasi_nn_header_dir ${CMAKE_CURRENT_SOURCE_DIR}/../../core/iwasm/libraries/wasi-nn/include)

set(headers
    ${wasi_nn_header_dir}/wasi_ephemeral_nn.h
    ${wasi_nn_header_dir}/wasi_nn.h
    ${wasi_nn_header_dir}/wasi_nn_types.h
)

set_property(TARGET wamr-wasi-nn PROPERTY PUBLIC_HEADER ${headers})

target_include_directories(wamr-wasi-nn
                           INTERFACE
                           $<BUILD_INTERFACE:${wasi_nn_header_dir}>
                           $<INSTALL_INTERFACE:include>)

install(TARGETS wamr-wasi-nn
        EXPORT wamr-wasi-nn-config
        PUBLIC_HEADER DESTINATION include/wamr)
install(EXPORT wamr-wasi-nn-config
        DESTINATION lib/cmake/wamr-wasi-nn)
