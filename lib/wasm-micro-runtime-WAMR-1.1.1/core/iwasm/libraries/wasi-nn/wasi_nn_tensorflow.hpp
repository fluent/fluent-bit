/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef WASI_NN_TENSORFLOW_HPP
#define WASI_NN_TENSORFLOW_HPP

#include <stdio.h>

#include "wasi_nn.h"
#include "logger.h"

#ifdef __cplusplus
extern "C" {
#endif

error
tensorflow_load(graph_builder_array builder, graph_encoding encoding,
                execution_target target, graph *graph);

error
tensorflow_init_execution_context(graph graph);

error
tensorflow_set_input(graph_execution_context ctx, uint32_t index,
                     tensor *input_tensor);

error
tensorflow_compute(graph_execution_context ctx);

error
tensorflow_get_output(graph_execution_context context, uint32_t index,
                      tensor_data output_tensor, uint32_t *output_tensor_size);

#ifdef __cplusplus
}
#endif

#endif
