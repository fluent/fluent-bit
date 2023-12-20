/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef WASI_NN_TENSORFLOWLITE_HPP
#define WASI_NN_TENSORFLOWLITE_HPP

#include "wasi_nn.h"

#ifdef __cplusplus
extern "C" {
#endif

error
tensorflowlite_load(void *tflite_ctx, graph_builder_array *builder,
                    graph_encoding encoding, execution_target target, graph *g);

error
tensorflowlite_init_execution_context(void *tflite_ctx, graph g,
                                      graph_execution_context *ctx);

error
tensorflowlite_set_input(void *tflite_ctx, graph_execution_context ctx,
                         uint32_t index, tensor *input_tensor);

error
tensorflowlite_compute(void *tflite_ctx, graph_execution_context ctx);

error
tensorflowlite_get_output(void *tflite_ctx, graph_execution_context ctx,
                          uint32_t index, tensor_data output_tensor,
                          uint32_t *output_tensor_size);

void
tensorflowlite_initialize(void **tflite_ctx);

void
tensorflowlite_destroy(void *tflite_ctx);

#ifdef __cplusplus
}
#endif

#endif
