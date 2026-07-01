/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef WASI_NN_BACKEND_H
#define WASI_NN_BACKEND_H

#include "wasi_nn_types.h"

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((visibility("default"))) wasi_nn_error
load(void *ctx, graph_builder_array *builder, graph_encoding encoding,
     execution_target target, graph *g);

__attribute__((visibility("default"))) wasi_nn_error
load_by_name(void *tflite_ctx, const char *name, uint32_t namelen, graph *g);

__attribute__((visibility("default"))) wasi_nn_error
load_by_name_with_config(void *ctx, const char *name, uint32_t namelen,
                         const char *config, uint32_t config_len, graph *g);

__attribute__((visibility("default"))) wasi_nn_error
init_execution_context(void *ctx, graph g, graph_execution_context *exec_ctx);

__attribute__((visibility("default"))) wasi_nn_error
set_input(void *ctx, graph_execution_context exec_ctx, uint32_t index,
          tensor *input_tensor);

__attribute__((visibility("default"))) wasi_nn_error
compute(void *ctx, graph_execution_context exec_ctx);

__attribute__((visibility("default"))) wasi_nn_error
get_output(void *ctx, graph_execution_context exec_ctx, uint32_t index,
           tensor_data *output_tensor, uint32_t *output_tensor_size);

__attribute__((visibility("default"))) wasi_nn_error
init_backend(void **ctx);

__attribute__((visibility("default"))) wasi_nn_error
deinit_backend(void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* WASI_NN_BACKEND_H */
