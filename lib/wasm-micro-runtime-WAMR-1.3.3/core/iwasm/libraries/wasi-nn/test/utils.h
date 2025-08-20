/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef WASI_NN_UTILS
#define WASI_NN_UTILS

#include <stdint.h>

#include "wasi_nn.h"

#define MAX_MODEL_SIZE 85000000
#define MAX_OUTPUT_TENSOR_SIZE 1000000
#define INPUT_TENSOR_DIMS 4
#define EPSILON 1e-8

typedef struct {
    float *input_tensor;
    uint32_t *dim;
    uint32_t elements;
} input_info;

/* wasi-nn wrappers */

error
wasm_load(char *model_name, graph *g, execution_target target);

error
wasm_init_execution_context(graph g, graph_execution_context *ctx);

error
wasm_set_input(graph_execution_context ctx, float *input_tensor, uint32_t *dim);

error
wasm_compute(graph_execution_context ctx);

error
wasm_get_output(graph_execution_context ctx, uint32_t index, float *out_tensor,
                uint32_t *out_size);

/* Utils */

float *
run_inference(execution_target target, float *input, uint32_t *input_size,
              uint32_t *output_size, char *model_name,
              uint32_t num_output_tensors);

input_info
create_input(int *dims);

#endif
