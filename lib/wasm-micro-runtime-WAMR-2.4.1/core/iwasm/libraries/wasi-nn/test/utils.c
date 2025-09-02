/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "utils.h"
#include "logger.h"
#include "wasi_nn.h"

#include <stdio.h>
#include <stdlib.h>

wasi_nn_error
wasm_load(char *model_name, graph *g, execution_target target)
{
    FILE *pFile = fopen(model_name, "r");
    if (pFile == NULL)
        return invalid_argument;

    uint8_t *buffer;
    size_t result;

    // allocate memory to contain the whole file:
    buffer = (uint8_t *)malloc(sizeof(uint8_t) * MAX_MODEL_SIZE);
    if (buffer == NULL) {
        fclose(pFile);
        return too_large;
    }

    result = fread(buffer, 1, MAX_MODEL_SIZE, pFile);
    if (result <= 0) {
        fclose(pFile);
        free(buffer);
        return too_large;
    }

    graph_builder_array arr;

    arr.size = 1;
    arr.buf = (graph_builder *)malloc(sizeof(graph_builder));
    if (arr.buf == NULL) {
        fclose(pFile);
        free(buffer);
        return too_large;
    }

    arr.buf[0].size = result;
    arr.buf[0].buf = buffer;

    wasi_nn_error res = load(&arr, tensorflowlite, target, g);

    fclose(pFile);
    free(buffer);
    free(arr.buf);
    return res;
}

wasi_nn_error
wasm_load_by_name(const char *model_name, graph *g)
{
    wasi_nn_error res = load_by_name(model_name, strlen(model_name), g);
    return res;
}

wasi_nn_error
wasm_init_execution_context(graph g, graph_execution_context *ctx)
{
    return init_execution_context(g, ctx);
}

wasi_nn_error
wasm_set_input(graph_execution_context ctx, float *input_tensor, uint32_t *dim)
{
    tensor_dimensions dims;
    dims.size = INPUT_TENSOR_DIMS;
    dims.buf = (uint32_t *)malloc(dims.size * sizeof(uint32_t));
    if (dims.buf == NULL)
        return too_large;

    tensor tensor;
    tensor.dimensions = &dims;
    for (int i = 0; i < tensor.dimensions->size; ++i)
        tensor.dimensions->buf[i] = dim[i];
    tensor.type = fp32;
    tensor.data = (uint8_t *)input_tensor;
    wasi_nn_error err = set_input(ctx, 0, &tensor);

    free(dims.buf);
    return err;
}

wasi_nn_error
wasm_compute(graph_execution_context ctx)
{
    return compute(ctx);
}

wasi_nn_error
wasm_get_output(graph_execution_context ctx, uint32_t index, float *out_tensor,
                uint32_t *out_size)
{
    return get_output(ctx, index, (uint8_t *)out_tensor, out_size);
}

float *
run_inference(execution_target target, float *input, uint32_t *input_size,
              uint32_t *output_size, char *model_name,
              uint32_t num_output_tensors)
{
    graph graph;

    if (wasm_load_by_name(model_name, &graph) != success) {
        NN_ERR_PRINTF("Error when loading model.");
        exit(1);
    }

    graph_execution_context ctx;
    if (wasm_init_execution_context(graph, &ctx) != success) {
        NN_ERR_PRINTF("Error when initialixing execution context.");
        exit(1);
    }

    if (wasm_set_input(ctx, input, input_size) != success) {
        NN_ERR_PRINTF("Error when setting input tensor.");
        exit(1);
    }

    if (wasm_compute(ctx) != success) {
        NN_ERR_PRINTF("Error when running inference.");
        exit(1);
    }

    float *out_tensor = (float *)malloc(sizeof(float) * MAX_OUTPUT_TENSOR_SIZE);
    if (out_tensor == NULL) {
        NN_ERR_PRINTF("Error when allocating memory for output tensor.");
        exit(1);
    }

    uint32_t offset = 0;
    for (int i = 0; i < num_output_tensors; ++i) {
        *output_size = MAX_OUTPUT_TENSOR_SIZE - *output_size;
        if (wasm_get_output(ctx, i, &out_tensor[offset], output_size)
            != success) {
            NN_ERR_PRINTF("Error when getting index %d.", i);
            break;
        }

        offset += *output_size;
    }
    *output_size = offset;
    return out_tensor;
}

input_info
create_input(int *dims)
{
    input_info input = { .dim = NULL, .input_tensor = NULL, .elements = 1 };

    input.dim = malloc(INPUT_TENSOR_DIMS * sizeof(uint32_t));
    if (input.dim)
        for (int i = 0; i < INPUT_TENSOR_DIMS; ++i) {
            input.dim[i] = dims[i];
            input.elements *= dims[i];
        }

    input.input_tensor = malloc(input.elements * sizeof(float));
    for (int i = 0; i < input.elements; ++i)
        input.input_tensor[i] = i;

    return input;
}
