/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "wasi_nn_common.h"
#include "wasm_export.h"
#include "bh_platform.h"

#include "wasi_nn.h"
#include "wasi_nn_tensorflow.hpp"
#include "logger.h"

/* Definition of 'wasi_nn.h' structs in WASM app format (using offset) */

typedef struct {
    uint32_t buf_offset;
    uint32_t size;
} graph_builder_wasm;

typedef struct {
    uint32_t buf_offset;
    uint32_t size;
} graph_builder_array_wasm;

typedef struct {
    uint32_t dimensions_offset;
    tensor_type type;
    uint32_t data_offset;
} tensor_wasm;

typedef struct {
    uint32_t buf_offset;
    uint32_t size;
} tensor_dimensions_wasm;

/* Global variables */

static uint8_t _is_initialized;
static graph_encoding _encoding;

/* Utils */

static error
check_initialized()
{
    if (!_is_initialized) {
        NN_ERR_PRINTF("Model not initialized.");
        return invalid_argument;
    }
    if (_encoding != tensorflow) {
        NN_ERR_PRINTF("Model encoding is not tensorflow.");
        return invalid_argument;
    }
    return success;
}

/* WASI-NN implementation */

error
wasi_nn_load(wasm_exec_env_t exec_env, graph_builder_array_wasm *builder,
             graph_encoding encoding, execution_target target, graph *graph)
{
    NN_DBG_PRINTF("Running wasi_nn_load [encoding=%d, target=%d]...", encoding,
                  target);

    wasm_module_inst_t instance = wasm_runtime_get_module_inst(exec_env);
    bh_assert(instance);

    if (!wasm_runtime_validate_native_addr(instance, builder,
                                           sizeof(graph_builder_array_wasm)))
        return invalid_argument;

    if (!wasm_runtime_validate_app_addr(instance, builder->buf_offset,
                                        builder->size * sizeof(uint32_t)))
        return invalid_argument;

    NN_DBG_PRINTF("Graph builder array contains %d elements", builder->size);

    graph_builder_wasm *gb_wasm =
        (graph_builder_wasm *)wasm_runtime_addr_app_to_native(
            instance, builder->buf_offset);

    graph_builder *gb_native = (graph_builder *)wasm_runtime_malloc(
        builder->size * sizeof(graph_builder));
    if (gb_native == NULL)
        return missing_memory;

    for (int i = 0; i < builder->size; ++i) {
        if (!wasm_runtime_validate_app_addr(instance, gb_wasm[i].buf_offset,
                                            gb_wasm[i].size
                                                * sizeof(uint8_t))) {
            wasm_runtime_free(gb_native);
            return invalid_argument;
        }

        gb_native[i].buf = (uint8_t *)wasm_runtime_addr_app_to_native(
            instance, gb_wasm[i].buf_offset);
        gb_native[i].size = gb_wasm[i].size;

        NN_DBG_PRINTF("Graph builder %d contains %d elements", i,
                      gb_wasm[i].size);
    }

    graph_builder_array gba_native = { .buf = gb_native,
                                       .size = builder->size };

    if (!wasm_runtime_validate_native_addr(instance, graph, sizeof(graph))) {
        wasm_runtime_free(gb_native);
        return invalid_argument;
    }

    switch (encoding) {
        case tensorflow:
            break;
        default:
            NN_ERR_PRINTF("Only tensorflow is supported.");
            wasm_runtime_free(gb_native);
            return invalid_argument;
    }

    _encoding = encoding;
    _is_initialized = 1;

    error res = tensorflow_load(gba_native, _encoding, target, graph);
    NN_DBG_PRINTF("wasi_nn_load finished with status %d [graph=%d]", res,
                  *graph);

    wasm_runtime_free(gb_native);
    return res;
}

error
wasi_nn_init_execution_context(wasm_exec_env_t exec_env, graph graph,
                               graph_execution_context *ctx)
{
    NN_DBG_PRINTF("Running wasi_nn_init_execution_context [graph=%d]...",
                  graph);
    error res;
    if (success != (res = check_initialized()))
        return res;
    res = tensorflow_init_execution_context(graph);
    *ctx = graph;
    NN_DBG_PRINTF(
        "wasi_nn_init_execution_context finished with status %d [ctx=%d]", res,
        *ctx);
    return res;
}

error
wasi_nn_set_input(wasm_exec_env_t exec_env, graph_execution_context ctx,
                  uint32_t index, tensor_wasm *input_tensor)
{
    NN_DBG_PRINTF("Running wasi_nn_set_input [ctx=%d, index=%d]...", ctx,
                  index);

    error res;
    if (success != (res = check_initialized()))
        return res;

    wasm_module_inst_t instance = wasm_runtime_get_module_inst(exec_env);
    bh_assert(instance);

    if (!wasm_runtime_validate_native_addr(instance, input_tensor,
                                           sizeof(tensor_wasm)))
        return invalid_argument;

    if (!wasm_runtime_validate_app_addr(
            instance, input_tensor->dimensions_offset, sizeof(uint32_t)))
        return invalid_argument;

    tensor_dimensions_wasm *dimensions_w =
        (tensor_dimensions_wasm *)wasm_runtime_addr_app_to_native(
            instance, input_tensor->dimensions_offset);

    if (!wasm_runtime_validate_app_addr(instance, dimensions_w->buf_offset,
                                        dimensions_w->size * sizeof(uint32_t)))
        return invalid_argument;

    tensor_dimensions dimensions = {
        .buf = (uint32_t *)wasm_runtime_addr_app_to_native(
            instance, dimensions_w->buf_offset),
        .size = dimensions_w->size
    };

    NN_DBG_PRINTF("Number of dimensions: %d", dimensions.size);
    int total_elements = 1;
    for (int i = 0; i < dimensions.size; ++i) {
        NN_DBG_PRINTF("Dimension %d: %d", i, dimensions.buf[i]);
        total_elements *= dimensions.buf[i];
    }
    NN_DBG_PRINTF("Tensor type: %d", input_tensor->type);

    if (!wasm_runtime_validate_app_addr(instance, input_tensor->data_offset,
                                        total_elements))
        return invalid_argument;

    tensor tensor = { .type = input_tensor->type,
                      .dimensions = &dimensions,
                      .data = (uint8_t *)wasm_runtime_addr_app_to_native(
                          instance, input_tensor->data_offset) };

    res = tensorflow_set_input(ctx, index, &tensor);
    NN_DBG_PRINTF("wasi_nn_set_input finished with status %d", res);
    return res;
}

error
wasi_nn_compute(wasm_exec_env_t exec_env, graph_execution_context ctx)
{
    NN_DBG_PRINTF("Running wasi_nn_compute [ctx=%d]...", ctx);
    error res;
    if (success != (res = check_initialized()))
        return res;

    res = tensorflow_compute(ctx);
    NN_DBG_PRINTF("wasi_nn_compute finished with status %d", res);
    return res;
}

error
wasi_nn_get_output(wasm_exec_env_t exec_env, graph_execution_context ctx,
                   uint32_t index, tensor_data output_tensor,
                   uint32_t *output_tensor_size)
{
    NN_DBG_PRINTF("Running wasi_nn_get_output [ctx=%d, index=%d]...", ctx,
                  index);
    error res;
    if (success != (res = check_initialized()))
        return res;

    res = tensorflow_get_output(ctx, index, output_tensor, output_tensor_size);
    NN_DBG_PRINTF("wasi_nn_get_output finished with status %d [data_size=%d]",
                  res, *output_tensor_size);
    return res;
}

/* Register WASI-NN in WAMR */

/* clang-format off */
#define REG_NATIVE_FUNC(func_name, signature) \
    { #func_name, wasi_nn_##func_name, signature, NULL }
/* clang-format on */

static NativeSymbol native_symbols_wasi_nn[] = {
    REG_NATIVE_FUNC(load, "(*ii*)i"),
    REG_NATIVE_FUNC(init_execution_context, "(i*)i"),
    REG_NATIVE_FUNC(set_input, "(ii*)i"),
    REG_NATIVE_FUNC(compute, "(i)i"),
    REG_NATIVE_FUNC(get_output, "(ii**)i"),
};

uint32_t
get_wasi_nn_export_apis(NativeSymbol **p_libc_wasi_apis)
{
    *p_libc_wasi_apis = native_symbols_wasi_nn;
    return sizeof(native_symbols_wasi_nn) / sizeof(NativeSymbol);
}
