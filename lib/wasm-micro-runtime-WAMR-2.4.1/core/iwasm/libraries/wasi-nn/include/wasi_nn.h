/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

/**
 * Following definition from:
 * [Oct 25th, 2022]
 * https://github.com/WebAssembly/wasi-nn/blob/0f77c48ec195748990ff67928a4b3eef5f16c2de/wasi-nn.wit.md
 */

#ifndef WASI_NN_H
#define WASI_NN_H

#include <stdint.h>
#include "wasi_nn_types.h"

#if WASM_ENABLE_WASI_EPHEMERAL_NN != 0
#define WASI_NN_IMPORT(name) \
    __attribute__((import_module("wasi_ephemeral_nn"), import_name(name)))
#else
#define WASI_NN_IMPORT(name) \
    __attribute__((import_module("wasi_nn"), import_name(name)))
#warning You are using "wasi_nn", which is a legacy WAMR-specific ABI. It's deperecated and will likely be removed in future versions of WAMR. Please use "wasi_ephemeral_nn" instead. (For a WASM module, use the wasi_ephemeral_nn.h header instead. For the runtime configurations, enable WASM_ENABLE_WASI_EPHEMERAL_NN/WAMR_BUILD_WASI_EPHEMERAL_NN.)
#endif

/**
 * @brief Load an opaque sequence of bytes to use for inference.
 *
 * @param builder   Model builder.
 * @param builder_len The size of model builder.
 * @param encoding  Model encoding.
 * @param target    Execution target.
 * @param g         Graph.
 * @return wasi_nn_error    Execution status.
 */
#if WASM_ENABLE_WASI_EPHEMERAL_NN != 0
WASI_NN_ERROR_TYPE
WASI_NN_NAME(load)
(WASI_NN_NAME(graph_builder) * builder, uint32_t builder_len,
 WASI_NN_NAME(graph_encoding) encoding, WASI_NN_NAME(execution_target) target,
 WASI_NN_NAME(graph) * g) WASI_NN_IMPORT("load");
#else
WASI_NN_ERROR_TYPE
WASI_NN_NAME(load)
(WASI_NN_NAME(graph_builder_array) * builder,
 WASI_NN_NAME(graph_encoding) encoding, WASI_NN_NAME(execution_target) target,
 WASI_NN_NAME(graph) * g) WASI_NN_IMPORT("load");
#endif

WASI_NN_ERROR_TYPE
WASI_NN_NAME(load_by_name)
(const char *name, uint32_t name_len, WASI_NN_NAME(graph) * g)
    WASI_NN_IMPORT("load_by_name");

/**
 * INFERENCE
 *
 */

/**
 * @brief Create an execution instance of a loaded graph.
 *
 * @param g         Graph.
 * @param ctx       Execution context.
 * @return wasi_nn_error    Execution status.
 */
WASI_NN_ERROR_TYPE
WASI_NN_NAME(init_execution_context)
(WASI_NN_NAME(graph) g, WASI_NN_NAME(graph_execution_context) * ctx)
    WASI_NN_IMPORT("init_execution_context");

/**
 * @brief Define the inputs to use for inference.
 *
 * @param ctx       Execution context.
 * @param index     Input tensor index.
 * @param tensor    Input tensor.
 * @return wasi_nn_error    Execution status.
 */
WASI_NN_ERROR_TYPE
WASI_NN_NAME(set_input)
(WASI_NN_NAME(graph_execution_context) ctx, uint32_t index,
 WASI_NN_NAME(tensor) * tensor) WASI_NN_IMPORT("set_input");

/**
 * @brief Compute the inference on the given inputs.
 *
 * @param ctx       Execution context.
 * @return wasi_nn_error    Execution status.
 */
WASI_NN_ERROR_TYPE
WASI_NN_NAME(compute)
(WASI_NN_NAME(graph_execution_context) ctx) WASI_NN_IMPORT("compute");

/**
 * @brief Extract the outputs after inference.
 *
 * @param ctx                   Execution context.
 * @param index                 Output tensor index.
 * @param output_tensor         Buffer where output tensor with index `index` is
 * copied.
 * @param output_tensor_size    Pointer to `output_tensor` maximum size.
 *                              After the function call it is updated with the
 * copied number of bytes.
 * @return wasi_nn_error                Execution status.
 */
#if WASM_ENABLE_WASI_EPHEMERAL_NN != 0
WASI_NN_ERROR_TYPE
WASI_NN_NAME(get_output)
(WASI_NN_NAME(graph_execution_context) ctx, uint32_t index,
 uint8_t *output_tensor, uint32_t output_tensor_max_size,
 uint32_t *output_tensor_size) WASI_NN_IMPORT("get_output");
#else
WASI_NN_ERROR_TYPE
WASI_NN_NAME(get_output)
(graph_execution_context ctx, uint32_t index, uint8_t *output_tensor,
 uint32_t *output_tensor_size) WASI_NN_IMPORT("get_output");
#endif

#endif
