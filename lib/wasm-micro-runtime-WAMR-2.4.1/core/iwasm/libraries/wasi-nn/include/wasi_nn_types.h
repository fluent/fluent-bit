/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef WASI_NN_TYPES_H
#define WASI_NN_TYPES_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* our host logic doesn't use any prefix. neither legacy wasi_nn.h does. */

#if !defined(__wasm__) || !defined(WASI_NN_NAME)
#define WASI_NN_NAME(name) name
#define WASI_NN_ERROR_NAME(name) name
#define WASI_NN_TYPE_NAME(name) name
#define WASI_NN_ENCODING_NAME(name) name
#define WASI_NN_TARGET_NAME(name) name
#define WASI_NN_ERROR_TYPE wasi_nn_error
#else
#define WASI_NN_ERROR_NAME(name) WASI_NN_NAME(error_##name)
#define WASI_NN_TYPE_NAME(name) WASI_NN_NAME(type_##name)
#define WASI_NN_ENCODING_NAME(name) WASI_NN_NAME(encoding_##name)
#define WASI_NN_TARGET_NAME(name) WASI_NN_NAME(target_##name)
#define WASI_NN_ERROR_TYPE WASI_NN_NAME(error);
#endif

/**
 * ERRORS
 *
 */

// sync up with
// https://github.com/WebAssembly/wasi-nn/blob/71320d95b8c6d43f9af7f44e18b1839db85d89b4/wasi-nn.witx#L5-L17
// Error codes returned by functions in this API.
typedef enum {
    WASI_NN_ERROR_NAME(success) = 0,
    WASI_NN_ERROR_NAME(invalid_argument),
    WASI_NN_ERROR_NAME(invalid_encoding),
    WASI_NN_ERROR_NAME(missing_memory),
    WASI_NN_ERROR_NAME(busy),
    WASI_NN_ERROR_NAME(runtime_error),
    WASI_NN_ERROR_NAME(unsupported_operation),
    WASI_NN_ERROR_NAME(too_large),
    WASI_NN_ERROR_NAME(not_found),

    // for WasmEdge-wasi-nn
    WASI_NN_ERROR_NAME(end_of_sequence) = 100,  // End of Sequence Found.
    WASI_NN_ERROR_NAME(context_full) = 101,     // Context Full.
    WASI_NN_ERROR_NAME(prompt_tool_long) = 102, // Prompt Too Long.
    WASI_NN_ERROR_NAME(model_not_found) = 103,  // Model Not Found.
} WASI_NN_ERROR_TYPE;

/**
 * TENSOR
 *
 */

// The dimensions of a tensor.
//
// The array length matches the tensor rank and each element in the array
// describes the size of each dimension.
typedef struct {
    uint32_t *buf;
    uint32_t size;
} WASI_NN_NAME(tensor_dimensions);

#if WASM_ENABLE_WASI_EPHEMERAL_NN != 0
// sync up with
// https://github.com/WebAssembly/wasi-nn/blob/71320d95b8c6d43f9af7f44e18b1839db85d89b4/wasi-nn.witx#L19-L28
// The type of the elements in a tensor.
typedef enum {
    WASI_NN_TYPE_NAME(fp16) = 0,
    WASI_NN_TYPE_NAME(fp32),
    WASI_NN_TYPE_NAME(fp64),
    WASI_NN_TYPE_NAME(u8),
    WASI_NN_TYPE_NAME(i32),
    WASI_NN_TYPE_NAME(i64),
} WASI_NN_NAME(tensor_type);
#else
typedef enum {
    WASI_NN_TYPE_NAME(fp16) = 0,
    WASI_NN_TYPE_NAME(fp32),
    WASI_NN_TYPE_NAME(up8),
    WASI_NN_TYPE_NAME(ip32),
} WASI_NN_NAME(tensor_type);
#endif /* WASM_ENABLE_WASI_EPHEMERAL_NN != 0 */

// The tensor data.
//
// Initially conceived as a sparse representation, each empty cell would be
// filled with zeros and the array length must match the product of all of the
// dimensions and the number of bytes in the type (e.g., a 2x2 tensor with
// 4-byte f32 elements would have a data array of length 16). Naturally, this
// representation requires some knowledge of how to lay out data in
// memory--e.g., using row-major ordering--and could perhaps be improved.
#if !defined(__wasm__) || WASM_ENABLE_WASI_EPHEMERAL_NN != 0
typedef struct {
    uint8_t *buf;
    uint32_t size;
} WASI_NN_NAME(tensor_data);
#else
typedef uint8_t *WASI_NN_NAME(tensor_data);
#endif

// A tensor.
typedef struct {
    // Describe the size of the tensor (e.g., 2x2x2x2 -> [2, 2, 2, 2]). To
    // represent a tensor containing a single value, use `[1]` for the tensor
    // dimensions.
#if WASM_ENABLE_WASI_EPHEMERAL_NN != 0 && defined(__wasm__)
    WASI_NN_NAME(tensor_dimensions) dimensions;
#else
    WASI_NN_NAME(tensor_dimensions) * dimensions;
#endif
    // Describe the type of element in the tensor (e.g., f32).
    uint8_t type;
    uint8_t _pad[3];
    // Contains the tensor data.
    WASI_NN_NAME(tensor_data) data;
} WASI_NN_NAME(tensor);

/**
 * GRAPH
 *
 */

// The graph initialization data.
//
// This consists of an array of buffers because implementing backends may encode
// their graph IR in parts (e.g., OpenVINO stores its IR and weights
// separately).
typedef struct {
    uint8_t *buf;
    uint32_t size;
} WASI_NN_NAME(graph_builder);

typedef struct {
    WASI_NN_NAME(graph_builder) * buf;
    uint32_t size;
} WASI_NN_NAME(graph_builder_array);

// An execution graph for performing inference (i.e., a model).
typedef uint32_t WASI_NN_NAME(graph);

// sync up with
// https://github.com/WebAssembly/wasi-nn/blob/main/wit/wasi-nn.wit#L75
// Describes the encoding of the graph. This allows the API to be implemented by
// various backends that encode (i.e., serialize) their graph IR with different
// formats.
typedef enum {
    WASI_NN_ENCODING_NAME(openvino) = 0,
    WASI_NN_ENCODING_NAME(onnx),
    WASI_NN_ENCODING_NAME(tensorflow),
    WASI_NN_ENCODING_NAME(pytorch),
    WASI_NN_ENCODING_NAME(tensorflowlite),
    WASI_NN_ENCODING_NAME(ggml),
    WASI_NN_ENCODING_NAME(autodetect),
    WASI_NN_ENCODING_NAME(unknown_backend),
} WASI_NN_NAME(graph_encoding);

// Define where the graph should be executed.
typedef enum WASI_NN_NAME(execution_target) {
    WASI_NN_TARGET_NAME(cpu) = 0,
    WASI_NN_TARGET_NAME(gpu),
    WASI_NN_TARGET_NAME(tpu),
} WASI_NN_NAME(execution_target);

// Bind a `graph` to the input and output tensors for an inference.
typedef uint32_t WASI_NN_NAME(graph_execution_context);

#ifdef __cplusplus
}
#endif
#endif
