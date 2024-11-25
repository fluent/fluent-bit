/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef WASI_NN_TYPES_H
#define WASI_NN_TYPES_H

#include <stdint.h>
#include <stdbool.h>

/**
 * ERRORS
 *
 */

// Error codes returned by functions in this API.
typedef enum {
    // No error occurred.
    success = 0,
    // Caller module passed an invalid argument.
    invalid_argument,
    // Invalid encoding.
    invalid_encoding,
    // Caller module is missing a memory export.
    missing_memory,
    // Device or resource busy.
    busy,
    // Runtime Error.
    runtime_error,
} error;

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
} tensor_dimensions;

// The type of the elements in a tensor.
typedef enum { fp16 = 0, fp32, up8, ip32 } tensor_type;

// The tensor data.
//
// Initially conceived as a sparse representation, each empty cell would be
// filled with zeros and the array length must match the product of all of the
// dimensions and the number of bytes in the type (e.g., a 2x2 tensor with
// 4-byte f32 elements would have a data array of length 16). Naturally, this
// representation requires some knowledge of how to lay out data in
// memory--e.g., using row-major ordering--and could perhaps be improved.
typedef uint8_t *tensor_data;

// A tensor.
typedef struct {
    // Describe the size of the tensor (e.g., 2x2x2x2 -> [2, 2, 2, 2]). To
    // represent a tensor containing a single value, use `[1]` for the tensor
    // dimensions.
    tensor_dimensions *dimensions;
    // Describe the type of element in the tensor (e.g., f32).
    tensor_type type;
    // Contains the tensor data.
    tensor_data data;
} tensor;

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
} graph_builder;

typedef struct {
    graph_builder *buf;
    uint32_t size;
} graph_builder_array;

// An execution graph for performing inference (i.e., a model).
typedef uint32_t graph;

// Describes the encoding of the graph. This allows the API to be implemented by
// various backends that encode (i.e., serialize) their graph IR with different
// formats.
typedef enum {
    openvino = 0,
    onnx,
    tensorflow,
    pytorch,
    tensorflowlite
} graph_encoding;

// Define where the graph should be executed.
typedef enum execution_target { cpu = 0, gpu, tpu } execution_target;

#endif
