/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef WASI_NN_COMMON_H
#define WASI_NN_COMMON_H

#include <stdint.h>

// The type of the elements in a tensor.
typedef enum { fp16 = 0, fp32, up8, ip32 } tensor_type;

// Describes the encoding of the graph. This allows the API to be implemented by
// various backends that encode (i.e., serialize) their graph IR with different
// formats.
typedef enum { openvino = 0, onnx, tensorflow, pytorch } graph_encoding;

// Define where the graph should be executed.
typedef enum { cpu = 0, gpu, tpu } execution_target;

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

// An execution graph for performing inference (i.e., a model).
typedef uint32_t graph;

// Bind a `graph` to the input and output tensors for an inference.
typedef uint32_t graph_execution_context;

#endif
