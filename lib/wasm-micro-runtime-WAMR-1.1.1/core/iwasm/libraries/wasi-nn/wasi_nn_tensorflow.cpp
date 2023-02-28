/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasi_nn_tensorflow.hpp"
#include "wasi_nn_common.h"
#include "bh_common.h"
#include "bh_platform.h"
#include "platform_common.h"

#include <tensorflow/lite/interpreter.h>
#include <tensorflow/lite/kernels/register.h>
#include <tensorflow/lite/model.h>
#include <tensorflow/lite/optional_debug_tools.h>
#include <tensorflow/lite/error_reporter.h>

/* Global variables */

static std::unique_ptr<tflite::Interpreter> interpreter;
static std::unique_ptr<tflite::FlatBufferModel> model;

static char *model_pointer = NULL;

/* WASI-NN (tensorflow) implementation */

error
tensorflow_load(graph_builder_array builder, graph_encoding encoding,
                execution_target target, graph *graph)
{
    if (model_pointer != NULL) {
        wasm_runtime_free(model_pointer);
        model_pointer = NULL;
    }

    if (builder.size != 1) {
        NN_ERR_PRINTF("Unexpected builder format.");
        return invalid_argument;
    }

    if (encoding != tensorflow) {
        NN_ERR_PRINTF("Encoding is not tensorflow.");
        return invalid_argument;
    }

    if (target != cpu) {
        NN_ERR_PRINTF("Only CPU target is supported.");
        return invalid_argument;
    }

    uint32_t size = builder.buf[0].size;

    model_pointer = (char *)wasm_runtime_malloc(size);
    if (model_pointer == NULL) {
        NN_ERR_PRINTF("Error when allocating memory for model.");
        return missing_memory;
    }

    bh_memcpy_s(model_pointer, size, builder.buf[0].buf, size);

    model = tflite::FlatBufferModel::BuildFromBuffer(model_pointer, size, NULL);
    if (model == NULL) {
        NN_ERR_PRINTF("Loading model error.");
        wasm_runtime_free(model_pointer);
        model_pointer = NULL;
        return missing_memory;
    }

    // Build the interpreter with the InterpreterBuilder.
    tflite::ops::builtin::BuiltinOpResolver resolver;
    tflite::InterpreterBuilder tflite_builder(*model, resolver);
    tflite_builder(&interpreter);
    if (interpreter == NULL) {
        NN_ERR_PRINTF("Error when generating the interpreter.");
        wasm_runtime_free(model_pointer);
        model_pointer = NULL;
        return missing_memory;
    }

    return success;
}

error
tensorflow_init_execution_context(graph graph)
{
    if (interpreter == NULL) {
        NN_ERR_PRINTF("Non-initialized interpreter.");
        return runtime_error;
    }
    interpreter->AllocateTensors();
    return success;
}

error
tensorflow_set_input(graph_execution_context ctx, uint32_t index,
                     tensor *input_tensor)
{
    if (interpreter == NULL) {
        NN_ERR_PRINTF("Non-initialized interpreter.");
        return runtime_error;
    }

    uint32_t num_tensors = interpreter->inputs().size();
    NN_DBG_PRINTF("Number of tensors (%d)", num_tensors);
    if (index + 1 > num_tensors) {
        return runtime_error;
    }

    auto tensor = interpreter->input_tensor(index);
    if (tensor == NULL) {
        NN_ERR_PRINTF("Missing memory");
        return missing_memory;
    }

    uint32_t model_tensor_size = 1;
    for (int i = 0; i < (int)tensor->dims->size; ++i)
        model_tensor_size *= (uint32_t)tensor->dims->data[i];

    uint32_t input_tensor_size = 1;
    for (int i = 0; i < input_tensor->dimensions->size; i++)
        input_tensor_size *= (uint32_t)input_tensor->dimensions->buf[i];

    if (model_tensor_size != input_tensor_size) {
        NN_ERR_PRINTF("Input tensor shape from the model is different than the "
                      "one provided");
        return invalid_argument;
    }

    auto *input = interpreter->typed_input_tensor<float>(index);
    if (input == NULL)
        return missing_memory;

    bh_memcpy_s(input, model_tensor_size * sizeof(float), input_tensor->data,
                model_tensor_size * sizeof(float));
    return success;
}

error
tensorflow_compute(graph_execution_context ctx)
{
    if (interpreter == NULL) {
        NN_ERR_PRINTF("Non-initialized interpreter.");
        return runtime_error;
    }
    interpreter->Invoke();
    return success;
}

error
tensorflow_get_output(graph_execution_context context, uint32_t index,
                      tensor_data output_tensor, uint32_t *output_tensor_size)
{
    if (interpreter == NULL) {
        NN_ERR_PRINTF("Non-initialized interpreter.");
        return runtime_error;
    }

    uint32_t num_output_tensors = interpreter->outputs().size();
    NN_DBG_PRINTF("Number of tensors (%d)", num_output_tensors);

    if (index + 1 > num_output_tensors) {
        return runtime_error;
    }

    auto tensor = interpreter->output_tensor(index);
    if (tensor == NULL) {
        NN_ERR_PRINTF("Missing memory");
        return missing_memory;
    }

    uint32_t model_tensor_size = 1;
    for (int i = 0; i < (int)tensor->dims->size; ++i)
        model_tensor_size *= (uint32_t)tensor->dims->data[i];

    if (*output_tensor_size < model_tensor_size) {
        NN_ERR_PRINTF("Insufficient memory to copy tensor %d", index);
        return missing_memory;
    }

    float *tensor_f = interpreter->typed_output_tensor<float>(index);
    for (int i = 0; i < model_tensor_size; ++i)
        NN_DBG_PRINTF("output: %f", tensor_f[i]);

    *output_tensor_size = model_tensor_size;
    bh_memcpy_s(output_tensor, model_tensor_size * sizeof(float), tensor_f,
                model_tensor_size * sizeof(float));
    return success;
}
