/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasi_nn.h"
#include "wasi_nn_tensorflowlite.hpp"
#include "logger.h"

#include "bh_common.h"
#include "bh_platform.h"
#include "platform_common.h"

#include <tensorflow/lite/interpreter.h>
#include <tensorflow/lite/kernels/register.h>
#include <tensorflow/lite/model.h>
#include <tensorflow/lite/optional_debug_tools.h>
#include <tensorflow/lite/error_reporter.h>

#if defined(WASI_NN_ENABLE_GPU)
#include <tensorflow/lite/delegates/gpu/delegate.h>
#endif

#if defined(WASI_NN_ENABLE_EXTERNAL_DELEGATE)
#include <tensorflow/lite/delegates/external/external_delegate.h>
#endif

/* Maximum number of graphs per WASM instance */
#define MAX_GRAPHS_PER_INST 10
/* Maximum number of graph execution context per WASM instance*/
#define MAX_GRAPH_EXEC_CONTEXTS_PER_INST 10

typedef struct {
    std::unique_ptr<tflite::Interpreter> interpreter;
} Interpreter;

typedef struct {
    char *model_pointer;
    std::unique_ptr<tflite::FlatBufferModel> model;
    execution_target target;
} Model;

typedef struct {
    uint32_t current_models;
    Model models[MAX_GRAPHS_PER_INST];
    uint32_t current_interpreters;
    Interpreter interpreters[MAX_GRAPH_EXEC_CONTEXTS_PER_INST];
    korp_mutex g_lock;
    TfLiteDelegate *delegate;
} TFLiteContext;

/* Utils */

static error
initialize_g(TFLiteContext *tfl_ctx, graph *g)
{
    os_mutex_lock(&tfl_ctx->g_lock);
    if (tfl_ctx->current_models == MAX_GRAPHS_PER_INST) {
        os_mutex_unlock(&tfl_ctx->g_lock);
        NN_ERR_PRINTF("Excedded max graphs per WASM instance");
        return runtime_error;
    }
    *g = tfl_ctx->current_models++;
    os_mutex_unlock(&tfl_ctx->g_lock);
    return success;
}
static error
initialize_graph_ctx(TFLiteContext *tfl_ctx, graph g,
                     graph_execution_context *ctx)
{
    os_mutex_lock(&tfl_ctx->g_lock);
    if (tfl_ctx->current_interpreters == MAX_GRAPH_EXEC_CONTEXTS_PER_INST) {
        os_mutex_unlock(&tfl_ctx->g_lock);
        NN_ERR_PRINTF("Excedded max graph execution context per WASM instance");
        return runtime_error;
    }
    *ctx = tfl_ctx->current_interpreters++;
    os_mutex_unlock(&tfl_ctx->g_lock);
    return success;
}

static error
is_valid_graph(TFLiteContext *tfl_ctx, graph g)
{
    if (g >= MAX_GRAPHS_PER_INST) {
        NN_ERR_PRINTF("Invalid graph: %d >= %d.", g, MAX_GRAPHS_PER_INST);
        return runtime_error;
    }
    if (tfl_ctx->models[g].model_pointer == NULL) {
        NN_ERR_PRINTF("Context (model) non-initialized.");
        return runtime_error;
    }
    if (tfl_ctx->models[g].model == NULL) {
        NN_ERR_PRINTF("Context (tflite model) non-initialized.");
        return runtime_error;
    }
    return success;
}

static error
is_valid_graph_execution_context(TFLiteContext *tfl_ctx,
                                 graph_execution_context ctx)
{
    if (ctx >= MAX_GRAPH_EXEC_CONTEXTS_PER_INST) {
        NN_ERR_PRINTF("Invalid graph execution context: %d >= %d", ctx,
                      MAX_GRAPH_EXEC_CONTEXTS_PER_INST);
        return runtime_error;
    }
    if (tfl_ctx->interpreters[ctx].interpreter == NULL) {
        NN_ERR_PRINTF("Context (interpreter) non-initialized.");
        return runtime_error;
    }
    return success;
}

/* WASI-NN (tensorflow) implementation */

error
tensorflowlite_load(void *tflite_ctx, graph_builder_array *builder,
                    graph_encoding encoding, execution_target target, graph *g)
{
    TFLiteContext *tfl_ctx = (TFLiteContext *)tflite_ctx;

    if (builder->size != 1) {
        NN_ERR_PRINTF("Unexpected builder format.");
        return invalid_argument;
    }

    if (encoding != tensorflowlite) {
        NN_ERR_PRINTF("Encoding is not tensorflowlite.");
        return invalid_argument;
    }

    if (target != cpu && target != gpu) {
        NN_ERR_PRINTF("Only CPU and GPU target is supported.");
        return invalid_argument;
    }

    error res;
    if (success != (res = initialize_g(tfl_ctx, g)))
        return res;

    uint32_t size = builder->buf[0].size;

    // Save model
    tfl_ctx->models[*g].model_pointer = (char *)wasm_runtime_malloc(size);
    if (tfl_ctx->models[*g].model_pointer == NULL) {
        NN_ERR_PRINTF("Error when allocating memory for model.");
        return missing_memory;
    }

    bh_memcpy_s(tfl_ctx->models[*g].model_pointer, size, builder->buf[0].buf,
                size);

    // Save model flatbuffer
    tfl_ctx->models[*g].model =
        std::move(tflite::FlatBufferModel::BuildFromBuffer(
            tfl_ctx->models[*g].model_pointer, size, NULL));

    if (tfl_ctx->models[*g].model == NULL) {
        NN_ERR_PRINTF("Loading model error.");
        wasm_runtime_free(tfl_ctx->models[*g].model_pointer);
        tfl_ctx->models[*g].model_pointer = NULL;
        return missing_memory;
    }

    // Save target
    tfl_ctx->models[*g].target = target;
    return success;
}

error
tensorflowlite_init_execution_context(void *tflite_ctx, graph g,
                                      graph_execution_context *ctx)
{
    TFLiteContext *tfl_ctx = (TFLiteContext *)tflite_ctx;

    error res;
    if (success != (res = is_valid_graph(tfl_ctx, g)))
        return res;

    if (success != (res = initialize_graph_ctx(tfl_ctx, g, ctx)))
        return res;

    // Build the interpreter with the InterpreterBuilder.
    tflite::ops::builtin::BuiltinOpResolver resolver;
    tflite::InterpreterBuilder tflite_builder(*tfl_ctx->models[g].model,
                                              resolver);
    tflite_builder(&tfl_ctx->interpreters[*ctx].interpreter);
    if (tfl_ctx->interpreters[*ctx].interpreter == NULL) {
        NN_ERR_PRINTF("Error when generating the interpreter.");
        return missing_memory;
    }

    bool use_default = false;
    switch (tfl_ctx->models[g].target) {
        case gpu:
        {
#if defined(WASI_NN_ENABLE_GPU)
            NN_WARN_PRINTF("GPU enabled.");
            // https://www.tensorflow.org/lite/performance/gpu
            TfLiteGpuDelegateOptionsV2 options =
                TfLiteGpuDelegateOptionsV2Default();
            options.inference_preference =
                TFLITE_GPU_INFERENCE_PREFERENCE_SUSTAINED_SPEED;
            options.inference_priority1 =
                TFLITE_GPU_INFERENCE_PRIORITY_MIN_LATENCY;
            tfl_ctx->delegate = TfLiteGpuDelegateV2Create(&options);
            if (tfl_ctx->delegate == NULL) {
                NN_ERR_PRINTF("Error when generating GPU delegate.");
                use_default = true;
                return missing_memory;
            }
            if (tfl_ctx->interpreters[*ctx]
                    .interpreter->ModifyGraphWithDelegate(tfl_ctx->delegate)
                != kTfLiteOk) {
                NN_ERR_PRINTF("Error when enabling GPU delegate.");
                use_default = true;
            }
#elif defined(WASI_NN_ENABLE_EXTERNAL_DELEGATE)
            NN_WARN_PRINTF("external delegation enabled.");
            TfLiteExternalDelegateOptions options =
                TfLiteExternalDelegateOptionsDefault(WASI_NN_EXT_DELEGATE_PATH);
            tfl_ctx->delegate = TfLiteExternalDelegateCreate(&options);
            if (tfl_ctx->delegate == NULL) {
                NN_ERR_PRINTF("Error when generating External delegate.");
                use_default = true;
                return missing_memory;
            }
            if (tfl_ctx->interpreters[*ctx]
                    .interpreter->ModifyGraphWithDelegate(tfl_ctx->delegate)
                != kTfLiteOk) {
                NN_ERR_PRINTF("Error when enabling External delegate.");
                use_default = true;
            }
#else
            NN_WARN_PRINTF("GPU not enabled.");
            use_default = true;
#endif
            break;
        }
        default:
            use_default = true;
    }
    if (use_default)
        NN_WARN_PRINTF("Default encoding is CPU.");

    tfl_ctx->interpreters[*ctx].interpreter->AllocateTensors();
    return success;
}

error
tensorflowlite_set_input(void *tflite_ctx, graph_execution_context ctx,
                         uint32_t index, tensor *input_tensor)
{
    TFLiteContext *tfl_ctx = (TFLiteContext *)tflite_ctx;

    error res;
    if (success != (res = is_valid_graph_execution_context(tfl_ctx, ctx)))
        return res;

    uint32_t num_tensors =
        tfl_ctx->interpreters[ctx].interpreter->inputs().size();
    NN_DBG_PRINTF("Number of tensors (%d)", num_tensors);
    if (index + 1 > num_tensors) {
        return runtime_error;
    }

    auto tensor = tfl_ctx->interpreters[ctx].interpreter->input_tensor(index);
    if (tensor == NULL) {
        NN_ERR_PRINTF("Missing memory");
        return missing_memory;
    }

    uint32_t model_tensor_size = 1;
    for (int i = 0; i < tensor->dims->size; ++i)
        model_tensor_size *= (uint32_t)tensor->dims->data[i];

    uint32_t input_tensor_size = 1;
    for (uint32_t i = 0; i < input_tensor->dimensions->size; i++)
        input_tensor_size *= (uint32_t)input_tensor->dimensions->buf[i];

    if (model_tensor_size != input_tensor_size) {
        NN_ERR_PRINTF("Input tensor shape from the model is different than the "
                      "one provided");
        return invalid_argument;
    }

    auto *input =
        tfl_ctx->interpreters[ctx].interpreter->typed_input_tensor<float>(
            index);
    if (input == NULL)
        return missing_memory;

    bh_memcpy_s(input, model_tensor_size * sizeof(float), input_tensor->data,
                model_tensor_size * sizeof(float));
    return success;
}

error
tensorflowlite_compute(void *tflite_ctx, graph_execution_context ctx)
{
    TFLiteContext *tfl_ctx = (TFLiteContext *)tflite_ctx;

    error res;
    if (success != (res = is_valid_graph_execution_context(tfl_ctx, ctx)))
        return res;

    tfl_ctx->interpreters[ctx].interpreter->Invoke();
    return success;
}

error
tensorflowlite_get_output(void *tflite_ctx, graph_execution_context ctx,
                          uint32_t index, tensor_data output_tensor,
                          uint32_t *output_tensor_size)
{
    TFLiteContext *tfl_ctx = (TFLiteContext *)tflite_ctx;

    error res;
    if (success != (res = is_valid_graph_execution_context(tfl_ctx, ctx)))
        return res;

    uint32_t num_output_tensors =
        tfl_ctx->interpreters[ctx].interpreter->outputs().size();
    NN_DBG_PRINTF("Number of tensors (%d)", num_output_tensors);

    if (index + 1 > num_output_tensors) {
        return runtime_error;
    }

    auto tensor = tfl_ctx->interpreters[ctx].interpreter->output_tensor(index);
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

    float *tensor_f =
        tfl_ctx->interpreters[ctx].interpreter->typed_output_tensor<float>(
            index);
    for (uint32_t i = 0; i < model_tensor_size; ++i)
        NN_DBG_PRINTF("output: %f", tensor_f[i]);

    *output_tensor_size = model_tensor_size;
    bh_memcpy_s(output_tensor, model_tensor_size * sizeof(float), tensor_f,
                model_tensor_size * sizeof(float));
    return success;
}

void
tensorflowlite_initialize(void **tflite_ctx)
{
    TFLiteContext *tfl_ctx = new TFLiteContext();
    if (tfl_ctx == NULL) {
        NN_ERR_PRINTF("Error when allocating memory for tensorflowlite.");
        return;
    }

    NN_DBG_PRINTF("Initializing models.");
    tfl_ctx->current_models = 0;
    for (int i = 0; i < MAX_GRAPHS_PER_INST; ++i) {
        tfl_ctx->models[i].model_pointer = NULL;
    }
    NN_DBG_PRINTF("Initializing interpreters.");
    tfl_ctx->current_interpreters = 0;

    if (os_mutex_init(&tfl_ctx->g_lock) != 0) {
        NN_ERR_PRINTF("Error while initializing the lock");
    }

    tfl_ctx->delegate = NULL;

    *tflite_ctx = (void *)tfl_ctx;
}

void
tensorflowlite_destroy(void *tflite_ctx)
{
    /*
        TensorFlow Lite memory is internally managed by tensorflow

        Related issues:
        * https://github.com/tensorflow/tensorflow/issues/15880
    */
    TFLiteContext *tfl_ctx = (TFLiteContext *)tflite_ctx;

    if (tfl_ctx->delegate != NULL) {
#if defined(WASI_NN_ENABLE_GPU)
        TfLiteGpuDelegateV2Delete(tfl_ctx->delegate);
#elif defined(WASI_NN_ENABLE_EXTERNAL_DELEGATE)
        TfLiteExternalDelegateDelete(tfl_ctx->delegate);
#endif
    }

    NN_DBG_PRINTF("Freeing memory.");
    for (int i = 0; i < MAX_GRAPHS_PER_INST; ++i) {
        tfl_ctx->models[i].model.reset();
        if (tfl_ctx->models[i].model_pointer)
            wasm_runtime_free(tfl_ctx->models[i].model_pointer);
        tfl_ctx->models[i].model_pointer = NULL;
    }
    for (int i = 0; i < MAX_GRAPH_EXEC_CONTEXTS_PER_INST; ++i) {
        tfl_ctx->interpreters[i].interpreter.reset();
    }
    os_mutex_destroy(&tfl_ctx->g_lock);
    delete tfl_ctx;
    NN_DBG_PRINTF("Memory free'd.");
}
