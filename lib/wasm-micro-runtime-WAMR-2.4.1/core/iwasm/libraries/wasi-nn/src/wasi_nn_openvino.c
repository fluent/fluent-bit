/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasi_nn_backend.h"
#include "utils/logger.h"
#include "bh_platform.h"

#include "openvino/c/openvino.h"

#if WASM_ENABLE_WASI_EPHEMERAL_NN == 0
#error This backend doesn't support legacy "wasi_nn" abi. Please enable WASM_ENABLE_WASI_EPHEMERAL_NN.
#endif

/*
 * refer to
 * https://docs.openvino.ai/2024/openvino-workflow/running-inference/integrate-openvino-with-your-application.html
 *
 * Steps about integrating OpenVINO are:
 *
 * 1. Create OpenVINO Runtime Core
 * 2. Compile Model
 * 3. Create Inference Request
 * 4. Set Inputs
 * 5. Start Inference
 * 6. Process Inference Results
 *
 * from 4. to 6. is the Inference Loop
 */

/* these limits are arbitrary. */
#define MAX_GRAPHS 4
#define MAX_EXECUTION_CONTEXTS 4

typedef struct {
    ov_core_t *core;
    /* keep input model files */
    struct OpenVINOGraph {
        void *weight_data;
        ov_tensor_t *weights_tensor;
        ov_model_t *model;
        ov_compiled_model_t *compiled_model;
    } graphs[MAX_GRAPHS];
    struct OpenVINOExecutionContext {
        struct OpenVINOGraph *graph;
        ov_infer_request_t *infer_request;
    } execution_contexts[MAX_EXECUTION_CONTEXTS];
    unsigned int n_graphs;
    unsigned int n_execution_contexts;
} OpenVINOContext;

/*
 * BE AWARE OF "goto fail"
 */
#define CHECK_OV_STATUS(status, error_code)                \
    do {                                                   \
        ov_status_e s = status;                            \
        if (s != OK) {                                     \
            NN_ERR_PRINTF("return status \"%s\", line %d", \
                          ov_get_error_info(s), __LINE__); \
            error_code = runtime_error;                    \
            goto fail;                                     \
        }                                                  \
    } while (0)

static void
dump_ov_shape_t(const ov_shape_t *shape, int32_t output_len, char *output)
{
    int ret = 0;

    ret = snprintf(output, output_len, "%" PRId64 ",[", shape->rank);
    if (!ret)
        return;

    output_len -= ret;
    output += ret;

    for (unsigned i = 0; i < shape->rank && output_len; i++) {
        ret = snprintf(output, output_len, " %" PRId64, shape->dims[i]);
        if (!ret)
            return;

        output_len -= ret;
        output += ret;
    }

    snprintf(output, output_len, "]");
    return;
}

#ifndef NDEBUG
static void
print_model_input_output_info(ov_model_t *model)
{
    wasi_nn_error ov_error = success;
    char *friendly_name = NULL;
    size_t input_size = 0;
    ov_output_const_port_t *input_port = NULL;
    ov_shape_t input_shape = { 0 };
    ov_element_type_e input_type;
    char shape_info[64] = { 0 };
    ov_output_const_port_t *output_port = NULL;
    ov_shape_t output_shape = { 0 };
    ov_element_type_e output_type;

    CHECK_OV_STATUS(ov_model_get_friendly_name(model, &friendly_name),
                    ov_error);
    NN_DBG_PRINTF("model name: %s", friendly_name);

    ov_model_inputs_size(model, &input_size);
    for (unsigned i = 0; i < input_size; i++) {
        CHECK_OV_STATUS(ov_model_const_input_by_index(model, i, &input_port),
                        ov_error);
        CHECK_OV_STATUS(ov_const_port_get_shape(input_port, &input_shape),
                        ov_error);
        CHECK_OV_STATUS(ov_port_get_element_type(input_port, &input_type),
                        ov_error);

        dump_ov_shape_t(&input_shape, 60, shape_info);
        NN_DBG_PRINTF("model input[%u]. element_type: %d, shape: %s", i,
                      input_type, shape_info);

        ov_shape_free(&input_shape);
        memset(&input_shape, 0, sizeof(input_shape));
        ov_output_const_port_free(input_port);
        input_port = NULL;
    }

    size_t output_size = 0;
    ov_model_outputs_size(model, &output_size);
    for (unsigned i = 0; i < output_size; i++) {
        CHECK_OV_STATUS(ov_model_const_output_by_index(model, i, &output_port),
                        ov_error);
        CHECK_OV_STATUS(ov_const_port_get_shape(output_port, &output_shape),
                        ov_error);
        CHECK_OV_STATUS(ov_port_get_element_type(output_port, &output_type),
                        ov_error);

        dump_ov_shape_t(&output_shape, 60, shape_info);
        NN_DBG_PRINTF("model output[%u]. element_type: %d, shape: %s", i,
                      output_type, shape_info);

        ov_shape_free(&output_shape);
        memset(&output_shape, 0, sizeof(output_shape));
        ov_output_const_port_free(output_port);
        output_port = NULL;
    }

    (void)ov_error;
fail:
    if (friendly_name)
        ov_free(friendly_name);
    ov_shape_free(&input_shape);
    if (input_port)
        ov_output_const_port_free(input_port);
    ov_shape_free(&output_shape);
    if (output_port)
        ov_output_const_port_free(output_port);
    return;
}
#endif

static ov_element_type_e
wasi_nn_tensor_type_to_openvino_element_type(tensor_type wasi_nn_type)
{
    switch (wasi_nn_type) {
        case fp16:
            return F16;
        case fp32:
            return F32;
#if WASM_ENABLE_WASI_EPHEMERAL_NN != 0
        case fp64:
            return F64;
        case i64:
            return I64;
        case u8:
            return U8;
        case i32:
            return I32;
#else
        case up8:
            return U8;
        case ip32:
            return I32;
#endif
        default:
            break;
    }

    NN_ERR_PRINTF("%d is an undefined tensor type", wasi_nn_type);
    return UNDEFINED;
}

static void
free_graph(struct OpenVINOGraph *graph)
{
    if (graph->weight_data)
        os_free(graph->weight_data);

    if (graph->weights_tensor)
        ov_tensor_free(graph->weights_tensor);

    if (graph->model)
        ov_model_free(graph->model);

    if (graph->compiled_model)
        ov_compiled_model_free(graph->compiled_model);
}

static void
free_execution_context(struct OpenVINOExecutionContext *c)
{
    if (c->infer_request)
        ov_infer_request_free(c->infer_request);
}

static wasi_nn_error
uint32_array_to_int64_array(uint32_t array_size, uint32_t *src, int64_t **dst)
{
    *dst = os_malloc(array_size * sizeof(int64_t));
    if (!(*dst))
        return runtime_error;

    for (unsigned i = 0; i < array_size; i++) {
        (*dst)[i] = src[i];
    }

    return success;
}

__attribute__((visibility("default"))) wasi_nn_error
load(void *ctx, graph_builder_array *builder, graph_encoding encoding,
     execution_target target, graph *g)
{
    OpenVINOContext *ov_ctx = (OpenVINOContext *)ctx;
    struct OpenVINOGraph *graph;
    unsigned int graph_idx;
    wasi_nn_error ret = unsupported_operation;

    if (encoding != openvino) {
        NN_ERR_PRINTF("Unexpected encoding %d.", encoding);
        return invalid_argument;
    }

    /*FIXME: unblock non-cpu device after supporting */
    if (target != cpu) {
        NN_ERR_PRINTF("Unexpected device %d.", target);
        return invalid_argument;
    }

    if (builder->size != 2) {
        NN_ERR_PRINTF("Unexpected builder format.");
        return invalid_argument;
    }

    /*
     * The first builder is the XML file.
     * The second builder is the weight file.
     */
    graph_builder xml = builder->buf[0];
    graph_builder weight = builder->buf[1];

    graph_idx = ov_ctx->n_graphs;
    if (graph_idx >= MAX_GRAPHS) {
        return runtime_error;
    }
    graph = &ov_ctx->graphs[graph_idx];
    memset(graph, 0, sizeof(*graph));

    /* transfer weight to an ov tensor */
    {
        graph->weight_data = os_malloc(weight.size);
        if (!graph->weight_data)
            goto fail;
        memcpy(graph->weight_data, weight.buf, weight.size);

        ov_element_type_e type = U8;
        int64_t dims[1] = { weight.size };
        ov_shape_t shape = { 1, dims };
        CHECK_OV_STATUS(ov_tensor_create_from_host_ptr(type, shape,
                                                       graph->weight_data,
                                                       &graph->weights_tensor),
                        ret);
    }

    /* load model from buffer */
    CHECK_OV_STATUS(ov_core_read_model_from_memory_buffer(
                        ov_ctx->core, (char *)xml.buf, xml.size,
                        graph->weights_tensor, &graph->model),
                    ret);
#ifndef NDEBUG
    print_model_input_output_info(graph->model);
#endif

    CHECK_OV_STATUS(ov_core_compile_model(ov_ctx->core, graph->model, "CPU", 0,
                                          &graph->compiled_model),
                    ret);

    *g = graph_idx;
    ov_ctx->n_graphs++;
    return success;
fail:
    free_graph(graph);
    return ret;
}

__attribute__((visibility("default"))) wasi_nn_error
load_by_name(void *ctx, const char *filename, uint32_t filename_len, graph *g)
{
    OpenVINOContext *ov_ctx = (OpenVINOContext *)ctx;
    struct OpenVINOGraph *graph;
    unsigned int graph_idx;
    wasi_nn_error ret = unsupported_operation;

    graph_idx = ov_ctx->n_graphs;
    if (graph_idx >= MAX_GRAPHS) {
        return runtime_error;
    }
    graph = &ov_ctx->graphs[graph_idx];

    memset(graph, 0, sizeof(*graph));
    CHECK_OV_STATUS(
        ov_core_read_model(ov_ctx->core, filename, NULL, &graph->model), ret);

    CHECK_OV_STATUS(ov_core_compile_model(ov_ctx->core, graph->model, "CPU", 0,
                                          &graph->compiled_model),
                    ret);

    *g = graph_idx;
    ov_ctx->n_graphs++;
    return success;
fail:
    free_graph(graph);
    return ret;
}

__attribute__((visibility("default"))) wasi_nn_error
init_execution_context(void *ctx, graph g, graph_execution_context *exec_ctx)
{
    OpenVINOContext *ov_ctx = (OpenVINOContext *)ctx;
    struct OpenVINOGraph *graph;
    struct OpenVINOExecutionContext *exec;
    unsigned int exec_idx;
    wasi_nn_error ret;

    if (g >= ov_ctx->n_graphs)
        return runtime_error;
    graph = &ov_ctx->graphs[g];

    exec_idx = ov_ctx->n_execution_contexts;
    if (exec_idx >= MAX_EXECUTION_CONTEXTS)
        return runtime_error;
    exec = &ov_ctx->execution_contexts[exec_idx];

    memset(exec, 0, sizeof(*exec));
    exec->graph = graph;

    CHECK_OV_STATUS(ov_compiled_model_create_infer_request(
                        graph->compiled_model, &exec->infer_request),
                    ret);

    *exec_ctx = exec_idx;
    ov_ctx->n_execution_contexts++;
    return success;
fail:
    return ret;
}

__attribute__((visibility("default"))) wasi_nn_error
set_input(void *ctx, graph_execution_context exec_ctx, uint32_t index,
          tensor *wasi_nn_tensor)
{
    OpenVINOContext *ov_ctx = (OpenVINOContext *)ctx;
    struct OpenVINOExecutionContext *exec;
    wasi_nn_error ret = unsupported_operation;
    ov_shape_t input_shape = { 0 };
    ov_tensor_t *input_tensor = NULL;
    int64_t *ov_dims = NULL;

    if (exec_ctx >= ov_ctx->n_execution_contexts)
        return runtime_error;
    exec = &ov_ctx->execution_contexts[exec_ctx];

    /* wasi_nn_tensor -> ov_tensor */
    {
        ret = uint32_array_to_int64_array(wasi_nn_tensor->dimensions->size,
                                          wasi_nn_tensor->dimensions->buf,
                                          &ov_dims);
        if (ret != success)
            goto fail;

        CHECK_OV_STATUS(ov_shape_create(wasi_nn_tensor->dimensions->size,
                                        ov_dims, &input_shape),
                        ret);

        ov_element_type_e input_type =
            wasi_nn_tensor_type_to_openvino_element_type(wasi_nn_tensor->type);
        if (input_type == UNDEFINED)
            goto fail;

        char shape_info[64] = { 0 };
        dump_ov_shape_t(&input_shape, 60, shape_info);
        NN_DBG_PRINTF("input tensor. element_type: %d, shape: %s", input_type,
                      shape_info);

        CHECK_OV_STATUS(ov_tensor_create_from_host_ptr(input_type, input_shape,
                                                       wasi_nn_tensor->data.buf,
                                                       &input_tensor),
                        ret);
    }

    /* install ov_tensor -> infer_request */
    CHECK_OV_STATUS(ov_infer_request_set_input_tensor_by_index(
                        exec->infer_request, index, input_tensor),
                    ret);
    ret = success;
fail:
    if (ov_dims)
        os_free(ov_dims);
    if (input_tensor)
        ov_tensor_free(input_tensor);
    ov_shape_free(&input_shape);

    return ret;
}

__attribute__((visibility("default"))) wasi_nn_error
compute(void *ctx, graph_execution_context exec_ctx)
{
    OpenVINOContext *ov_ctx = (OpenVINOContext *)ctx;
    struct OpenVINOExecutionContext *exec;
    wasi_nn_error ret = unsupported_operation;

    if (exec_ctx >= ov_ctx->n_execution_contexts)
        return runtime_error;
    exec = &ov_ctx->execution_contexts[exec_ctx];

    CHECK_OV_STATUS(ov_infer_request_infer(exec->infer_request), ret);
    ret = success;
fail:
    return ret;
}

__attribute__((visibility("default"))) wasi_nn_error
get_output(void *ctx, graph_execution_context exec_ctx, uint32_t index,
           tensor_data *output_tensor, uint32_t *output_tensor_size)
{
    OpenVINOContext *ov_ctx = (OpenVINOContext *)ctx;
    struct OpenVINOExecutionContext *exec;
    wasi_nn_error ret = unsupported_operation;
    ov_tensor_t *ov_tensor = NULL;
    void *data = NULL;
    size_t byte_size = 0;

    if (exec_ctx >= ov_ctx->n_execution_contexts)
        return runtime_error;
    exec = &ov_ctx->execution_contexts[exec_ctx];

    CHECK_OV_STATUS(ov_infer_request_get_output_tensor_by_index(
                        exec->infer_request, index, &ov_tensor),
                    ret);

    CHECK_OV_STATUS(ov_tensor_get_byte_size(ov_tensor, &byte_size), ret);

    if (byte_size > output_tensor->size) {
        ret = too_large;
        goto fail;
    }

    CHECK_OV_STATUS(ov_tensor_data(ov_tensor, &data), ret);

    memcpy(output_tensor->buf, data, byte_size);

    *output_tensor_size = (uint32_t)byte_size;

    ret = success;

fail:
    if (ov_tensor)
        ov_tensor_free(ov_tensor);
    return ret;
}

__attribute__((visibility("default"))) wasi_nn_error
init_backend(void **ctx)
{
    ov_version_t version;
    OpenVINOContext *ov_ctx = NULL;
    wasi_nn_error ret = unsupported_operation;

    if (!ctx) {
        ret = invalid_argument;
        goto fail;
    }

    /* Get OpenVINO runtime version */
    CHECK_OV_STATUS(ov_get_openvino_version(&version), ret);
    NN_INFO_PRINTF("OpenVINO INFO:");
    NN_INFO_PRINTF("  Description : %s", version.description);
    NN_INFO_PRINTF("  Build Number: %s", version.buildNumber);
    ov_version_free(&version);

    ov_ctx = (OpenVINOContext *)os_malloc(sizeof(OpenVINOContext));
    if (!ov_ctx) {
        NN_ERR_PRINTF("Allocate for OpenVINOContext failed");
        ret = runtime_error;
        goto fail;
    }

    memset(ov_ctx, 0, sizeof(OpenVINOContext));

    /* Initialize OpenVINO Runtime Core */
    CHECK_OV_STATUS(ov_core_create(&ov_ctx->core), ret);

    *ctx = (void *)ov_ctx;
    return success;
fail:
    os_free(ov_ctx);
    return ret;
}

__attribute__((visibility("default"))) wasi_nn_error
deinit_backend(void *ctx)
{
    OpenVINOContext *ov_ctx = (OpenVINOContext *)ctx;
    unsigned int i;

    if (!ov_ctx)
        return invalid_argument;

    for (i = 0; i < ov_ctx->n_execution_contexts; i++)
        free_execution_context(&ov_ctx->execution_contexts[i]);

    for (i = 0; i < ov_ctx->n_graphs; i++)
        free_graph(&ov_ctx->graphs[i]);

    if (ov_ctx->core)
        ov_core_free(ov_ctx->core);

    os_free(ov_ctx);
    return success;
}
