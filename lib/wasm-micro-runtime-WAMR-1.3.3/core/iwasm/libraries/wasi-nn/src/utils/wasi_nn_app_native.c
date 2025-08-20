/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasi_nn_app_native.h"

static error
graph_builder_app_native(wasm_module_inst_t instance,
                         graph_builder_wasm *builder_wasm,
                         graph_builder *builder)
{
    if (!wasm_runtime_validate_app_addr(instance, builder_wasm->buf_offset,
                                        builder_wasm->size * sizeof(uint8_t))) {
        NN_ERR_PRINTF("builder_wasm->buf_offset is invalid");
        return invalid_argument;
    }

    builder->buf = (uint8_t *)wasm_runtime_addr_app_to_native(
        instance, builder_wasm->buf_offset);
    builder->size = builder_wasm->size;
    return success;
}

error
graph_builder_array_app_native(wasm_module_inst_t instance,
                               graph_builder_array_wasm *builder_array_wasm,
                               graph_builder_array *builder_array)
{
    if (!wasm_runtime_validate_native_addr(instance, builder_array_wasm,
                                           sizeof(graph_builder_array_wasm))) {
        NN_ERR_PRINTF("builder_array_wasm is invalid");
        return invalid_argument;
    }

    NN_DBG_PRINTF("Graph builder array contains %d elements",
                  builder_array_wasm->size);

    if (!wasm_runtime_validate_app_addr(
            instance, builder_array_wasm->buf_offset,
            builder_array_wasm->size * sizeof(graph_builder_wasm))) {
        NN_ERR_PRINTF("builder_array_wasm->buf_offset is invalid");
        return invalid_argument;
    }

    graph_builder_wasm *builder_wasm =
        (graph_builder_wasm *)wasm_runtime_addr_app_to_native(
            instance, builder_array_wasm->buf_offset);

    graph_builder *builder = (graph_builder *)wasm_runtime_malloc(
        builder_array_wasm->size * sizeof(graph_builder));
    if (builder == NULL)
        return missing_memory;

    for (uint32_t i = 0; i < builder_array_wasm->size; ++i) {
        error res;
        if (success
            != (res = graph_builder_app_native(instance, &builder_wasm[i],
                                               &builder[i]))) {
            wasm_runtime_free(builder);
            return res;
        }

        NN_DBG_PRINTF("Graph builder %d contains %d elements", i,
                      builder->size);
    }

    builder_array->buf = builder;
    builder_array->size = builder_array_wasm->size;
    return success;
}

static error
tensor_data_app_native(wasm_module_inst_t instance, uint32_t total_elements,
                       tensor_wasm *input_tensor_wasm, tensor_data *data)
{
    if (!wasm_runtime_validate_app_addr(
            instance, input_tensor_wasm->data_offset, total_elements)) {
        NN_ERR_PRINTF("input_tensor_wasm->data_offset is invalid");
        return invalid_argument;
    }
    *data = (tensor_data)wasm_runtime_addr_app_to_native(
        instance, input_tensor_wasm->data_offset);
    return success;
}

static error
tensor_dimensions_app_native(wasm_module_inst_t instance,
                             tensor_wasm *input_tensor_wasm,
                             tensor_dimensions **dimensions)
{
    if (!wasm_runtime_validate_app_addr(instance,
                                        input_tensor_wasm->dimensions_offset,
                                        sizeof(tensor_dimensions_wasm))) {
        NN_ERR_PRINTF("input_tensor_wasm->dimensions_offset is invalid");
        return invalid_argument;
    }

    tensor_dimensions_wasm *dimensions_wasm =
        (tensor_dimensions_wasm *)wasm_runtime_addr_app_to_native(
            instance, input_tensor_wasm->dimensions_offset);

    if (!wasm_runtime_validate_app_addr(instance, dimensions_wasm->buf_offset,
                                        sizeof(tensor_dimensions))) {
        NN_ERR_PRINTF("dimensions_wasm->buf_offset is invalid");
        return invalid_argument;
    }

    *dimensions =
        (tensor_dimensions *)wasm_runtime_malloc(sizeof(tensor_dimensions));
    if (dimensions == NULL)
        return missing_memory;

    (*dimensions)->size = dimensions_wasm->size;
    (*dimensions)->buf = (uint32_t *)wasm_runtime_addr_app_to_native(
        instance, dimensions_wasm->buf_offset);

    NN_DBG_PRINTF("Number of dimensions: %d", (*dimensions)->size);
    return success;
}

error
tensor_app_native(wasm_module_inst_t instance, tensor_wasm *input_tensor_wasm,
                  tensor *input_tensor)
{
    NN_DBG_PRINTF("Converting tensor_wasm to tensor");
    if (!wasm_runtime_validate_native_addr(instance, input_tensor_wasm,
                                           sizeof(tensor_wasm))) {
        NN_ERR_PRINTF("input_tensor_wasm is invalid");
        return invalid_argument;
    }

    error res;

    tensor_dimensions *dimensions = NULL;
    if (success
        != (res = tensor_dimensions_app_native(instance, input_tensor_wasm,
                                               &dimensions))) {
        NN_ERR_PRINTF("error when parsing dimensions");
        return res;
    }

    uint32_t total_elements = 1;
    for (uint32_t i = 0; i < dimensions->size; ++i) {
        total_elements *= dimensions->buf[i];
        NN_DBG_PRINTF("Dimension %d: %d", i, dimensions->buf[i]);
    }
    NN_DBG_PRINTF("Tensor type: %d", input_tensor_wasm->type);
    NN_DBG_PRINTF("Total number of elements: %d", total_elements);

    tensor_data data = NULL;
    if (success
        != (res = tensor_data_app_native(instance, total_elements,
                                         input_tensor_wasm, &data))) {
        wasm_runtime_free(dimensions);
        return res;
    }

    input_tensor->type = input_tensor_wasm->type;
    input_tensor->dimensions = dimensions;
    input_tensor->data = data;
    return success;
}
