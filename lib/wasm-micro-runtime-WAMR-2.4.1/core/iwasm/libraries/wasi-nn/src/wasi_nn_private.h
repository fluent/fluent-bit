/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef WASI_NN_PRIVATE_H
#define WASI_NN_PRIVATE_H

#include "wasi_nn_types.h"
#include "wasm_export.h"

#include "bh_platform.h"

typedef struct {
    korp_mutex lock;
    bool busy;
    bool is_backend_ctx_initialized;
    bool is_model_loaded;
    graph_encoding backend;
    void *backend_ctx;
} WASINNContext;

typedef wasi_nn_error (*LOAD)(void *, graph_builder_array *, graph_encoding,
                              execution_target, graph *);
typedef wasi_nn_error (*LOAD_BY_NAME)(void *, const char *, uint32_t, graph *);
typedef wasi_nn_error (*LOAD_BY_NAME_WITH_CONFIG)(void *, const char *,
                                                  uint32_t, void *, uint32_t,
                                                  graph *);
typedef wasi_nn_error (*INIT_EXECUTION_CONTEXT)(void *, graph,
                                                graph_execution_context *);
typedef wasi_nn_error (*SET_INPUT)(void *, graph_execution_context, uint32_t,
                                   tensor *);
typedef wasi_nn_error (*COMPUTE)(void *, graph_execution_context);
typedef wasi_nn_error (*GET_OUTPUT)(void *, graph_execution_context, uint32_t,
                                    tensor_data *, uint32_t *);
/* wasi-nn general APIs */
typedef wasi_nn_error (*BACKEND_INITIALIZE)(void **);
typedef wasi_nn_error (*BACKEND_DEINITIALIZE)(void *);

typedef struct {
    LOAD load;
    LOAD_BY_NAME load_by_name;
    LOAD_BY_NAME_WITH_CONFIG load_by_name_with_config;
    INIT_EXECUTION_CONTEXT init_execution_context;
    SET_INPUT set_input;
    COMPUTE compute;
    GET_OUTPUT get_output;
    BACKEND_INITIALIZE init;
    BACKEND_DEINITIALIZE deinit;
} api_function;

#endif
