/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef WASI_NN_PRIVATE_H
#define WASI_NN_PRIVATE_H

#include "wasi_nn_types.h"
#include "wasm_export.h"

typedef struct {
    bool is_model_loaded;
    graph_encoding current_encoding;
    void *tflite_ctx;
} WASINNContext;

/**
 * @brief Destroy wasi-nn on app exists
 *
 */

void
wasi_nn_destroy(wasm_module_inst_t instance);

#endif
