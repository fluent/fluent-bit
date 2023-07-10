/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef WASI_NN_PRIVATE_H
#define WASI_NN_PRIVATE_H

#include "wasi_nn_types.h"

typedef struct {
    bool is_initialized;
    graph_encoding current_encoding;
    void *tflite_ctx;
} WASINNContext;

/**
 * @brief Initialize wasi-nn
 *
 */
WASINNContext *
wasi_nn_initialize();
/**
 * @brief Destroy wasi-nn on app exists
 *
 */

void
wasi_nn_destroy(WASINNContext *wasi_nn_ctx);

#endif
