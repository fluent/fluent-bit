/*
 * Copyright (C) 2025 Midokura Japan KK.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#define WASM_ENABLE_WASI_EPHEMERAL_NN 1
#define WASI_NN_NAME(name) wasi_ephemeral_nn_##name

#include "wasi_nn.h"

#undef WASM_ENABLE_WASI_EPHEMERAL_NN
#undef WASI_NN_NAME
