/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef WASI_NN_HOST_H
#define WASI_NN_HOST_H

#include "lib_export.h"

uint32_t
get_wasi_nn_export_apis(NativeSymbol **p_native_symbols);

bool
wasi_nn_initialize();

void
wasi_nn_destroy();

#endif /* WASI_NN_HOST_H */