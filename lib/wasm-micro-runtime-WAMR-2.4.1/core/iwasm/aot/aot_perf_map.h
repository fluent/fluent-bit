/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_PERF_MAP_H_
#define _AOT_PERF_MAP_H_

#include "aot_runtime.h"

bool
aot_create_perf_map(const AOTModule *module, char *error_buf,
                    uint32 error_buf_size);

#endif /* _AOT_PERF_MAP_H_ */