/*
 * Copyright (C) 2025 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_VALIDATOR_H_
#define _AOT_VALIDATOR_H_

#include "aot_runtime.h"

bool
aot_module_validate(const AOTModule *module, char *error_buf,
                    uint32 error_buf_size);

#endif /* _AOT_VALIDATOR_H_ */
