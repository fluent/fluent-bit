/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef LIB_BASE_RUNTIME_LIB_H_
#define LIB_BASE_RUNTIME_LIB_H_

#include "runtime_timer.h"

bool
init_wasm_timer();
void
exit_wasm_timer();
timer_ctx_t
get_wasm_timer_ctx();
timer_ctx_t
create_wasm_timer_ctx(unsigned int module_id, int prealloc_num);
void
destroy_module_timer_ctx(unsigned int module_id);

#endif /* LIB_BASE_RUNTIME_LIB_H_ */
