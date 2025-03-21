/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _TIMER_API_H_
#define _TIMER_API_H_

#include "bh_platform.h"
#include "wasm_export.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int timer_id_t;

/*
 * timer interfaces
 */

typedef unsigned int timer_id_t;

timer_id_t
wasm_create_timer(wasm_exec_env_t exec_env, int interval, bool is_period,
                  bool auto_start);
void
wasm_timer_destroy(wasm_exec_env_t exec_env, timer_id_t timer_id);
void
wasm_timer_cancel(wasm_exec_env_t exec_env, timer_id_t timer_id);
void
wasm_timer_restart(wasm_exec_env_t exec_env, timer_id_t timer_id, int interval);
uint32
wasm_get_sys_tick_ms(wasm_exec_env_t exec_env);

#ifdef __cplusplus
}
#endif

#endif /* end of _TIMER_API_H_ */
