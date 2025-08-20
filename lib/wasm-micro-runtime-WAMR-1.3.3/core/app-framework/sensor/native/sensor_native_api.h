/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _SENSOR_NATIVE_API_H_
#define _SENSOR_NATIVE_API_H_

#include "bh_platform.h"
#include "wasm_export.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
wasm_sensor_config(wasm_exec_env_t exec_env, uint32 sensor, uint32 interval,
                   int bit_cfg, uint32 delay);
uint32
wasm_sensor_open(wasm_exec_env_t exec_env, char *name, int instance);

bool
wasm_sensor_config_with_attr_container(wasm_exec_env_t exec_env, uint32 sensor,
                                       char *buffer, int len);

bool
wasm_sensor_close(wasm_exec_env_t exec_env, uint32 sensor);

#ifdef __cplusplus
}
#endif

#endif /* end of _SENSOR_NATIVE_API_H_ */
