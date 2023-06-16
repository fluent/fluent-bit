/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _SENSOR_API_H_
#define _SENSOR_API_H_

#include "bh_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

uint32
wasm_sensor_open(const char *name, int instance);

bool
wasm_sensor_config(uint32 sensor, uint32 interval, int bit_cfg, uint32 delay);

bool
wasm_sensor_config_with_attr_container(uint32 sensor, char *buffer, uint32 len);

bool
wasm_sensor_close(uint32 sensor);

#ifdef __cplusplus
}
#endif

#endif /* end of _SENSOR_API_H_ */
