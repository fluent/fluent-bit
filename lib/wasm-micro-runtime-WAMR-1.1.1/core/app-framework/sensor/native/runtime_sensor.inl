/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

EXPORT_WASM_API_WITH_SIG(wasm_sensor_open, "($i)i"),
EXPORT_WASM_API_WITH_SIG(wasm_sensor_config, "(iiii)i"),
EXPORT_WASM_API_WITH_SIG(wasm_sensor_config_with_attr_container, "(i*~)i"),
EXPORT_WASM_API_WITH_SIG(wasm_sensor_close, "(i)i"),
