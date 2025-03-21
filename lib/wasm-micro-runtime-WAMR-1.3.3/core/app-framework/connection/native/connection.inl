/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

EXPORT_WASM_API_WITH_SIG(wasm_open_connection, "($*~)i"),
EXPORT_WASM_API_WITH_SIG(wasm_close_connection, "(i)"),
EXPORT_WASM_API_WITH_SIG(wasm_send_on_connection, "(i*~)i"),
EXPORT_WASM_API_WITH_SIG(wasm_config_connection, "(i*~)i"),
