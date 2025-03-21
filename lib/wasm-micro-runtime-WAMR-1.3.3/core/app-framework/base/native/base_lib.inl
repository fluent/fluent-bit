/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

    EXPORT_WASM_API_WITH_SIG(wasm_register_resource, "($)"),
    EXPORT_WASM_API_WITH_SIG(wasm_response_send, "(*~)i"),
    EXPORT_WASM_API_WITH_SIG(wasm_post_request, "(*~)"),
    EXPORT_WASM_API_WITH_SIG(wasm_sub_event, "($)"),
    EXPORT_WASM_API_WITH_SIG(wasm_create_timer, "(iii)i"),
    EXPORT_WASM_API_WITH_SIG(wasm_timer_destroy, "(i)"),
    EXPORT_WASM_API_WITH_SIG(wasm_timer_cancel, "(i)"),
    EXPORT_WASM_API_WITH_SIG(wasm_timer_restart, "(ii)"),
    EXPORT_WASM_API_WITH_SIG(wasm_get_sys_tick_ms, "()i"),
