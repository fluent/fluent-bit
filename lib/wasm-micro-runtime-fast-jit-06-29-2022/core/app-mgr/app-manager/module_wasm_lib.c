/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "module_wasm_lib.h"

static bool
wasm_lib_module_init(void)
{
    return false;
}

static bool
wasm_lib_module_install(request_t *msg)
{
    (void)msg;
    return false;
}

static bool
wasm_lib_module_uninstall(request_t *msg)
{
    (void)msg;
    return false;
}

static void
wasm_lib_module_watchdog_kill(module_data *m_data)
{
    (void)m_data;
}

static bool
wasm_lib_module_handle_host_url(void *queue_msg)
{
    (void)queue_msg;
    return false;
}

static module_data *
wasm_lib_module_get_module_data(void *inst)
{
    (void)inst;
    return NULL;
}

/* clang-format off */
module_interface wasm_lib_module_interface = {
    wasm_lib_module_init,
    wasm_lib_module_install,
    wasm_lib_module_uninstall,
    wasm_lib_module_watchdog_kill,
    wasm_lib_module_handle_host_url,
    wasm_lib_module_get_module_data,
    NULL
};
/* clang-format on */
