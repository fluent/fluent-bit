/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "connection_lib.h"
#include "wasm_export.h"
#include "native_interface.h"
#include "connection_native_api.h"

/* Note:
 *
 * This file is the consumer of connection lib which is implemented by different
 * platforms
 */

uint32
wasm_open_connection(wasm_exec_env_t exec_env, char *name, char *args_buf,
                     uint32 len)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    attr_container_t *args;

    args = (attr_container_t *)args_buf;

    if (connection_impl._open != NULL)
        return connection_impl._open(module_inst, name, args);

    return -1;
}

void
wasm_close_connection(wasm_exec_env_t exec_env, uint32 handle)
{
    if (connection_impl._close != NULL)
        connection_impl._close(handle);
}

int
wasm_send_on_connection(wasm_exec_env_t exec_env, uint32 handle, char *data,
                        uint32 len)
{
    if (connection_impl._send != NULL)
        return connection_impl._send(handle, data, len);

    return -1;
}

bool
wasm_config_connection(wasm_exec_env_t exec_env, uint32 handle, char *cfg_buf,
                       uint32 len)
{
    attr_container_t *cfg;

    cfg = (attr_container_t *)cfg_buf;

    if (connection_impl._config != NULL)
        return connection_impl._config(handle, cfg);

    return false;
}
