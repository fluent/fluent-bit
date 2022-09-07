/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef CONNECTION_API_H_
#define CONNECTION_API_H_

#include "bh_platform.h"
#include "wasm_export.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * connection interfaces
 */

uint32
wasm_open_connection(wasm_exec_env_t exec_env, char *name, char *args_buf,
                     uint32 len);
void
wasm_close_connection(wasm_exec_env_t exec_env, uint32 handle);
int
wasm_send_on_connection(wasm_exec_env_t exec_env, uint32 handle, char *data,
                        uint32 len);
bool
wasm_config_connection(wasm_exec_env_t exec_env, uint32 handle, char *cfg_buf,
                       uint32 len);

#ifdef __cplusplus
}
#endif

#endif /* end of CONNECTION_API_H_ */
