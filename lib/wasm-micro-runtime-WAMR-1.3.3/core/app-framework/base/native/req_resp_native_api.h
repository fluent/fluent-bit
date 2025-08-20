/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _REQ_RESP_API_H_
#define _REQ_RESP_API_H_

#include "bh_platform.h"
#include "wasm_export.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
wasm_response_send(wasm_exec_env_t exec_env, char *buffer, int size);
void
wasm_register_resource(wasm_exec_env_t exec_env, char *url);
void
wasm_post_request(wasm_exec_env_t exec_env, char *buffer, int size);
void
wasm_sub_event(wasm_exec_env_t exec_env, char *url);

#ifdef __cplusplus
}
#endif

#endif /* end of _REQ_RESP_API_H_ */
