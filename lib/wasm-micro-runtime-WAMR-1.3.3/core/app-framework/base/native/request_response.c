/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "app_manager_export.h"
#include "coap_ext.h"
#include "wasm_export.h"
#include "bh_assert.h"

extern void
module_request_handler(request_t *request, void *user_data);

bool
wasm_response_send(wasm_exec_env_t exec_env, char *buffer, int size)
{
    if (buffer != NULL) {
        response_t response[1];

        if (NULL == unpack_response(buffer, size, response))
            return false;

        am_send_response(response);

        return true;
    }

    return false;
}

void
wasm_register_resource(wasm_exec_env_t exec_env, char *url)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    if (url != NULL) {
        unsigned int mod_id =
            app_manager_get_module_id(Module_WASM_App, module_inst);
        bh_assert(mod_id != ID_NONE);
        am_register_resource(url, module_request_handler, mod_id);
    }
}

void
wasm_post_request(wasm_exec_env_t exec_env, char *buffer, int size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    if (buffer != NULL) {
        request_t req[1];

        if (!unpack_request(buffer, size, req))
            return;

        // TODO: add permission check, ensure app can't do harm

        // set sender to help dispatch the response to the sender ap
        unsigned int mod_id =
            app_manager_get_module_id(Module_WASM_App, module_inst);
        bh_assert(mod_id != ID_NONE);
        req->sender = mod_id;

        if (req->action == COAP_EVENT) {
            am_publish_event(req);
            return;
        }

        am_dispatch_request(req);
    }
}

void
wasm_sub_event(wasm_exec_env_t exec_env, char *url)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    if (url != NULL) {
        unsigned int mod_id =
            app_manager_get_module_id(Module_WASM_App, module_inst);

        bh_assert(mod_id != ID_NONE);
        am_register_event(url, mod_id);
    }
}
