/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_app.h"
#include "wa-inc/request.h"

void
res1_handler(request_t *request)
{
    response_t response[1];
    attr_container_t *payload;

    printf("[resp] ### user resource 1 handler called\n");

    printf("[resp] ###### dump request ######\n");
    printf("[resp] sender: %lu\n", request->sender);
    printf("[resp] url: %s\n", request->url);
    printf("[resp] action: %d\n", request->action);
    printf("[resp] payload:\n");
    if (request->payload != NULL && request->fmt == FMT_ATTR_CONTAINER)
        attr_container_dump((attr_container_t *)request->payload);
    printf("[resp] #### dump request end ###\n");

    payload = attr_container_create("wasm app response payload");
    if (payload == NULL)
        return;

    attr_container_set_string(&payload, "key1", "value1");
    attr_container_set_string(&payload, "key2", "value2");

    make_response_for_request(request, response);
    set_response(response, CONTENT_2_05, FMT_ATTR_CONTAINER,
                 (const char *)payload,
                 attr_container_get_serialize_length(payload));
    printf("[resp] response payload len %d\n",
           attr_container_get_serialize_length(payload));
    printf("[resp] reciver: %lu, mid:%d\n", response->reciever, response->mid);
    api_response_send(response);

    attr_container_destroy(payload);
}

void
on_init()
{
    /* register resource uri */
    api_register_resource_handler("/url1", res1_handler);
}

void
on_destroy()
{
    /* real destroy work including killing timer and closing sensor is
     * accomplished in wasm app library version of on_destroy() */
}
