/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_app.h"
#include "wa-inc/request.h"

uint32 mid;
unsigned long sender;

void
my_response_handler(response_t *response, void *user_data)
{
    attr_container_t *payload;
    printf("### user resource 1 handler called\n");

    payload = attr_container_create("wasm app response payload");
    if (payload == NULL)
        return;

    attr_container_set_string(&payload, "key1", "value1");
    attr_container_set_string(&payload, "key2", "value2");

    response->mid = mid;
    response->reciever = sender;
    set_response(response, CONTENT_2_05, FMT_ATTR_CONTAINER,
                 (const char *)payload,
                 attr_container_get_serialize_length(payload));
    printf("reciver: %lu, mid:%d\n", response->reciever, response->mid);
    api_response_send(response);

    attr_container_destroy(payload);
}

static void
test_send_request(const char *url, const char *tag)
{
    request_t request[1];

    init_request(request, (char *)url, COAP_PUT, 0, NULL, 0);
    api_send_request(request, my_response_handler, (void *)tag);
}

void
res1_handler(request_t *request)
{
    mid = request->mid;
    sender = request->sender;
    test_send_request("url1", "a general request");
}

void
res2_handler(request_t *request)
{
    mid = request->mid;
    sender = request->sender;
    test_send_request("/app/App1/url1", "a general request");
}

void
on_init()
{
    /* register resource uri */
    api_register_resource_handler("/res1", res1_handler);
    api_register_resource_handler("/res2", res2_handler);
}

void
on_destroy()
{
    /* real destroy work including killing timer and closing sensor is
     * accomplished in wasm app library version of on_destroy() */
}
