/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_app.h"
#include "wa-inc/request.h"
#include "wa-inc/timer_wasm_app.h"

/* User global variable */
int num = 0;

/* Timer callback */
void
timer1_update(user_timer_t timer)
{
    if (num < 2)
        num++;
}

void
res1_handler(request_t *request)
{
    user_timer_t timer;

    /* set up a timer */
    timer = api_timer_create(1000, true, false, timer1_update);
    api_timer_restart(timer, 1000);

    response_t response[1];

    make_response_for_request(request, response);

    set_response(response, CONTENT_2_05, FMT_ATTR_CONTAINER, NULL, 0);

    api_response_send(response);
}

void
res2_handler(request_t *request)
{
    response_t response[1];
    attr_container_t *payload;

    if (num == 2) {
        attr_container_t *payload;
        printf("### user resource 1 handler called\n");

        payload = attr_container_create("wasm app response payload");
        if (payload == NULL)
            return;

        attr_container_set_int(&payload, "num", num);

        make_response_for_request(request, response);

        set_response(response, CONTENT_2_05, FMT_ATTR_CONTAINER,
                     (const char *)payload,
                     attr_container_get_serialize_length(payload));
        printf("reciver: %lu, mid:%d\n", response->reciever, response->mid);
        api_response_send(response);

        attr_container_destroy(payload);
    }
}

void
on_init()
{
    /* register resource uri */
    api_register_resource_handler("/res1", res1_handler);
    api_register_resource_handler("/check_timer", res2_handler);
}

void
on_destroy()
{
    /* real destroy work including killing timer and closing sensor is
     * accomplished in wasm app library version of on_destroy() */
}
