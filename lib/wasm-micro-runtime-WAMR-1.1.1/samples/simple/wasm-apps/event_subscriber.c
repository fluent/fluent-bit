/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_app.h"
#include "wa-inc/request.h"

void
over_heat_event_handler(request_t *request)
{
    printf("### user over heat event handler called\n");

    if (request->payload != NULL && request->fmt == FMT_ATTR_CONTAINER)
        attr_container_dump((attr_container_t *)request->payload);
}

void
on_init()
{
    api_subscribe_event("alert/overheat", over_heat_event_handler);
}

void
on_destroy()
{
    /* real destroy work including killing timer and closing sensor is
       accomplished in wasm app library version of on_destroy() */
}
