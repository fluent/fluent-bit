/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_app.h"
#include "wa-inc/request.h"
#include "wa-inc/timer_wasm_app.h"

int num = 0;

void
publish_overheat_event()
{
    attr_container_t *event;

    event = attr_container_create("event");
    attr_container_set_string(&event, "warning", "temperature is over high");

    api_publish_event("alert/overheat", FMT_ATTR_CONTAINER, event,
                      attr_container_get_serialize_length(event));

    attr_container_destroy(event);
}

/* Timer callback */
void
timer1_update(user_timer_t timer)
{
    publish_overheat_event();
}

void
start_timer()
{
    user_timer_t timer;

    /* set up a timer */
    timer = api_timer_create(1000, true, false, timer1_update);
    api_timer_restart(timer, 1000);
}

void
on_init()
{
    start_timer();
}

void
on_destroy()
{
    /* real destroy work including killing timer and closing sensor is
       accomplished in wasm app library version of on_destroy() */
}
