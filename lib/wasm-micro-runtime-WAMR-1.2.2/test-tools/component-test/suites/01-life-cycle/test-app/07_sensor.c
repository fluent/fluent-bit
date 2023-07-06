/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_app.h"
#include "wa-inc/request.h"
#include "wa-inc/sensor.h"

uint32 mid;
unsigned long sender;

/* Sensor event callback*/
void
sensor_event_handler(sensor_t sensor, attr_container_t *event, void *user_data)
{
    printf("### app get sensor event\n");

    response_t response[1];
    attr_container_t *payload;

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

void
res1_handler(request_t *request)
{
    mid = request->mid;
    sender = request->sender;

    sensor_t sensor;
    char *user_data;
    attr_container_t *config;

    printf("### app on_init 1\n");
    /* open a sensor */
    user_data = malloc(100);
    printf("### app on_init 2\n");
    sensor = sensor_open("sensor_test", 0, sensor_event_handler, user_data);
    printf("### app on_init 3\n");

    /* config the sensor */
    sensor_config(sensor, 2000, 0, 0);
    printf("### app on_init 4\n");
}

void
on_init()
{
    /* register resource uri */
    api_register_resource_handler("/res1", res1_handler);
}

void
on_destroy()
{
    /* real destroy work including killing timer and closing sensor is
     * accomplished in wasm app library version of on_destroy() */
}
