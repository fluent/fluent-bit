/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_app.h"
#include "wa-inc/sensor.h"

static sensor_t sensor1 = NULL;
static sensor_t sensor2 = NULL;
static char *user_data = NULL;

/* Sensor event callback*/
void
sensor_event_handler(sensor_t sensor, attr_container_t *event, void *user_data)
{
    if (sensor == sensor1) {
        printf("### app get sensor event from sensor1\n");
        attr_container_dump(event);
    }
    else {
        printf("### app get sensor event from sensor2\n");
        attr_container_dump(event);
    }
}

void
on_init()
{
    attr_container_t *config;

    printf("### app on_init 1\n");
    /* open a sensor */
    user_data = malloc(100);
    if (!user_data) {
        printf("allocate memory failed\n");
        return;
    }

    printf("### app on_init 2\n");
    sensor1 = sensor_open("sensor_test1", 0, sensor_event_handler, user_data);
    if (!sensor1) {
        printf("open sensor1 failed\n");
        return;
    }
    /* config the sensor */
    sensor_config(sensor1, 1000, 0, 0);

    printf("### app on_init 3\n");
    sensor2 = sensor_open("sensor_test2", 0, sensor_event_handler, user_data);
    if (!sensor2) {
        printf("open sensor2 failed\n");
        return;
    }
    /* config the sensor */
    sensor_config(sensor2, 5000, 0, 0);

    printf("### app on_init 4\n");
    /*
    config = attr_container_create("sensor config");
    sensor_config(sensor, config);
    attr_container_destroy(config);
    */
}

void
on_destroy()
{
    if (NULL != sensor1) {
        sensor_config(sensor1, 0, 0, 0);
    }

    if (NULL != sensor2) {
        sensor_config(sensor2, 0, 0, 0);
    }

    if (NULL != user_data) {
        free(user_data);
    }

    /* real destroy work including killing timer and closing sensor is
       accomplished in wasm app library version of on_destroy() */
}
