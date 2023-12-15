/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef LIB_EXTENSION_RUNTIME_SENSOR_H_
#define LIB_EXTENSION_RUNTIME_SENSOR_H_

#include "bh_platform.h"
#include "bi-inc/attr_container.h"
#include "wasm_export.h"
#include "sensor_native_api.h"

struct _sys_sensor;
typedef struct _sys_sensor *sensor_obj_t;

typedef struct _sensor_client {
    struct _sensor_client *next;
    unsigned int client_id; // the app id
    uint32 interval;
    int bit_cfg;
    uint32 delay;
    void (*client_callback)(void *client, uint32, attr_container_t *);
} sensor_client_t;

typedef struct _sys_sensor {
    struct _sys_sensor *next;
    char *name;
    int sensor_instance;
    char *description;
    uint32 sensor_id;
    sensor_client_t *clients;
    /* app, sensor mgr and app mgr may access the clients at the same time,
       so need a lock to protect the clients */
    korp_mutex lock;
    uint32 last_read;
    uint32 read_interval;
    uint32 default_interval;

    /* TODO: may support other type return value, such as 'cbor' */
    attr_container_t *(*read)(void *);
    bool (*config)(void *, void *);

} sys_sensor_t;

sensor_obj_t
add_sys_sensor(char *name, char *description, int instance,
               uint32 default_interval, void *read_func, void *config_func);
sensor_obj_t
find_sys_sensor(const char *name, int instance);
sensor_obj_t
find_sys_sensor_id(uint32 sensor_id);
void
refresh_read_interval(sensor_obj_t sensor);
void
sensor_cleanup_callback(uint32 module_id);
uint32
check_sensor_timers();
void
reschedule_sensor_read();

bool
init_sensor_framework();
void
start_sensor_framework();
void
exit_sensor_framework();

#endif /* LIB_EXTENSION_RUNTIME_SENSOR_H_ */
