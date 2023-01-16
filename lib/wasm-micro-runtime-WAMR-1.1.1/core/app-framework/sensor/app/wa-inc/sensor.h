/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AEE_SENSOR_H_
#define _AEE_SENSOR_H_

#include "bi-inc/attr_container.h"

#ifdef __cplusplus
extern "C" {
#endif

/* board producer define sensor */
struct _sensor;
typedef struct _sensor *sensor_t;

/**
 * @typedef sensor_event_handler_f
 *
 * @brief Define the signature of callback function for API
 * sensor_open() to handle sensor event.
 *
 * @param sensor the sensor which the event belong to
 * @param sensor_event the sensor event
 * @param user_data user data associated with the sensor which is set when
 * calling sensor_open().
 *
 * @see sensor_open
 */
typedef void (*sensor_event_handler_f)(sensor_t sensor,
                                       attr_container_t *sensor_event,
                                       void *user_data);

/*
 *****************
 * Sensor APIs
 *****************
 */

/**
 * @brief Open sensor.
 *
 * @param name sensor name
 * @param index sensor index
 * @param handler callback function to handle the sensor event
 * @param user_data user data
 *
 * @return the sensor opened if success, NULL otherwise
 */
sensor_t
sensor_open(const char *name, int index, sensor_event_handler_f handler,
            void *user_data);

/**
 * @brief Configure sensor with interval/bit_cfg/delay values.
 *
 * @param sensor the sensor to be configured
 * @param interval sensor event interval
 * @param bit_cfg sensor bit config
 * @param delay sensor delay
 *
 * @return true if success, false otherwise
 */
bool
sensor_config(sensor_t sensor, int interval, int bit_cfg, int delay);

/**
 * @brief Configure sensor with attr_container_t object.
 *
 * @param sensor the sensor to be configured
 * @param cfg the configuration
 *
 * @return true if success, false otherwise
 */
bool
sensor_config_with_attr_container(sensor_t sensor, attr_container_t *cfg);

/**
 * @brief Close sensor.
 *
 * @param sensor the sensor to be closed
 *
 * @return true if success, false otherwise
 */
bool
sensor_close(sensor_t sensor);

#ifdef __cplusplus
}
#endif

#endif
