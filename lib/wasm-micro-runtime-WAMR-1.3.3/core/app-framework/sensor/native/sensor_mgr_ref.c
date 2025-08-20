/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_platform.h"
#include "runtime_sensor.h"
#include "bi-inc/attr_container.h"
#include "module_wasm_app.h"
#include "wasm_export.h"

/*
 *
 *   One reference implementation for sensor manager
 *
 *
 */
static korp_cond cond;
static korp_mutex mutex;
static bool sensor_check_thread_run = true;

void
app_mgr_sensor_event_callback(module_data *m_data, bh_message_t msg)
{
    uint32 argv[3];
    wasm_function_inst_t func_onSensorEvent;

    bh_assert(SENSOR_EVENT_WASM == bh_message_type(msg));
    wasm_data *wasm_app_data = (wasm_data *)m_data->internal_data;
    wasm_module_inst_t inst = wasm_app_data->wasm_module_inst;

    sensor_event_data_t *payload =
        (sensor_event_data_t *)bh_message_payload(msg);
    if (payload == NULL)
        return;

    func_onSensorEvent =
        wasm_runtime_lookup_function(inst, "_on_sensor_event", "(i32i32i32)");
    if (!func_onSensorEvent)
        func_onSensorEvent = wasm_runtime_lookup_function(
            inst, "on_sensor_event", "(i32i32i32)");
    if (!func_onSensorEvent) {
        printf("Cannot find function on_sensor_event\n");
    }
    else {
        int32 sensor_data_offset;
        uint32 sensor_data_len;

        if (payload->data_fmt == FMT_ATTR_CONTAINER) {
            sensor_data_len =
                attr_container_get_serialize_length(payload->data);
        }
        else {
            printf("Unsupported sensor data format: %d\n", payload->data_fmt);
            return;
        }

        sensor_data_offset =
            wasm_runtime_module_dup_data(inst, payload->data, sensor_data_len);
        if (sensor_data_offset == 0) {
            const char *exception = wasm_runtime_get_exception(inst);
            if (exception) {
                printf("Got exception running wasm code: %s\n", exception);
                wasm_runtime_clear_exception(inst);
            }
            return;
        }

        argv[0] = payload->sensor_id;
        argv[1] = (uint32)sensor_data_offset;
        argv[2] = sensor_data_len;

        if (!wasm_runtime_call_wasm(wasm_app_data->exec_env, func_onSensorEvent,
                                    3, argv)) {
            const char *exception = wasm_runtime_get_exception(inst);
            bh_assert(exception);
            printf(":Got exception running wasm code: %s\n", exception);
            wasm_runtime_clear_exception(inst);
            wasm_runtime_module_free(inst, sensor_data_offset);
            return;
        }

        wasm_runtime_module_free(inst, sensor_data_offset);
    }
}

static void
thread_sensor_check(void *arg)
{
    while (sensor_check_thread_run) {
        uint32 ms_to_expiry = check_sensor_timers();
        if (ms_to_expiry == UINT32_MAX)
            ms_to_expiry = 5000;
        os_mutex_lock(&mutex);
        os_cond_reltimedwait(&cond, &mutex, ms_to_expiry * 1000);
        os_mutex_unlock(&mutex);
    }
}

static void
cb_wakeup_thread()
{
    os_cond_signal(&cond);
}

void
set_sensor_reshceduler(void (*callback)());

bool
init_sensor_framework()
{
    /* init the mutext and conditions */
    if (os_cond_init(&cond) != 0) {
        return false;
    }

    if (os_mutex_init(&mutex) != 0) {
        os_cond_destroy(&cond);
        return false;
    }

    set_sensor_reshceduler(cb_wakeup_thread);

    wasm_register_msg_callback(SENSOR_EVENT_WASM,
                               app_mgr_sensor_event_callback);

    wasm_register_cleanup_callback(sensor_cleanup_callback);

    return true;
}

void
start_sensor_framework()
{
    korp_tid tid;

    os_thread_create(&tid, (void *)thread_sensor_check, NULL,
                     BH_APPLET_PRESERVED_STACK_SIZE);
}

void
exit_sensor_framework()
{
    sensor_check_thread_run = false;
    reschedule_sensor_read();

    // todo: wait the sensor thread termination
}
