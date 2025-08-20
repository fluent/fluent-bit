/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "runtime_sensor.h"
#include "app_manager_export.h"
#include "module_wasm_app.h"
#include "bh_platform.h"

static sys_sensor_t *g_sys_sensors = NULL;
static uint32 g_sensor_id_max = 0;

static sensor_client_t *
find_sensor_client(sys_sensor_t *sensor, unsigned int client_id,
                   bool remove_if_found);

void (*rechedule_sensor_callback)() = NULL;

/*
 *  API for the applications to call - don't call it from the runtime
 *
 */

static void
sensor_event_cleaner(sensor_event_data_t *sensor_event)
{
    if (sensor_event->data != NULL) {
        if (sensor_event->data_fmt == FMT_ATTR_CONTAINER)
            attr_container_destroy(sensor_event->data);
        else
            wasm_runtime_free(sensor_event->data);
    }

    wasm_runtime_free(sensor_event);
}

static void
wasm_sensor_callback(void *client, uint32 sensor_id, void *user_data)
{
    attr_container_t *sensor_data = (attr_container_t *)user_data;
    attr_container_t *sensor_data_clone;
    int sensor_data_len;
    sensor_event_data_t *sensor_event;
    bh_message_t msg;
    sensor_client_t *c = (sensor_client_t *)client;

    module_data *module = module_data_list_lookup_id(c->client_id);
    if (module == NULL)
        return;

    if (sensor_data == NULL)
        return;

    sensor_data_len = attr_container_get_serialize_length(sensor_data);
    sensor_data_clone =
        (attr_container_t *)wasm_runtime_malloc(sensor_data_len);
    if (sensor_data_clone == NULL)
        return;

    /* multiple sensor clients may use/free the sensor data, so make a copy */
    bh_memcpy_s(sensor_data_clone, sensor_data_len, sensor_data,
                sensor_data_len);

    sensor_event =
        (sensor_event_data_t *)wasm_runtime_malloc(sizeof(*sensor_event));
    if (sensor_event == NULL) {
        wasm_runtime_free(sensor_data_clone);
        return;
    }

    memset(sensor_event, 0, sizeof(*sensor_event));
    sensor_event->sensor_id = sensor_id;
    sensor_event->data = sensor_data_clone;
    sensor_event->data_fmt = FMT_ATTR_CONTAINER;

    msg = bh_new_msg(SENSOR_EVENT_WASM, sensor_event, sizeof(*sensor_event),
                     sensor_event_cleaner);
    if (!msg) {
        sensor_event_cleaner(sensor_event);
        return;
    }

    bh_post_msg2(module->queue, msg);
}

bool
wasm_sensor_config(wasm_exec_env_t exec_env, uint32 sensor, uint32 interval,
                   int bit_cfg, uint32 delay)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    attr_container_t *attr_cont;
    sensor_client_t *c;
    sensor_obj_t s = find_sys_sensor_id(sensor);
    if (s == NULL)
        return false;

    unsigned int mod_id =
        app_manager_get_module_id(Module_WASM_App, module_inst);
    bh_assert(mod_id != ID_NONE);

    os_mutex_lock(&s->lock);

    c = find_sensor_client(s, mod_id, false);
    if (c == NULL) {
        os_mutex_unlock(&s->lock);
        return false;
    }

    c->interval = interval;
    c->bit_cfg = bit_cfg;
    c->delay = delay;

    os_mutex_unlock(&s->lock);

    if (s->config != NULL) {
        attr_cont = attr_container_create("config sensor");
        attr_container_set_int(&attr_cont, "interval", (int)interval);
        attr_container_set_int(&attr_cont, "bit_cfg", bit_cfg);
        attr_container_set_int(&attr_cont, "delay", (int)delay);
        s->config(s, attr_cont);
        attr_container_destroy(attr_cont);
    }

    refresh_read_interval(s);

    reschedule_sensor_read();

    return true;
}

uint32
wasm_sensor_open(wasm_exec_env_t exec_env, char *name, int instance)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    if (name != NULL) {
        sensor_client_t *c;
        sys_sensor_t *s = find_sys_sensor(name, instance);
        if (s == NULL)
            return (uint32)-1;

        unsigned int mod_id =
            app_manager_get_module_id(Module_WASM_App, module_inst);
        bh_assert(mod_id != ID_NONE);

        os_mutex_lock(&s->lock);

        c = find_sensor_client(s, mod_id, false);
        if (c) {
            // the app already opened this sensor
            os_mutex_unlock(&s->lock);
            return (uint32)-1;
        }

        sensor_client_t *client =
            (sensor_client_t *)wasm_runtime_malloc(sizeof(sensor_client_t));
        if (client == NULL) {
            os_mutex_unlock(&s->lock);
            return (uint32)-1;
        }

        memset(client, 0, sizeof(sensor_client_t));
        client->client_id = mod_id;
        client->client_callback = (void *)wasm_sensor_callback;
        client->interval = s->default_interval;
        client->next = s->clients;
        s->clients = client;

        os_mutex_unlock(&s->lock);

        refresh_read_interval(s);

        reschedule_sensor_read();

        return s->sensor_id;
    }

    return (uint32)-1;
}

bool
wasm_sensor_config_with_attr_container(wasm_exec_env_t exec_env, uint32 sensor,
                                       char *buffer, int len)
{
    if (buffer != NULL) {
        attr_container_t *cfg = (attr_container_t *)buffer;
        sensor_obj_t s = find_sys_sensor_id(sensor);
        if (s == NULL)
            return false;

        if (s->config == NULL)
            return false;

        return s->config(s, cfg);
    }

    return false;
}

bool
wasm_sensor_close(wasm_exec_env_t exec_env, uint32 sensor)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    unsigned int mod_id =
        app_manager_get_module_id(Module_WASM_App, module_inst);
    unsigned int client_id = mod_id;
    sensor_obj_t s = find_sys_sensor_id(sensor);
    sensor_client_t *c;

    bh_assert(mod_id != ID_NONE);

    if (s == NULL)
        return false;

    os_mutex_lock(&s->lock);
    if ((c = find_sensor_client(s, client_id, true)) != NULL)
        wasm_runtime_free(c);
    os_mutex_unlock(&s->lock);

    refresh_read_interval(s);

    reschedule_sensor_read();

    return true;
}

/*
 *
 * sensor framework API - don't expose to the applications
 *
 */
void
set_sensor_reshceduler(void (*callback)())
{
    rechedule_sensor_callback = callback;
}

// used for other threads to wakeup the sensor read thread
void
reschedule_sensor_read()
{
    if (rechedule_sensor_callback)
        rechedule_sensor_callback();
}

void
refresh_read_interval(sensor_obj_t sensor)
{
    sensor_client_t *c;
    uint32 interval = sensor->default_interval;
    os_mutex_lock(&sensor->lock);

    c = sensor->clients;
    if (c)
        interval = c->interval;

    while (c) {
        if (c->interval < interval)
            interval = c->interval;
        c = c->next;
    }

    os_mutex_unlock(&sensor->lock);

    sensor->read_interval = interval;
}

sensor_obj_t
add_sys_sensor(char *name, char *description, int instance,
               uint32 default_interval, void *read_func, void *config_func)
{
    sys_sensor_t *s = (sys_sensor_t *)wasm_runtime_malloc(sizeof(sys_sensor_t));
    if (s == NULL)
        return NULL;

    memset(s, 0, sizeof(*s));
    s->name = bh_strdup(name);
    s->sensor_instance = instance;
    s->default_interval = default_interval;

    if (!s->name) {
        wasm_runtime_free(s);
        return NULL;
    }

    if (description) {
        s->description = bh_strdup(description);
        if (!s->description) {
            wasm_runtime_free(s->name);
            wasm_runtime_free(s);
            return NULL;
        }
    }

    g_sensor_id_max++;
    if (g_sensor_id_max == UINT32_MAX)
        g_sensor_id_max++;
    s->sensor_id = g_sensor_id_max;

    s->read = read_func;
    s->config = config_func;

    if (g_sys_sensors == NULL) {
        g_sys_sensors = s;
    }
    else {
        s->next = g_sys_sensors;
        g_sys_sensors = s;
    }

    if (os_mutex_init(&s->lock) != 0) {
        if (s->description) {
            wasm_runtime_free(s->description);
        }
        wasm_runtime_free(s->name);
        wasm_runtime_free(s);
    }

    return s;
}

sensor_obj_t
find_sys_sensor(const char *name, int instance)
{
    sys_sensor_t *s = g_sys_sensors;
    while (s) {
        if (strcmp(s->name, name) == 0 && s->sensor_instance == instance)
            return s;

        s = s->next;
    }
    return NULL;
}

sensor_obj_t
find_sys_sensor_id(uint32 sensor_id)
{
    sys_sensor_t *s = g_sys_sensors;
    while (s) {
        if (s->sensor_id == sensor_id)
            return s;

        s = s->next;
    }
    return NULL;
}

sensor_client_t *
find_sensor_client(sys_sensor_t *sensor, unsigned int client_id,
                   bool remove_if_found)
{
    sensor_client_t *prev = NULL, *c = sensor->clients;

    while (c) {
        sensor_client_t *next = c->next;
        if (c->client_id == client_id) {
            if (remove_if_found) {
                if (prev)
                    prev->next = next;
                else
                    sensor->clients = next;
            }
            return c;
        }
        else {
            prev = c;
            c = c->next;
        }
    }

    return NULL;
}

// return the milliseconds to next check
uint32
check_sensor_timers()
{
    uint32 ms_to_next_check = UINT32_MAX;
    uint32 now = (uint32)bh_get_tick_ms();

    sys_sensor_t *s = g_sys_sensors;
    while (s) {
        uint32 last_read = s->last_read;
        uint32 elpased_ms = bh_get_elpased_ms(&last_read);

        if (s->read_interval <= 0 || s->clients == NULL) {
            s = s->next;
            continue;
        }

        if (elpased_ms >= s->read_interval) {
            attr_container_t *data = s->read(s);
            if (data) {
                sensor_client_t *client = s->clients;
                while (client) {
                    client->client_callback(client, s->sensor_id, data);
                    client = client->next;
                }
                attr_container_destroy(data);
            }

            s->last_read = now;

            if (s->read_interval < ms_to_next_check)
                ms_to_next_check = s->read_interval;
        }
        else {
            uint32 remaining = s->read_interval - elpased_ms;
            if (remaining < ms_to_next_check)
                ms_to_next_check = remaining;
        }

        s = s->next;
    }

    return ms_to_next_check;
}

void
sensor_cleanup_callback(uint32 module_id)
{
    sys_sensor_t *s = g_sys_sensors;

    while (s) {
        sensor_client_t *c;
        os_mutex_lock(&s->lock);
        if ((c = find_sensor_client(s, module_id, true)) != NULL) {
            wasm_runtime_free(c);
        }
        os_mutex_unlock(&s->lock);
        s = s->next;
    }
}
