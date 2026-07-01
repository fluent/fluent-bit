/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_input_plugin.h>
#include <cmetrics/cmt_math.h>
#include <systemd/sd-bus.h>
#include <stdarg.h>

#include "ne.h"
#include "ne_utils.h"
#include "ne_systemd_linux.h"

#include <unistd.h>
#include <float.h>

static int str_ends_with(char *haystack, char *needle, int caseless) {
    size_t haystack_length;
    size_t trailer_offset;
    size_t needle_length;
    int    result;

    haystack_length = strlen(haystack);
    needle_length = strlen(needle);

    if (needle_length > haystack_length) {
        return FLB_FALSE;
    }

    trailer_offset = haystack_length - needle_length;

    if (caseless) {
        result = strcasecmp(&haystack[trailer_offset],
                            needle);
    }
    else {
        result = strcmp(&haystack[trailer_offset],
                        needle);
    }

    if (result == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static void clear_property_variable(char property_type, void *property_value)
{
    if (property_type == 'y') {
        *((uint8_t *) property_value) = 0;
    }
    else if (property_type == 'b') {
        *((int *) property_value) = 0;
    }
    else if (property_type == 'n') {
        *((int16_t *) property_value) = 0;
    }
    else if (property_type == 'q') {
        *((uint16_t *) property_value) = 0;
    }
    else if (property_type == 'i') {
        *((int32_t *) property_value) = 0;
    }
    else if (property_type == 'u') {
        *((uint32_t *) property_value) = 0;
    }
    else if (property_type == 'x') {
        *((int64_t *) property_value) = 0;
    }
    else if (property_type == 't') {
        *((uint64_t *) property_value) = 0;
    }
    else if (property_type == 'd') {
        *((double *) property_value) = 0;
    }
    else if (property_type == 's') {
        *((char **) property_value) = NULL;
    }
    else if (property_type == 'o') {
        *((char **) property_value) = NULL;
    }
    else if (property_type == 'g') {
        *((char **) property_value) = NULL;
    }
    else if (property_type == 'h') {
        *((int32_t *) property_value) = -1;
    }
}

static int get_system_property(struct flb_ne *ctx,
                               char *interface,
                               char *property_name,
                               char  property_type,
                               void *property_value)
{
    int result;

    clear_property_variable(property_type, property_value);

    if (interface == NULL) {
        interface = "org.freedesktop.systemd1.Manager";
    }

    if (property_type == 's' ||
        property_type == 'o' ||
        property_type == 'g') {
        result = sd_bus_get_property_string((sd_bus *) ctx->systemd_dbus_handle,
                                             "org.freedesktop.systemd1",
                                             "/org/freedesktop/systemd1",
                                             interface,
                                             property_name,
                                             NULL,
                                             property_value);
    }
    else {
        result = sd_bus_get_property_trivial((sd_bus *) ctx->systemd_dbus_handle,
                                             "org.freedesktop.systemd1",
                                             "/org/freedesktop/systemd1",
                                             interface,
                                             property_name,
                                             NULL,
                                             property_type,
                                             property_value);
    }

    if (result < 0) {
        return -1;
    }

    return 0;
}

static int get_unit_property(struct flb_ne *ctx,
                             struct ne_systemd_unit *unit,
                             char *interface,
                             char *property_name,
                             char property_type,
                             void *property_value)
{
    int result;

    clear_property_variable(property_type, property_value);

    if (interface == NULL) {
        if (unit->unit_type == SYSTEMD_UNIT_TYPE_SERVICE) {
            interface = "org.freedesktop.systemd1.Service";
        }
        else if (unit->unit_type == SYSTEMD_UNIT_TYPE_MOUNT) {
            interface = "org.freedesktop.systemd1.Mount";
        }
        else if (unit->unit_type == SYSTEMD_UNIT_TYPE_SOCKET) {
            interface = "org.freedesktop.systemd1.Socket";
        }
        else if (unit->unit_type == SYSTEMD_UNIT_TYPE_TIMER) {
            interface = "org.freedesktop.systemd1.Timer";
        }
        else {
            interface = unit->name;
        }
    }

    if (property_type == 's' ||
        property_type == 'o' ||
        property_type == 'g') {
        result = sd_bus_get_property_string((sd_bus *) ctx->systemd_dbus_handle,
                                             "org.freedesktop.systemd1",
                                             unit->path,
                                             interface,
                                             property_name,
                                             NULL,
                                             property_value);
    }
    else {
        result = sd_bus_get_property_trivial((sd_bus *) ctx->systemd_dbus_handle,
                                             "org.freedesktop.systemd1",
                                             unit->path,
                                             interface,
                                             property_name,
                                             NULL,
                                             property_type,
                                             property_value);
    }

    if (result < 0) {
        return -1;
    }

    return 0;
}

static int ne_systemd_update_unit_state(struct flb_ne *ctx)
{
    char                    *unit_states[] = { "activating", "active",
                                               "deactivating", "inactive",
                                               "failed" };
    double                   timer_trigger_timestamp;
    uint64_t                 deactivating_units;
    uint64_t                 activating_units;
    double                   unit_start_time;
    uint64_t                 inactive_units;
    uint64_t                 active_units;
    uint64_t                 failed_units;
    int                      include_flag;
    uint64_t                 timestamp;
    int                      result;
    size_t                   index;
    sd_bus_message          *reply;
    struct ne_systemd_unit   unit;
    sd_bus                  *bus;

    bus = (sd_bus *) ctx->systemd_dbus_handle;

    result = sd_bus_call_method(bus,
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager",
                                "ListUnits",
                                NULL,
                                &reply,
                                "");

    if (result < 0) {
        return -1;
    }

    result = sd_bus_message_enter_container(reply, 'a', "(ssssssouso)");

    if (result < 0) {
        sd_bus_message_unref(reply);

        return -2;
    }

    timestamp = cfl_time_now();

    deactivating_units = 0;
    activating_units = 0;
    inactive_units = 0;
    active_units = 0;
    failed_units = 0;

    do {
        result = sd_bus_message_read(reply,
                                     "(ssssssouso)",
                                     &unit.name,
                                     &unit.description,
                                     &unit.load_state,
                                     &unit.active_state,
                                     &unit.sub_state,
                                     &unit.followed,
                                     &unit.path,
                                     &unit.job_id,
                                     &unit.job_type,
                                     &unit.object_path);


        if (result < 0) {
            sd_bus_message_unref(reply);

            return -3;
        }
        else if(result > 0) {
            unit.type = NULL;

            if (strcasecmp(unit.active_state, "activating") == 0) {
                activating_units++;
            }
            else if (strcasecmp(unit.active_state, "deactivating") == 0) {
                deactivating_units++;
            }
            else if (strcasecmp(unit.active_state, "inactive") == 0) {
                inactive_units++;
            }
            else if (strcasecmp(unit.active_state, "active") == 0) {
                active_units++;
            }
            else if (strcasecmp(unit.active_state, "failed") == 0) {
                failed_units++;
            }

            if (ctx->systemd_regex_include_list != NULL) {
                include_flag = flb_regex_match(ctx->systemd_regex_include_list,
                                               (unsigned char *) unit.name,
                                               strlen(unit.name));
            }
            else {
                include_flag = FLB_TRUE;
            }

            if (!include_flag) {
                continue;
            }

            if (ctx->systemd_regex_exclude_list != NULL) {
                include_flag = !flb_regex_match(ctx->systemd_regex_exclude_list,
                                                (unsigned char *) unit.name,
                                                strlen(unit.name));
            }
            else {
                include_flag = FLB_TRUE;
            }

            if (!include_flag) {
                continue;
            }

            if (strcasecmp(unit.load_state, "loaded") != 0) {
                continue;
            }

            if (str_ends_with(unit.name, ".service", FLB_TRUE)) {
                unit.unit_type = SYSTEMD_UNIT_TYPE_SERVICE;

                result = get_service_type(ctx,
                                          &unit,
                                          &unit.type);

                if (ctx->systemd_include_service_restarts) {
                    result = get_service_restart_count(ctx,
                                                       &unit,
                                                       &unit.restart_count);

                    cmt_counter_set(ctx->systemd_service_restarts,
                                    timestamp,
                                    unit.restart_count,
                                    1,
                                    (char *[]){ unit.name });

                }

                if (ctx->systemd_include_service_task_metrics) {
                    result = get_service_active_tasks(ctx,
                                                      &unit,
                                                      &unit.active_tasks);

                    if (unit.active_tasks != UINT64_MAX) {
                        cmt_gauge_set(ctx->systemd_unit_tasks,
                                      timestamp,
                                      unit.active_tasks,
                                      1,
                                      (char *[]){ unit.name });
                    }

                    result = get_service_max_tasks(ctx,
                                                   &unit,
                                                   &unit.max_tasks);

                    if (unit.max_tasks != UINT64_MAX) {
                        cmt_gauge_set(ctx->systemd_unit_tasks_max,
                                      timestamp,
                                      unit.max_tasks,
                                      1,
                                      (char *[]){ unit.name });
                    }
                }

                result = 1;
            }
            else if (str_ends_with(unit.name, ".mount", FLB_TRUE)) {
                unit.unit_type = SYSTEMD_UNIT_TYPE_MOUNT;
            }
            else if (str_ends_with(unit.name, ".socket", FLB_TRUE)) {
                unit.unit_type = SYSTEMD_UNIT_TYPE_SOCKET;

                result = get_socket_accepted_connection_count(
                            ctx,
                            &unit,
                            &unit.accepted_connections);

                result = get_socket_active_connection_count(
                            ctx,
                            &unit,
                            &unit.active_connections);

                result = get_socket_refused_connection_count(
                            ctx,
                            &unit,
                            &unit.refused_connections);

                cmt_gauge_set(ctx->systemd_socket_accepted_connections,
                              timestamp,
                              unit.accepted_connections,
                              1,
                              (char *[]){ unit.name });

                cmt_gauge_set(ctx->systemd_socket_active_connections,
                              timestamp,
                              unit.active_connections,
                              1,
                              (char *[]){ unit.name });

                cmt_gauge_set(ctx->systemd_socket_refused_connections,
                              timestamp,
                              unit.refused_connections,
                              1,
                              (char *[]){ unit.name });

                result = 1;
            }
            else if (str_ends_with(unit.name, ".timer", FLB_TRUE)) {
                unit.unit_type = SYSTEMD_UNIT_TYPE_TIMER;

                result = get_timer_last_trigger_timestamp(
                            ctx,
                            &unit,
                            &unit.last_trigger_timestamp);

                timer_trigger_timestamp  = (double) unit.last_trigger_timestamp;
                timer_trigger_timestamp /= 1000000.0;

                cmt_gauge_set(ctx->systemd_timer_last_trigger_seconds,
                              timestamp,
                              timer_trigger_timestamp,
                              1,
                              (char *[]){ unit.name });

                result = 1;
            }
            else {
                unit.unit_type = SYSTEMD_UNIT_TYPE_UNDEFINED;
            }

            if (ctx->systemd_include_unit_start_times) {
                if (strcasecmp(unit.active_state, "active") == 0) {
                    result = get_unit_start_time(ctx, &unit, &unit.start_time);

                    unit_start_time  = (double) unit.start_time;
                    unit_start_time /= 1000000.0;
                }
                else {
                    unit_start_time = 0;
                }

                cmt_gauge_set(ctx->systemd_unit_start_times,
                              timestamp,
                              unit_start_time,
                              1,
                              (char *[]){ unit.name });

                result = 1;
            }

            for(index = 0 ; index < 5 ; index++) {
                cmt_gauge_set(ctx->systemd_unit_state,
                              timestamp,
                              0,
                              3,
                              (char *[]){ unit.name,
                                          unit_states[index],
                                          unit.type
                                        });
            }

            cmt_gauge_set(ctx->systemd_unit_state,
                          timestamp,
                          1,
                          3,
                          (char *[]){ unit.name,
                                      unit.active_state,
                                      unit.type
                                    });


            if (unit.type != NULL) {
                free(unit.type);
            }
        }
    }
    while (result > 0);

    sd_bus_message_exit_container(reply);

    sd_bus_message_unref(reply);

    cmt_gauge_set(ctx->systemd_units,
                  timestamp,
                  activating_units,
                  1,
                  (char *[]){ "activating" });

    cmt_gauge_set(ctx->systemd_units,
                  timestamp,
                  deactivating_units,
                  1,
                  (char *[]){ "deactivating" });

    cmt_gauge_set(ctx->systemd_units,
                  timestamp,
                  inactive_units,
                  1,
                  (char *[]){ "inactive" });

    cmt_gauge_set(ctx->systemd_units,
                  timestamp,
                  active_units,
                  1,
                  (char *[]){ "active" });

    cmt_gauge_set(ctx->systemd_units,
                  timestamp,
                  failed_units,
                  1,
                  (char *[]){ "failed" });

    return 0;
}

static int ne_systemd_update_system_state(struct flb_ne *ctx)
{
    int       system_running;
    uint64_t  timestamp;
    char     *version;
    int       result;
    char     *state;

    timestamp = cfl_time_now();

    if (!ctx->systemd_initialization_flag) {
        result = get_system_version(ctx, &version);

        if (result != 0) {
            return -1;
        }

        ctx->libsystemd_version_text = version;
        ctx->libsystemd_version = strtod(version, NULL);

        cmt_gauge_set(ctx->systemd_version,
                      timestamp,
                      ctx->libsystemd_version,
                      1,
                      (char *[]){ ctx->libsystemd_version_text });
    }
    else {
        cmt_gauge_add(ctx->systemd_version,
                      timestamp,
                      0,
                      1,
                      (char *[]){ ctx->libsystemd_version_text });
    }

    result = get_system_state(ctx, &state);

    if (result != 0) {
        return -2;
    }

    system_running = 0;

    if (strcasecmp(state, "running") == 0) {
        system_running = 1;
    }

    cmt_gauge_set(ctx->systemd_system_running,
                  timestamp,
                  system_running,
                  0,
                  NULL);
    free(state);

    return 0;
}

static int ne_systemd_init(struct flb_ne *ctx)
{
    int result;

    ctx->systemd_dbus_handle = NULL;

    result = sd_bus_open_system((sd_bus **) &ctx->systemd_dbus_handle);

    if (result < 0) {
        return -1;
    }

    ctx->systemd_socket_accepted_connections = cmt_gauge_create(ctx->cmt,
                                                                "node",
                                                                "systemd",
                                                                "socket_accepted_connections_total",
                                                                "Total number of accepted " \
                                                                "socket connections.",
                                                                1,
                                                                (char *[]) {"name"});

    if (ctx->systemd_socket_accepted_connections == NULL) {
        return -1;
    }

    ctx->systemd_socket_active_connections = cmt_gauge_create(ctx->cmt,
                                                              "node",
                                                              "systemd",
                                                              "socket_current_connections",
                                                              "Current number of socket " \
                                                              "connections.",
                                                              1,
                                                              (char *[]) {"name"});

    if (ctx->systemd_socket_active_connections == NULL) {
        return -1;
    }

    ctx->systemd_socket_refused_connections = cmt_gauge_create(ctx->cmt,
                                                               "node",
                                                               "systemd",
                                                               "socket_refused_connections_total",
                                                               "Total number of refused " \
                                                               "socket connections.",
                                                               1,
                                                               (char *[]) {"name"});

    if (ctx->systemd_socket_refused_connections == NULL) {
        return -1;
    }

    ctx->systemd_system_running = cmt_gauge_create(ctx->cmt,
                                                   "node",
                                                   "systemd",
                                                   "system_running",
                                                   "Whether the system is " \
                                                   "operational (see 'systemctl" \
                                                   " is-system-running')",
                                                   0, NULL);

    if (ctx->systemd_system_running == NULL) {
        return -1;
    }

    ctx->systemd_timer_last_trigger_seconds = cmt_gauge_create(ctx->cmt,
                                                               "node",
                                                               "systemd",
                                                               "timer_last_trigger_seconds",
                                                               "Seconds since epoch of " \
                                                               "last trigger.",
                                                               1,
                                                               (char *[]) {"name"});

    if (ctx->systemd_timer_last_trigger_seconds == NULL) {
        return -1;
    }

    ctx->systemd_service_restarts = cmt_counter_create(ctx->cmt,
                                                       "node",
                                                       "systemd",
                                                       "service_restart_total",
                                                       "Service unit count of " \
                                                       "Restart triggers",
                                                       1, (char *[]) {"name"});

    if (ctx->systemd_service_restarts == NULL) {
        return -1;
    }

    cmt_counter_allow_reset(ctx->systemd_service_restarts);

    ctx->systemd_unit_tasks = cmt_gauge_create(ctx->cmt,
                                               "node",
                                               "systemd",
                                               "unit_tasks_current",
                                               "Current number of tasks " \
                                               "per Systemd unit.",
                                               1, (char *[]) {"name"});

    if (ctx->systemd_unit_tasks == NULL) {
        return -1;
    }

    ctx->systemd_unit_tasks_max = cmt_gauge_create(ctx->cmt,
                                                   "node",
                                                   "systemd",
                                                   "unit_tasks_max",
                                                   "Maximum number of tasks " \
                                                   "per Systemd unit.",
                                                   1, (char *[]) {"name"});

    if (ctx->systemd_unit_tasks == NULL) {
        return -1;
    }

    ctx->systemd_unit_start_times = cmt_gauge_create(ctx->cmt,
                                                     "node",
                                                     "systemd",
                                                     "unit_start_time_seconds",
                                                     "Start time of the unit since " \
                                                     "unix epoch in seconds.",
                                                     1, (char *[]) {"name"});

    if (ctx->systemd_unit_start_times == NULL) {
        return -1;
    }

    ctx->systemd_unit_state = cmt_gauge_create(ctx->cmt,
                                               "node",
                                               "systemd",
                                               "unit_state",
                                               "Systemd unit",
                                               3, (char *[]) {"name",
                                                              "state",
                                                              "type"});

    if (ctx->systemd_unit_state == NULL) {
        return -1;
    }

    ctx->systemd_units = cmt_gauge_create(ctx->cmt,
                                          "node",
                                          "systemd",
                                          "units",
                                          "Summary of systemd unit states",
                                          1, (char *[]) {"state"});

    if (ctx->systemd_units == NULL) {
        return -1;
    }

    ctx->systemd_version = cmt_gauge_create(ctx->cmt,
                                            "node",
                                            "systemd",
                                            "version",
                                            "Detected systemd version",
                                            1, (char *[]) {"version"});

    if (ctx->systemd_version == NULL) {
        return -1;
    }

    if (ctx->systemd_regex_include_list_text != NULL) {
        ctx->systemd_regex_include_list = \
            flb_regex_create(ctx->systemd_regex_include_list_text);

        if (ctx->systemd_regex_include_list == NULL) {
            return -1;
        }
    }

    if (ctx->systemd_regex_exclude_list_text != NULL) {
        ctx->systemd_regex_exclude_list = \
            flb_regex_create(ctx->systemd_regex_exclude_list_text);

        if (ctx->systemd_regex_exclude_list == NULL) {
            return -1;
        }
    }

    return 0;
}

static int ne_systemd_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    int result;
    struct flb_ne *ctx = (struct flb_ne *)in_context;

    result = ne_systemd_update_system_state(ctx);

    if (result != 0) {
        return result;
    }

    result = ne_systemd_update_unit_state(ctx);

    if (result != 0) {
        return result;
    }

    if (!ctx->systemd_initialization_flag) {
        ctx->systemd_initialization_flag = FLB_TRUE;
    }

    return 0;
}

static int ne_systemd_exit(struct flb_ne *ctx)
{
    if (ctx->systemd_dbus_handle != NULL) {
        sd_bus_unref((sd_bus *) ctx->systemd_dbus_handle);

        ctx->systemd_dbus_handle = NULL;
    }

    if (ctx->systemd_regex_include_list != NULL) {
        flb_regex_destroy(ctx->systemd_regex_include_list);
    }

    if (ctx->systemd_regex_exclude_list != NULL) {
        flb_regex_destroy(ctx->systemd_regex_exclude_list);
    }

    if (ctx->libsystemd_version_text != NULL) {
        flb_free(ctx->libsystemd_version_text);
    }
    return 0;
}

struct flb_ne_collector systemd_collector = {
    .name = "systemd",
    .cb_init = ne_systemd_init,
    .cb_update = ne_systemd_update,
    .cb_exit = ne_systemd_exit
};
