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

#ifndef FLB_IN_NE_SYSTEMD_LINUX_H
#define FLB_IN_NE_SYSTEMD_LINUX_H

#include "ne.h"

#define SYSTEMD_UNIT_TYPE_UNDEFINED 0
#define SYSTEMD_UNIT_TYPE_SERVICE   1
#define SYSTEMD_UNIT_TYPE_SOCKET    2
#define SYSTEMD_UNIT_TYPE_MOUNT     3
#define SYSTEMD_UNIT_TYPE_TIMER     4

struct ne_systemd_unit {
    char     *name;
    char     *description;
    char     *load_state;
    char     *active_state;
    char     *sub_state;
    char     *followed;
    char     *path;
    uint32_t  job_id;
    char     *job_type;
    char     *object_path;

    /* not part of the unit list result */
    uint64_t  start_time;
    int       unit_type;
    char     *type;

    /* services */
    uint32_t  restart_count;
    uint64_t  active_tasks;
    uint64_t  max_tasks;

    /* sockets */
    uint32_t  accepted_connections;
    uint32_t  active_connections;
    uint32_t  refused_connections;

    /* timers */
    uint64_t  last_trigger_timestamp;
};

#define get_system_state(context, output_variable) \
            get_system_property(context, NULL, "SystemState", \
                                's', (void *) (output_variable))

#define get_system_version(context, output_variable) \
            get_system_property(context, NULL, "Version", \
                                's', (void *) (output_variable))

#define get_service_type(context, unit, output_variable) \
            get_unit_property(context, unit, NULL, "Type", \
                              's', (void *) (output_variable))

#define get_service_active_tasks(context, unit, output_variable) \
            get_unit_property(context, unit, NULL, "TasksCurrent", \
                              't', (void *) (output_variable))

#define get_service_max_tasks(context, unit, output_variable) \
            get_unit_property(context, unit, NULL, "TasksMax", \
                              't', (void *) (output_variable))

#define get_service_restart_count(context, unit, output_variable) \
            get_unit_property(context, unit, NULL, "NRestarts", \
                              'u', (void *) (output_variable))

#define get_socket_accepted_connection_count(context, unit, output_variable) \
            get_unit_property(context, unit, NULL, "NAccepted", \
                              'u', (void *) (output_variable))

#define get_socket_active_connection_count(context, unit, output_variable) \
            get_unit_property(context, unit, NULL, "NConnections", \
                              'u', (void *) (output_variable))

#define get_socket_refused_connection_count(context, unit, output_variable) \
            get_unit_property(context, unit, NULL, "NRefused", \
                              'u', (void *) (output_variable))

#define get_timer_last_trigger_timestamp(context, unit, output_variable) \
            get_unit_property(context, unit, NULL, "LastTriggerUSec", \
                              't', (void *) (output_variable))

#define get_unit_start_time(context, unit, output_variable) \
            get_unit_property(context, \
                              unit, \
                              "org.freedesktop.systemd1.Unit", \
                              "ActiveEnterTimestamp", \
                              't', (void *) (output_variable))
#endif
