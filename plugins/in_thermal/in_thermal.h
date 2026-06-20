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

#ifndef FLB_IN_THERMAL_H
#define FLB_IN_THERMAL_H

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_log_event_encoder.h>

#ifdef FLB_HAVE_REGEX
#include <fluent-bit/flb_regex.h>
#endif

/* Temperature Input configuration & context */
struct flb_in_thermal_config {
    /* setup */
    int coll_fd;                  /* collector id/fd                       */
    int interval_sec;             /* interval collection time (Second)     */
    int interval_nsec;            /* interval collection time (Nanosecond) */
    int prev_device_num;          /* number of thermal devices             */
#ifdef FLB_HAVE_REGEX
    struct    flb_regex *name_regex;   /* compiled filter by name */
    struct    flb_regex *type_regex;   /* compiled filter by type */
    flb_sds_t name_rgx; /* optional filter by name */
    flb_sds_t type_rgx; /* optional filter by type */
#endif
    struct flb_input_instance *ins;
    struct flb_log_event_encoder *log_encoder;
};

int in_thermal_pre_run(void *in_context, struct flb_config *config);
int in_thermal_collect(struct flb_input_instance *i_ins,
                   struct flb_config *config, void *in_context);
void *in_thermal_flush(void *in_context, size_t *size);

extern struct flb_input_plugin in_thermal_plugin;

#endif
