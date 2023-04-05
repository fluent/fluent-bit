/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
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

#ifndef FLB_PROCESSOR_H
#define FLB_PROCESSOR_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_format.h>

#define FLB_PROCESSOR_LOGS      1
#define FLB_PROCESSOR_METRICS   2
#define FLB_PROCESSOR_TRACES    4

/* Type of processor unit: 'pipeline filter' or 'native unit' */
#define FLB_PROCESSOR_UNIT_NATIVE    0
#define FLB_PROCESSOR_UNIT_FILTER    1

struct flb_processor_unit {
    int event_type;
    int unit_type;
    flb_sds_t name;

    /*
     * Opaque data type for custom reference (for pipeline filters this
     * contains the filter instance context.
     */
    void *ctx;

    /*
     * pipeline filters needs to be linked somewhere since the destroy
     * function will do the mk_list_del(). To avoid corruptions we link
     * normal filters here, this list is never iterated or used besides
     * for this purpose.
     */
    struct mk_list unused_list;

    /* link to struct flb_processor->(logs, metrics, traces) list */
    struct mk_list _head;

    /* link to parent processor */
    void *parent;
};

struct flb_processor {
    int is_active;

    /* user-defined processor name */
    flb_sds_t name;

    /* lists for different types */
    struct mk_list logs;
    struct mk_list metrics;
    struct mk_list traces;

    /*
     * opaque data type to reference anything specific from the caller, for input
     * plugins this will contain the input instance context.
     */
    void *data;

    /* Fluent Bit context */
    struct flb_config *config;
};


struct flb_processor *flb_processor_create(struct flb_config *config, char *name, void *data);

int flb_processor_is_active(struct flb_processor *proc);

int flb_processor_init(struct flb_processor *proc);
void flb_processor_destroy(struct flb_processor *proc);

int flb_processor_run(struct flb_processor *proc,
                      int type,
                      const char *tag, size_t tag_len,
                      void *data, size_t data_size,
                      void **out_buf, size_t *out_size);


struct flb_processor_unit *flb_processor_unit_create(struct flb_processor *proc,
                                                     int event_type,
                                                     char *unit_name);
void flb_processor_unit_destroy(struct flb_processor_unit *pu);
int flb_processor_unit_set_property(struct flb_processor_unit *pu, const char *k, const char *v);

int flb_processors_load_from_config_format_group(struct flb_processor *proc, struct flb_cf_group *g);

#endif
