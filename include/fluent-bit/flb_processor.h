/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_config_format.h>

#include <ctraces/ctraces.h>
#include <cmetrics/cmetrics.h>
#include <cprofiles/cprofiles.h>

/* Processor plugin result values */
#define FLB_PROCESSOR_SUCCESS        0
#define FLB_PROCESSOR_FAILURE       -1

/* Processor event types */
#define FLB_PROCESSOR_LOGS           1
#define FLB_PROCESSOR_METRICS        2
#define FLB_PROCESSOR_TRACES         4
#define FLB_PROCESSOR_PROFILES       8

/* Type of processor unit: 'pipeline filter' or 'native unit' */
#define FLB_PROCESSOR_UNIT_NATIVE    0
#define FLB_PROCESSOR_UNIT_FILTER    1


/* The current values mean the processor stack will
 * wait for 2 seconds at most in 50 millisecond increments
 * for each processor unit.
 *
 * This is the worst case scenario and in reality there will
 * be no wait in 99.9% of the cases.
 */
#define FLB_PROCESSOR_LOCK_RETRY_LIMIT 40
#define FLB_PROCESSOR_LOCK_RETRY_DELAY 50000

/* These forward definitions are necessary in order to avoid
 * inclussion conflicts.
 */

struct flb_log_event;
struct flb_input_instance;
struct flb_log_event_decoder;
struct flb_log_event_encoder;
struct flb_processor_instance;
struct flb_condition;

struct flb_processor_unit {
    int event_type;
    int unit_type;
    flb_sds_t name;
    size_t stage;

    /*
     * Opaque data type for custom reference (for pipeline filters this
     * contains the filter instance context.
     */
    void *ctx;

    /* Conditional processing: if set, determines if the processor should
     * be applied to a specific record
     */
    struct flb_condition *condition;

    /* This lock is meant to cover the case where two output plugin
     * worker threads flb_output_flush_create calls overlap which
     * could cause flb_processor_run to be invoked by both of them
     * at the same time with the same context.
     *
     * This could cause certain non thread aware filters such as
     * filter_lua to modify internal structures leading to corruption
     * and crashes.
    */
    pthread_mutex_t lock;
    /*
     * pipeline filters needs to be linked somewhere since the destroy
     * function will do the mk_list_del(). To avoid corruptions we link
     * normal filters here, this list is never iterated or used besides
     * for this purpose.
     */
    struct mk_list unused_list;

    /* link to struct flb_processor->(logs, metrics, traces, profiles) list */
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
    struct mk_list profiles;

    size_t stage_count;
    /*
     * opaque data type to reference anything specific from the caller, for input
     * plugins this will contain the input instance context.
     */
    void *data;
    int source_plugin_type;

    flb_pipefd_t notification_channel;

    /* Fluent Bit context */
    struct flb_config *config;
};

struct flb_processor_plugin {
    int flags;             /* Flags (not available at the moment */
    char *name;            /* Processor short name               */
    char *description;     /* Description                        */

    /* Config map */
    struct flb_config_map *config_map;

    /* Callbacks */
    int (*cb_init) (struct flb_processor_instance *,
                    void *,
                    int,
                    struct flb_config *);

    int (*cb_process_logs) (struct flb_processor_instance *,
                            void *,       /* struct flb_mp_chunk_cobj_create */
                            const char *,
                            int);

    int (*cb_process_metrics) (struct flb_processor_instance *,
                               struct cmt *, /* in */
                               struct cmt **, /* out */
                               const char *,
                               int);

    int (*cb_process_traces) (struct flb_processor_instance *,
                              struct ctrace *,
                              struct ctrace **,
                              const char *,
                              int);

    int (*cb_process_profiles) (struct flb_processor_instance *,
                              struct cprof *,
                              const char *,
                              int);

    int (*cb_exit) (struct flb_processor_instance *, void *);

    /* Notification: this callback will be invoked anytime a notification is received*/
    int (*cb_notification) (struct flb_processor_instance *, struct flb_config *, void *);

    struct mk_list _head;  /* Link to parent list (config->filters) */
};

struct flb_processor_instance {
    int id;                                /* instance id              */
    int log_level;                         /* instance log level       */
    int event_type;                        /* event type               */
    char name[32];                         /* numbered name            */
    char *alias;                           /* alias name               */
    void *context;                         /* Instance local context   */
    void *data;
    struct flb_processor_unit *pu;         /* processor unit linked to */
    struct flb_processor_plugin *p;        /* original plugin          */
    struct mk_list properties;             /* config properties        */
    struct mk_list *config_map;            /* configuration map        */

    struct flb_log_event_decoder *log_decoder;
    struct flb_log_event_encoder *log_encoder;

    /*
     * CMetrics
     * --------
     */
    struct cmt *cmt;                      /* parent context               */

    flb_pipefd_t notification_channel;

    /* Keep a reference to the original context this instance belongs to */
    struct flb_config *config;
};


/* Processor stack */

struct flb_processor *flb_processor_create(struct flb_config *config,
                                           char *name,
                                           void *source_plugin_instance,
                                           int source_plugin_type);

int flb_processor_is_active(struct flb_processor *proc);

int flb_processor_init(struct flb_processor *proc);
void flb_processor_destroy(struct flb_processor *proc);

int flb_processor_run(struct flb_processor *proc,
                      size_t starting_stage,
                      int type,
                      const char *tag, size_t tag_len,
                      void *data, size_t data_size,
                      void **out_buf, size_t *out_size);


struct flb_processor_unit *flb_processor_unit_create(struct flb_processor *proc,
                                                     int event_type,
                                                     const char *unit_name);
void flb_processor_unit_destroy(struct flb_processor_unit *pu);
int flb_processor_unit_set_property(struct flb_processor_unit *pu, const char *k, struct cfl_variant *v);
int flb_processor_unit_set_property_str(struct flb_processor_unit *pu, const char *k, const char *v);

int flb_processors_load_from_config_format_group(struct flb_processor *proc, struct flb_cf_group *g);

/* Processor plugin instance */
struct flb_processor_instance *flb_processor_instance_create(struct flb_config *config,
                                                             struct flb_processor_unit *pu,
                                                             int event_type,
                                                             const char *name, void *data);

void flb_processor_instance_destroy(
        struct flb_processor_instance *ins);

int flb_processor_instance_init(
        struct flb_processor_instance *ins,
        void *source_plugin_instance,
        int source_plugin_type,
        struct flb_config *config);

void flb_processor_instance_exit(
        struct flb_processor_instance *ins,
        struct flb_config *config);

void flb_processor_instance_set_context(
        struct flb_processor_instance *ins,
        void *context);

int flb_processor_instance_check_properties(
        struct flb_processor_instance *ins,
        struct flb_config *config);

int flb_processor_instance_set_property(
        struct flb_processor_instance *ins,
        const char *k, struct cfl_variant *v);

const char *flb_processor_instance_get_property(
                const char *key,
                struct flb_processor_instance *ins);

const char *flb_processor_instance_get_name(
                struct flb_processor_instance *ins);

static inline int flb_processor_instance_config_map_set(
                    struct flb_processor_instance *ins,
                    void *context)
{
    return flb_config_map_set(&ins->properties, ins->config_map, context);
}

static inline
struct flb_input_instance *flb_processor_get_input_instance(struct flb_processor_unit *pu)
{
        struct flb_processor *processor;
        struct flb_input_instance *ins;

        processor = (struct flb_processor *) pu->parent;
        ins = (struct flb_input_instance *) processor->data;

        return ins;
}

struct mk_list *flb_processor_get_global_config_map(struct flb_config *config);

#endif
