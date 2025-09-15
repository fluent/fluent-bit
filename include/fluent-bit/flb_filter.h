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

#ifndef FLB_FILTER_H
#define FLB_FILTER_H

#include <fluent-bit/flb_info.h>

#ifdef FLB_HAVE_REGEX
#include <fluent-bit/flb_regex.h>
#endif

#ifdef FLB_HAVE_METRICS
#include <fluent-bit/flb_metrics.h>
#endif

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_input_chunk.h>
#include <msgpack.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_counter.h>

#define FLB_FILTER_MODIFIED 1
#define FLB_FILTER_NOTOUCH  2

/*
 * Types are defined by creating a mask using numbers. However, it's important
 * to note that the masks used in this process are different from the ones used
 * in flb_event.h. The original chunk values are not actually masks, but rather set
 * numbers starting from 0; this is for compatibility reasons.
 */
#define FLB_FILTER_LOGS        1
#define FLB_FILTER_METRICS     2
#define FLB_FILTER_TRACES      4

struct flb_input_instance;
struct flb_filter_instance;

struct flb_filter_plugin {
    int event_type;        /* Event type: logs, metrics, traces */
    int flags;             /* Flags (not available at the moment */
    char *name;            /* Filter short name            */
    char *description;     /* Description                  */

    /* Config map */
    struct flb_config_map *config_map;

    /* Callbacks */
    int (*cb_pre_run) (struct flb_filter_instance *, struct flb_config *, void *);
    int (*cb_init) (struct flb_filter_instance *, struct flb_config *, void *);
    int (*cb_filter) (const void *, size_t,
                      const char *, int,
                      void **, size_t *,
                      struct flb_filter_instance *,
                      struct flb_input_instance *,
                      void *, struct flb_config *);
    int (*cb_exit) (void *, struct flb_config *);

    /* Notification: this callback will be invoked anytime a notification is received*/
    int (*cb_notification) (struct flb_filter_instance *, struct flb_config *, void *);

    struct mk_list _head;  /* Link to parent list (config->filters) */
};

struct flb_filter_instance {
    int event_type;                /* Event type: logs, metrics, traces */
    int id;                        /* instance id              */
    int log_level;                 /* instance log level       */
    int log_suppress_interval;     /* log suppression interval     */
    char name[32];                 /* numbered name            */
    char *alias;                   /* alias name               */
    char *match;                   /* match rule based on Tags */
#ifdef FLB_HAVE_REGEX
    struct flb_regex *match_regex; /* match rule (regex) based on Tags */
#endif
    void *parent_processor;        /* Parent processor         */
    void *context;                 /* Instance local context   */
    void *data;
    struct flb_filter_plugin *p;   /* original plugin          */
    struct mk_list properties;     /* config properties        */
    struct mk_list *config_map;    /* configuration map        */

    struct mk_list _head;          /* link to config->filters  */

    /*
     * CMetrics
     * --------
     */
    struct cmt *cmt;                      /* parent context               */
    struct cmt_counter *cmt_records;      /* m: filter_records_total      */
    struct cmt_counter *cmt_bytes;        /* m: filter_bytes_total        */
    struct cmt_counter *cmt_add_records;  /* m: filter_add_records_total  */
    struct cmt_counter *cmt_drop_records; /* m: filter_drop_records_total */
    struct cmt_counter *cmt_drop_bytes;   /* m: filter_drop_bytes_total   */

#ifdef FLB_HAVE_METRICS
    struct flb_metrics *metrics;   /* metrics                  */
#endif
    flb_pipefd_t notification_channel;

    /* Keep a reference to the original context this instance belongs to */
    struct flb_config *config;
};

struct mk_list *flb_filter_get_global_config_map(struct flb_config *config);

static inline int flb_filter_config_map_set(struct flb_filter_instance *ins,
                                            void *context)
{
    return flb_config_map_set(&ins->properties, ins->config_map, context);
}

int flb_filter_set_property(struct flb_filter_instance *ins,
                            const char *k, const char *v);
const char *flb_filter_get_property(const char *key,
                                    struct flb_filter_instance *ins);

struct flb_filter_instance *flb_filter_new(struct flb_config *config,
                                           const char *filter, void *data);
void flb_filter_instance_exit(struct flb_filter_instance *ins,
                              struct flb_config *config);

void flb_filter_exit(struct flb_config *config);
void flb_filter_do(struct flb_input_chunk *ic,
                   const void *data, size_t bytes,
                   void **out_data, size_t *out_bytes,
                   const char *tag, int tag_len,
                   struct flb_config *config);
const char *flb_filter_name(struct flb_filter_instance *ins);

int flb_filter_match_property_existence(struct flb_filter_instance *ins);
int flb_filter_plugin_property_check(struct flb_filter_instance *ins,
                                     struct flb_config *config);
int flb_filter_init(struct flb_config *config, struct flb_filter_instance *ins);
int flb_filter_init_all(struct flb_config *config);
void flb_filter_set_context(struct flb_filter_instance *ins, void *context);
void flb_filter_instance_destroy(struct flb_filter_instance *ins);

#endif
