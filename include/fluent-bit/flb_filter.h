/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_input_chunk.h>
#include <msgpack.h>

#define FLB_FILTER_MODIFIED 1
#define FLB_FILTER_NOTOUCH  2

struct flb_input_instance;
struct flb_filter_instance;

struct flb_filter_plugin {
    int flags;             /* Flags (not available at the moment */
    char *name;            /* Filter short name            */
    char *description;     /* Description                  */

    /* Callbacks */
    int (*cb_init) (struct flb_filter_instance *, struct flb_config *, void *);
    int (*cb_filter) (void *, size_t, char *, int,
                      void **, size_t *,
                      struct flb_filter_instance *,
                      void *, struct flb_config *);
    int (*cb_exit) (void *, struct flb_config *);

    struct mk_list _head;  /* Link to parent list (config->filters) */
};

struct flb_filter_instance {
    int id;                        /* instance id              */
    char name[16];                 /* numbered name            */
    char *alias;                   /* alias name               */
    char *match;                   /* match rule based on Tags */
#ifdef FLB_HAVE_REGEX
    struct flb_regex *match_regex; /* match rule (regex) based on Tags */
#endif
    void *context;                 /* Instance local context   */
    void *data;
    struct flb_filter_plugin *p;   /* original plugin          */
    struct mk_list properties;     /* config properties        */
    struct mk_list _head;          /* link to config->filters  */

#ifdef FLB_HAVE_METRICS
    struct flb_metrics *metrics;   /* metrics                  */
#endif

    /* Keep a reference to the original context this instance belongs to */
    struct flb_config *config;
};

int flb_filter_set_property(struct flb_filter_instance *filter, char *k, char *v);
char *flb_filter_get_property(char *key, struct flb_filter_instance *i);

struct flb_filter_instance *flb_filter_new(struct flb_config *config,
                                           char *filter, void *data);
void flb_filter_exit(struct flb_config *config);
void flb_filter_do(struct flb_input_chunk *ic,
                   void *data, size_t bytes,
                   char *tag, int tag_len,
                   struct flb_config *config);
char *flb_filter_name(struct flb_filter_instance *in);
void flb_filter_initialize_all(struct flb_config *config);
void flb_filter_set_context(struct flb_filter_instance *ins, void *context);

#endif
