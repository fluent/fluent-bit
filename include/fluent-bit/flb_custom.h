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

#ifndef FLB_CUSTOM_H
#define FLB_CUSTOM_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#ifdef FLB_HAVE_METRICS
#include <fluent-bit/flb_metrics.h>
#endif

/* Custom plugin flag masks */
#define FLB_CUSTOM_NET_CLIENT   1   /* custom may use upstream net.* properties  */
#define FLB_CUSTOM_NET_SERVER   2   /* custom may use downstream net.* properties  */

/* Custom plugin types */
#define FLB_CUSTOM_PLUGIN_CORE   0
#define FLB_CUSTOM_PLUGIN_PROXY  1

struct flb_custom_instance;

struct flb_custom_plugin {
    /*
     * The type defines if this is a core-based plugin or it's handled by
     * some specific proxy.
     */
    int type;
    void *proxy;

    int flags;             /* Flags (not available at the moment */
    char *name;            /* Custom plugin short name           */
    char *description;     /* Description                        */

    /* Config map */
    struct flb_config_map *config_map;

    /* Callbacks */
    int (*cb_init) (struct flb_custom_instance *, struct flb_config *, void *);
    int (*cb_run) (const void *, size_t, const char *, int,
                   void **, size_t *,
                   struct flb_custom_instance *,
                   void *, struct flb_config *);
    int (*cb_exit) (void *, struct flb_config *);

    /* Destroy */
    void (*cb_destroy) (struct flb_custom_plugin *);

    struct mk_list _head;  /* Link to parent list (config->custom) */
};

struct flb_custom_instance {
    int id;                        /* instance id              */
    int log_level;                 /* instance log level       */
    char name[32];                 /* numbered name            */
    char *alias;                   /* alias name               */
    void *context;                 /* instance local context   */
    void *data;
    struct flb_custom_plugin *p;   /* original plugin          */
    struct mk_list properties;     /* config properties        */
    struct mk_list net_properties; /* net properties           */
    struct mk_list *config_map;    /* configuration map        */
    struct mk_list *net_config_map;/* net configuration map    */
    struct mk_list _head;          /* link to config->customs  */

    /*
     * CMetrics
     * --------
     */
    struct cmt *cmt;                      /* parent context               */

    /* Keep a reference to the original context this instance belongs to */
    struct flb_config *config;
};

static inline int flb_custom_config_map_set(struct flb_custom_instance *ins,
                                            void *context)
{
    return flb_config_map_set(&ins->properties, ins->config_map, context);
}

int flb_custom_set_property(struct flb_custom_instance *ins,
                            const char *k, const char *v);
const char *flb_custom_get_property(const char *key,
                                    struct flb_custom_instance *ins);

struct flb_custom_instance *flb_custom_new(struct flb_config *config,
                                           const char *custom, void *data);
void flb_custom_exit(struct flb_config *config);
const char *flb_custom_name(struct flb_custom_instance *ins);
int flb_custom_plugin_property_check(struct flb_custom_instance *ins,
                                    struct flb_config *config);
int flb_custom_init_all(struct flb_config *config);
void flb_custom_set_context(struct flb_custom_instance *ins, void *context);
void flb_custom_instance_destroy(struct flb_custom_instance *ins);
int flb_custom_log_check(struct flb_custom_instance *ins, int l);

#endif
