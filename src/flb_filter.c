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

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_utils.h>
#include <chunkio/chunkio.h>

#ifdef FLB_HAVE_CHUNK_TRACE
#include <fluent-bit/flb_chunk_trace.h>
#endif /* FLB_HAVE_CHUNK_TRACE */

struct flb_config_map filter_global_properties[] = {
    {
        FLB_CONFIG_MAP_STR, "match", NULL,
        0, FLB_FALSE, 0,
        "Set a tag pattern to match the records that this filter should process. "
        "Supports exact matches or wildcards (e.g., '*')."
    },
    {
        FLB_CONFIG_MAP_STR, "match_regex", NULL,
        0, FLB_FALSE, 0,
        "Set a regular expression to match tags for filtering. This allows more flexible matching "
        "compared to simple wildcards."
    },
    {
        FLB_CONFIG_MAP_STR, "alias", NULL,
        0, FLB_FALSE, 0,
        "Sets an alias for the filter instance. This is useful when using multiple instances of the same "
        "filter plugin. If no alias is set, the instance will be named using the plugin name and a sequence number."
    },
    {
        FLB_CONFIG_MAP_STR, "log_level", "info",
        0, FLB_FALSE, 0,
        "Specifies the log level for this filter plugin. If not set, the plugin "
        "will use the global log level defined in the 'service' section. If the global "
        "log level is also not specified, it defaults to 'info'."
    },
    {
        FLB_CONFIG_MAP_TIME, "log_suppress_interval", "0",
        0, FLB_FALSE, 0,
        "Allows suppression of repetitive log messages from the filter plugin that appear similar within a specified "
        "time interval. Defaults to 0, meaning no suppression."
    },

    {0}
};

struct mk_list *flb_filter_get_global_config_map(struct flb_config *config)
{
    return flb_config_map_create(config, filter_global_properties);
}

static inline int instance_id(struct flb_config *config)
{
    struct flb_filter_instance *entry;

    if (mk_list_size(&config->filters) == 0) {
        return 0;
    }

    entry = mk_list_entry_last(&config->filters, struct flb_filter_instance,
                               _head);
    return (entry->id + 1);
}

static int is_active(struct mk_list *in_properties)
{
    struct mk_list *head;
    struct flb_kv *kv;

    mk_list_foreach(head, in_properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (strcasecmp(kv->key, "active") == 0) {
            /* Skip checking deactivation ... */
            if (strcasecmp(kv->val, "FALSE") == 0 || strcmp(kv->val, "0") == 0) {
                return FLB_FALSE;
            }
        }
    }
    return FLB_TRUE;
}

static inline int prop_key_check(const char *key, const char *kv, int k_len)
{
    int len;

    len = strlen(key);
    if (strncasecmp(key, kv, k_len) == 0 && len == k_len) {
        return 0;
    }

    return -1;
}

void flb_filter_do(struct flb_input_chunk *ic,
                   const void *data, size_t bytes,
                   void **out_data, size_t *out_bytes,
                   const char *tag, int tag_len,
                   struct flb_config *config)
{
    int ret;
#ifdef FLB_HAVE_METRICS
    int in_records = 0;
    int out_records = 0;
    int diff = 0;
    int pre_records = 0;
    uint64_t ts;
    char *name;
#endif
    char *ntag;
    char *work_data;
    size_t work_size;
    size_t ingested_size;
    size_t dropped_size;
    void *out_buf;
    size_t out_size;
    struct mk_list *head;
    struct flb_filter_instance *f_ins;
    struct flb_input_instance *i_ins = ic->in;
/* measure time between filters for chunk traces. */
#ifdef FLB_HAVE_CHUNK_TRACE
    struct flb_time tm_start;
    struct flb_time tm_finish;
#endif /* FLB_HAVE_CHUNK_TRACE */

    *out_data = NULL;
    *out_bytes = 0;

    /* For the incoming Tag make sure to create a NULL terminated reference */
    ntag = flb_malloc(tag_len + 1);
    if (!ntag) {
        flb_errno();
        flb_error("[filter] could not filter record due to memory problems");
        return;
    }
    memcpy(ntag, tag, tag_len);
    ntag[tag_len] = '\0';

    work_data = (char *) data;
    work_size = bytes;
    ingested_size = bytes;

#ifdef FLB_HAVE_METRICS
    /* timestamp */
    ts = cfl_time_now();
#endif

    /* Count number of incoming records */
    in_records = ic->added_records;
    pre_records = ic->total_records - in_records;

    /* Iterate filters */
    mk_list_foreach(head, &config->filters) {
        f_ins = mk_list_entry(head, struct flb_filter_instance, _head);

        if (is_active(&f_ins->properties) == FLB_FALSE) {
            continue;
        }

        if (flb_router_match(ntag, tag_len, f_ins->match
#ifdef FLB_HAVE_REGEX
        , f_ins->match_regex
#else
        , NULL
#endif
           )) {
            /* Reset filtered buffer */
            out_buf = NULL;
            out_size = 0;

#ifdef FLB_HAVE_CHUNK_TRACE
            if (ic->trace) {
                flb_time_get(&tm_start);
            }
#endif /* FLB_HAVE_CHUNK_TRACE */

            /* Invoke the filter callback */
            ret = f_ins->p->cb_filter(work_data,      /* msgpack buffer   */
                                      work_size,      /* msgpack size     */
                                      ntag, tag_len,  /* input tag        */
                                      &out_buf,       /* new data         */
                                      &out_size,      /* new data size    */
                                      f_ins,          /* filter instance  */
                                      i_ins,          /* input instance   */
                                      f_ins->context, /* filter priv data */
                                      config);

#ifdef FLB_HAVE_CHUNK_TRACE
            if (ic->trace) {
                flb_time_get(&tm_finish);
            }
#endif /* FLB_HAVE_CHUNK_TRACE */

#ifdef FLB_HAVE_METRICS
            name = (char *) flb_filter_name(f_ins);

            cmt_counter_add(f_ins->cmt_records, ts, in_records,
                    1, (char *[]) {name});
            cmt_counter_add(f_ins->cmt_bytes, ts, out_size,
                    1, (char *[]) {name});

            flb_metrics_sum(FLB_METRIC_N_RECORDS, in_records, f_ins->metrics);
            flb_metrics_sum(FLB_METRIC_N_BYTES, out_size, f_ins->metrics);
#endif

            /* Override buffer just if it was modified */
            if (ret == FLB_FILTER_MODIFIED) {
                /* release intermediate buffer */
                if (work_data != data) {
                    flb_free(work_data);
                }

                work_data = (char *) out_buf;
                work_size = out_size;
                dropped_size = 0;
                if (ingested_size > out_size) {
                    dropped_size = ingested_size - out_size;
                }

                /* all records removed, no data to continue processing */
                if (out_size == 0) {
#ifdef FLB_HAVE_CHUNK_TRACE
                    if (ic->trace) {
                        flb_chunk_trace_filter(ic->trace, (void *)f_ins, &tm_start, &tm_finish, "", 0);
                    }
#endif /* FLB_HAVE_CHUNK_TRACE */

                    ic->total_records = pre_records;

#ifdef FLB_HAVE_METRICS
                    /* cmetrics */
                    cmt_counter_add(f_ins->cmt_drop_records, ts, in_records,
                                    1, (char *[]) {name});
                    cmt_counter_add(f_ins->cmt_drop_bytes, ts, dropped_size,
                                    1, (char *[]) {name});

                    /* [OLD] Summarize all records removed */
                    flb_metrics_sum(FLB_METRIC_N_DROPPED,
                                    in_records, f_ins->metrics);
                    flb_metrics_sum(FLB_METRIC_N_DROPPED_BYTES,
                                    dropped_size, f_ins->metrics);
#endif
                    break;
                }
                else {
                    out_records = flb_mp_count(out_buf, out_size);

#ifdef FLB_HAVE_METRICS
                    if (out_records > in_records) {
                        diff = (out_records - in_records);

                        /* cmetrics */
                        cmt_counter_add(f_ins->cmt_add_records, ts, diff,
                                    1, (char *[]) {name});
                        cmt_counter_add(f_ins->cmt_drop_bytes, ts, dropped_size,
                                    1, (char *[]) {name});

                        /* [OLD] Summarize new records */
                        flb_metrics_sum(FLB_METRIC_N_ADDED,
                                        diff, f_ins->metrics);
                        flb_metrics_sum(FLB_METRIC_N_DROPPED_BYTES,
                                        dropped_size, f_ins->metrics);
                    }
                    else if (out_records < in_records) {
                        diff = (in_records - out_records);

                        /* cmetrics */
                        cmt_counter_add(f_ins->cmt_drop_records, ts, diff,
                                    1, (char *[]) {name});
                        cmt_counter_add(f_ins->cmt_drop_bytes, ts, dropped_size,
                                    1, (char *[]) {name});

                        /* [OLD] Summarize dropped records */
                        flb_metrics_sum(FLB_METRIC_N_DROPPED,
                                        diff, f_ins->metrics);
                        flb_metrics_sum(FLB_METRIC_N_DROPPED_BYTES,
                                        dropped_size, f_ins->metrics);
                    }
#endif

                    /* set number of records in new chunk */
                    in_records = out_records;
                    ic->total_records = pre_records + in_records;
                }

#ifdef FLB_HAVE_CHUNK_TRACE
                if (ic->trace) {
                    flb_chunk_trace_filter(ic->trace, (void *)f_ins, &tm_start, &tm_finish, out_buf, out_size);
                }
#endif /* FLB_HAVE_CHUNK_TRACE */
            }
        }
    }

    *out_data = work_data;
    *out_bytes = work_size;

    flb_free(ntag);
}

int flb_filter_set_property(struct flb_filter_instance *ins,
                            const char *k, const char *v)
{
    int len;
    int ret;
    flb_sds_t tmp;
    struct flb_kv *kv;

    len = strlen(k);
    tmp = flb_env_var_translate(ins->config->env, v);
    if (!tmp) {
        return -1;
    }

    /* Check if the key is a known/shared property */
#ifdef FLB_HAVE_REGEX
    if (prop_key_check("match_regex", k, len) == 0) {
        ins->match_regex = flb_regex_create(tmp);
        flb_sds_destroy(tmp);
    }
    else
#endif
    if (prop_key_check("match", k, len) == 0) {
        flb_utils_set_plugin_string_property("match", &ins->match, tmp);
    }
    else if (prop_key_check("alias", k, len) == 0 && tmp) {
        flb_utils_set_plugin_string_property("alias", &ins->alias, tmp);
    }
    else if (prop_key_check("log_level", k, len) == 0 && tmp) {
        ret = flb_log_get_level_str(tmp);
        flb_sds_destroy(tmp);
        if (ret == -1) {
            return -1;
        }
        ins->log_level = ret;
    }
    else if (prop_key_check("log_suppress_interval", k, len) == 0 && tmp) {
        ret = flb_utils_time_to_seconds(tmp);
        flb_sds_destroy(tmp);
        if (ret == -1) {
            return -1;
        }
        ins->log_suppress_interval = ret;
    }
    else {
        /*
         * Create the property, we don't pass the value since we will
         * map it directly to avoid an extra memory allocation.
         */
        kv = flb_kv_item_create(&ins->properties, (char *) k, NULL);
        if (!kv) {
            if (tmp) {
                flb_sds_destroy(tmp);
            }
            return -1;
        }
        kv->val = tmp;
    }

    return 0;
}

const char *flb_filter_get_property(const char *key,
                                    struct flb_filter_instance *ins)
{
    return flb_kv_get_key_value(key, &ins->properties);
}

void flb_filter_instance_exit(struct flb_filter_instance *ins,
                              struct flb_config *config)
{
    struct flb_filter_plugin *p;

    p = ins->p;
    if (p->cb_exit && ins->context) {
        p->cb_exit(ins->context, config);
    }
}

/* Invoke exit call for the filter plugin */
void flb_filter_exit(struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_filter_instance *ins;
    struct flb_filter_plugin *p;

    mk_list_foreach_safe(head, tmp, &config->filters) {
        ins = mk_list_entry(head, struct flb_filter_instance, _head);
        p = ins->p;
        if (!p) {
            continue;
        }
        flb_filter_instance_exit(ins, config);
        flb_filter_instance_destroy(ins);
    }
}

struct flb_filter_instance *flb_filter_new(struct flb_config *config,
                                           const char *filter, void *data)
{
    int id;
    struct mk_list *head;
    struct flb_filter_plugin *plugin;
    struct flb_filter_instance *instance = NULL;

    if (!filter) {
        return NULL;
    }

    mk_list_foreach(head, &config->filter_plugins) {
        plugin = mk_list_entry(head, struct flb_filter_plugin, _head);
        if (strcasecmp(plugin->name, filter) == 0) {
            break;
        }
        plugin = NULL;
    }

    if (!plugin) {
        return NULL;
    }

    instance = flb_calloc(1, sizeof(struct flb_filter_instance));
    if (!instance) {
        flb_errno();
        return NULL;
    }
    instance->config = config;

    /*
     * Initialize event type, if not set, default to FLB_FILTER_LOGS. Note that a
     * zero value means it's undefined.
     */
    if (plugin->event_type == 0) {
        instance->event_type = FLB_FILTER_LOGS;
    }
    else {
        instance->event_type = plugin->event_type;
    }

    /* Get an ID */
    id =  instance_id(config);

    /* format name (with instance id) */
    snprintf(instance->name, sizeof(instance->name) - 1,
             "%s.%i", plugin->name, id);

    instance->id    = id;
    instance->alias = NULL;
    instance->p     = plugin;
    instance->data  = data;
    instance->match = NULL;
#ifdef FLB_HAVE_REGEX
    instance->match_regex = NULL;
#endif
    instance->log_level = -1;
    instance->log_suppress_interval = -1;

    mk_list_init(&instance->properties);
    mk_list_add(&instance->_head, &config->filters);

    return instance;
}

/* Return an instance name or alias */
const char *flb_filter_name(struct flb_filter_instance *ins)
{
    if (ins->alias) {
        return ins->alias;
    }

    return ins->name;
}

int flb_filter_plugin_property_check(struct flb_filter_instance *ins,
                                     struct flb_config *config)
{
    int ret = 0;
    struct mk_list *config_map;
    struct flb_filter_plugin *p = ins->p;

    if (p->config_map) {
        /*
         * Create a dynamic version of the configmap that will be used by the specific
         * instance in question.
         */
        config_map = flb_config_map_create(config, p->config_map);
        if (!config_map) {
            flb_error("[filter] error loading config map for '%s' plugin",
                      p->name);
            return -1;
        }
        ins->config_map = config_map;

        /* Validate incoming properties against config map */
        ret = flb_config_map_properties_check(ins->p->name,
                                              &ins->properties, ins->config_map);
        if (ret == -1) {
            if (config->program_name) {
                flb_helper("try the command: %s -F %s -h\n",
                           config->program_name, ins->p->name);
            }
            return -1;
        }
    }

    return 0;
}

int flb_filter_match_property_existence(struct flb_filter_instance *ins)
{
    if (!ins->match
#ifdef FLB_HAVE_REGEX
              && !ins->match_regex
#endif
        ) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

int flb_filter_init(struct flb_config *config, struct flb_filter_instance *ins)
{
    int ret;
    uint64_t ts;
    char *name;
    struct flb_filter_plugin *p;

    if (flb_filter_match_property_existence(ins) == FLB_FALSE) {
        flb_warn("[filter] NO match rule for %s filter instance, unloading.",
                 ins->name);
        return -1;
    }

    if (ins->log_level == -1 && config->log) {
        ins->log_level = config->log->level;
    }

    p = ins->p;

    /* Get name or alias for the instance */
    name = (char *) flb_filter_name(ins);
    ts = cfl_time_now();

    /* CMetrics */
    ins->cmt = cmt_create();
    if (!ins->cmt) {
        flb_error("[filter] could not create cmetrics context: %s",
                  flb_filter_name(ins));
        return -1;
    }

    /* Register generic filter plugin metrics */
    ins->cmt_records = cmt_counter_create(ins->cmt,
                                              "fluentbit", "filter",
                                              "records_total",
                                              "Total number of new records processed.",
                                              1, (char *[]) {"name"});
    cmt_counter_set(ins->cmt_records, ts, 0, 1, (char *[]) {name});

    /* Register generic filter plugin metrics */
    ins->cmt_bytes = cmt_counter_create(ins->cmt,
                                              "fluentbit", "filter",
                                              "bytes_total",
                                              "Total number of new bytes processed.",
                                              1, (char *[]) {"name"});
    cmt_counter_set(ins->cmt_bytes, ts, 0, 1, (char *[]) {name});

    /* Register generic filter plugin metrics */
    ins->cmt_add_records = cmt_counter_create(ins->cmt,
                                              "fluentbit", "filter",
                                              "add_records_total",
                                              "Total number of new added records.",
                                              1, (char *[]) {"name"});
    cmt_counter_set(ins->cmt_add_records, ts, 0, 1, (char *[]) {name});

    /* Register generic filter plugin metrics */
    ins->cmt_drop_records = cmt_counter_create(ins->cmt,
                                              "fluentbit", "filter",
                                              "drop_records_total",
                                              "Total number of dropped records.",
                                              1, (char *[]) {"name"});
    cmt_counter_set(ins->cmt_drop_records, ts, 0, 1, (char *[]) {name});

    /* Register generic filter plugin metrics */
    ins->cmt_drop_bytes = cmt_counter_create(ins->cmt,
                                             "fluentbit", "filter",
                                             "drop_bytes_total",
                                             "Total number of dropped bytes.",
                                             1, (char *[]) {"name"});
    cmt_counter_set(ins->cmt_drop_bytes, ts, 0, 1, (char *[]) {name});

    /* OLD Metrics API */
#ifdef FLB_HAVE_METRICS

    /* Create the metrics context */
    ins->metrics = flb_metrics_create(name);
    if (!ins->metrics) {
        flb_warn("[filter] cannot initialize metrics for %s filter, "
                 "unloading.", name);
        return -1;
    }

    /* Register filter metrics */
    flb_metrics_add(FLB_METRIC_N_DROPPED, "drop_records", ins->metrics);
    flb_metrics_add(FLB_METRIC_N_ADDED, "add_records", ins->metrics);
    flb_metrics_add(FLB_METRIC_N_RECORDS, "records", ins->metrics);
    flb_metrics_add(FLB_METRIC_N_BYTES, "bytes", ins->metrics);
    flb_metrics_add(FLB_METRIC_N_DROPPED_BYTES, "drop_bytes", ins->metrics);
#endif

    /*
     * Before to call the initialization callback, make sure that the received
     * configuration parameters are valid if the plugin is registering a config map.
     */
    if (flb_filter_plugin_property_check(ins, config) == -1) {
        return -1;
    }

    if (is_active(&ins->properties) == FLB_FALSE) {
        return 0;
    }

    /* Run pre_run callback for the filter */
    if (p->cb_pre_run) {
        ret = p->cb_pre_run(ins, config, ins->data);
        if (ret != 0) {
            flb_error("Failed pre_run callback on filter %s", ins->name);
            return -1;
        }
    }

    /* Initialize the input */
    if (p->cb_init) {
        ret = p->cb_init(ins, config, ins->data);
        if (ret != 0) {
            flb_error("Failed initialize filter %s", ins->name);
            return -1;
        }
    }

    return 0;
}

/* Initialize all filter plugins */
int flb_filter_init_all(struct flb_config *config)
{
    int ret;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_filter_instance *ins;

    /* Iterate all active filter instance plugins */
    mk_list_foreach_safe(head, tmp, &config->filters) {
        ins = mk_list_entry(head, struct flb_filter_instance, _head);
        ret = flb_filter_init(config, ins);
        if (ret == -1) {
            flb_filter_instance_destroy(ins);
            return -1;
        }

        ins->notification_channel = \
            config->notification_channels[1];
    }

    return 0;
}

void flb_filter_instance_destroy(struct flb_filter_instance *ins)
{
    if (!ins) {
        return;
    }

    /* destroy config map */
    if (ins->config_map) {
        flb_config_map_destroy(ins->config_map);
    }

    /* release properties */
    flb_kv_release(&ins->properties);

    if (ins->match != NULL) {
        flb_sds_destroy(ins->match);
    }

#ifdef FLB_HAVE_REGEX
    if (ins->match_regex) {
        flb_regex_destroy(ins->match_regex);
    }
#endif

    /* Remove metrics */
#ifdef FLB_HAVE_METRICS
    if (ins->cmt) {
        cmt_destroy(ins->cmt);
    }

    if (ins->metrics) {
        flb_metrics_destroy(ins->metrics);
    }
#endif
    if (ins->alias) {
        flb_sds_destroy(ins->alias);
    }

    mk_list_del(&ins->_head);

    flb_free(ins);
}

void flb_filter_set_context(struct flb_filter_instance *ins, void *context)
{
    ins->context = context;
}
