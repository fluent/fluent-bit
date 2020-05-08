/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_pack.h>
#include <chunkio/chunkio.h>

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
                   const char *tag, int tag_len,
                   struct flb_config *config)
{
    int ret;
#ifdef FLB_HAVE_METRICS
    int in_records = 0;
    int out_records = 0;
    int diff = 0;
    int pre_records = 0;
#endif
    char *ntag;
    const char *work_data;
    size_t work_size;
    void *out_buf;
    size_t cur_size;
    size_t out_size;
    ssize_t content_size;
    ssize_t write_at;
    struct mk_list *head;
    struct flb_filter_instance *f_ins;

    /* For the incoming Tag make sure to create a NULL terminated reference */
    ntag = flb_malloc(tag_len + 1);
    if (!ntag) {
        flb_errno();
        flb_error("[filter] could not filter record due to memory problems");
        return;
    }
    memcpy(ntag, tag, tag_len);
    ntag[tag_len] = '\0';


    work_data = (const char *) data;
    work_size = bytes;

#ifdef FLB_HAVE_METRICS
    /* Count number of incoming records */
    in_records = ic->added_records;
    pre_records = ic->total_records - in_records;
#endif

    /* Iterate filters */
    mk_list_foreach(head, &config->filters) {
        f_ins = mk_list_entry(head, struct flb_filter_instance, _head);
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

            content_size = cio_chunk_get_content_size(ic->chunk);

            /* where to position the new content if modified ? */
            write_at = (content_size - work_size);

            /* Invoke the filter callback */
            ret = f_ins->p->cb_filter(work_data,      /* msgpack buffer   */
                                      work_size,      /* msgpack size     */
                                      tag, tag_len,   /* input tag        */
                                      &out_buf,       /* new data         */
                                      &out_size,      /* new data size    */
                                      f_ins,          /* filter instance  */
                                      f_ins->context, /* filter priv data */
                                      config);

            /* Override buffer just if it was modified */
            if (ret == FLB_FILTER_MODIFIED) {
                /* all records removed, no data to continue processing */
                if (out_size == 0) {
                    /* reset data content length */
                    flb_input_chunk_write_at(ic, write_at, "", 0);

#ifdef FLB_HAVE_METRICS
                    ic->total_records = pre_records;

                    /* Summarize all records removed */
                    flb_metrics_sum(FLB_METRIC_N_DROPPED,
                                    in_records, f_ins->metrics);
#endif
                    break;
                }
                else {
#ifdef FLB_HAVE_METRICS
                    out_records = flb_mp_count(out_buf, out_size);
                    if (out_records > in_records) {
                        diff = (out_records - in_records);
                        /* Summarize new records */
                        flb_metrics_sum(FLB_METRIC_N_ADDED,
                                        diff, f_ins->metrics);
                    }
                    else if (out_records < in_records) {
                        diff = (in_records - out_records);
                        /* Summarize dropped records */
                        flb_metrics_sum(FLB_METRIC_N_DROPPED,
                                        diff, f_ins->metrics);
                    }

                    /* set number of records in new chunk */
                    in_records = out_records;
                    ic->total_records = pre_records + in_records;
#endif
                }
                ret = flb_input_chunk_write_at(ic, write_at,
                                               out_buf, out_size);
                if (ret == -1) {
                    flb_error("[filter] could not write data to storage. "
                              "Skipping filtering.");
                    flb_free(out_buf);
                    continue;
                }

                /* Point back the 'data' pointer to the new address */
                ret = cio_chunk_get_content(ic->chunk,
                                            (char **) &work_data, &cur_size);
                if (ret != CIO_OK) {
                    flb_error("[filter] error retrieving data chunk");
                }
                else {
                    work_data += (cur_size - out_size);
                    work_size = out_size;
                }
                flb_free(out_buf);
            }
        }
    }

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
        ins->match = tmp;
    }
    else if (prop_key_check("alias", k, len) == 0 && tmp) {
        ins->alias = tmp;
    }
    else if (prop_key_check("log_level", k, len) == 0 && tmp) {
        ret = flb_log_get_level_str(tmp);
        flb_sds_destroy(tmp);
        if (ret == -1) {
            return -1;
        }
        ins->log_level = ret;
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
        if (strcmp(plugin->name, filter) == 0) {
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

/* Initialize all filter plugins */
int flb_filter_init_all(struct flb_config *config)
{
    int ret;
#ifdef FLB_HAVE_METRICS
    const char *name;
#endif
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *config_map;
    struct flb_filter_plugin *p;
    struct flb_filter_instance *ins;

    /* Iterate all active filter instance plugins */
    mk_list_foreach_safe(head, tmp, &config->filters) {
        ins = mk_list_entry(head, struct flb_filter_instance, _head);

        if (!ins->match
#ifdef FLB_HAVE_REGEX
            && !ins->match_regex
#endif
            ) {
            flb_warn("[filter] NO match rule for %s filter instance, unloading.",
                     ins->name);
            mk_list_del(&ins->_head);
            flb_free(ins);
            continue;
        }
        if (ins->log_level == -1) {
            ins->log_level = config->log->level;
        }

        p = ins->p;

        /* Metrics */
#ifdef FLB_HAVE_METRICS
        /* Get name or alias for the instance */
        name = flb_filter_name(ins);

        /* Create the metrics context */
        ins->metrics = flb_metrics_create(name);
        if (!ins->metrics) {
            flb_warn("[filter] cannot initialize metrics for %s filter, "
                     "unloading.", name);
            mk_list_del(&ins->_head);
            flb_free(ins);
            continue;
        }

        /* Register filter metrics */
        flb_metrics_add(FLB_METRIC_N_DROPPED, "drop_records", ins->metrics);
        flb_metrics_add(FLB_METRIC_N_ADDED, "add_records", ins->metrics);
#endif

        /*
         * Before to call the initialization callback, make sure that the received
         * configuration parameters are valid if the plugin is registering a config map.
         */
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
                flb_filter_instance_destroy(ins);
                return -1;
            }
        }

        /* Initialize the input */
        if (p->cb_init) {
            ret = p->cb_init(ins, config, ins->data);
            if (ret != 0) {
                flb_error("Failed initialize filter %s", ins->name);
                flb_filter_instance_destroy(ins);
                return -1;
            }
        }
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
