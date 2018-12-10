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

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_router.h>
#include <chunkio/chunkio.h>

static inline int instance_id(struct flb_filter_plugin *p,
                              struct flb_config *config)
{
    int c = 0;
    struct mk_list *head;
    struct flb_filter_instance *entry;

    mk_list_foreach(head, &config->filters) {
        entry = mk_list_entry(head, struct flb_filter_instance, _head);
        if (entry->p == p) {
            c++;
        }
    }

    return c;
}

static inline int prop_key_check(char *key, char *kv, int k_len)
{
    int len;

    len = strlen(key);
    if (strncasecmp(key, kv, k_len) == 0 && len == k_len) {
        return 0;
    }

    return -1;
}

void flb_filter_do(struct flb_input_chunk *ic,
                   void *data, size_t bytes,
                   char *tag, int tag_len,
                   struct flb_config *config)
{
    int ret;
    int in_records = 0;
    int out_records = 0;
    int diff = 0;
    void *out_buf;
    size_t cur_size;
    size_t out_size;
    ssize_t content_size;
    struct mk_list *head;
    struct flb_filter_instance *f_ins;
    msgpack_zone *mp_zone = NULL;

    content_size = cio_chunk_get_content_size(ic->chunk);
    if (content_size <= 0) {
        flb_error("[filter] cannot retrieve original content size");
        return;
    }
    content_size -= bytes;

    /* Count number of incoming records */
    mp_zone = msgpack_zone_new(MSGPACK_ZONE_CHUNK_SIZE);

    /* Iterate filters */
    mk_list_foreach(head, &config->filters) {
        f_ins = mk_list_entry(head, struct flb_filter_instance, _head);
        if (flb_router_match(tag, tag_len, f_ins->match
#ifdef FLB_HAVE_REGEX
        , f_ins->match_regex
#endif
           )) {
            /* Reset filtered buffer */
            out_buf = NULL;
            out_size = 0;

            /* Count number of incoming records */
            in_records = flb_mp_count_zone(data, bytes, mp_zone);

            /* Invoke the filter callback */
            ret = f_ins->p->cb_filter(data, bytes,    /* msgpack raw data */
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
                    flb_input_chunk_write_at(ic, content_size, "", 0);

#ifdef FLB_HAVE_METRICS
                    /* Summarize all records removed */
                    flb_metrics_sum(FLB_METRIC_N_DROPPED,
                                    in_records, f_ins->metrics);
                    msgpack_zone_clear(mp_zone);
#endif

                    break;
                }
                else {
#ifdef FLB_HAVE_METRICS
                    out_records = flb_mp_count_zone(out_buf, out_size,
                                                    mp_zone);

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
                    msgpack_zone_clear(mp_zone);
#endif
                }
                ret = flb_input_chunk_write_at(ic, content_size,
                                               out_buf, out_size);
                /* Point back the 'data' pointer to the new address */
                bytes = out_size;
                data = cio_chunk_get_content(ic->chunk, &cur_size);
                data += content_size;
                flb_free(out_buf);
            }
        }
    }

    msgpack_zone_free(mp_zone);
}

int flb_filter_set_property(struct flb_filter_instance *filter, char *k, char *v)
{
    int len;
    char *tmp;
    struct flb_config_prop *prop;

    len = strlen(k);
    tmp = flb_env_var_translate(filter->config->env, v);
    if (!tmp) {
        return -1;
    }

    /* Check if the key is a known/shared property */
#ifdef FLB_HAVE_REGEX
    if (prop_key_check("match_regex", k, len) == 0) {
        filter->match_regex = flb_regex_create((unsigned char *) tmp);
    }
    else
#endif
    if (prop_key_check("match", k, len) == 0) {
        filter->match = tmp;
    }
    else if (prop_key_check("alias", k, len) == 0 && tmp) {
        filter->alias = tmp;
    }
    else {
        /* Append any remaining configuration key to prop list */
        prop = flb_malloc(sizeof(struct flb_config_prop));
        if (!prop) {
            flb_free(tmp);
            return -1;
        }

        prop->key = flb_strdup(k);
        prop->val = tmp;
        mk_list_add(&prop->_head, &filter->properties);
    }

    return 0;
}

char *flb_filter_get_property(char *key, struct flb_filter_instance *i)
{
    return flb_config_prop_get(key, &i->properties);
}

/* Invoke exit call for the filter plugin */
void flb_filter_exit(struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *tmp_prop;
    struct mk_list *head_prop;
    struct flb_config_prop *prop;
    struct flb_filter_instance *ins;
    struct flb_filter_plugin *p;

    mk_list_foreach_safe(head, tmp, &config->filters) {
        ins = mk_list_entry(head, struct flb_filter_instance, _head);
        p = ins->p;

        /* Check a exit callback */
        if (p->cb_exit) {
            p->cb_exit(ins->context, config);
        }

        /* release properties */
        mk_list_foreach_safe(head_prop, tmp_prop, &ins->properties) {
            prop = mk_list_entry(head_prop, struct flb_config_prop, _head);

            flb_free(prop->key);
            flb_free(prop->val);

            mk_list_del(&prop->_head);
            flb_free(prop);
        }

        if (ins->match != NULL) {
            flb_free(ins->match);
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
            flb_free(ins->alias);
        }

        mk_list_del(&ins->_head);
        flb_free(ins);
    }
}

struct flb_filter_instance *flb_filter_new(struct flb_config *config,
                                           char *filter, void *data)
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

    instance = flb_malloc(sizeof(struct flb_filter_instance));
    if (!instance) {
        flb_errno();
        return NULL;
    }
    instance->config = config;

    /* Get an ID */
    id =  instance_id(plugin, config);

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
    mk_list_init(&instance->properties);
    mk_list_add(&instance->_head, &config->filters);

    return instance;
}

/* Return an instance name or alias */
char *flb_filter_name(struct flb_filter_instance *in)
{
    if (in->alias) {
        return in->alias;
    }

    return in->name;
}

/* Initialize all filter plugins */
void flb_filter_initialize_all(struct flb_config *config)
{
    int ret;
    char *name;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *tmp_prop;
    struct mk_list *head_prop;
    struct flb_config_prop *prop;
    struct flb_filter_plugin *p;
    struct flb_filter_instance *in;

    /* Iterate all active filter instance plugins */
    mk_list_foreach_safe(head, tmp, &config->filters) {
        in = mk_list_entry(head, struct flb_filter_instance, _head);

        if (!in->match
#ifdef FLB_HAVE_REGEX
            && !in->match_regex
#endif
            ) {
            flb_warn("[filter] NO match rule for %s filter instance, unloading.",
                     in->name);
            mk_list_del(&in->_head);
            flb_free(in);
            continue;
        }


        p = in->p;

        /* Metrics */
#ifdef FLB_HAVE_METRICS
        /* Get name or alias for the instance */
        name = flb_filter_name(in);

        /* Create the metrics context */
        in->metrics = flb_metrics_create(name);
        if (!in->metrics) {
            flb_warn("[filter] cannot initialize metrics for %s filter, "
                     "unloading.", name);
            mk_list_del(&in->_head);
            flb_free(in);
            continue;
        }

        /* Register filter metrics */
        flb_metrics_add(FLB_METRIC_N_DROPPED, "drop_records", in->metrics);
        flb_metrics_add(FLB_METRIC_N_ADDED, "add_records", in->metrics);
#endif

        /* Initialize the input */
        if (p->cb_init) {
            ret = p->cb_init(in, config, in->data);
            if (ret != 0) {
                flb_error("Failed initialize filter %s", in->name);

                /* release properties */
                mk_list_foreach_safe(head_prop, tmp_prop, &in->properties) {
                    prop = mk_list_entry(head_prop, struct flb_config_prop, _head);
                    flb_free(prop->key);
                    flb_free(prop->val);
                    mk_list_del(&prop->_head);
                    flb_free(prop);
                }

                if (in->match != NULL) {
                    flb_free(in->match);
                }

#ifdef FLB_HAVE_REGEX
                if (in->match_regex) {
                    flb_regex_destroy(in->match_regex);
                }
#endif

#ifdef FLB_HAVE_METRICS
                flb_metrics_destroy(in->metrics);
#endif
                mk_list_del(&in->_head);
                flb_free(in);
            }
        }
    }
}

void flb_filter_set_context(struct flb_filter_instance *ins, void *context)
{
    ins->context = context;
}
