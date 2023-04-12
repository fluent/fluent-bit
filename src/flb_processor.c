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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_event.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_kv.h>

/*
 * A processor creates a chain of processing units for different telemetry data
 * types such as logs, metrics and traces.
 *
 * From a design perspective, a Processor can be run independently from inputs, outputs
 * or unit tests directly.
 */
struct flb_processor *flb_processor_create(struct flb_config *config, char *name, void *data)
{
    struct flb_processor *proc;

    proc = flb_calloc(1, sizeof(struct flb_processor));
    if (!proc) {
        flb_errno();
        return NULL;
    }
    proc->config = config;
    proc->data = data;
    proc->is_active = FLB_FALSE;

    /* lists for types */
    mk_list_init(&proc->logs);
    mk_list_init(&proc->metrics);
    mk_list_init(&proc->traces);

    return proc;
}

struct flb_processor_unit *flb_processor_unit_create(struct flb_processor *proc,
                                                     int event_type,
                                                     char *unit_name)
{
    struct mk_list *head;
    int    filter_event_type;
    struct flb_filter_plugin *f = NULL;
    struct flb_filter_instance *f_ins;
    struct flb_config *config = proc->config;
    struct flb_processor_unit *pu = NULL;
    struct flb_native_processor_plugin *native_processor;
    struct flb_native_processor_instance *native_processor_instance;

    /*
     * Looking the processor unit by using it's name and type, the first list we
     * will iterate are the common pipeline filters.
     */
    mk_list_foreach(head, &config->filter_plugins) {
        f = mk_list_entry(head, struct flb_filter_plugin, _head);

        filter_event_type = f->event_type;

        if (filter_event_type == 0) {
            filter_event_type = FLB_FILTER_LOGS;
        }

        /* skip filters which don't handle the required type */
        if ((event_type & filter_event_type) != 0) {
            if (strcmp(f->name, unit_name) == 0) {
                break;
            }
        }

        f = NULL;
    }

    /* allocate and initialize processor unit context */
    pu = flb_calloc(1, sizeof(struct flb_processor_unit));
    if (!pu) {
        flb_errno();
        return NULL;
    }
    pu->parent = proc;
    pu->event_type = event_type;
    pu->name = flb_sds_create(unit_name);
    if (!pu->name) {
        flb_free(pu);
        return NULL;
    }
    mk_list_init(&pu->unused_list);

    /* If we matched a pipeline filter, create the speacial processing unit for it */
    if (f) {
        /* create an instance of the filter */
        f_ins = flb_filter_new(config, unit_name, NULL);
        if (!f_ins) {
            flb_sds_destroy(pu->name);
            flb_free(pu);

            return NULL;
        }
        /* matching rule: just set to workaround the pipeline initializer */
        f_ins->match = flb_sds_create("*");

        /* unit type and context */
        pu->unit_type = FLB_PROCESSOR_UNIT_FILTER;
        pu->ctx = f_ins;


        /*
         * The filter was added to the linked list config->filters, since this filter
         * won't run as part of the normal pipeline, we just unlink the node.
         */
        mk_list_del(&f_ins->_head);

        /* link the filter to the unused list */
        mk_list_add(&f_ins->_head, &pu->unused_list);
    }
    else {
        pu->unit_type = FLB_PROCESSOR_UNIT_NATIVE;

        /* create an instance of the processor */
        native_processor_instance = flb_native_processor_new(config, unit_name, NULL);

        if (native_processor_instance == NULL) {
            flb_error("[processor] error creating native processor instance %s", pu->name);

            flb_free(pu);

            return NULL;
        }

        /* unit type and context */
        pu->ctx = (void *) native_processor_instance;
    }

    /* Link the processor unit to the proper list */
    if (event_type == FLB_PROCESSOR_LOGS) {
        mk_list_add(&pu->_head, &proc->logs);
    }
    else if (event_type == FLB_PROCESSOR_METRICS) {
        mk_list_add(&pu->_head, &proc->metrics);
    }
    else if (event_type == FLB_PROCESSOR_TRACES) {
        mk_list_add(&pu->_head, &proc->traces);
    }

    return pu;
}

int flb_processor_unit_set_property(struct flb_processor_unit *pu, const char *k, const char *v)
{
    if (pu->unit_type == FLB_PROCESSOR_UNIT_FILTER) {
        return flb_filter_set_property(pu->ctx, k, v);
    }

    return flb_native_processor_set_property(
            (struct flb_native_processor_instance *) pu->ctx,
            k, v);
}

void flb_processor_unit_destroy(struct flb_processor_unit *pu)
{
    struct flb_processor *proc = pu->parent;
    struct flb_config *config = proc->config;

    if (pu->unit_type == FLB_PROCESSOR_UNIT_FILTER) {
        flb_filter_instance_exit(pu->ctx, config);
        flb_filter_instance_destroy(pu->ctx);
    }
    else {
        flb_native_processor_instance_exit(
            (struct flb_native_processor_instance *) pu->ctx,
            config);

        flb_native_processor_instance_destroy(
            (struct flb_native_processor_instance *) pu->ctx);
    }

    flb_sds_destroy(pu->name);
    flb_free(pu);
}

/* Initialize a specific unit */
int flb_processor_unit_init(struct flb_processor_unit *pu)
{
    int ret = -1;
    struct flb_config;
    struct flb_processor *proc = pu->parent;

    if (pu->unit_type == FLB_PROCESSOR_UNIT_FILTER) {
        ret = flb_filter_init(proc->config, pu->ctx);
        if (ret == -1) {
            flb_error("[processor] error initializing unit filter %s", pu->name);
            return -1;
        }
    }
    else {
        ret = flb_native_processor_init(
                proc->config,
                (struct flb_native_processor_instance *) pu->ctx);

        if (ret == -1) {
            flb_error("[processor] error initializing unit native processor "
                      "%s", pu->name);

            return -1;
        }
    }

    return ret;
}

/* Initialize the processor and all the units */
int flb_processor_init(struct flb_processor *proc)
{
    int ret;
    int count = 0;
    struct mk_list *head;
    struct flb_processor_unit *pu;

    /* Go through every unit and initialize it */
    mk_list_foreach(head, &proc->logs) {
        pu = mk_list_entry(head, struct flb_processor_unit, _head);
        ret = flb_processor_unit_init(pu);
        if (ret == -1) {
            return -1;
        }
        count++;
    }

    mk_list_foreach(head, &proc->metrics) {
        pu = mk_list_entry(head, struct flb_processor_unit, _head);
        ret = flb_processor_unit_init(pu);
        if (ret == -1) {
            return -1;
        }
        count++;
    }

    mk_list_foreach(head, &proc->traces) {
        pu = mk_list_entry(head, struct flb_processor_unit, _head);
        ret = flb_processor_unit_init(pu);
        if (ret == -1) {
            return -1;
        }
        count++;
    }

    if (count > 0) {
        proc->is_active = FLB_TRUE;
    }
    return 0;
}

int flb_processor_is_active(struct flb_processor *proc)
{
    if (proc->is_active) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

/*
 * This function will run all the processor units for the given tag and data, note
 * that depending of the 'type', 'data' can reference a msgpack for logs, a CMetrics
 * context for metrics or a 'CTraces' context for traces.
 */
int flb_processor_run(struct flb_processor *proc,
                      int type,
                      const char *tag, size_t tag_len,
                      void *data, size_t data_size,
                      void **out_buf, size_t *out_size)
{
    int ret;
    void *cur_buf;
    size_t cur_size;
    void *tmp_buf;
    size_t tmp_size;
    struct mk_list *head;
    struct mk_list *list = NULL;
    struct flb_processor_unit *pu;
    struct flb_filter_instance *f_ins;
    struct flb_native_processor_instance *p_ins;

    if (type == FLB_PROCESSOR_LOGS) {
        list = &proc->logs;
    }
    else if (type == FLB_PROCESSOR_METRICS) {
        list = &proc->metrics;
    }
    else if (type == FLB_PROCESSOR_TRACES) {
        list = &proc->traces;
    }

    /* set current data buffer */
    cur_buf = data;
    cur_size = data_size;

    /* iterate list units */
    mk_list_foreach(head, list) {
        pu = mk_list_entry(head, struct flb_processor_unit, _head);

        /* run the unit */
        if (pu->unit_type == FLB_PROCESSOR_UNIT_FILTER) {
            /* get the filter context */
            f_ins = pu->ctx;

            /* run the filtering callback */
            ret = f_ins->p->cb_filter(cur_buf, cur_size,    /* msgpack buffer */
                                      tag, tag_len,         /* tag */
                                      &tmp_buf, &tmp_size,  /* output buffer */
                                      f_ins,                /* filter instance */
                                      proc->data,           /* (input/output) instance context */
                                      f_ins->context,       /* filter context */
                                      proc->config);

            /*
             * The cb_filter() function return status tells us if something changed
             * during it process. The possible values are:
             *
             * - FLB_FILTER_MODIFIED: the record was modified and the output buffer
             *                        contains the new record.
             *
             * - FLB_FILTER_NOTOUCH: the record was not modified.
             *
             */
            if (ret == FLB_FILTER_MODIFIED) {
                /*
                 * if the content has been modified and the returned size is zero, it means
                 * the whole content has been dropped, on this case we just return since
                 * no more data exists to be processed.
                 */
                if (out_size == 0) {
                    *out_buf = NULL;
                    *out_size = 0;
                    return 0;
                }

                /* release intermediate buffer */
                if (cur_buf != data) {
                    flb_free(cur_buf);

                }

                /* set new buffer */
                cur_buf = tmp_buf;
                cur_size = tmp_size;
            }
            else if (ret == FLB_FILTER_NOTOUCH) {
                /* keep original data, do nothing */
            }
        }
        else {
            /* get the processor context */
            p_ins = pu->ctx;

            ret = 0;

            /* run the process callback */
            if (type == FLB_PROCESSOR_LOGS) {
                if (p_ins->p->cb_process_logs != NULL) {
                    ret = p_ins->p->cb_process_logs(
                                        cur_buf, cur_size,    /* msgpack buffer */
                                        tag, tag_len,         /* tag */
                                        &tmp_buf, &tmp_size,  /* output buffer */
                                        p_ins,                /* filter instance */
                                        proc->data,           /* (input/output) instance context */
                                        p_ins->context,       /* filter context */
                                        proc->config);
                }
            }
            else if (type == FLB_PROCESSOR_METRICS) {
                if (p_ins->p->cb_process_metrics != NULL) {
                    ret = p_ins->p->cb_process_metrics(
                                        (struct cmt *) cur_buf, /* cmetrics context */
                                        tag, tag_len,         /* tag */
                                        &tmp_buf, &tmp_size,  /* output buffer */
                                        p_ins,                /* filter instance */
                                        proc->data,           /* (input/output) instance context */
                                        p_ins->context,       /* filter context */
                                        proc->config);
                }
            }
            else if (type == FLB_PROCESSOR_TRACES) {
                if (p_ins->p->cb_process_traces != NULL) {
                    ret = p_ins->p->cb_process_traces(
                                        (struct ctrace *) cur_buf, /* ctraces context */
                                        tag, tag_len,         /* tag */
                                        &tmp_buf, &tmp_size,  /* output buffer */
                                        p_ins,                /* filter instance */
                                        proc->data,           /* (input/output) instance context */
                                        p_ins->context,       /* filter context */
                                        proc->config);
                }
            }
        }
    }

    /* set output buffer */
    if (out_buf != NULL) {
        *out_buf = cur_buf;
    }

    if (out_size != NULL) {
        *out_size = cur_size;
    }

    return 0;
}

void flb_processor_destroy(struct flb_processor *proc)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_processor_unit *pu;

    mk_list_foreach_safe(head, tmp, &proc->logs) {
        pu = mk_list_entry(head, struct flb_processor_unit, _head);
        mk_list_del(&pu->_head);
        flb_processor_unit_destroy(pu);
    }

    mk_list_foreach_safe(head, tmp, &proc->metrics) {
        pu = mk_list_entry(head, struct flb_processor_unit, _head);
        mk_list_del(&pu->_head);
        flb_processor_unit_destroy(pu);
    }

    mk_list_foreach_safe(head, tmp, &proc->traces) {
        pu = mk_list_entry(head, struct flb_processor_unit, _head);
        mk_list_del(&pu->_head);
        flb_processor_unit_destroy(pu);
    }
    flb_free(proc);
}


static int load_from_config_format_group(struct flb_processor *proc, int type, struct cfl_variant *val)
{
    int i;
    int ret;
    char *name;
    struct cfl_variant *tmp;
    struct cfl_array *array;
    struct cfl_kvlist *kvlist;
    struct cfl_kvpair *pair = NULL;
    struct cfl_list *head;
    struct flb_processor_unit *pu;

    if (val->type != CFL_VARIANT_ARRAY) {
        return -1;
    }

    array = val->data.as_array;
    for (i = 0; i < array->entry_count; i++) {
        /* every entry in the array must be a map */
        tmp = array->entries[i];
        if (tmp->type != CFL_VARIANT_KVLIST) {
            return -1;
        }

        kvlist = tmp->data.as_kvlist;

        /* get the processor name, this is a mandatory config field */
        tmp = cfl_kvlist_fetch(kvlist, "name");
        if (!tmp) {
            flb_error("processor configuration don't have a 'name' defined");
            return -1;
        }

        /* create the processor unit and load all the properties */
        name = tmp->data.as_string;
        pu = flb_processor_unit_create(proc, type, name);
        if (!pu) {
            flb_error("cannot create '%s' processor unit", name);
            return -1;
        }

        /* iterate list of properties and set each one (skip name) */
        cfl_list_foreach(head, &kvlist->list) {
            pair = cfl_list_entry(head, struct cfl_kvpair, _head);
            if (strcmp(pair->key, "name") == 0) {
                continue;
            }

            if (pair->val->type != CFL_VARIANT_STRING) {
                continue;
            }

            ret = flb_processor_unit_set_property(pu, pair->key, pair->val->data.as_string);
            if (ret == -1) {
                flb_error("cannot set property '%s' for processor '%s'", pair->key, name);
                return -1;
            }
        }
    }

    return 0;

}

/* Load processors into an input instance */
int flb_processors_load_from_config_format_group(struct flb_processor *proc, struct flb_cf_group *g)
{
    int ret;
    struct cfl_variant *val;

    /* logs */
    val = cfl_kvlist_fetch(g->properties, "logs");
    if (val) {
        ret = load_from_config_format_group(proc, FLB_PROCESSOR_LOGS, val);
        if (ret == -1) {
            flb_error("failed to load 'logs' processors");
            return -1;
        }
    }

    /* metrics */
    val = cfl_kvlist_fetch(g->properties, "metrics");
    if (val) {
        ret = load_from_config_format_group(proc, FLB_PROCESSOR_METRICS, val);
        if (ret == -1) {
            flb_error("failed to load 'metrics' processors");
            return -1;
        }
    }

    /* traces */
    val = cfl_kvlist_fetch(g->properties, "traces");
    if (val) {
        ret = load_from_config_format_group(proc, FLB_PROCESSOR_TRACES, val);
        if (ret == -1) {
            flb_error("failed to load 'traces' processors");
            return -1;
        }
    }

    /* initialize processors */
    ret = flb_processor_init(proc);
    if (ret == -1) {
        return -1;
    }

    return 0;
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


int flb_native_processor_set_property(struct flb_native_processor_instance *ins,
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

    if (prop_key_check("alias", k, len) == 0 && tmp) {
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


const char *flb_native_processor_get_property(
                const char *key,
                struct flb_native_processor_instance *ins)
{
    return flb_kv_get_key_value(key, &ins->properties);
}

struct flb_native_processor_instance *flb_native_processor_new(
                                        struct flb_config *config,
                                        const char *name, void *data)
{
    struct flb_native_processor_instance *instance;
    struct flb_native_processor_plugin   *plugin;
    struct mk_list                       *head;
    int                                   id;

    if (name == NULL) {
        return NULL;
    }

    mk_list_foreach(head, &config->native_processor_plugins) {
        plugin = mk_list_entry(head, struct flb_native_processor_plugin, _head);
        if (strcasecmp(plugin->name, name) == 0) {
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
        instance->event_type = FLB_PROCESSOR_LOGS;
    }
    else {
        instance->event_type = plugin->event_type;
    }

    /* Get an ID */
    id =  0;

    /* format name (with instance id) */
    snprintf(instance->name, sizeof(instance->name) - 1,
             "%s.%i", plugin->name, id);

    instance->id    = id;
    instance->alias = NULL;
    instance->p     = plugin;
    instance->data  = data;
    instance->log_level = -1;

    mk_list_init(&instance->properties);

    return instance;
}

void flb_native_processor_instance_exit(
        struct flb_native_processor_instance *ins,
        struct flb_config *config)
{
    struct flb_native_processor_plugin *plugin;

    plugin = ins->p;
    if (plugin->cb_exit != NULL &&
        ins->context != NULL) {
        plugin->cb_exit(ins->context, config);
    }
}

const char *flb_native_processor_name(struct flb_native_processor_instance *ins)
{
    if (ins->alias) {
        return ins->alias;
    }

    return ins->name;
}

int flb_native_processor_plugin_property_check(
        struct flb_native_processor_instance *ins,
        struct flb_config *config)
{
    int ret = 0;
    struct mk_list *config_map;
    struct flb_native_processor_plugin *p = ins->p;

    if (p->config_map) {
        /*
         * Create a dynamic version of the configmap that will be used by the specific
         * instance in question.
         */
        config_map = flb_config_map_create(config, p->config_map);
        if (!config_map) {
            flb_error("[native processor] error loading config map for '%s' plugin",
                      p->name);
            return -1;
        }
        ins->config_map = config_map;

        /* Validate incoming properties against config map */
        ret = flb_config_map_properties_check(ins->p->name,
                                              &ins->properties,
                                              ins->config_map);
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

int flb_native_processor_init(
        struct flb_config *config,
        struct flb_native_processor_instance *ins)
{
    int ret;
    uint64_t ts;
    char *name;
    struct flb_native_processor_plugin *p;

    if (ins->log_level == -1 &&
        config->log != NULL) {
        ins->log_level = config->log->level;
    }

    p = ins->p;

    /* Get name or alias for the instance */
    name = (char *) flb_native_processor_name(ins);
    ts = cfl_time_now();

    /* CMetrics */
    ins->cmt = cmt_create();
    if (!ins->cmt) {
        flb_error("[filter] could not create cmetrics context: %s",
                  flb_filter_name(ins));
        return -1;
    }

    /*
     * Before to call the initialization callback, make sure that the received
     * configuration parameters are valid if the plugin is registering a config map.
     */
    if (flb_filter_plugin_property_check(ins, config) == -1) {
        return -1;
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


// int flb_native_processor_init_all(struct flb_config *config);
void flb_native_processor_set_context(
        struct flb_native_processor_instance *ins,
        void *context)
{
    ins->context = context;
}

void flb_native_processor_instance_destroy(
        struct flb_native_processor_instance *ins)
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

    /* Remove metrics */
#ifdef FLB_HAVE_METRICS
    if (ins->cmt) {
        cmt_destroy(ins->cmt);
    }
#endif

    if (ins->alias) {
        flb_sds_destroy(ins->alias);
    }

    // mk_list_del(&ins->_head);
    flb_free(ins);
}











