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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_event.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_conditionals.h>
#include <cfl/cfl.h>

struct flb_config_map processor_global_properties[] = {
    {
        FLB_CONFIG_MAP_STR, "alias", NULL,
        0, FLB_FALSE, 0,
        "Sets an alias for the processor instance. This is useful when using multiple instances of the same "
        "processor plugin. If no alias is set, the instance will be named using the plugin name and a sequence number."
    },
    {
        FLB_CONFIG_MAP_STR, "log_level", "info",
        0, FLB_FALSE, 0,
        "Specifies the log level for this processor plugin. If not set, the plugin "
        "will use the global log level defined in the 'service' section. If the global "
        "log level is also not specified, it defaults to 'info'."
    },

    {0}
};

struct mk_list *flb_processor_get_global_config_map(struct flb_config *config)
{
    return flb_config_map_create(config, processor_global_properties);
}


static int acquire_lock(pthread_mutex_t *lock,
                        size_t retry_limit,
                        size_t retry_delay)
{
    size_t retry_count;
    int    result;

    retry_count = 0;

    do {
        result = pthread_mutex_lock(lock);

        if (result != 0) {

            if (result == EAGAIN) {
                retry_count++;

                usleep(retry_delay);
            }
            else {
                break;
            }
        }
    }
    while (result != 0 &&
           retry_count < retry_limit);

    if (result != 0) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int release_lock(pthread_mutex_t *lock,
                        size_t retry_limit,
                        size_t retry_delay)
{
    size_t retry_count;
    int    result;

    retry_count = 0;

    do {
        result = pthread_mutex_unlock(lock);

        if (result != 0) {

            if (result == EAGAIN) {
                retry_count++;

                usleep(retry_delay);
            }
            else {
                break;
            }
        }
    }
    while (result != 0 &&
           retry_count < retry_limit);

    if (result != 0) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

/*
 * A processor creates a chain of processing units for different telemetry data
 * types such as logs, metrics, traces and profiles.
 *
 * From a design perspective, a Processor can be run independently from inputs, outputs
 * or unit tests directly.
 */
struct flb_processor *flb_processor_create(struct flb_config *config,
                                           char *name,
                                           void *source_plugin_instance,
                                           int source_plugin_type)
{
    struct flb_processor *proc;

    proc = flb_calloc(1, sizeof(struct flb_processor));

    if (!proc) {
        flb_errno();
        return NULL;
    }

    proc->config = config;
    proc->is_active = FLB_FALSE;
    proc->data = source_plugin_instance;
    proc->source_plugin_type = source_plugin_type;

    /* lists for types */
    mk_list_init(&proc->logs);
    mk_list_init(&proc->metrics);
    mk_list_init(&proc->traces);
    mk_list_init(&proc->profiles);

    return proc;
}

struct flb_processor_unit *flb_processor_unit_create(struct flb_processor *proc,
                                                     int event_type,
                                                     const char *unit_name)
{
    int result;
    struct mk_list *head;
    int    filter_event_type;
    struct flb_filter_plugin *f = NULL;
    struct flb_filter_instance *f_ins;
    struct flb_config *config = proc->config;
    struct flb_processor_unit *pu = NULL;
    struct flb_processor_instance *processor_instance;

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
    pu->condition = NULL;

    if (!pu->name) {
        flb_free(pu);
        return NULL;
    }
    mk_list_init(&pu->unused_list);

    result = pthread_mutex_init(&pu->lock, NULL);

    if (result != 0) {
        flb_sds_destroy(pu->name);
        flb_free(pu);

        return NULL;
    }

    /* If we matched a pipeline filter, create the speacial processing unit for it */
    if (f) {
        /* create an instance of the filter */
        f_ins = flb_filter_new(config, unit_name, NULL);

        if (!f_ins) {
            pthread_mutex_destroy(&pu->lock);
            flb_sds_destroy(pu->name);
            flb_free(pu);

            return NULL;
        }

        f_ins->parent_processor = (void *) pu;

        /* matching rule: just set to workaround the pipeline initializer */
        f_ins->match = flb_sds_create("*");

        if (f_ins->match == NULL) {
            flb_filter_instance_destroy(f_ins);

            pthread_mutex_destroy(&pu->lock);
            flb_sds_destroy(pu->name);
            flb_free(pu);

            return NULL;
        }

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
        processor_instance = flb_processor_instance_create(config,
                                                           pu,
                                                           pu->event_type,
                                                           unit_name, NULL);

        if (processor_instance == NULL) {
            flb_error("[processor] error creating processor '%s': plugin doesn't exist or failed to initialize", unit_name);

            pthread_mutex_destroy(&pu->lock);
            flb_sds_destroy(pu->name);
            flb_free(pu);

            return NULL;
        }

        /* unit type and context */
        pu->ctx = (void *) processor_instance;
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
    else if (event_type == FLB_PROCESSOR_PROFILES) {
        mk_list_add(&pu->_head, &proc->profiles);
    }

    pu->stage = proc->stage_count;
    proc->stage_count++;

    return pu;
}

/* Parse and set a condition property for a processor unit */
static int flb_processor_unit_set_condition(struct flb_processor_unit *pu, struct cfl_variant *v)
{
    struct cfl_variant *val;
    struct cfl_variant *rule_val;
    struct cfl_kvlist *kvlist;
    struct flb_condition *condition;
    enum flb_rule_operator rule_op;
    enum flb_condition_operator cond_op;
    const char *field;
    const char *operator;
    void *value = NULL;
    int value_count;
    enum record_context_type context;
    int i;
    int j;
    int ret;
    struct cfl_variant *array_val;
    int is_array_value = 0;

    flb_debug("[processor] processing condition property for processor unit '%s'", pu->name);

    /* Conditions must be specified as key-value maps */
    if (v->type != CFL_VARIANT_KVLIST) {
        flb_error("[processor] condition must be a map");
        return -1;
    }

    kvlist = v->data.as_kvlist;

    /* First check for operator (AND/OR) */
    val = cfl_kvlist_fetch(kvlist, "op");
    if (val != NULL && val->type == CFL_VARIANT_STRING) {
        if (strcasecmp(val->data.as_string, "and") == 0) {
            cond_op = FLB_COND_OP_AND;
        }
        else if (strcasecmp(val->data.as_string, "or") == 0) {
            cond_op = FLB_COND_OP_OR;
        }
        else {
            flb_error("[processor] invalid condition operator '%s', must be 'and' or 'or'",
                        val->data.as_string);
            return -1;
        }
    }
    else {
        /* Default to AND if not specified */
        cond_op = FLB_COND_OP_AND;
    }

    /* Create a condition with the specified operator */
    condition = flb_condition_create(cond_op);
    if (!condition) {
        flb_error("[processor] error creating condition");
        return -1;
    }

    /* Look for the rules array */
    val = cfl_kvlist_fetch(kvlist, "rules");
    if (!val || val->type != CFL_VARIANT_ARRAY || val->data.as_array->entry_count == 0) {
        flb_error("[processor] condition requires a non-empty 'rules' array");
        flb_condition_destroy(condition);
        return -1;
    }

    /* Process each rule in the array */
    flb_debug("[processor] processing %zu rule(s) for condition", val->data.as_array->entry_count);
    for (i = 0; i < val->data.as_array->entry_count; i++) {
        rule_val = val->data.as_array->entries[i];

        if (rule_val->type != CFL_VARIANT_KVLIST) {
            flb_error("[processor] each rule must be a map");
            flb_condition_destroy(condition);
            return -1;
        }

        flb_debug("[processor] processing rule #%d", i+1);

        kvlist = rule_val->data.as_kvlist;

        /* Extract field */
        rule_val = cfl_kvlist_fetch(kvlist, "field");
        if (!rule_val || rule_val->type != CFL_VARIANT_STRING) {
            flb_error("[processor] rule missing 'field' property");
            flb_condition_destroy(condition);
            return -1;
        }
        field = rule_val->data.as_string;
        flb_debug("[processor] condition rule field: '%s'", field);

        /* Extract operator */
        rule_val = cfl_kvlist_fetch(kvlist, "op");
        if (!rule_val || rule_val->type != CFL_VARIANT_STRING) {
            flb_error("[processor] rule missing 'op' property");
            flb_condition_destroy(condition);
            return -1;
        }
        operator = rule_val->data.as_string;
        flb_debug("[processor] condition rule operator: '%s'", operator);

        /* Determine rule operator */
        if (strcasecmp(operator, "eq") == 0) {
            rule_op = FLB_RULE_OP_EQ;
        }
        else if (strcasecmp(operator, "neq") == 0) {
            rule_op = FLB_RULE_OP_NEQ;
        }
        else if (strcasecmp(operator, "gt") == 0) {
            rule_op = FLB_RULE_OP_GT;
        }
        else if (strcasecmp(operator, "lt") == 0) {
            rule_op = FLB_RULE_OP_LT;
        }
        else if (strcasecmp(operator, "gte") == 0) {
            rule_op = FLB_RULE_OP_GTE;
        }
        else if (strcasecmp(operator, "lte") == 0) {
            rule_op = FLB_RULE_OP_LTE;
        }
        else if (strcasecmp(operator, "regex") == 0) {
            rule_op = FLB_RULE_OP_REGEX;
        }
        else if (strcasecmp(operator, "not_regex") == 0) {
            rule_op = FLB_RULE_OP_NOT_REGEX;
        }
        else if (strcasecmp(operator, "in") == 0) {
            rule_op = FLB_RULE_OP_IN;
        }
        else if (strcasecmp(operator, "not_in") == 0) {
            rule_op = FLB_RULE_OP_NOT_IN;
        }
        else {
            flb_error("[processor] invalid rule operator '%s'", operator);
            flb_condition_destroy(condition);
            return -1;
        }

        /* Extract value */
        rule_val = cfl_kvlist_fetch(kvlist, "value");
        if (!rule_val) {
            flb_error("[processor] rule missing 'value' property");
            flb_condition_destroy(condition);
            return -1;
        }

        /* Handle different value types */
        value = NULL;
        value_count = 1;

        /* Check that IN and NOT_IN operators only work with array values */
        if ((rule_op == FLB_RULE_OP_IN || rule_op == FLB_RULE_OP_NOT_IN) &&
            rule_val->type != CFL_VARIANT_ARRAY) {
            flb_error("[processor] 'in' and 'not_in' operators require array values, got %d type instead",
                    rule_val->type);
            flb_condition_destroy(condition);
            return -1;
        }

        if (rule_val->type == CFL_VARIANT_STRING) {
            value = rule_val->data.as_string;
            flb_debug("[processor] condition rule value (string): %s",
                        (char *)value);
        }
        else if (rule_val->type == CFL_VARIANT_INT) {
            value = &rule_val->data.as_int64;
            flb_debug("[processor] condition rule value (int): %lld",
                    rule_val->data.as_int64);
        }
        else if (rule_val->type == CFL_VARIANT_UINT) {
            value = &rule_val->data.as_uint64;
            flb_debug("[processor] condition rule value (uint): %lu",
                    (unsigned long)rule_val->data.as_uint64);
        }
        else if (rule_val->type == CFL_VARIANT_DOUBLE) {
            value = &rule_val->data.as_double;
            flb_debug("[processor] condition rule value (double): %f",
                    rule_val->data.as_double);
        }
        else if (rule_val->type == CFL_VARIANT_ARRAY) {
            /* For IN and NOT_IN operators, we need to handle arrays */
            if (rule_op != FLB_RULE_OP_IN && rule_op != FLB_RULE_OP_NOT_IN) {
                flb_error("[processor] array values can only be used with 'in' or 'not_in' operators");
                flb_condition_destroy(condition);
                return -1;
            }

            /* Extract all string values from the array */
            value = flb_calloc(rule_val->data.as_array->entry_count, sizeof(flb_sds_t));
            if (!value) {
                flb_errno();
                flb_condition_destroy(condition);
                return -1;
            }

            /* Mark that we've allocated an array value */
            is_array_value = 1;

            for (j = 0; j < rule_val->data.as_array->entry_count; j++) {
                array_val = rule_val->data.as_array->entries[j];
                if (array_val->type != CFL_VARIANT_STRING) {
                    flb_error("[processor] array values must be strings");
                    flb_free(value);
                    flb_condition_destroy(condition);
                    return -1;
                }

                ((flb_sds_t *)value)[j] = flb_sds_create(array_val->data.as_string);
            }

            value_count = rule_val->data.as_array->entry_count;
        }
        else {
            flb_error("[processor] unsupported value type for rule");
            flb_condition_destroy(condition);
            return -1;
        }

        /* Determine context (body or metadata) */
        rule_val = cfl_kvlist_fetch(kvlist, "context");
        if (rule_val && rule_val->type == CFL_VARIANT_STRING) {
            if (strcasecmp(rule_val->data.as_string, "metadata") == 0) {
                context = RECORD_CONTEXT_METADATA;
            }
            else {
                context = RECORD_CONTEXT_BODY;
            }
        }
        else {
            /* Default to body context */
            context = RECORD_CONTEXT_BODY;
        }

        flb_debug("[processor] adding rule: field='%s', op=%d, context=%d",
                field, rule_op, context);

        /* Add rule to the condition */
        ret = flb_condition_add_rule(condition, field, rule_op, value, value_count, context);

        /*
         * Free array value if we allocated it. For 'in' and 'not_in' operators,
         * flb_condition_add_rule makes its own copy of the strings in the array,
         * so we need to free our copies whether or not the rule was added successfully.
         */
        if (is_array_value) {
            for (j = 0; j < value_count; j++) {
                flb_sds_destroy(((flb_sds_t *)value)[j]);
            }
            flb_free(value);
            is_array_value = 0;
        }

        if (ret != FLB_TRUE) {
            flb_error("[processor] error adding rule to condition (ret=%d)", ret);
            flb_condition_destroy(condition);
            return -1;
        }
        else {
            flb_debug("[processor] successfully added rule to condition");
        }
    }

    /* Assign the created condition to the processor unit */
    if (pu->condition != NULL) {
        flb_condition_destroy(pu->condition);
    }
    pu->condition = condition;

    return 0;
}

int flb_processor_unit_set_property(struct flb_processor_unit *pu, const char *k, struct cfl_variant *v)
{
    struct cfl_variant *val;
    int i;
    int ret;

    /* Handle the "condition" property for processor units */
    if (strcasecmp(k, "condition") == 0) {
        return flb_processor_unit_set_condition(pu, v);
    }

    /* Handle normal properties */
    if (pu->unit_type == FLB_PROCESSOR_UNIT_FILTER) {
        if (v->type == CFL_VARIANT_STRING) {
            return flb_filter_set_property(pu->ctx, k, v->data.as_string);
        }
        else if (v->type == CFL_VARIANT_ARRAY) {
            for (i = 0; i < v->data.as_array->entry_count; i++) {
                val = v->data.as_array->entries[i];
                ret = flb_filter_set_property(pu->ctx, k, val->data.as_string);

                if (ret == -1) {
                    return ret;
                }
            }
            return 0;
        }
    }

    return flb_processor_instance_set_property(
            (struct flb_processor_instance *) pu->ctx,
            k, v);
}

int flb_processor_unit_set_property_str(struct flb_processor_unit *pu, const char *k, const char *v)
{
    int ret;
    struct cfl_variant *val;

    if (!pu || !k || !v) {
        return -1;
    }

    val = cfl_variant_create_from_string((char *) v);
    if (!val) {
        return -1;
    }

    ret = flb_processor_unit_set_property(pu, k, val);
    cfl_variant_destroy(val);

    return ret;
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
        flb_processor_instance_exit(
            (struct flb_processor_instance *) pu->ctx,
            config);

        flb_processor_instance_destroy(
            (struct flb_processor_instance *) pu->ctx);
    }

    pthread_mutex_destroy(&pu->lock);

    /* Free the condition if it exists */
    if (pu->condition) {
        flb_condition_destroy(pu->condition);
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

        ((struct flb_filter_instance *) pu->ctx)->notification_channel = \
            proc->notification_channel;
    }
    else {
        ret = flb_processor_instance_init(
                (struct flb_processor_instance *) pu->ctx,
                proc->data,
                0,
                proc->config);

        if (ret == -1) {
            flb_error("[processor] error initializing unit native processor "
                      "%s", pu->name);

            return -1;
        }

        ((struct flb_processor_instance *) pu->ctx)->notification_channel = \
            proc->notification_channel;
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
            flb_error("[processor] initialization of processor unit '%s' failed", pu->name);
            return -1;
        }
        count++;
    }

    mk_list_foreach(head, &proc->metrics) {
        pu = mk_list_entry(head, struct flb_processor_unit, _head);
        ret = flb_processor_unit_init(pu);

        if (ret == -1) {
            flb_error("[processor] initialization of processor unit '%s' failed", pu->name);
            return -1;
        }
        count++;
    }

    mk_list_foreach(head, &proc->traces) {
        pu = mk_list_entry(head, struct flb_processor_unit, _head);
        ret = flb_processor_unit_init(pu);

        if (ret == -1) {
            flb_error("[processor] initialization of processor unit '%s' failed", pu->name);
            return -1;
        }
        count++;
    }

    mk_list_foreach(head, &proc->profiles) {
        pu = mk_list_entry(head, struct flb_processor_unit, _head);
        ret = flb_processor_unit_init(pu);

        if (ret == -1) {
            flb_error("[processor] initialization of processor unit '%s' failed", pu->name);
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

#include <fluent-bit/flb_pack.h>

/*
 * This function will run all the processor units for the given tag and data, note
 * that depending of the 'type', 'data' can reference a msgpack for logs, a CMetrics
 * context for metrics, a 'CTraces' context for traces or a 'CProfiles' context for
 * profiles.
 */
int flb_processor_run(struct flb_processor *proc,
                      size_t starting_stage,
                      int type,
                      const char *tag, size_t tag_len,
                      void *data, size_t data_size,
                      void **out_buf, size_t *out_size)
{
    int ret;
    int finalize;
    void *cur_buf = NULL;
    size_t cur_size;
    void *tmp_buf = NULL;
    size_t tmp_size;
    struct mk_list *head;
    struct mk_list *list = NULL;
    struct flb_processor_unit *pu;
    struct flb_processor_unit *pu_next;
    struct flb_filter_instance *f_ins;
    struct flb_processor_instance *p_ins;
    struct flb_mp_chunk_cobj *chunk_cobj = NULL;
#ifdef FLB_HAVE_METRICS
    int in_records = 0;
    int out_records = 0;
    int diff = 0;
    uint64_t ts;
    char *name;
#endif

    if (type == FLB_PROCESSOR_LOGS) {
        list = &proc->logs;
    }
    else if (type == FLB_PROCESSOR_METRICS) {
        list = &proc->metrics;
    }
    else if (type == FLB_PROCESSOR_TRACES) {
        list = &proc->traces;
    }
    else if (type == FLB_PROCESSOR_PROFILES) {
        list = &proc->profiles;
    }

#ifdef FLB_HAVE_METRICS
    /* timestamp */
    ts = cfl_time_now();
#endif

    /* set current data buffer */
    cur_buf = data;
    cur_size = data_size;

    /* iterate list units */
    mk_list_foreach(head, list) {
        pu = mk_list_entry(head, struct flb_processor_unit, _head);

        /* This is meant to be used when filters or processors re-inject
         * records in the pipeline. This way we can ensure that they will
         * continue the process at the right stage.
         */
        if (pu->stage < starting_stage) {
            continue;
        }

        tmp_buf = NULL;
        tmp_size = 0;

        ret = acquire_lock(&pu->lock,
                           FLB_PROCESSOR_LOCK_RETRY_LIMIT,
                           FLB_PROCESSOR_LOCK_RETRY_DELAY);

        if (ret != FLB_TRUE) {
            return -1;
        }

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
#ifdef FLB_HAVE_METRICS
            name = (char *) (flb_filter_name(f_ins));
            in_records = flb_mp_count(cur_buf, cur_size);
            cmt_counter_add(f_ins->cmt_records, ts, in_records,
                    1, (char *[]) {name});
            cmt_counter_add(f_ins->cmt_bytes, ts, tmp_size,
                    1, (char *[]) {name});

            flb_metrics_sum(FLB_METRIC_N_RECORDS, in_records, f_ins->metrics);
            flb_metrics_sum(FLB_METRIC_N_BYTES, tmp_size, f_ins->metrics);
#endif
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

                /* release intermediate buffer */
                if (cur_buf != data) {
                    flb_free(cur_buf);
                }

                /*
                 * if the content has been modified and the returned size is zero, it means
                 * the whole content has been dropped, on this case we just return since
                 * no more data exists to be processed.
                 */
                if (tmp_size == 0) {
                    *out_buf = NULL;
                    *out_size = 0;

#ifdef FLB_HAVE_METRICS
                    /* cmetrics */
                    cmt_counter_add(f_ins->cmt_drop_records, ts, in_records,
                                    1, (char *[]) {name});

                    /* [OLD] Summarize all records removed */
                    flb_metrics_sum(FLB_METRIC_N_DROPPED,
                                    in_records, f_ins->metrics);
#endif
                    release_lock(&pu->lock,
                                 FLB_PROCESSOR_LOCK_RETRY_LIMIT,
                                 FLB_PROCESSOR_LOCK_RETRY_DELAY);

                    return 0;
                }

                /* set new buffer */
                cur_buf = tmp_buf;
                cur_size = tmp_size;
                out_records = flb_mp_count(tmp_buf, tmp_size);
#ifdef FLB_HAVE_METRICS
                    if (out_records > in_records) {
                        diff = (out_records - in_records);

                        /* cmetrics */
                        cmt_counter_add(f_ins->cmt_add_records, ts, diff,
                                    1, (char *[]) {name});

                        /* [OLD] Summarize new records */
                        flb_metrics_sum(FLB_METRIC_N_ADDED,
                                        diff, f_ins->metrics);
                    }
                    else if (out_records < in_records) {
                        diff = (in_records - out_records);

                        /* cmetrics */
                        cmt_counter_add(f_ins->cmt_drop_records, ts, diff,
                                    1, (char *[]) {name});

                        /* [OLD] Summarize dropped records */
                        flb_metrics_sum(FLB_METRIC_N_DROPPED,
                                        diff, f_ins->metrics);
                    }
#endif

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

                    /* if no previous chunkj_cobj exist, create instance. Note that this context will last
                     * until no more processors exists or the next one is a "filter" type processor.
                     */
                    if (!chunk_cobj) {
                        flb_log_event_decoder_reset(p_ins->log_decoder, cur_buf, cur_size);

                        /* create the context */
                        chunk_cobj = flb_mp_chunk_cobj_create(p_ins->log_encoder, p_ins->log_decoder);
                        if (chunk_cobj == NULL) {
                            flb_log_event_decoder_reset(p_ins->log_decoder, NULL, 0);
                            if (cur_buf != data) {
                                flb_free(cur_buf);
                            }

                            release_lock(&pu->lock,
                                        FLB_PROCESSOR_LOCK_RETRY_LIMIT,
                                        FLB_PROCESSOR_LOCK_RETRY_DELAY);

                            return -1;
                        }
                    }

                    /* Set the processor condition if it exists */
                    if (pu->condition) {
                        flb_debug("[processor] setting condition for chunk processing (pu=%s)", pu->name);
                        chunk_cobj->condition = pu->condition;
                    }
                    else {
                        flb_debug("[processor] no condition set for processor unit (pu=%s)", pu->name);
                    }

                    /* Invoke processor plugin callback */
                    ret = p_ins->p->cb_process_logs(p_ins, chunk_cobj, tag, tag_len);
                    if (ret != FLB_PROCESSOR_SUCCESS) {
                        flb_warn("[processor] failed to process chunk");
                    }
                    chunk_cobj->record_pos = NULL;

                    /* Clear the condition after processing */
                    chunk_cobj->condition = NULL;
                    finalize = FLB_FALSE;

                    /* is this processing_unit the last one from the list ? */
                    if (head->next == list ) {
                        finalize = FLB_TRUE;
                    }
                    else {
                        pu_next = mk_list_entry(head->next, struct flb_processor_unit, _head);
                        if (pu_next->unit_type == FLB_PROCESSOR_UNIT_FILTER) {
                            /*
                             * The next iterationm requires a raw msgpack buffer, let's do the
                             * encoding.
                             */
                            finalize = FLB_TRUE;
                        }
                    }

                    if (finalize == FLB_TRUE) {
                        if (cfl_list_size(&chunk_cobj->records) == 0) {
                            flb_log_event_encoder_reset(p_ins->log_encoder);
                            flb_mp_chunk_cobj_destroy(chunk_cobj);

                            *out_buf = NULL;
                            *out_size = 0;

                            release_lock(&pu->lock,
                                        FLB_PROCESSOR_LOCK_RETRY_LIMIT,
                                        FLB_PROCESSOR_LOCK_RETRY_DELAY);
                            return 0;
                        }

                        /* encode chunk_cobj as msgpack */
                        ret = flb_mp_chunk_cobj_encode(chunk_cobj, (char **) &tmp_buf, &tmp_size);
                        if (ret != 0) {
                            flb_log_event_decoder_reset(p_ins->log_decoder, NULL, 0);

                            if (cur_buf != data) {
                                flb_free(cur_buf);
                            }

                            release_lock(&pu->lock,
                                        FLB_PROCESSOR_LOCK_RETRY_LIMIT,
                                        FLB_PROCESSOR_LOCK_RETRY_DELAY);

                            return -1;
                        }

                        if (cur_buf != data) {
                            flb_free(cur_buf);
                        }

                        cur_buf = tmp_buf;
                        cur_size = tmp_size;


                        flb_log_event_decoder_reset(p_ins->log_decoder, NULL, 0);
                        flb_log_event_encoder_claim_internal_buffer_ownership(p_ins->log_encoder);
                        flb_mp_chunk_cobj_destroy(chunk_cobj);
                        chunk_cobj = NULL;
                    }
                }
            }
            else if (type == FLB_PROCESSOR_METRICS) {

                if (p_ins->p->cb_process_metrics != NULL) {
                    ret = p_ins->p->cb_process_metrics(p_ins,
                                                       (struct cmt *) cur_buf,
                                                       (struct cmt **) &tmp_buf,
                                                       tag,
                                                       tag_len);

                    if (ret != FLB_PROCESSOR_SUCCESS) {
                        release_lock(&pu->lock,
                                     FLB_PROCESSOR_LOCK_RETRY_LIMIT,
                                     FLB_PROCESSOR_LOCK_RETRY_DELAY);

                        out_buf = NULL;

                        return -1;
                    }

                    if (cur_buf != data && cur_buf != tmp_buf) {
                        cmt_destroy(cur_buf);
                    }

                    if (tmp_buf != NULL) {
                        cur_buf = tmp_buf;
                    }
                }
            }
            else if (type == FLB_PROCESSOR_TRACES) {
                if (p_ins->p->cb_process_traces != NULL) {
                    tmp_buf = NULL;
                    out_size = NULL;
                    ret = p_ins->p->cb_process_traces(p_ins,
                                                      (struct ctrace *) cur_buf,
                                                      (struct ctrace **) &tmp_buf,
                                                      tag,
                                                      tag_len);
                    if (ret == FLB_PROCESSOR_FAILURE) {
                        release_lock(&pu->lock,
                                     FLB_PROCESSOR_LOCK_RETRY_LIMIT,
                                     FLB_PROCESSOR_LOCK_RETRY_DELAY);

                        return -1;
                    }
                    else if (ret == FLB_PROCESSOR_SUCCESS) {
                        if (tmp_buf == NULL) {
                            /*
                             * the processsor ran successfuly but there is no
                             * trace output, that means that the invoked processor
                             * will enqueue the trace through a different mechanism,
                             * we just return saying nothing else is needed.
                             */
                            release_lock(&pu->lock,
                                         FLB_PROCESSOR_LOCK_RETRY_LIMIT,
                                         FLB_PROCESSOR_LOCK_RETRY_DELAY);
                            return 0;
                        }
                    }

                }
            }
            else if (type == FLB_PROCESSOR_PROFILES) {
                if (p_ins->p->cb_process_profiles != NULL) {
                    ret = p_ins->p->cb_process_profiles(p_ins,
                                                        (struct cprof *) cur_buf,
                                                        tag,
                                                        tag_len);

                    if (ret != FLB_PROCESSOR_SUCCESS) {
                        release_lock(&pu->lock,
                                     FLB_PROCESSOR_LOCK_RETRY_LIMIT,
                                     FLB_PROCESSOR_LOCK_RETRY_DELAY);

                        return -1;
                    }
                }
            }
        }

        release_lock(&pu->lock,
                     FLB_PROCESSOR_LOCK_RETRY_LIMIT,
                     FLB_PROCESSOR_LOCK_RETRY_DELAY);
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

    mk_list_foreach_safe(head, tmp, &proc->profiles) {
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
    struct cfl_list *tmp2;
    struct flb_processor_unit *pu;
    struct flb_filter_instance *f_ins;

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
            flb_error("[processor] configuration missing required 'name' field");
            return -1;
        }

        /* create the processor unit and load all the properties */
        name = tmp->data.as_string;
        pu = flb_processor_unit_create(proc, type, name);

        if (!pu) {
            return -1;
        }

        /* Handle condition property first if it exists */
        tmp = cfl_kvlist_fetch(kvlist, "condition");
        if (tmp) {
            ret = flb_processor_unit_set_property(pu, "condition", tmp);
            if (ret == -1) {
                flb_error("[processor] failed to set condition for processor '%s'", name);
                return -1;
            }
        }

        /* iterate list of properties and set each one (skip name and condition) */
        cfl_list_foreach_safe(head, tmp2, &kvlist->list) {
            pair = cfl_list_entry(head, struct cfl_kvpair, _head);

            if (strcmp(pair->key, "name") == 0 ||
                strcmp(pair->key, "condition") == 0) {
                continue;
            }

            /* If filter plugin in processor unit has its own match rule,
             * we must release the pre-allocated '*' match at first.
             */
            if (pu->unit_type == FLB_PROCESSOR_UNIT_FILTER) {

                if (strcmp(pair->key, "match") == 0) {
                    f_ins = (struct flb_filter_instance *)pu->ctx;

                    if (f_ins->match != NULL) {
                        flb_sds_destroy(f_ins->match);
                        f_ins->match = NULL;
                    }
                }
            }

            ret = flb_processor_unit_set_property(pu, pair->key, pair->val);

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

    /* profiles */
    val = cfl_kvlist_fetch(g->properties, "profiles");
    if (val) {
        ret = load_from_config_format_group(proc, FLB_PROCESSOR_PROFILES, val);

        if (ret == -1) {
            flb_error("failed to load 'profiles' processors");
            return -1;
        }
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

int flb_processor_instance_set_property(struct flb_processor_instance *ins,
                                        const char *k, struct cfl_variant *v)
{
    int len;
    int ret;
    struct flb_kv *kv;
    cfl_sds_t tmp = NULL;

    len = strlen(k);

    /* Special handling for condition property */
    if (prop_key_check("condition", k, len) == 0) {
        /* When condition is passed to a processor instance, forward it to the parent processor unit */
        if (ins->pu) {
            ret = flb_processor_unit_set_property(ins->pu, k, v);
            if (ret == -1) {
                flb_error("[processor] error setting condition for processor unit");
                return -1;
            }
            return 0;
        }
    }

    if (v->type == CFL_VARIANT_STRING) {
        tmp = flb_env_var_translate(ins->config->env, v->data.as_string);

        if (!tmp) {
            return -1;
        }
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


        if (v->type == CFL_VARIANT_STRING) {
            kv->val = tmp;
        }
        else {
            /* Hacky workaround: We store the variant address in a char * just to pass
             * the variant reference to the plugin. After this happens,
             * kv->val must be set to NULL (done in flb_config_map.c) */
            kv->val = (void *)v;
        }
    }

    return 0;
}

const char *flb_processor_instance_get_property(
                const char *key,
                struct flb_processor_instance *ins)
{
    return flb_kv_get_key_value(key, &ins->properties);
}

struct flb_processor_instance *flb_processor_instance_create(struct flb_config *config,
                                                             struct flb_processor_unit *pu,
                                                             int event_type,
                                                             const char *name, void *data)
{
    struct flb_processor_instance *instance;
    struct flb_processor_plugin   *plugin;
    struct mk_list                *head;
    int                            id;

    if (name == NULL) {
        return NULL;
    }

    mk_list_foreach(head, &config->processor_plugins) {
        plugin = mk_list_entry(head, struct flb_processor_plugin, _head);

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

    /* Get an ID */
    id =  0;

    /* format name (with instance id) */
    snprintf(instance->name, sizeof(instance->name) - 1,
             "%s.%i", plugin->name, id);

    instance->id         = id;
    instance->event_type = event_type;
    instance->alias = NULL;
    instance->p     = plugin;
    instance->data  = data;
    instance->log_level = -1;
    instance->pu = pu;

    mk_list_init(&instance->properties);

    instance->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (instance->log_encoder == NULL) {
        flb_plg_error(instance, "log event encoder initialization error");
        flb_processor_instance_destroy(instance);
        instance = NULL;
    }


    instance->log_decoder = flb_log_event_decoder_create(NULL, 0);
    if (instance->log_decoder == NULL) {
        flb_plg_error(instance, "log event decoder initialization error");
        flb_processor_instance_destroy(instance);
        instance = NULL;
    }
    flb_log_event_decoder_read_groups(instance->log_decoder, FLB_TRUE);

    return instance;
}

void flb_processor_instance_exit(struct flb_processor_instance *ins, struct flb_config *config)
{
    struct flb_processor_plugin *plugin;

    plugin = ins->p;

    if (plugin->cb_exit != NULL && ins->context != NULL) {
        plugin->cb_exit(ins, ins->context);
    }
}

const char *flb_processor_instance_get_name(struct flb_processor_instance *ins)
{
    if (ins->alias) {
        return ins->alias;
    }

    return ins->name;
}

int flb_processor_instance_check_properties(
        struct flb_processor_instance *ins,
        struct flb_config *config)
{
    int ret = 0;
    struct mk_list *config_map;
    struct flb_processor_plugin *p = ins->p;
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_kv *kv;
    int has_condition = FLB_FALSE;

    /* Check if there's a condition property and temporarily remove it */
    mk_list_foreach_safe(head, tmp, &ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        if (strcasecmp(kv->key, "condition") == 0) {
            has_condition = FLB_TRUE;
            mk_list_del(&kv->_head);
            break;
        }
    }

    if (p->config_map) {
        /*
         * Create a dynamic version of the configmap that will be used by the specific
         * instance in question.
         */
        config_map = flb_config_map_create(config, p->config_map);

        if (!config_map) {
            flb_error("[native processor] error loading config map for '%s' plugin",
                      p->name);

            /* Put the condition property back */
            if (has_condition) {
                mk_list_add(&kv->_head, &ins->properties);
            }

            return -1;
        }
        ins->config_map = config_map;

        /* Validate incoming properties against config map */
        ret = flb_config_map_properties_check(ins->p->name,
                                              &ins->properties,
                                              ins->config_map);

        /* Put the condition property back */
        if (has_condition) {
            mk_list_add(&kv->_head, &ins->properties);
        }

        if (ret == -1) {
            if (config->program_name) {
                flb_helper("try the command: %s -F %s -h\n",
                           config->program_name, ins->p->name);
            }
            return -1;
        }
    }
    else if (has_condition) {
        /* Put the condition property back if no config map */
        mk_list_add(&kv->_head, &ins->properties);
    }

    return 0;
}

int flb_processor_instance_init(
        struct flb_processor_instance *ins,
        void *source_plugin_instance,
        int source_plugin_type,
        struct flb_config *config)
{
    int ret;
    char *name;
    struct flb_processor_plugin *p;

    if (ins->log_level == -1 &&
        config->log != NULL) {
        ins->log_level = config->log->level;
    }

    p = ins->p;

    /* Get name or alias for the instance */
    name = (char *) flb_processor_instance_get_name(ins);

    /* CMetrics */
    ins->cmt = cmt_create();

    if (!ins->cmt) {
        flb_error("[processor] could not create cmetrics context: %s",
                  name);
        return -1;
    }

    /*
     * Before to call the initialization callback, make sure that the received
     * configuration parameters are valid if the plugin is registering a config map.
     */
    if (flb_processor_instance_check_properties(ins, config) == -1) {
        return -1;
    }

    /* Initialize the input */
    if (p->cb_init != NULL) {
        ret = p->cb_init(ins,
                         source_plugin_instance,
                         source_plugin_type,
                         config);

        if (ret != 0) {
            flb_error("[processor] failed initialize processor %s", ins->name);
            return -1;
        }
    }

    return 0;
}

void flb_processor_instance_set_context(struct flb_processor_instance *ins, void *context)
{
    ins->context = context;
}

void flb_processor_instance_destroy(struct flb_processor_instance *ins)
{
    if (ins == NULL) {
        return;
    }

    /* destroy config map */
    if (ins->config_map != NULL) {
        flb_config_map_destroy(ins->config_map);
    }

    /* release properties */
    flb_kv_release(&ins->properties);

    /* Remove metrics */
#ifdef FLB_HAVE_METRICS
    if (ins->cmt != NULL) {
        cmt_destroy(ins->cmt);
    }
#endif

    if (ins->alias != NULL) {
        flb_sds_destroy(ins->alias);
    }

    if (ins->log_encoder != NULL) {
        flb_log_event_encoder_destroy(ins->log_encoder);
    }

    if (ins->log_decoder != NULL) {
        flb_log_event_decoder_destroy(ins->log_decoder);
    }

    flb_free(ins);
}
