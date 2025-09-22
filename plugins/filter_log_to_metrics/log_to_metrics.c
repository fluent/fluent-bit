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

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_utils.h>
#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_histogram.h>
#include <msgpack.h>
#include <stdio.h>
#include <sys/types.h>

#include "log_to_metrics.h"

static char kubernetes_label_keys[NUMBER_OF_KUBERNETES_LABELS][16] =
    {
        "namespace_name",
        "pod_name",
        "container_name",
        "docker_id",
        "pod_id"
    };

static void delete_rules(struct log_to_metrics_ctx *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct grep_rule *rule;

    mk_list_foreach_safe(head, tmp, &ctx->rules) {
        rule = mk_list_entry(head, struct grep_rule, _head);
        flb_sds_destroy(rule->field);
        flb_free(rule->regex_pattern);
        flb_ra_destroy(rule->ra);
        flb_regex_destroy(rule->regex);
        mk_list_del(&rule->_head);
        flb_free(rule);
    }
}

static int log_to_metrics_destroy(struct log_to_metrics_ctx *ctx)
{
    int i;

    if (!ctx) {
        return 0;
    }

    if (ctx->cmt) {
        cmt_destroy(ctx->cmt);
    }

    delete_rules(ctx);

    if (ctx->value_ra != NULL) {
        flb_ra_destroy(ctx->value_ra);
    }

    if (ctx->label_accessors != NULL) {
        for (i = 0; i < MAX_LABEL_COUNT; i++) {
            flb_free(ctx->label_accessors[i]);
        }
        flb_free(ctx->label_accessors);
    }
    if (ctx->label_keys != NULL) {
        for (i = 0; i < MAX_LABEL_COUNT; i++) {
            flb_free(ctx->label_keys[i]);
        }
        flb_free(ctx->label_keys);
    }

    flb_free(ctx->buckets);
    flb_free(ctx);
    return 0;
}

static int set_rules(struct log_to_metrics_ctx *ctx,
                     struct flb_filter_instance *f_ins)
{
    int type;
    struct mk_list *head;
    struct mk_list *split;
    struct flb_split_entry *sentry;
    struct flb_kv *kv;
    struct grep_rule *rule;

    /* Iterate all filter properties */
    mk_list_foreach(head, &f_ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        type = -1;

        /* Get the type */
        if (strcasecmp(kv->key, "regex") == 0) {
            type = GREP_REGEX;
        }
        else if (strcasecmp(kv->key, "exclude") == 0) {
            type = GREP_EXCLUDE;
        }

        if (type == -1) {
            continue;
        }

        /* Create a new rule */
        rule = flb_calloc(1, sizeof(struct grep_rule));
        if (!rule) {
            flb_errno();
            return -1;
        }
        rule->type = type;

        /* As a value we expect a pair of field name and a regular expression */
        split = flb_utils_split(kv->val, ' ', 1);
        if (mk_list_size(split) != 2) {
            flb_plg_error(ctx->ins,
                "invalid regex, expected field and regular expression");
            delete_rules(ctx);
            flb_free(rule);
            flb_utils_split_free(split);
            return -1;
        }

        /* Get first value (field) */
        sentry = mk_list_entry_first(split, struct flb_split_entry, _head);
        rule->field = flb_sds_create_len(sentry->value, sentry->len);
        if (!rule->field) {
            flb_errno();
            flb_free(rule);
            flb_utils_split_free(split);
            return -1;
        }

        /* Get remaining content (regular expression) */
        sentry = mk_list_entry_last(split, struct flb_split_entry, _head);
        rule->regex_pattern = flb_strndup(sentry->value, sentry->len);
        if (rule->regex_pattern == NULL) {
            flb_errno();
            delete_rules(ctx);
            flb_free(rule);
            flb_utils_split_free(split);
            return -1;
        }

        /* Release split */
        flb_utils_split_free(split);

        /* Create a record accessor context for this rule */
        rule->ra = flb_ra_create(rule->field, FLB_FALSE);
        if (!rule->ra) {
            flb_plg_error(ctx->ins, "invalid record accessor? '%s'",
                          rule->field);
            delete_rules(ctx);
            flb_free(rule);
            return -1;
        }

        /* Convert string to regex pattern */
        rule->regex = flb_regex_create(rule->regex_pattern);
        if (!rule->regex) {
            flb_plg_error(ctx->ins, "could not compile regex pattern '%s'",
                          rule->regex_pattern);
            delete_rules(ctx);
            flb_free(rule);
            return -1;
        }

        /* Link to parent list */
        mk_list_add(&rule->_head, &ctx->rules);
    }

    return 0;
}

/* Given a msgpack record, do some filter action based on the defined rules */
static inline int grep_filter_data(msgpack_object map,
                                   struct log_to_metrics_ctx *ctx)
{
    ssize_t ret;
    struct mk_list *head;
    struct grep_rule *rule;

    /* For each rule, validate against map fields */
    mk_list_foreach(head, &ctx->rules) {
        rule = mk_list_entry(head, struct grep_rule, _head);

        ret = flb_ra_regex_match(rule->ra, map, rule->regex, NULL);
        if (ret <= 0) { /* no match */
            if (rule->type == GREP_REGEX) {
                return GREP_RET_EXCLUDE;
            }
        }
        else {
            if (rule->type == GREP_EXCLUDE) {
                return GREP_RET_EXCLUDE;
            }
            else {
                return GREP_RET_KEEP;
            }
        }
    }

    return GREP_RET_KEEP;
}

static int set_labels(struct log_to_metrics_ctx *ctx,
                      char **label_accessors,
                      char **label_keys,
                      struct flb_filter_instance *f_ins)
{

    struct mk_list *head;
    struct mk_list *split;
    flb_sds_t tmp;
    struct flb_kv *kv;
    struct flb_split_entry *sentry;
    int counter = 0;
    int i;

    if (MAX_LABEL_COUNT < NUMBER_OF_KUBERNETES_LABELS){
        return -1;
    }

    if (ctx->kubernetes_mode){
        for (i = 0; i < NUMBER_OF_KUBERNETES_LABELS; i++){
            snprintf(label_keys[i], MAX_LABEL_LENGTH - 1, "%s", kubernetes_label_keys[i]);
        }
        counter = NUMBER_OF_KUBERNETES_LABELS;
    }

    /* Iterate all filter properties */
    mk_list_foreach(head, &f_ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        if (counter >= MAX_LABEL_COUNT) {
            return MAX_LABEL_COUNT;
        }

        if (strcasecmp(kv->key, "label_field") == 0) {
            snprintf(label_accessors[counter], MAX_LABEL_LENGTH - 1, "%s", kv->val);
            snprintf(label_keys[counter], MAX_LABEL_LENGTH - 1, "%s", kv->val);
            counter++;
        }
        else if (strcasecmp(kv->key, "add_label") == 0) {
            split = flb_utils_split(kv->val, ' ', 1);
            if (mk_list_size(split) != 2) {
                flb_plg_error(ctx->ins, "invalid label, expected name and key");
                flb_utils_split_free(split);
                return -1;
            }

            sentry = mk_list_entry_first(split, struct flb_split_entry, _head);
            tmp = flb_sds_create_len(sentry->value, sentry->len);
            snprintf(label_keys[counter], MAX_LABEL_LENGTH - 1, "%s", tmp);
            flb_sds_destroy(tmp);

            sentry = mk_list_entry_last(split, struct flb_split_entry, _head);
            tmp = flb_sds_create_len(sentry->value, sentry->len);
            snprintf(label_accessors[counter], MAX_LABEL_LENGTH - 1, "%s", tmp);
            flb_sds_destroy(tmp);
            counter++;

            flb_utils_split_free(split);
        }
        else {
            continue;
        }
    }

    return counter;
}

static int convert_double(char *str, double *value)
{
    char *endptr = str;
    int valid = 1;
    int i = 0;

    /* input validation */
    for (i = 0; str[i] != '\0'; i++) {
        if (!(str[i]>='0') && !(str[i] <= '9') && str[i] != '.'
                        && str[i] != '-' && str[i] != '+') {
            valid = 0;
            break;
        }
    }
    /* convert to double */
    if (valid) {
        *value = strtod(str, &endptr);
        if (str == endptr) {
            valid = 0;
        }
    }
    return valid;
}

static void sort_doubles_ascending(double *arr, int size)
{
    int i, j;
    double tmp;

    for (i = 0; i < size - 1; i++) {
        for (j = 0; j < size - i - 1; j++) {
            if (arr[j] > arr[j + 1]) {
                tmp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = tmp;
            }
        }
    }
}
static int set_buckets(struct log_to_metrics_ctx *ctx,
                      struct flb_filter_instance *f_ins)
{

    struct mk_list *head;
    struct flb_kv *kv;
    double parsed_double = 0.0;
    int counter = 0;
    int valid = 1;

    /* Iterate filter properties to get count of buckets to allocate memory */
    mk_list_foreach(head, &f_ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (strcasecmp(kv->key, "bucket") != 0) {
            continue;
        }
        counter++;
    }

    if (counter == 0) {
        ctx->buckets = NULL;
        ctx->bucket_counter = 0;
        return 0;
    }

    /* Allocate the memory for buckets */
    ctx->buckets = (double *) flb_calloc(1, counter * sizeof(double));
    if (!ctx->buckets) {
        flb_errno();
        return -1;
    }

    /* Set the buckets */
    counter = 0;
    mk_list_foreach(head, &f_ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        if (strcasecmp(kv->key, "bucket") != 0) {
            continue;
        }
        valid = convert_double(kv->val, &parsed_double);
        if(!valid){
            flb_plg_error(ctx->ins, "Error during conversion");
            return -1;
        }
        else{
            ctx->buckets[counter++] = parsed_double;
        }
    }
    ctx->bucket_counter = counter;
    sort_doubles_ascending(ctx->buckets, counter);
    return 0;
}

static int fill_labels(struct log_to_metrics_ctx *ctx, char **label_values,
                       char kubernetes_label_values
                       [NUMBER_OF_KUBERNETES_LABELS][MAX_LABEL_LENGTH],
                       char **label_accessors, int label_counter, msgpack_object map)
{
    int label_iterator_start = 0;
    int i;
    struct flb_record_accessor *ra = NULL;
    struct flb_ra_value *rval = NULL;

    if (label_counter == 0 && !ctx->kubernetes_mode){
        return 0;
    }
    if (MAX_LABEL_COUNT < NUMBER_OF_KUBERNETES_LABELS){
        flb_errno();
        return -1;
    }

    if (ctx->kubernetes_mode){
        for (i = 0; i < NUMBER_OF_KUBERNETES_LABELS; i++){
            snprintf(label_values[i], MAX_LABEL_LENGTH - 1, "%s", kubernetes_label_values[i]);
        }
        label_iterator_start = NUMBER_OF_KUBERNETES_LABELS;
    }

    for (i = label_iterator_start; i < label_counter; i++){
        ra = flb_ra_create(label_accessors[i], FLB_TRUE);
        if (!ra) {
            flb_warn("invalid record accessor key, aborting");
            break;
        }

        rval = flb_ra_get_value_object(ra, map);
        if (!rval) {
        /* Set value to empty string, so the value will be dropped in Cmetrics*/
        label_values[i][0] = '\0';
        }
        else if (rval->type == FLB_RA_STRING) {
            snprintf(label_values[i], MAX_LABEL_LENGTH - 1, "%s",
            rval->val.string);
        }
        else if (rval->type == FLB_RA_FLOAT) {
            snprintf(label_values[i], MAX_LABEL_LENGTH - 1, "%f",
            rval->val.f64);
        }
        else if (rval->type == FLB_RA_INT) {
            snprintf(label_values[i], MAX_LABEL_LENGTH - 1, "%ld",
            (long)rval->val.i64);
        }
        else {
            flb_warn("cannot convert given value to metric");
            break;
        }
        if (rval){
            flb_ra_key_value_destroy(rval);
            rval = NULL;
        }
        if (ra){
            flb_ra_destroy(ra);
            ra = NULL;
        }
    }
    return label_counter;
}

/* Timer callback to inject metrics into the pipeline */
static void cb_send_metric_chunk(struct flb_config *config, void *data)
{
    int ret;
    struct log_to_metrics_ctx *ctx = data;

    /* Check that metric context is not empty */
    if (ctx->cmt == NULL || ctx->input_ins == NULL) {
        return;
    }
    
    if (ctx->new_data) {
        ret = flb_input_metrics_append(ctx->input_ins, ctx->tag,
            strlen(ctx->tag), ctx->cmt);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "could not append metrics");
        }
    }

    /* Check if we are shutting down. If so, stop our timer */
    if (config->is_shutting_down) {
        if(ctx->timer && ctx->timer->active) {
            flb_plg_debug(ctx->ins, "Stopping callback timer");
            flb_sched_timer_cb_disable(ctx->timer);
        }
    }
    ctx->new_data = FLB_FALSE;
}

static int cb_log_to_metrics_init(struct flb_filter_instance *f_ins,
                        struct flb_config *config, void *data)
{
    int ret;
    struct log_to_metrics_ctx *ctx;
    flb_sds_t tmp;
    char metric_description[MAX_METRIC_LENGTH];
    char metric_name[MAX_METRIC_LENGTH];
    char metric_namespace[MAX_METRIC_LENGTH];
    char metric_subsystem[MAX_METRIC_LENGTH];
    char value_field[MAX_METRIC_LENGTH];
    struct flb_input_instance *input_ins;
    struct flb_sched *sched;


    int i;
    /* Create context */
    ctx = flb_calloc(1, sizeof(struct log_to_metrics_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = f_ins;

    if (flb_filter_config_map_set(f_ins, ctx) < 0) {
        flb_errno();
        flb_plg_error(f_ins, "configuration error");
        flb_free(ctx);
        return -1;
    }
    mk_list_init(&ctx->rules);

    if (ctx->metric_name == NULL) {
        flb_plg_error(f_ins, "metric_name is not set");
        log_to_metrics_destroy(ctx);
        return -1;
    }

    /* Load rules */
    ret = set_rules(ctx, f_ins);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Set the context */
    flb_filter_set_context(f_ins, ctx);

    /* Set buckets for histogram */
    ctx->buckets = NULL;
    ctx->bucket_counter = 0;
    ctx->histogram_buckets = NULL;

    if (set_buckets(ctx, f_ins) < 0) {
        flb_plg_error(f_ins, "Setting buckets failed");
        log_to_metrics_destroy(ctx);
        return -1;
    }

    ctx->label_accessors = NULL;
    ctx->label_accessors = (char **) flb_calloc(1, MAX_LABEL_COUNT * sizeof(char *));
    if (!ctx->label_accessors) {
        flb_errno();
        log_to_metrics_destroy(ctx);
        return -1;
    }

    for (i = 0; i < MAX_LABEL_COUNT; i++) {
        ctx->label_accessors[i] = flb_calloc(1, MAX_LABEL_LENGTH * sizeof(char));
        if (!ctx->label_accessors[i]) {
            flb_errno();
            log_to_metrics_destroy(ctx);
            return -1;
        }
    }

    /* Set label keys */
    ctx->label_keys = (char **) flb_calloc(1, MAX_LABEL_COUNT * sizeof(char *));
    for (i = 0; i < MAX_LABEL_COUNT; i++) {
        ctx->label_keys[i] = flb_calloc(1, MAX_LABEL_LENGTH * sizeof(char));
        if (!ctx->label_keys[i]) {
            flb_errno();
            log_to_metrics_destroy(ctx);
            return -1;
        }
    }

    ret = set_labels(ctx, ctx->label_accessors, ctx->label_keys, f_ins);
    if (ret < 0){
        log_to_metrics_destroy(ctx);
        return -1;
    }
    ctx->label_counter = ret;

    /* Check metric tag */
    if (ctx->tag == NULL || strlen(ctx->tag) == 0) {
        flb_plg_error(f_ins, "Metric tag is not set");
        log_to_metrics_destroy(ctx);
        return -1;
    }

    /* Check property metric mode */
    ctx->mode = 0;
    if (ctx->mode_name != NULL) {
        if (strcasecmp(ctx->mode_name,
                       FLB_LOG_TO_METRICS_COUNTER_STR) == 0) {
            ctx->mode = FLB_LOG_TO_METRICS_COUNTER;
        }
        else if (strcasecmp(ctx->mode_name,
                            FLB_LOG_TO_METRICS_GAUGE_STR) == 0) {
            ctx->mode = FLB_LOG_TO_METRICS_GAUGE;
        }
        else if (strcasecmp(ctx->mode_name,
                            FLB_LOG_TO_METRICS_HISTOGRAM_STR) == 0) {
            ctx->mode = FLB_LOG_TO_METRICS_HISTOGRAM;
        }
        else {
            flb_plg_error(f_ins,
                          "invalid 'mode' value. Only "
                          "'counter', 'gauge' or "
                          "'histogram' types are allowed");
            log_to_metrics_destroy(ctx);
            return -1;
        }
    }
    else {
        flb_plg_error(f_ins, "configuration property not set");
        log_to_metrics_destroy(ctx);
        return -1;
    }

    /* Check property metric name */
    if (ctx->metric_name == NULL) {
        flb_plg_error(f_ins, "metric_name is not set");
        log_to_metrics_destroy(ctx);
        return -1;
    }
    snprintf(metric_name, sizeof(metric_name) - 1, "%s", ctx->metric_name);
    snprintf(metric_namespace, sizeof(metric_namespace) - 1, "%s", ctx->metric_namespace);

    /* Check property subsystem name */
    if (ctx->metric_subsystem == NULL || strlen(ctx->metric_subsystem) == 0) {
        snprintf(metric_subsystem, sizeof(metric_subsystem) - 1, "%s",
                 ctx->mode_name);
    }
    else {
        snprintf(metric_subsystem, sizeof(metric_subsystem) - 1, "%s",
                 ctx->metric_subsystem);
    }

    /* Check property metric description */
    if (ctx->metric_description == NULL ||
        strlen(ctx->metric_description) == 0) {
        flb_plg_error(f_ins, "metric_description is not set");
        log_to_metrics_destroy(ctx);
        return -1;
    }
    snprintf(metric_description, sizeof(metric_description) - 1, "%s",
             ctx->metric_description);

    /* Value field only needed for modes gauge and histogram */
    if (ctx->mode > 0) {
        if (ctx->value_field == NULL || strlen(ctx->value_field) == 0) {
            flb_plg_error(f_ins, "value_field is not set");
            log_to_metrics_destroy(ctx);
            return -1;
        }
        snprintf(value_field, sizeof(value_field) - 1, "%s",
                    ctx->value_field);

        ctx->value_ra = flb_ra_create(ctx->value_field, FLB_TRUE);
        if (ctx->value_ra == NULL) {
            flb_plg_error(f_ins, "invalid record accessor key for value_field");
            log_to_metrics_destroy(ctx);
            return -1;
        }
    }


    /* Check if buckets are defined for histogram, if not assume defaults */
    if (ctx->mode == FLB_LOG_TO_METRICS_HISTOGRAM) {
        if (ctx->bucket_counter == 0){
            flb_plg_warn(f_ins,
                        "buckets are not set for histogram."
                        "Will use defaults: 0.005, 0.01, 0.025, "
                        "0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0");
            ctx->histogram_buckets = cmt_histogram_buckets_default_create();
        }
        else{
            ctx->histogram_buckets = cmt_histogram_buckets_create_size(ctx->buckets, ctx->bucket_counter);
        }
    }


    /* create the metric */
    ctx->cmt = NULL;
    ctx->cmt = cmt_create();

    /* Depending on mode create different types of cmetrics metrics */
    switch (ctx->mode) {
        case FLB_LOG_TO_METRICS_COUNTER:
            ctx->c = cmt_counter_create(ctx->cmt, metric_namespace, metric_subsystem,
                                        metric_name, metric_description,
                                        ctx->label_counter, ctx->label_keys);
            break;
        case FLB_LOG_TO_METRICS_GAUGE:
            ctx->g = cmt_gauge_create(ctx->cmt, metric_namespace, metric_subsystem,
                                      metric_name, metric_description,
                                      ctx->label_counter, ctx->label_keys);
            break;
        case FLB_LOG_TO_METRICS_HISTOGRAM:
            ctx->h = cmt_histogram_create(ctx->cmt, metric_namespace, metric_subsystem,
                                          metric_name, metric_description,
                                          ctx->histogram_buckets,
                                          ctx->label_counter, ctx->label_keys);
            break;
        default:
            flb_plg_error(f_ins, "unsupported mode");
            log_to_metrics_destroy(ctx);
            return -1;
    }

    tmp = (char *) flb_filter_get_property("emitter_name", f_ins);
    /* If emitter_name is not set, use the default name */
    if (tmp == NULL) {
        tmp = (char *) flb_filter_name(f_ins);
        ctx->emitter_name = flb_sds_create_size(64);
        ctx->emitter_name = flb_sds_printf(&ctx->emitter_name, "emitter_for_%s", tmp);
    }
    else {
        ctx->emitter_name = flb_sds_create(tmp);
    }

    ret = flb_input_name_exists(ctx->emitter_name, config);
    if (ret) {
        flb_plg_error(f_ins, "emitter_name '%s' already exists",
                      ctx->emitter_name);
        flb_sds_destroy(ctx->emitter_name);
        log_to_metrics_destroy(ctx);
        return -1;
    }
    input_ins = flb_input_new(config, "emitter", NULL, FLB_FALSE);
    if (!input_ins) {
        flb_plg_error(f_ins, "cannot create metrics emitter instance");
        flb_sds_destroy(ctx->emitter_name);
        log_to_metrics_destroy(ctx);
        return -1;
    }
    /* Set the alias for emitter */
    ret = flb_input_set_property(input_ins, "alias", ctx->emitter_name);
    if (ret == -1) {
        flb_plg_warn(ctx->ins,
                     "cannot set emitter_name");
        flb_sds_destroy(ctx->emitter_name);
        log_to_metrics_destroy(ctx);
        return -1;
    }

    flb_sds_destroy(ctx->emitter_name);

    /* Set the storage type for emitter */
    ret = flb_input_set_property(input_ins, "storage.type", "memory");
    if (ret == -1) {
        flb_plg_error(f_ins, "cannot set storage type for emitter instance");
        log_to_metrics_destroy(ctx);
        return -1;
    }

    /* Set the emitter_mem_buf_limit */
    if(ctx->emitter_mem_buf_limit > 0) {
        input_ins->mem_buf_limit = ctx->emitter_mem_buf_limit;
    }

    /* Initialize emitter plugin */
    ret = flb_input_instance_init(input_ins, config);
    if (ret == -1) {
        flb_errno();
        flb_plg_error(f_ins, "cannot initialize metrics emitter instance.");
        log_to_metrics_destroy(ctx);
        return -1;
    }

    ret = flb_storage_input_create(config->cio, input_ins);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot initialize storage for metrics stream");
        log_to_metrics_destroy(ctx);
        return -1;
    }
    ctx->input_ins = input_ins;


    if (ctx->flush_interval_sec <= 0) {
        ctx->flush_interval_sec = strtol(DEFAULT_INTERVAL_SEC, NULL, 10);
    }
    if (ctx->flush_interval_nsec <= 0) {
        ctx->flush_interval_nsec = strtol(DEFAULT_INTERVAL_NSEC, NULL, 10);
    }
    if (ctx->flush_interval_sec == 0 && ctx->flush_interval_nsec == 0) {
        flb_plg_debug(ctx->ins, "Interval is set to 0, will not use timer and "
                "send metrics immediately");
        ctx->timer_mode = FLB_FALSE;
        return 0;
    }
    
    /* Initialize timer for scheduled metric updates */
    sched = flb_sched_ctx_get();
    if(sched == 0) {
        flb_plg_error(f_ins, "could not get scheduler context");
        log_to_metrics_destroy(ctx);
        return -1;
    }
    /* Convert flush_interval_sec and flush_interval_nsec to milliseconds */
    ctx->timer_interval = (ctx->flush_interval_sec * 1000) + 
                        (ctx->flush_interval_nsec / 1000000);
    flb_plg_debug(ctx->ins,
                      "Creating metric timer with frequency %d ms",
                        ctx->timer_interval);
    
    ret = flb_sched_timer_cb_create(sched, FLB_SCHED_TIMER_CB_PERM,
                                    ctx->timer_interval, cb_send_metric_chunk,
                                    ctx, &ctx->timer);
    if (ret < 0) {
        flb_plg_error(f_ins, "could not create timer callback");
        log_to_metrics_destroy(ctx);
        return -1;
    }
    ctx->timer_mode = FLB_TRUE;
    return 0;
}

static int cb_log_to_metrics_filter(const void *data, size_t bytes,
                            const char *tag, int tag_len,
                            void **out_buf, size_t *out_size,
                            struct flb_filter_instance *f_ins,
                            struct flb_input_instance *i_ins, void *context,
                            struct flb_config *config)
{
    int ret;
    int filter_ret = FLB_FILTER_NOTOUCH;
    msgpack_unpacked result;
    msgpack_object map;
    msgpack_object root;
    size_t off = 0;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    uint64_t ts;
    struct log_to_metrics_ctx *ctx = context;
    struct flb_ra_value *rval = NULL;
    struct flb_record_accessor *ra = NULL;
    char fmt[MAX_LABEL_LENGTH];
    char **label_values = NULL;
    int label_count = 0;
    int i;
    double gauge_value = 0;
    double histogram_value = 0;
    char kubernetes_label_values
        [NUMBER_OF_KUBERNETES_LABELS][MAX_LABEL_LENGTH];

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /* Iterate each item array and apply rules and generate metric values */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) ==
           MSGPACK_UNPACK_SUCCESS) {
        root = result.data;
        if (root.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        /* get time and map */
        map = root.via.array.ptr[1];

        ret = grep_filter_data(map, context);
        if (ret == GREP_RET_KEEP) {
            ts = cfl_time_now();
            if(ctx->kubernetes_mode) {
                for (i = 0; i < NUMBER_OF_KUBERNETES_LABELS; i++) {
                    snprintf(fmt, MAX_LABEL_LENGTH - 1, "$kubernetes['%s']",
                                kubernetes_label_keys[i]);
                    ra = flb_ra_create(fmt, FLB_TRUE);
                    if (!ra) {
                        flb_plg_error(ctx->ins, "invalid record accessor key, aborting");
                        break;
                    }
                    rval = flb_ra_get_value_object(ra, map);
                    if (!rval) {
                        flb_plg_error(ctx->ins, "given value field is empty or not "
                                      "existent: %s. Skipping labels.", fmt);
                                      ctx->label_counter = 0;
                    }
                    else if (rval->type != FLB_RA_STRING) {
                        flb_plg_error(ctx->ins, "cannot access label %s", kubernetes_label_keys[i]);
                        break;
                    }
                    else {
                        snprintf(kubernetes_label_values[i],
                                MAX_LABEL_LENGTH - 1, "%s", rval->val.string);
                    }
                    if (rval){
                        flb_ra_key_value_destroy(rval);
                        rval = NULL;
                    }
                    if (ra){
                        flb_ra_destroy(ra);
                        ra = NULL;
                    }
                }
            }
            if (ctx->label_counter > 0){
                /* Fill optional labels */
                label_values = flb_malloc(MAX_LABEL_COUNT * sizeof(char *));
                for (i = 0; i < MAX_LABEL_COUNT; i++) {
                    label_values[i] = flb_malloc(MAX_LABEL_LENGTH *
                                                    sizeof(char));
                }

                label_count = fill_labels(ctx, label_values,
                                    kubernetes_label_values, ctx->label_accessors,
                                    ctx->label_counter, map);
                if (label_count != ctx->label_counter){
                    label_count = 0;
                }
            }

            /* Calculating and setting metric depending on the mode */
            switch (ctx->mode) {
                case FLB_LOG_TO_METRICS_COUNTER:
                    ret = cmt_counter_inc(ctx->c, ts, label_count,
                                    label_values);
                    break;

                case FLB_LOG_TO_METRICS_GAUGE:
                    rval = flb_ra_get_value_object(ctx->value_ra, map);

                    if (!rval) {
                        flb_warn("given value field is empty or not existent");
                        break;
                    }
                    if (rval->type == FLB_RA_STRING) {
                        sscanf(rval->val.string, "%lf", &gauge_value);
                    }
                    else if (rval->type == FLB_RA_FLOAT) {
                        gauge_value = rval->val.f64;
                    }
                    else if (rval->type == FLB_RA_INT) {
                        gauge_value = (double)rval->val.i64;
                    }
                    else {
                        flb_plg_error(f_ins,
                                    "cannot convert given value to metric");
                        flb_ra_key_value_destroy(rval);
                        rval = NULL;
                        break;
                    }

                    ret = cmt_gauge_set(ctx->g, ts, gauge_value,
                                    label_count, label_values);
                    flb_ra_key_value_destroy(rval);
                    rval = NULL;
                    break;

                case FLB_LOG_TO_METRICS_HISTOGRAM:
                    rval = flb_ra_get_value_object(ctx->value_ra, map);

                    if (!rval) {
                        flb_warn("given value field is empty or not existent");
                        break;
                    }
                    if (rval->type == FLB_RA_STRING) {
                        sscanf(rval->val.string, "%lf", &histogram_value);
                    }
                    else if (rval->type == FLB_RA_FLOAT) {
                        histogram_value = rval->val.f64;
                    }
                    else if (rval->type == FLB_RA_INT) {
                        histogram_value = (double)rval->val.i64;
                    }
                    else {
                        flb_plg_error(f_ins,
                                    "cannot convert given value to metric");
                        flb_ra_key_value_destroy(rval);
                        rval = NULL;
                        break;
                    }

                    ret = cmt_histogram_observe(ctx->h, ts, histogram_value,
                                    label_count, label_values);
                    flb_ra_key_value_destroy(rval);
                    rval = NULL;
                    break;
                default:
                    flb_plg_error(f_ins, "unsupported mode");
                    log_to_metrics_destroy(ctx);
                    return -1;
            }

            if (!ctx->timer_mode) {
                ret = flb_input_metrics_append(ctx->input_ins, ctx->tag,
                                            strlen(ctx->tag), ctx->cmt);

	            if (ret != 0) {
                    flb_plg_error(ctx->ins, "could not append metrics. "
                        "Please consider to use flush_interval_sec and flush_interval_nsec");
                }
            }
            else {
                ctx->new_data = FLB_TRUE;
            }

            /* Cleanup */
            msgpack_unpacked_destroy(&result);
            if (label_values != NULL){
                for (i = 0; i < MAX_LABEL_COUNT; i++) {
                    if (label_values[i] != NULL){
                        flb_free(label_values[i]);
                    }
                }
                flb_free(label_values);
            }
        }
        else if (ret == GREP_RET_EXCLUDE) {
            /* Do nothing */
        }
    }


    if (ctx->discard_logs) {
        *out_buf = NULL;
        *out_size = 0;
        filter_ret = FLB_FILTER_MODIFIED;
    }

    /* Cleanup */
    msgpack_unpacked_destroy(&result);
    msgpack_sbuffer_destroy(&tmp_sbuf);

    /* this can be FLB_FILTER_NOTOUCH or FLB_FILTER_MODIFIED */
    return filter_ret;
}

static int cb_log_to_metrics_exit(void *data, struct flb_config *config)
{
    struct log_to_metrics_ctx *ctx = data;
    if(ctx->timer != NULL) {
        flb_plg_debug(ctx->ins, "Destroying callback timer");
        flb_sched_timer_destroy(ctx->timer);
    }
    return log_to_metrics_destroy(ctx);
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "regex", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Optional filter for records in which the content of KEY "
     "matches the regular expression."
    },
    {
     FLB_CONFIG_MAP_STR, "exclude", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Optional filter for records in which the content of KEY "
     "does not matches the regular expression."
    },
    {
     FLB_CONFIG_MAP_STR, "metric_mode", "counter",
     0, FLB_TRUE, offsetof(struct log_to_metrics_ctx, mode_name),
     "Mode selector. Values counter, gauge,"
     " or histogram. Summary is not supported"
    },
    {
     FLB_CONFIG_MAP_STR, "value_field", NULL,
     0, FLB_TRUE, offsetof(struct log_to_metrics_ctx, value_field),
     "Numeric field to use for gauge or histogram"
    },
    {
     FLB_CONFIG_MAP_STR, "metric_name", "a",
     0, FLB_TRUE, offsetof(struct log_to_metrics_ctx, metric_name),
     "Name of the metric"
    },
    {
     FLB_CONFIG_MAP_STR, "metric_namespace",
     DEFAULT_LOG_TO_METRICS_NAMESPACE,
     0, FLB_TRUE, offsetof(struct log_to_metrics_ctx, metric_namespace),
     "Namespace of the metric"
    },
    {
     FLB_CONFIG_MAP_STR, "metric_subsystem",NULL,
     0, FLB_TRUE, offsetof(struct log_to_metrics_ctx, metric_subsystem),
     "Subsystem of the metric"
    },
    {
     FLB_CONFIG_MAP_STR, "metric_description", NULL,
     0, FLB_TRUE, offsetof(struct log_to_metrics_ctx, metric_description),
     "Help text for metric"
    },
    {
     FLB_CONFIG_MAP_BOOL, "kubernetes_mode", "false",
     0, FLB_TRUE, offsetof(struct log_to_metrics_ctx, kubernetes_mode),
     "Enable kubernetes log metric fields"
    },
    {
     FLB_CONFIG_MAP_STR, "add_label", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Add a label to the metric by supporting record accessor pattern"
    },
    {
     FLB_CONFIG_MAP_STR, "label_field", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Specify message field that should be included in the metric"
    },
    {
     FLB_CONFIG_MAP_STR, "bucket", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Specify bucket for histogram metric"
    },
    {
     FLB_CONFIG_MAP_STR, "tag", NULL,
     0, FLB_TRUE, offsetof(struct log_to_metrics_ctx, tag),
     "Metric Tag"
    },
    {
     FLB_CONFIG_MAP_STR, "emitter_name", NULL,
     0, FLB_TRUE, offsetof(struct log_to_metrics_ctx, emitter_name),
     "Name of the emitter (advanced users)"
    },
    {
     FLB_CONFIG_MAP_SIZE, "emitter_mem_buf_limit", FLB_MEM_BUF_LIMIT_DEFAULT,
     0, FLB_TRUE, offsetof(struct log_to_metrics_ctx, emitter_mem_buf_limit),
     "set a buffer limit to restrict memory usage of metrics emitter"
    },
    {
      FLB_CONFIG_MAP_INT, "flush_interval_sec", DEFAULT_INTERVAL_SEC,
      0, FLB_TRUE, offsetof(struct log_to_metrics_ctx, flush_interval_sec),
      "Set the timer interval for metrics emission. If flush_interval_sec and "
      "flush_interval_nsec are set to 0, the timer is disabled (default)."
    },
    {
      FLB_CONFIG_MAP_INT, "flush_interval_nsec", DEFAULT_INTERVAL_NSEC,
      0, FLB_TRUE, offsetof(struct log_to_metrics_ctx, flush_interval_nsec),
      "Set the timer interval (subseconds) for metrics emission. "
      "If flush_interval_sec and flush_interval_nsec are set to 0, the timer is disabled "
      "(default). Final precision is milliseconds."
    },
    {
     FLB_CONFIG_MAP_BOOL, "discard_logs", "false",
     0, FLB_TRUE, offsetof(struct log_to_metrics_ctx, discard_logs),
     "Flag that defines if logs should be discarded after processing. This applies "
     "for all logs, no matter if they have emitted metrics or not."
    },

    {0}
};

struct flb_filter_plugin filter_log_to_metrics_plugin = {
    .name = "log_to_metrics",
    .description = "generate log derived metrics",
    .cb_init = cb_log_to_metrics_init,
    .cb_filter = cb_log_to_metrics_filter,
    .cb_exit = cb_log_to_metrics_exit,
    .config_map = config_map,
    .flags = 0};
