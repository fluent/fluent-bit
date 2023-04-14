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

#include "log_to_metrics.h"
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


static char kubernetes_label_keys[NUMBER_OF_KUBERNETES_LABELS][16] = 
    { "namespace_name",
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
    if(ctx->histogram_buckets){
        cmt_histogram_buckets_destroy(ctx->histogram_buckets);
    }

    if (ctx->cmt) {
        cmt_destroy(ctx->cmt);
    }
    
    delete_rules(ctx);

    if (ctx->label_keys != NULL) {
        for (i = 0; i < MAX_LABEL_COUNT; i++) {
            flb_free(ctx->label_keys[i]);
        }
        flb_free(ctx->label_keys);
    }
    flb_free(ctx->buckets);
    flb_free(ctx->bucket_counter);
    flb_free(ctx->label_counter);
    flb_free(ctx);
    return 0;
}

static int set_rules(struct log_to_metrics_ctx *ctx,
                     struct flb_filter_instance *f_ins)
{
    flb_sds_t tmp;
    struct mk_list *head;
    struct mk_list *split;
    struct flb_split_entry *sentry;
    struct flb_kv *kv;
    struct grep_rule *rule;

    /* Iterate all filter properties */
    mk_list_foreach(head, &f_ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        /* Create a new rule */
        rule = flb_malloc(sizeof(struct grep_rule));
        if (!rule) {
            flb_errno();
            return -1;
        }

        /* Get the type */
        if (strcasecmp(kv->key, "regex") == 0) {
            rule->type = GREP_REGEX;
        }
        else if (strcasecmp(kv->key, "exclude") == 0) {
            rule->type = GREP_EXCLUDE;
        }
        else {
            flb_free(rule);
            continue;
        }

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
        if (*sentry->value == '$') {
            rule->field = flb_sds_create_len(sentry->value, sentry->len);
        }
        else {
            rule->field = flb_sds_create_size(sentry->len + 2);
            tmp = flb_sds_cat(rule->field, "$", 1);
            rule->field = tmp;

            tmp = flb_sds_cat(rule->field, sentry->value, sentry->len);
            rule->field = tmp;
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
                      char **label_keys, 
                      int *label_counter, 
                      struct flb_filter_instance *f_ins)
{

    struct mk_list *head;
    struct flb_kv *kv; 
    int counter = 0;
    int i;
    if (MAX_LABEL_COUNT < NUMBER_OF_KUBERNETES_LABELS){
        flb_errno();
        return -1;
    }
    if (ctx->kubernetes_mode){
        for (i = 0; i < NUMBER_OF_KUBERNETES_LABELS; i++){ 
        snprintf(label_keys[i], MAX_LABEL_LENGTH - 1, "%s", 
                kubernetes_label_keys[i]);
        }
        counter = NUMBER_OF_KUBERNETES_LABELS;
    }

    /* Iterate all filter properties */
    mk_list_foreach(head, &f_ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        if (strcasecmp(kv->key, "label_field") != 0) {
            continue;
        }

        if (counter >= MAX_LABEL_COUNT) {
            return MAX_LABEL_COUNT;
        }
        snprintf(label_keys[counter++], MAX_LABEL_LENGTH - 1, "%s", kv->val);
    }
    *label_counter = counter;
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
    /* Allocate the memory for buckets */
    ctx->buckets = (double *) flb_malloc(counter * sizeof(double));
    /* Set the buckets */
    counter = 0;
    mk_list_foreach(head, &f_ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        if (strcasecmp(kv->key, "bucket") != 0) {
            continue;
        }
        valid = convert_double(kv->val, &parsed_double);
        if(!valid){
            flb_error("Error during conversion");
            return -1;
        }
        else{
            ctx->buckets[counter++] = parsed_double;
        }
    }
    *ctx->bucket_counter = counter;
    sort_doubles_ascending(ctx->buckets, counter);
    return 0;
}

static int fill_labels(struct log_to_metrics_ctx *ctx, char **label_values,
            char kubernetes_label_values
                [NUMBER_OF_KUBERNETES_LABELS][MAX_LABEL_LENGTH],
            char **label_keys, int label_counter, msgpack_object map)
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
            if (kubernetes_label_keys[i] == NULL){
                return -1;
            }
            snprintf(label_values[i], MAX_LABEL_LENGTH - 1, "%s", 
                    kubernetes_label_values[i]);
        }
        label_iterator_start = NUMBER_OF_KUBERNETES_LABELS;
    }

    for (i = label_iterator_start; i < label_counter; i++){
        ra = flb_ra_create(label_keys[i], FLB_TRUE);
        if (!ra) {
            flb_warn("invalid record accessor key, aborting");
            break;
        }

        rval = flb_ra_get_value_object(ra, map);
        if (!rval) {
        /* Set value to empty string, so the value will be dropped in Cmetrics*/
        label_values[i][0] = '\0';
        } else if (rval->type == FLB_RA_STRING) {
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

static int cb_log_to_metrics_init(struct flb_filter_instance *f_ins,
                        struct flb_config *config, void *data)
{
    int ret;
    struct log_to_metrics_ctx *ctx;
    flb_sds_t tmp;
    char metric_description[MAX_METRIC_LENGTH];
    char metric_name[MAX_METRIC_LENGTH];
    char value_field[MAX_METRIC_LENGTH];
    struct flb_input_instance *input_ins;
    int label_count;
    int i;
    /* Create context */
    ctx = flb_malloc(sizeof(struct log_to_metrics_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    if (flb_filter_config_map_set(f_ins, ctx) < 0) {
        flb_errno();
        flb_plg_error(f_ins, "configuration error");
        flb_free(ctx);
        return -1;
    }
    mk_list_init(&ctx->rules);

    ctx->ins = f_ins;

    /* Load rules */
    ret = set_rules(ctx, f_ins);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Set the context */
    flb_filter_set_context(f_ins, ctx);

    /* Set buckets for histogram */
    ctx->bucket_counter = NULL;
    ctx->histogram_buckets = NULL;
    ctx->buckets = NULL;
    ctx->bucket_counter = flb_malloc(sizeof(int));
    if(set_buckets(ctx, f_ins) != 0)
    {
        flb_plg_error(f_ins, "Setting buckets failed");
        log_to_metrics_destroy(ctx);
        return -1;
    }

    /* Set label keys */
    ctx->label_keys = NULL;
    ctx->label_keys = (char **) flb_malloc(MAX_LABEL_COUNT * sizeof(char *));
    for (i = 0; i < MAX_LABEL_COUNT; i++) {
        ctx->label_keys[i] = flb_malloc(MAX_LABEL_LENGTH * sizeof(char));
    }
    ctx->label_counter = NULL;
    ctx->label_counter = flb_malloc(sizeof(int));
    label_count = set_labels(ctx, ctx->label_keys, ctx->label_counter, f_ins);
    if (label_count < 0){
        log_to_metrics_destroy(ctx);
        return -1;
    }

    /* Check metric tag */
    if (ctx->tag == NULL || strlen(ctx->tag) == 0) {
        flb_plg_error(f_ins, "Metric tag is not set");
        log_to_metrics_destroy(ctx);
        return -1;
    }

    /* Check property metric mode */
    ctx->mode = 0; 
    tmp = (char *)flb_filter_get_property("metric_mode", f_ins);
    if (tmp != NULL) {
        if (strcasecmp(tmp, FLB_LOG_TO_METRICS_COUNTER_STR) == 0) {
            ctx->mode = FLB_LOG_TO_METRICS_COUNTER;
        }
        else if (strcasecmp(tmp, FLB_LOG_TO_METRICS_GAUGE_STR) == 0) {
            ctx->mode = FLB_LOG_TO_METRICS_GAUGE;
        }
        else if (strcasecmp(tmp, FLB_LOG_TO_METRICS_HISTOGRAM_STR) == 0) {
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
    if (ctx->metric_name == NULL || strlen(ctx->metric_name) == 0) {
        flb_plg_error(f_ins, "metric_name is not set");
        log_to_metrics_destroy(ctx);
        return -1;
    }
    snprintf(metric_name, sizeof(metric_name) - 1, "%s", ctx->metric_name);

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
    }


    /* Check if buckets are defined for histogram, if not assume defaults */
    if (ctx->mode == FLB_LOG_TO_METRICS_HISTOGRAM ){
        if (ctx->bucket_counter == 0){
            flb_plg_error(f_ins,
                "buckets are not set for histogram."
                "Will use defaults: 0.005, 0.01, 0.025, "
                "0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0");
            ctx->histogram_buckets = cmt_histogram_buckets_default_create();
        }
        else{
            ctx->histogram_buckets = cmt_histogram_buckets_create_size(
                                        ctx->buckets, *ctx->bucket_counter);
        }
    }


    /* create the metric */
    ctx->cmt = NULL;
    ctx->cmt = cmt_create();

    /* Depending on mode create different types of cmetrics metrics */
    switch (ctx->mode) {
        case FLB_LOG_TO_METRICS_COUNTER:
            ctx->c = cmt_counter_create(ctx->cmt, "log_metric", "counter",
                                   metric_name, metric_description, 
                                   label_count, ctx->label_keys);
            break;
        case FLB_LOG_TO_METRICS_GAUGE:
            ctx->g = cmt_gauge_create(ctx->cmt, "log_metric", "gauge",
                                      metric_name, metric_description, 
                                      label_count, ctx->label_keys);
            break;
        case FLB_LOG_TO_METRICS_HISTOGRAM:
            ctx->h = cmt_histogram_create(ctx->cmt, "log_metric", "histogram",
                                   metric_name, metric_description,
                                   ctx->histogram_buckets,
                                   label_count, ctx->label_keys);
            break;
        default:
            flb_plg_error(f_ins, "unsupported mode");
            log_to_metrics_destroy(ctx);
            return -1;
    }

    input_ins = flb_input_new(config, "emitter", NULL, FLB_FALSE);
    if (!input_ins) {
        flb_plg_error(f_ins, "cannot create metrics emitter instance");
        log_to_metrics_destroy(ctx);
        return -1;
    }

    /* Set the storage type for emitter */
    ret = flb_input_set_property(input_ins, "storage.type", "memory");
    if (ret == -1) {
        flb_plg_error(f_ins, "cannot set storage type for emitter instance");
        log_to_metrics_destroy(ctx);
        return -1;
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
            if(ctx->kubernetes_mode){
                for(i = 0; i < NUMBER_OF_KUBERNETES_LABELS; i++){
                    if (kubernetes_label_keys[i] == NULL){
                        flb_error("error during kubernetes label processing. "
                                    "Skipping labels.");
                                    ctx->label_counter = 0;
                        break;
                    }
                    snprintf(fmt, MAX_LABEL_LENGTH - 1, "$kubernetes['%s']",
                                kubernetes_label_keys[i]);
                    ra = flb_ra_create(fmt, FLB_TRUE);
                    if (!ra) {
                        flb_error("invalid record accessor key, aborting");
                        break;
                    }
                    rval = flb_ra_get_value_object(ra, map);
                    if (!rval) {
                        flb_error("given value field is empty or not "
                                    "existent: %s. Skipping labels.", fmt);
                                    ctx->label_counter = 0;
                    }
                    else if (rval->type != FLB_RA_STRING) {
                        flb_plg_error(f_ins,
                            "cannot access label %s", kubernetes_label_keys[i]);
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
                                    kubernetes_label_values, ctx->label_keys, 
                                    *ctx->label_counter, map);
                if (label_count != *ctx->label_counter){
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
                    ra = flb_ra_create(ctx->value_field, FLB_TRUE);
                    if (!ra) {
                        flb_error("invalid record accessor key, aborting");
                        break;
                    }

                    rval = flb_ra_get_value_object(ra, map);

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
                        break;
                    }
                    
                    ret = cmt_gauge_set(ctx->g, ts, gauge_value,
                                    label_count, label_values);
                    if (rval) {
                        flb_ra_key_value_destroy(rval);
                        rval = NULL;
                    }
                    if (ra) {
                        flb_ra_destroy(ra);
                        ra = NULL;
                    }
                    break;

                case FLB_LOG_TO_METRICS_HISTOGRAM:
                    ra = flb_ra_create(ctx->value_field, FLB_TRUE);
                    if (!ra) {
                        flb_error("invalid record accessor key, aborting");
                        break;
                    }

                    rval = flb_ra_get_value_object(ra, map);

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
                        break;
                    }

                    ret = cmt_histogram_observe(ctx->h, ts, histogram_value,
                                    label_count, label_values);
                    if (rval) {
                        flb_ra_key_value_destroy(rval);
                        rval = NULL;
                    }
                    if (ra) {
                        flb_ra_destroy(ra);
                        ra = NULL;
                    }
                    break;
                default:
                    flb_plg_error(f_ins, "unsupported mode");
                    log_to_metrics_destroy(ctx);
                    return -1;
            }
            
            ret = flb_input_metrics_append(ctx->input_ins, ctx->tag, strlen(ctx->tag), ctx->cmt);

	    if (ret != 0) {
                flb_plg_error(ctx->ins, "could not append metrics");
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
    /* Cleanup */
    msgpack_unpacked_destroy(&result);
    msgpack_sbuffer_destroy(&tmp_sbuf);

    /* Do not modify message stream */
    return FLB_FILTER_NOTOUCH;
}

static int cb_log_to_metrics_exit(void *data, struct flb_config *config)
{
    struct log_to_metrics_ctx *ctx = data;

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
     FLB_FALSE, FLB_TRUE,
     offsetof(struct log_to_metrics_ctx, mode),
     "Mode selector. Values counter, gauge,"
     " or histogram. Summary is not supported"
    },
    {
     FLB_CONFIG_MAP_STR, "value_field", NULL, 
     FLB_FALSE, FLB_TRUE,
     offsetof(struct log_to_metrics_ctx, value_field),
     "Numeric field to use for gauge or histogram"
    },
    {
     FLB_CONFIG_MAP_STR, "metric_name", NULL, 
     FLB_FALSE, FLB_TRUE,
     offsetof(struct log_to_metrics_ctx, metric_name),
     "Name of metric"
    },
    {
     FLB_CONFIG_MAP_STR, "metric_description", NULL, 
     FLB_FALSE, FLB_TRUE,
     offsetof(struct log_to_metrics_ctx, metric_description),
     "Help text for metric"
    },
    {
     FLB_CONFIG_MAP_BOOL, "kubernetes_mode", "false",
     0, FLB_TRUE, offsetof(struct log_to_metrics_ctx, kubernetes_mode),
     "Enable kubernetes log metric fields"
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
     FLB_FALSE, FLB_TRUE,
     offsetof(struct log_to_metrics_ctx, tag),
     "Metric Tag"
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
