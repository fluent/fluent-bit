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

#include <stdio.h>

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_record_accessor.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_map.h>

#include <cfl/cfl.h>

#define PROMOTE_STATIC_METRICS_ON_LABEL_INSERT

typedef int (*label_transformer)(struct cmt_metric *, cfl_sds_t *value);

struct label_kv {
    cfl_sds_t key;
    cfl_sds_t val;
    /*
     * record accessor is only set if a '$' string exists in the
     * given value string, otherwise the string is copied directly into 'val'
     */
    struct flb_record_accessor *ra;
    struct cfl_list _head;
};
struct internal_processor_context {
    struct mk_list *update_list;
    struct mk_list *insert_list;
    struct mk_list *upsert_list;
    struct mk_list *delete_list;
    struct mk_list *hash_list;

    /* internal labels ready to append */
    struct cfl_list update_labels;
    struct cfl_list insert_labels;
    struct cfl_list upsert_labels;
    struct mk_list  delete_labels;
    struct mk_list  hash_labels;

    struct flb_processor_instance *instance;
    struct flb_config *config;
};


/*
 * CMETRICS
 */

static void cmt_label_destroy(struct cmt_label *label)
{
    if (label != NULL) {
        if (!cfl_list_entry_is_orphan(&label->_head)) {
            cfl_list_del(&label->_head);
        }

        if (label->key != NULL) {
            cfl_sds_destroy(label->key);
        }

        if (label->val != NULL) {
            cfl_sds_destroy(label->val);
        }

        free(label);
    }
}

/* we can't use flb_* memory functions here because this will
 * be released by cmetrics using the standard allocator.
 */

static struct cmt_map_label *cmt_map_label_create(char *name)
{
    struct cmt_map_label *label;

    label = calloc(1, sizeof(struct cmt_map_label));

    if (label != NULL) {
        label->name = cfl_sds_create(name);

        if (label->name == NULL) {
            free(label);

            label = NULL;
        }

    }

    return label;
}

static void cmt_map_label_destroy(struct cmt_map_label *label)
{
    if (label != NULL) {
        if (!cfl_list_entry_is_orphan(&label->_head)) {
            cfl_list_del(&label->_head);
        }

        if (label->name != NULL) {
            cfl_sds_destroy(label->name);
        }

        free(label);
    }
}

static struct cmt_metric *map_metric_create(uint64_t hash,
                                            int labels_count, char **labels_val)
{
    int i;
    char *name;
    struct cmt_metric *metric;
    struct cmt_map_label *label;

    metric = calloc(1, sizeof(struct cmt_metric));
    if (!metric) {
        cmt_errno();
        return NULL;
    }
    cfl_list_init(&metric->labels);
    metric->val = 0.0;
    metric->hash = hash;

    for (i = 0; i < labels_count; i++) {
        label = malloc(sizeof(struct cmt_map_label));
        if (!label) {
            cmt_errno();
            goto error;
        }

        name = labels_val[i];
        label->name = cfl_sds_create(name);
        if (!label->name) {
            cmt_errno();
            free(label);
            goto error;
        }
        cfl_list_add(&label->_head, &metric->labels);
    }

    return metric;

 error:
    free(metric);
    return NULL;
}

static void map_metric_destroy(struct cmt_metric *metric)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct cmt_map_label *label;

    cfl_list_foreach_safe(head, tmp, &metric->labels) {
        label = cfl_list_entry(head, struct cmt_map_label, _head);
        cfl_sds_destroy(label->name);
        cfl_list_del(&label->_head);
        free(label);
    }

    if (metric->hist_buckets) {
        free(metric->hist_buckets);
    }
    if (metric->sum_quantiles) {
        free(metric->sum_quantiles);
    }

    cfl_list_del(&metric->_head);
    free(metric);
}


/*
 * LOCAL
 */
static int hex_encode(unsigned char *input_buffer,
                      size_t input_length,
                      cfl_sds_t *output_buffer)
{
    const char hex[] = "0123456789abcdef";
    cfl_sds_t  result;
    size_t     index;

    if (cfl_sds_alloc(*output_buffer) <= (input_length * 2)) {
        result = cfl_sds_increase(*output_buffer,
                                  (input_length * 2) -
                                  cfl_sds_alloc(*output_buffer));

        if (result == NULL) {
            return FLB_FALSE;
        }

        *output_buffer = result;
    }

    for (index = 0; index < input_length; index++) {
        (*output_buffer)[index * 2 + 0] = hex[(input_buffer[index] >> 4) & 0xF];
        (*output_buffer)[index * 2 + 1] = hex[(input_buffer[index] >> 0) & 0xF];
    }

    cfl_sds_set_len(*output_buffer, input_length * 2);

    (*output_buffer)[index * 2] = '\0';

    return FLB_TRUE;
}

static int process_label_modification_list_setting(
                struct flb_processor_instance *plugin_instance,
                const char *setting_name,
                struct mk_list *source_list,
                struct mk_list *destination_list)
{
    struct flb_config_map_val *source_entry;
    struct mk_list            *iterator;
    int                        result;

    if (source_list == NULL ||
        mk_list_is_empty(source_list) == 0) {

        return 0;
    }

    flb_config_map_foreach(iterator, source_entry, source_list) {
        result = flb_slist_add(destination_list, source_entry->val.str);

        if (result != 0) {
            flb_plg_error(plugin_instance,
                          "could not append label name %s\n",
                          source_entry->val.str);

            return -1;
        }
    }

    return 0;
}

static int process_label_modification_kvlist_setting(
                struct flb_processor_instance *plugin_instance,
                const char *setting_name,
                struct mk_list *source_list,
                struct cfl_list *destination_list)
{
    struct flb_config_map_val *source_entry;
    struct mk_list            *iterator;
    struct flb_slist_entry    *value;
    struct flb_slist_entry    *key;
    struct label_kv           *kv_node;

    if (source_list == NULL ||
        mk_list_is_empty(source_list) == 0) {

        return 0;
    }

    flb_config_map_foreach(iterator, source_entry, source_list) {
        if (mk_list_size(source_entry->val.list) != 2) {
            flb_plg_error(plugin_instance,
                          "'%s' expects a key and a value, "
                          "e.g: '%s version 1.8.0'",
                          setting_name, setting_name);

            return -1;
        }

        key = mk_list_entry_first(source_entry->val.list,
                                  struct flb_slist_entry, _head);

        value = mk_list_entry_last(source_entry->val.list,
                                   struct flb_slist_entry, _head);

        kv_node = flb_malloc(sizeof(struct label_kv));
        if (kv_node == NULL) {
            flb_errno();
            return -1;
        }

        /* only initialize record accessor if a pattern is found */
        if (strchr(value->str, '$') != NULL) {
            kv_node->ra = flb_ra_create(value->str, FLB_FALSE);
            if (kv_node->ra == NULL) {
                flb_plg_error(plugin_instance,
                              "could not create record accessor for '%s'",
                              value->str);
                return -1;
            }
        }
        else {
            kv_node->ra = NULL;
        }

        kv_node->key = cfl_sds_create(key->str);
        if (kv_node->key == NULL) {
            flb_ra_destroy(kv_node->ra);
            flb_free(kv_node);
            flb_plg_error(plugin_instance,
                          "could not create label key '%s'",
                          key->str);
            return -1;
        }

        kv_node->val = cfl_sds_create(value->str);
        if (kv_node->val == NULL) {
            cfl_sds_destroy(kv_node->key);
            flb_ra_destroy(kv_node->ra);
            flb_free(kv_node);
            flb_plg_error(plugin_instance,
                          "could not create label value '%s'",
                          value->str);
            return -1;
        }

        cfl_list_add(&kv_node->_head, destination_list);
    }

    return 0;
}

static void destroy_label_kv_list(struct cfl_list *list)
{
    struct cfl_list  *tmp;
    struct cfl_list  *iterator;
    struct label_kv *kv_node;

    cfl_list_foreach_safe(iterator, tmp, list) {
        kv_node = cfl_list_entry(iterator, struct label_kv, _head);

        cfl_sds_destroy(kv_node->key);
        cfl_sds_destroy(kv_node->val);

        if (kv_node->ra != NULL) {
            flb_ra_destroy(kv_node->ra);
        }

        cfl_list_del(&kv_node->_head);
        flb_free(kv_node);
    }
}

static void destroy_context(struct internal_processor_context *context)
{
    if (context != NULL) {

        destroy_label_kv_list(&context->update_labels);
        destroy_label_kv_list(&context->insert_labels);
        destroy_label_kv_list(&context->upsert_labels);

        flb_slist_destroy(&context->delete_labels);
        flb_slist_destroy(&context->hash_labels);

        flb_free(context);
    }
}

static struct internal_processor_context *create_context(struct flb_processor_instance *processor_instance,
                                                         struct flb_config *config)
{
    int                                result;
    struct internal_processor_context *context;

    context = flb_calloc(1, sizeof(struct internal_processor_context));
    if (!context) {
        flb_errno();
        return NULL;
    }

    context->instance = processor_instance;
    context->config = config;

    cfl_list_init(&context->update_labels);
    cfl_list_init(&context->insert_labels);
    cfl_list_init(&context->upsert_labels);

    flb_slist_create(&context->delete_labels);
    flb_slist_create(&context->hash_labels);

    result = flb_processor_instance_config_map_set(processor_instance, (void *) context);

    if (result == 0) {
        result = process_label_modification_kvlist_setting(processor_instance,
                                                            "update",
                                                            context->update_list,
                                                            &context->update_labels);
    }

    if (result == 0) {
        result = process_label_modification_kvlist_setting(processor_instance,
                                                            "insert",
                                                            context->insert_list,
                                                            &context->insert_labels);
    }

    if (result == 0) {
        result = process_label_modification_kvlist_setting(processor_instance,
                                                            "upsert",
                                                            context->upsert_list,
                                                            &context->upsert_labels);
    }

    if (result == 0) {
        result = process_label_modification_list_setting(processor_instance,
                                                            "delete",
                                                            context->delete_list,
                                                            &context->delete_labels);
    }

    if (result == 0) {
        result = process_label_modification_list_setting(processor_instance,
                                                            "hash",
                                                            context->hash_list,
                                                            &context->hash_labels);
    }

    if (result != 0) {
        destroy_context(context);

        context = NULL;
    }

    return context;
}

static int cb_init(struct flb_processor_instance *processor_instance,
                   void *source_plugin_instance,
                   int source_plugin_type,
                   struct flb_config *config)
{
    processor_instance->context = (void *) create_context(
                                            processor_instance, config);

    if (processor_instance->context == NULL) {
        return FLB_PROCESSOR_FAILURE;
    }

    return FLB_PROCESSOR_SUCCESS;
}


static int cb_exit(struct flb_processor_instance *processor_instance, void *data)
{
    if (processor_instance != NULL && data != NULL) {
        destroy_context(data);
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int metrics_context_contains_static_label(struct cmt *metrics_context,
                                                 char *label_name)
{
    struct cfl_list  *label_iterator;
    struct cmt_label *label;

    cfl_list_foreach(label_iterator, &metrics_context->static_labels->list) {
        label = cfl_list_entry(label_iterator,
                               struct cmt_label, _head);

        if (strcasecmp(label_name, label->key) == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static int metrics_context_insert_static_label(struct cmt *metrics_context,
                                               char *label_name,
                                               char *label_value)
{
    if (cmt_label_add(metrics_context, label_name, label_value) != 0) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int metrics_context_update_static_label(struct cmt *metrics_context,
                                               char *label_name,
                                               char *label_value)
{
    struct cfl_list  *iterator;
    cfl_sds_t         result;
    struct cmt_label *label;

    cfl_list_foreach(iterator, &metrics_context->static_labels->list) {
        label = cfl_list_entry(iterator,
                               struct cmt_label, _head);

        if (strcasecmp(label_name, label->key) == 0) {
            cfl_sds_set_len(label->val, 0);

            result = cfl_sds_cat(label->val, label_value, strlen(label_value));

            if (result == NULL) {
                return FLB_FALSE;
            }

            label->val = result;

            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static int metrics_context_transform_static_label(struct cmt *metrics_context,
                                                  char *label_name,
                                                  label_transformer transformer)
{
    struct cfl_list  *iterator;
    struct cmt_label *label;

    cfl_list_foreach(iterator, &metrics_context->static_labels->list) {
        label = cfl_list_entry(iterator,
                               struct cmt_label, _head);

        if (strcasecmp(label_name, label->key) == 0) {
            return transformer(NULL, &label->val);
        }
    }

    return FLB_FALSE;
}

static int metrics_context_upsert_static_label(struct cmt *metrics_context,
                                               char *label_name,
                                               char *label_value)
{
    int result;

    result = metrics_context_contains_static_label(metrics_context,
                                                   label_name);

    if (result == FLB_TRUE) {
        return metrics_context_update_static_label(metrics_context,
                                                   label_name,
                                                   label_value);
    }

    return metrics_context_insert_static_label(metrics_context,
                                               label_name,
                                               label_value);
}

static int metrics_context_remove_static_label(struct cmt *metrics_context,
                                               char *label_name)
{
    struct cfl_list  *iterator;
    struct cmt_label *label;

    cfl_list_foreach(iterator,
                     &metrics_context->static_labels->list) {
        label = cfl_list_entry(iterator, struct cmt_label, _head);

        if (strcasecmp(label_name, label->key) == 0) {
            cmt_label_destroy(label);

            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static ssize_t metrics_map_get_label_index(struct cmt_map *map, char *label_name)
{
    struct cfl_list      *iterator;
    struct cmt_map_label *label;
    ssize_t               index;

    index = 0;

    cfl_list_foreach(iterator, &map->label_keys) {
        label = cfl_list_entry(iterator, struct cmt_map_label, _head);

        if (strcasecmp(label_name, label->name) == 0) {
            return index;
        }

        index++;
    }

    return -1;
}

static ssize_t metrics_map_insert_label_name(struct cmt_map *map, char *label_name)
{
    struct cmt_map_label *label;
    ssize_t               index;

    label = cmt_map_label_create(label_name);

    if (label == NULL) {
        return -1;
    }

    map->label_count++;

    cfl_list_add(&label->_head, &map->label_keys);

    index = (ssize_t) cfl_list_size(&map->label_keys);
    index--;

    return index;
}

static int metrics_map_contains_label(struct cmt_map *map, char *label_name)
{
    ssize_t result;

    result = metrics_map_get_label_index(map, label_name);

    if (result != -1) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int metrics_map_remove_label_name(struct cmt_map *map,
                                         size_t label_index)
{
    struct cfl_list      *iterator;
    struct cmt_map_label *label;
    size_t                index;

    index = 0;

    cfl_list_foreach(iterator, &map->label_keys) {
        label = cfl_list_entry(iterator, struct cmt_map_label, _head);

        if (label_index == index) {
            cmt_map_label_destroy(label);

            return FLB_TRUE;
        }

        index++;
    }

    return FLB_FALSE;
}

int metrics_data_point_remove_label_value(struct cmt_metric *metric,
                                          size_t label_index)
{
    struct cfl_list      *iterator;
    struct cmt_map_label *label;
    size_t                index;

    index = 0;

    cfl_list_foreach(iterator, &metric->labels) {
        label = cfl_list_entry(iterator, struct cmt_map_label, _head);

        if (label_index == index) {
            cmt_map_label_destroy(label);

            return FLB_TRUE;
        }

        index++;
    }

    return FLB_FALSE;
}

int metrics_data_point_transform_label_value(struct cmt_metric *metric,
                                             size_t label_index,
                                             label_transformer transformer)
{
    struct cfl_list      *iterator;
    struct cmt_map_label *label;
    size_t                index;

    index = 0;

    cfl_list_foreach(iterator, &metric->labels) {
        label = cfl_list_entry(iterator, struct cmt_map_label, _head);

        if (label_index == index) {
            return transformer(metric, &label->name);
        }

        index++;
    }

    return FLB_FALSE;
}

int metrics_data_point_set_label_value(struct cmt_metric *metric,
                                       size_t label_index,
                                       char *label_value,
                                       int overwrite,
                                       int insert)
{
    struct cmt_map_label *new_label;
    struct cfl_list      *iterator;
    cfl_sds_t             result;
    size_t                index;
    struct cmt_map_label *label;

    label = NULL;
    index = 0;

    cfl_list_foreach(iterator, &metric->labels) {
        label = cfl_list_entry(iterator, struct cmt_map_label, _head);

        if (label_index == index) {
            break;
        }

        index++;
    }

    if (label_index != index) {
        return FLB_FALSE;
    }

    if (insert == FLB_TRUE) {
        new_label = cmt_map_label_create(label_value);

        if (new_label == NULL) {
            return FLB_FALSE;
        }

        if (label != NULL) {
            cfl_list_add_after(&new_label->_head,
                               &label->_head,
                               &metric->labels);
        }
        else {
            cfl_list_append(&new_label->_head,
                            &metric->labels);
        }
    }
    else {
        if (label == NULL) {
            return FLB_FALSE;
        }

        if (label->name == NULL) {
            label->name = cfl_sds_create(label_value);

            if (label->name == NULL) {
                return FLB_FALSE;
            }
        }
        else {
            if (overwrite == FLB_TRUE ||
                cfl_sds_len(label->name) == 0) {
                cfl_sds_set_len(label->name, 0);

                result = cfl_sds_cat(label->name,
                                     label_value,
                                     strlen(label_value));

                if (result == NULL) {
                    return FLB_FALSE;
                }

                label->name = result;
            }
        }
    }

    return FLB_TRUE;
}


int metrics_map_convert_static_metric(struct cmt_map *map,
                                      size_t label_index,
                                      char *label_value)
{
    struct cmt_metric *metric;
    int                result;
    size_t             index;
    cfl_hash_state_t   state;
    uint64_t           hash;

    cfl_hash_64bits_reset(&state);

    cfl_hash_64bits_update(&state,
                           map->opts->fqname,
                           cfl_sds_len(map->opts->fqname));

    for (index = 0 ; index < map->label_count ; index++) {
        if (index != label_index) {
            cfl_hash_64bits_update(&state,
                                   "_NULL_",
                                   6);
        }
        else {
            cfl_hash_64bits_update(&state,
                                   label_value,
                                   strlen(label_value));
        }
    }

    hash = cfl_hash_64bits_digest(&state);

    metric = map_metric_create(hash, 0, NULL);

    if (metric == NULL) {
        return FLB_FALSE;
    }

    for (index = 0 ; index < map->label_count ; index++) {
        if (index != label_index) {
            result = metrics_data_point_set_label_value(metric,
                                                        index,
                                                        "",
                                                        FLB_TRUE,
                                                        FLB_TRUE);
        }
        else {
            result = metrics_data_point_set_label_value(metric,
                                                        index,
                                                        label_value,
                                                        FLB_TRUE,
                                                        FLB_TRUE);
        }

        if (result != FLB_TRUE) {
            map_metric_destroy(metric);

            return FLB_FALSE;
        }
    }

    metric->val = map->metric.val;

    metric->hist_buckets = map->metric.hist_buckets;
    metric->hist_count = map->metric.hist_count;
    metric->hist_sum = map->metric.hist_sum;

    metric->sum_quantiles_set = map->metric.sum_quantiles_set;
    metric->sum_quantiles = map->metric.sum_quantiles;
    metric->sum_quantiles_count = map->metric.sum_quantiles_count;
    metric->sum_count = map->metric.sum_count;
    metric->sum_sum = map->metric.sum_sum;

    metric->timestamp = map->metric.timestamp;

    map->metric_static_set = 0;

    cfl_list_add(&metric->_head, &map->metrics);

    memset(&map->metric, 0, sizeof(struct cmt_metric));

    return FLB_TRUE;
}

int metrics_map_remove_label_value(struct cmt_map *map,
                                   size_t label_index)
{
    struct cfl_list   *iterator;
    struct cmt_metric *metric;
    int                result;

    result = FLB_TRUE;

    cfl_list_foreach(iterator, &map->metrics) {
        metric = cfl_list_entry(iterator, struct cmt_metric, _head);

        result = metrics_data_point_remove_label_value(metric, label_index);

        if (result == FLB_FALSE) {
            break;
        }
    }

    return result;
}

int metrics_map_set_label_value(struct cmt_map *map,
                                size_t label_index,
                                char *label_value,
                                int overwrite,
                                int insert)
{
    struct cfl_list   *iterator;
    struct cmt_metric *metric;
    int                result;

    result = FLB_TRUE;

    cfl_list_foreach(iterator, &map->metrics) {
        metric = cfl_list_entry(iterator, struct cmt_metric, _head);

        result = metrics_data_point_set_label_value(metric,
                                                    label_index,
                                                    label_value,
                                                    overwrite,
                                                    insert);

        if (result == FLB_FALSE) {
            break;
        }
    }


#ifdef PROMOTE_STATIC_METRICS_ON_LABEL_INSERT
    if (map->metric_static_set == 1 && insert) {
        result = metrics_map_convert_static_metric(map,
                                                   label_index,
                                                   label_value);

        if(result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }
#endif

    return result;
}

int metrics_map_transform_label_value(struct cmt_map *map,
                                      size_t label_index,
                                      label_transformer transformer)
{
    struct cfl_list   *iterator;
    struct cmt_metric *metric;
    int                result;

    result = FLB_TRUE;

    cfl_list_foreach(iterator, &map->metrics) {
        metric = cfl_list_entry(iterator, struct cmt_metric, _head);

        result = metrics_data_point_transform_label_value(metric,
                                                          label_index,
                                                          transformer);

        if (result == FLB_FALSE) {
            break;
        }
    }

    return result;
}

int metrics_map_update_label(struct cmt_map *map,
                             char *label_name,
                             char *label_value)
{
    ssize_t label_index;
    int     result;

    label_index = metrics_map_get_label_index(map, label_name);
    if (label_index == -1) {
        return FLB_TRUE;
    }

    result = metrics_map_set_label_value(map,
                                         label_index,
                                         label_value,
                                         FLB_TRUE,
                                         FLB_FALSE);

    if(result == FLB_FALSE) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

int metrics_map_transform_label(struct cmt_map *map,
                                char *label_name,
                                label_transformer transformer)
{
    ssize_t label_index;
    int     result;

    label_index = metrics_map_get_label_index(map, label_name);

    if (label_index == -1) {
        return FLB_TRUE;
    }

    result = metrics_map_transform_label_value(map,
                                               label_index,
                                               transformer);

    if(result == FLB_FALSE) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

int metrics_map_insert_label(struct cmt_map *map,
                             char *label_name,
                             char *label_value)
{
    ssize_t label_index;
    int     label_added;
    int     result;

    label_added = FLB_FALSE;
    label_index = metrics_map_get_label_index(map, label_name);

    if (label_index == -1) {
        label_index = metrics_map_insert_label_name(map, label_name);
        label_added = FLB_TRUE;
    }

    if (label_index == -1) {
        return FLB_FALSE;
    }

    result = metrics_map_set_label_value(map,
                                         label_index,
                                         label_value,
                                         FLB_FALSE,
                                         label_added);

    if(result == FLB_FALSE) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

int metrics_map_upsert_label(struct cmt_map *map,
                             char *label_name,
                             char *label_value)
{
    ssize_t label_index;
    int     label_added;
    int     result;

    label_added = FLB_FALSE;
    label_index = metrics_map_get_label_index(map, label_name);

    if (label_index == -1) {
        label_index = metrics_map_insert_label_name(map, label_name);
        label_added = FLB_TRUE;
    }

    if (label_index == -1) {
        return FLB_FALSE;
    }

    result = metrics_map_set_label_value(map,
                                         label_index,
                                         label_value,
                                         FLB_TRUE,
                                         label_added);

    if(result == FLB_FALSE) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

int metrics_map_remove_label(struct cmt_map *map,
                             char *label_name)
{
    ssize_t label_index;
    int     result;

    label_index = metrics_map_get_label_index(map, label_name);

    if (label_index == -1) {
        return FLB_TRUE;
    }

    map->label_count--;

    result = metrics_map_remove_label_name(map, label_index);

    if(result == FLB_TRUE) {
        result = metrics_map_remove_label_value(map, label_index);
    }

    return result;
}

static int metrics_context_contains_dynamic_label(struct cmt *metrics_context,
                                                  char *label_name)
{
    struct cfl_list      *metric_iterator;
    struct cmt_histogram *histogram;
    struct cmt_summary   *summary;
    struct cmt_untyped   *untyped;
    struct cmt_counter   *counter;
    struct cmt_gauge     *gauge;

    cfl_list_foreach(metric_iterator, &metrics_context->histograms) {
        histogram = cfl_list_entry(metric_iterator, struct cmt_histogram, _head);

        if(metrics_map_contains_label(histogram->map, label_name) == FLB_TRUE) {
            return FLB_TRUE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->summaries) {
        summary = cfl_list_entry(metric_iterator, struct cmt_summary, _head);

        if(metrics_map_contains_label(summary->map, label_name) == FLB_TRUE) {
            return FLB_TRUE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->untypeds) {
        untyped = cfl_list_entry(metric_iterator, struct cmt_untyped, _head);

        if(metrics_map_contains_label(untyped->map, label_name) == FLB_TRUE) {
            return FLB_TRUE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->counters) {
        counter = cfl_list_entry(metric_iterator, struct cmt_counter, _head);

        if(metrics_map_contains_label(counter->map, label_name) == FLB_TRUE) {
            return FLB_TRUE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->gauges) {
        gauge = cfl_list_entry(metric_iterator, struct cmt_gauge, _head);

        if(metrics_map_contains_label(gauge->map, label_name) == FLB_TRUE) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static int metrics_context_insert_dynamic_label(struct cmt *metrics_context,
                                                char *label_name,
                                                char *label_value)
{
    struct cfl_list      *metric_iterator;
    struct cmt_histogram *histogram;
    struct cmt_summary   *summary;
    struct cmt_untyped   *untyped;
    struct cmt_counter   *counter;
    int                   result;
    struct cmt_gauge     *gauge;

    cfl_list_foreach(metric_iterator, &metrics_context->histograms) {
        histogram = cfl_list_entry(metric_iterator, struct cmt_histogram, _head);

        result = metrics_map_insert_label(histogram->map,
                                          label_name,
                                          label_value);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->summaries) {
        summary = cfl_list_entry(metric_iterator, struct cmt_summary, _head);

        result = metrics_map_insert_label(summary->map,
                                          label_name,
                                          label_value);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->untypeds) {
        untyped = cfl_list_entry(metric_iterator, struct cmt_untyped, _head);

        result = metrics_map_insert_label(untyped->map,
                                          label_name,
                                          label_value);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->counters) {
        counter = cfl_list_entry(metric_iterator, struct cmt_counter, _head);

        result = metrics_map_insert_label(counter->map,
                                          label_name,
                                          label_value);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->gauges) {
        gauge = cfl_list_entry(metric_iterator, struct cmt_gauge, _head);

        result = metrics_map_insert_label(gauge->map,
                                          label_name,
                                          label_value);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

static int metrics_context_update_dynamic_label(struct cmt *metrics_context,
                                                char *label_name,
                                                char *label_value)
{
    struct cfl_list      *metric_iterator;
    struct cmt_histogram *histogram;
    struct cmt_summary   *summary;
    struct cmt_untyped   *untyped;
    struct cmt_counter   *counter;
    int                   result;
    struct cmt_gauge     *gauge;

    cfl_list_foreach(metric_iterator, &metrics_context->histograms) {
        histogram = cfl_list_entry(metric_iterator, struct cmt_histogram, _head);

        result = metrics_map_update_label(histogram->map,
                                          label_name,
                                          label_value);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->summaries) {
        summary = cfl_list_entry(metric_iterator, struct cmt_summary, _head);

        result = metrics_map_update_label(summary->map,
                                          label_name,
                                          label_value);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->untypeds) {
        untyped = cfl_list_entry(metric_iterator, struct cmt_untyped, _head);

        result = metrics_map_update_label(untyped->map,
                                          label_name,
                                          label_value);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->counters) {
        counter = cfl_list_entry(metric_iterator, struct cmt_counter, _head);

        result = metrics_map_update_label(counter->map,
                                          label_name,
                                          label_value);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->gauges) {
        gauge = cfl_list_entry(metric_iterator, struct cmt_gauge, _head);

        result = metrics_map_update_label(gauge->map,
                                          label_name,
                                          label_value);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

static int metrics_context_transform_dynamic_label(struct cmt *metrics_context,
                                                   char *label_name,
                                                   label_transformer transformer)
{
    struct cfl_list      *metric_iterator;
    struct cmt_histogram *histogram;
    struct cmt_summary   *summary;
    struct cmt_untyped   *untyped;
    struct cmt_counter   *counter;
    int                   result;
    struct cmt_gauge     *gauge;

    cfl_list_foreach(metric_iterator, &metrics_context->histograms) {
        histogram = cfl_list_entry(metric_iterator, struct cmt_histogram, _head);

        result = metrics_map_transform_label(histogram->map,
                                             label_name,
                                             transformer);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->summaries) {
        summary = cfl_list_entry(metric_iterator, struct cmt_summary, _head);

        result = metrics_map_transform_label(summary->map,
                                             label_name,
                                             transformer);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->untypeds) {
        untyped = cfl_list_entry(metric_iterator, struct cmt_untyped, _head);

        result = metrics_map_transform_label(untyped->map,
                                             label_name,
                                             transformer);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->counters) {
        counter = cfl_list_entry(metric_iterator, struct cmt_counter, _head);

        result = metrics_map_transform_label(counter->map,
                                             label_name,
                                             transformer);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->gauges) {
        gauge = cfl_list_entry(metric_iterator, struct cmt_gauge, _head);

        result = metrics_map_transform_label(gauge->map,
                                             label_name,
                                             transformer);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

static int metrics_context_upsert_dynamic_label(struct cmt *metrics_context,
                                                char *label_name,
                                                char *label_value)
{
    struct cfl_list      *metric_iterator;
    struct cmt_histogram *histogram;
    struct cmt_summary   *summary;
    struct cmt_untyped   *untyped;
    struct cmt_counter   *counter;
    int                   result;
    struct cmt_gauge     *gauge;

    cfl_list_foreach(metric_iterator, &metrics_context->histograms) {
        histogram = cfl_list_entry(metric_iterator, struct cmt_histogram, _head);

        result = metrics_map_upsert_label(histogram->map,
                                          label_name,
                                          label_value);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->summaries) {
        summary = cfl_list_entry(metric_iterator, struct cmt_summary, _head);

        result = metrics_map_upsert_label(summary->map,
                                          label_name,
                                          label_value);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->untypeds) {
        untyped = cfl_list_entry(metric_iterator, struct cmt_untyped, _head);

        result = metrics_map_upsert_label(untyped->map,
                                          label_name,
                                          label_value);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->counters) {
        counter = cfl_list_entry(metric_iterator, struct cmt_counter, _head);

        result = metrics_map_upsert_label(counter->map,
                                          label_name,
                                          label_value);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->gauges) {
        gauge = cfl_list_entry(metric_iterator, struct cmt_gauge, _head);

        result = metrics_map_upsert_label(gauge->map,
                                          label_name,
                                          label_value);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

static int metrics_context_remove_dynamic_label(struct cmt *metrics_context,
                                                char *label_name)
{
    struct cfl_list      *metric_iterator;
    struct cmt_histogram *histogram;
    struct cmt_summary   *summary;
    struct cmt_untyped   *untyped;
    struct cmt_counter   *counter;
    int                   result;
    struct cmt_gauge     *gauge;

    cfl_list_foreach(metric_iterator, &metrics_context->histograms) {
        histogram = cfl_list_entry(metric_iterator, struct cmt_histogram, _head);

        result = metrics_map_remove_label(histogram->map,
                                          label_name);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->summaries) {
        summary = cfl_list_entry(metric_iterator, struct cmt_summary, _head);

        result = metrics_map_remove_label(summary->map,
                                          label_name);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->untypeds) {
        untyped = cfl_list_entry(metric_iterator, struct cmt_untyped, _head);

        result = metrics_map_remove_label(untyped->map,
                                          label_name);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->counters) {
        counter = cfl_list_entry(metric_iterator, struct cmt_counter, _head);

        result = metrics_map_remove_label(counter->map,
                                          label_name);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->gauges) {
        gauge = cfl_list_entry(metric_iterator, struct cmt_gauge, _head);

        result = metrics_map_remove_label(gauge->map,
                                          label_name);

        if (result == FLB_FALSE) {
            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

/*
 * Retrieve the value based on a potential record_accessor patern or a direct
 * mapping of the value set in the configuration. If the returned buffer
 * must be freed by the caller, then 'destroy_buf' will be set to FLB_TRUE,
 * otherwise it will be set to FLB_FALSE.
 */
static flb_sds_t get_label_value(struct label_kv *pair, char *tag, int tag_len, int *destroy_buf)
{
    flb_sds_t value;
    msgpack_object o = {0};

    *destroy_buf = FLB_FALSE;

    if (pair->ra != NULL) {
        /* get the value using a record accessor pattern */
        value = flb_ra_translate(pair->ra, tag, tag_len, o, NULL);
        if (value == NULL) {
            return NULL;
        }
        *destroy_buf = FLB_TRUE;
    }
    else {
        /* use the pre-defined string */
        value = pair->val;
    }

    return value;
}

static int update_labels(struct cmt *metrics_context,
                         char *tag, int tag_len,
                         struct cfl_list *labels)
{
    int              result;
    int              destroy_buf = FLB_FALSE;
    struct cfl_list *iterator;
    struct label_kv *pair;
    flb_sds_t        value = NULL;

    cfl_list_foreach(iterator, labels) {
        pair = cfl_list_entry(iterator, struct label_kv, _head);

        result = metrics_context_contains_dynamic_label(metrics_context,
                                                        pair->key);
        value = get_label_value(pair, tag, tag_len, &destroy_buf);
        if (value == NULL) {
            return FLB_FALSE;
        }

        if (result == FLB_TRUE) {
            result = metrics_context_update_dynamic_label(metrics_context,
                                                          pair->key,
                                                          value);


            if (result == FLB_FALSE) {
                if (destroy_buf == FLB_TRUE) {
                    flb_sds_destroy(value);
                }
                return FLB_FALSE;
            }
        }

        result = metrics_context_contains_static_label(metrics_context,
                                                       pair->key);

        if (result == FLB_TRUE) {
            result = metrics_context_update_static_label(metrics_context,
                                                         pair->key,
                                                         value);

            if (result == FLB_FALSE) {
                if (destroy_buf == FLB_TRUE) {
                    flb_sds_destroy(value);
                }
                return FLB_FALSE;
            }
        }
    }

    if (destroy_buf == FLB_TRUE) {
        flb_sds_destroy(value);
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int insert_labels(struct cmt *metrics_context,
                         char *tag, int tag_len,
                         struct cfl_list *labels)
{
    int              result;
    int              destroy_buf = FLB_FALSE;
    struct cfl_list *iterator;
    struct label_kv *pair;
    flb_sds_t        value = NULL;

    cfl_list_foreach(iterator, labels) {
        pair = cfl_list_entry(iterator, struct label_kv, _head);

        value = get_label_value(pair, tag, tag_len, &destroy_buf);
        if (value == NULL) {
            return FLB_FALSE;
        }

        /* check if the label exists in the metrics labels list (dynamic) */
        result = metrics_context_contains_dynamic_label(metrics_context,
                                                        pair->key);
        if (result == FLB_FALSE) {
            /* retrieve the new label */
            result = metrics_context_insert_dynamic_label(metrics_context,
                                                        pair->key,
                                                        value);

            if (result == FLB_FALSE) {
                if (destroy_buf == FLB_TRUE) {
                    flb_sds_destroy(value);
                }
                return FLB_FALSE;
            }
        }

        /* static label: metric with no labels that needs to be moved to dynamic */
        result = metrics_context_contains_static_label(metrics_context,
                                                       pair->key);

        if (result == FLB_TRUE) {
            result = metrics_context_insert_static_label(metrics_context,
                                                         pair->key,
                                                         value);


            if (result == FLB_FALSE) {
                if (destroy_buf == FLB_TRUE) {
                    flb_sds_destroy(value);
                }
                return FLB_FALSE;
            }
        }
    }

    if (destroy_buf == FLB_TRUE) {
        flb_sds_destroy(value);
    }

    return FLB_PROCESSOR_SUCCESS;
}


static int upsert_labels(struct cmt *metrics_context,
                         char *tag, int tag_len,
                         struct cfl_list *labels)
{
    int              result;
    int destroy_buf = FLB_FALSE;
    struct cfl_list *iterator;
    struct label_kv  *pair;
    flb_sds_t value = NULL;

    cfl_list_foreach(iterator, labels) {
        pair = cfl_list_entry(iterator, struct label_kv, _head);

        value = get_label_value(pair, tag, tag_len, &destroy_buf);
        if (value == NULL) {
            return FLB_FALSE;
        }

        result = metrics_context_contains_dynamic_label(metrics_context,
                                                        pair->key);

        if (result == FLB_TRUE) {
            result = metrics_context_upsert_dynamic_label(metrics_context,
                                                          pair->key,
                                                          value);

            if (result == FLB_FALSE) {
                if (destroy_buf == FLB_TRUE) {
                    flb_sds_destroy(value);
                }
                return FLB_FALSE;
            }
        }
        else {
            result = metrics_context_upsert_static_label(metrics_context,
                                                         pair->key,
                                                         value);

            if (result == FLB_FALSE) {
                if (destroy_buf == FLB_TRUE) {
                    flb_sds_destroy(value);
                }
                return FLB_FALSE;
            }
        }
    }

    if (destroy_buf == FLB_TRUE) {
        flb_sds_destroy(value);
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int delete_labels(struct cmt *metrics_context,
                         struct mk_list *labels)
{
    struct mk_list         *iterator;
    int                     result;
    struct flb_slist_entry *entry;

    mk_list_foreach(iterator, labels) {
        entry = mk_list_entry(iterator, struct flb_slist_entry, _head);

        result = metrics_context_contains_dynamic_label(metrics_context,
                                                        entry->str);

        if (result == FLB_TRUE) {
            result = metrics_context_remove_dynamic_label(metrics_context,
                                                          entry->str);

            if (result == FLB_FALSE) {
                return FLB_FALSE;
            }
        }
        else {
            result = metrics_context_contains_static_label(metrics_context,
                                                           entry->str);

            if (result == FLB_TRUE) {
                result = metrics_context_remove_static_label(metrics_context,
                                                             entry->str);

                if (result == FLB_FALSE) {
                    return FLB_FALSE;
                }
            }
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int hash_transformer(struct cmt_metric *metric, cfl_sds_t *value)
{
    unsigned char digest_buffer[32];
    int           result;

    if (value == NULL) {
        return FLB_FALSE;
    }

    if (cfl_sds_len(*value) == 0) {
        return FLB_TRUE;
    }

    result = flb_hash_simple(FLB_HASH_SHA256,
                             (unsigned char *) *value,
                             cfl_sds_len(*value),
                             digest_buffer,
                             sizeof(digest_buffer));

    if (result != FLB_CRYPTO_SUCCESS) {
        return FLB_FALSE;
    }

    return hex_encode(digest_buffer, sizeof(digest_buffer), value);
}

static int hash_labels(struct cmt *metrics_context,
                       struct mk_list *labels)
{
    struct mk_list         *iterator;
    int                     result;
    struct flb_slist_entry *entry;

    mk_list_foreach(iterator, labels) {
        entry = mk_list_entry(iterator, struct flb_slist_entry, _head);

        result = metrics_context_contains_dynamic_label(metrics_context,
                                                        entry->str);

        if (result == FLB_TRUE) {
            result = metrics_context_transform_dynamic_label(metrics_context,
                                                             entry->str,
                                                             hash_transformer);

            if (result == FLB_FALSE) {
                return FLB_FALSE;
            }
        }
        else {
            result = metrics_context_contains_static_label(metrics_context,
                                                           entry->str);

            if (result == FLB_TRUE) {
                result = metrics_context_transform_static_label(metrics_context,
                                                                entry->str,
                                                                hash_transformer);

                if (result == FLB_FALSE) {
                    return FLB_FALSE;
                }
            }
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_process_metrics(struct flb_processor_instance *processor_instance,
                              struct cmt *metrics_context,
                              struct cmt **out_context,
                              const char *tag,
                              int tag_len)
{
    struct cmt                        *out_cmt;
    struct internal_processor_context *processor_context;
    int                                result;

    processor_context =
        (struct internal_processor_context *) processor_instance->context;

    out_cmt = cmt_create();
    if (out_cmt == NULL) {
        flb_plg_error(processor_instance, "could not create out_cmt context");
        return FLB_PROCESSOR_FAILURE;
    }

    result = cmt_cat(out_cmt, metrics_context);
    if (result != 0) {
        cmt_destroy(out_cmt);

        return FLB_PROCESSOR_FAILURE;
    }

    result = delete_labels(out_cmt,
                           &processor_context->delete_labels);

    if (result == FLB_PROCESSOR_SUCCESS) {
        result = update_labels(out_cmt, (char *) tag, tag_len,
                               &processor_context->update_labels);
    }

    if (result == FLB_PROCESSOR_SUCCESS) {
        result = upsert_labels(out_cmt, (char *) tag, tag_len,
                               &processor_context->upsert_labels);
    }

    if (result == FLB_PROCESSOR_SUCCESS) {
        result = insert_labels(out_cmt, (char *) tag, tag_len,
                               &processor_context->insert_labels);
    }

    if (result == FLB_PROCESSOR_SUCCESS) {
        result = hash_labels(out_cmt,
                             &processor_context->hash_labels);
    }

    if (result != FLB_PROCESSOR_SUCCESS) {
        return FLB_PROCESSOR_FAILURE;
    }

    *out_context = out_cmt;
    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_SLIST_1, "update", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                update_list),
        "Updates a label. Usage : 'update label_name value'"
    },
    {
        FLB_CONFIG_MAP_SLIST_1, "insert", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                insert_list),
        "Inserts a label. Usage : 'insert label_name value'"
    },
    {
        FLB_CONFIG_MAP_SLIST_1, "upsert", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                upsert_list),
        "Inserts or updates a label. Usage : 'upsert label_name value'"
    },
    {
        FLB_CONFIG_MAP_STR, "delete", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                delete_list),
        "Deletes a label. Usage : 'delete label_name'"
    },
    {
        FLB_CONFIG_MAP_STR, "hash", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                hash_list),
        "Replaces a labels value with its SHA1 hash. Usage : 'hash label_name'"
    },

    /* EOF */
    {0}
};

struct flb_processor_plugin processor_labels_plugin = {
    .name               = "labels",
    .description        = "Modifies metrics labels",
    .cb_init            = cb_init,
    .cb_process_logs    = NULL,
    .cb_process_metrics = cb_process_metrics,
    .cb_process_traces  = NULL,
    .cb_exit            = cb_exit,
    .config_map         = config_map,
    .flags              = 0
};
