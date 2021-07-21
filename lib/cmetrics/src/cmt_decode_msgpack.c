/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021 Eduardo Silva <eduardo@calyptia.com>
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

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_sds.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_compat.h>
#include <cmetrics/cmt_encode_msgpack.h>
#include <cmetrics/cmt_decode_msgpack.h>

#include <mpack/mpack.h>

static struct cmt_map_label *find_label_by_index(struct mk_list *label_list, size_t desired_index)
{
    struct mk_list *head;
    size_t          entry_index;

    entry_index = 0;

    mk_list_foreach(head, label_list) {
        if (entry_index == desired_index) {
            return mk_list_entry(head, struct cmt_map_label, _head);
        }

        entry_index++;
    }

    return NULL;
}

static int unpack_opts_ns(mpack_reader_t *reader, size_t index, void *context)
{
    struct cmt_opts *opts;

    opts = (struct cmt_opts *) context;

    return cmt_mpack_consume_string_tag(reader, &opts->namespace);
}

static int unpack_opts_ss(mpack_reader_t *reader, size_t index, void *context)
{
    struct cmt_opts *opts;

    opts = (struct cmt_opts *) context;

    return cmt_mpack_consume_string_tag(reader, &opts->subsystem);
}

static int unpack_opts_name(mpack_reader_t *reader, size_t index, void *context)
{
    struct cmt_opts *opts;

    opts = (struct cmt_opts *) context;

    return cmt_mpack_consume_string_tag(reader, &opts->name);
}

static int unpack_opts_desc(mpack_reader_t *reader, size_t index, void *context)
{
    struct cmt_opts *opts;

    opts = (struct cmt_opts *) context;

    return cmt_mpack_consume_string_tag(reader, &opts->description);
}

static int unpack_opts(mpack_reader_t *reader, struct cmt_opts *opts)
{
    int                                   result;
    struct cmt_mpack_map_entry_callback_t callbacks[] = {
                                                            {"ns",     unpack_opts_ns},
                                                            {"ss",     unpack_opts_ss},
                                                            {"name",   unpack_opts_name},
                                                            {"desc",   unpack_opts_desc},
                                                            {NULL,     NULL}
                                                        };

    if (NULL == reader ||
        NULL == opts   ) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    memset(opts, 0, sizeof(struct cmt_opts));

    result = cmt_mpack_unpack_map(reader, callbacks, (void *) opts);

    if (CMT_DECODE_MSGPACK_SUCCESS == result) {
        /* Allocate enough space for the three components, the separators
         * and the terminator so we don't have to worry about possible realloc issues
         * later on.
         */

        opts->fqname = cmt_sds_create_size(cmt_sds_len(opts->namespace) + \
                                           cmt_sds_len(opts->subsystem) + \
                                           cmt_sds_len(opts->name) + \
                                           4);

        if (NULL == opts->fqname) {
            return CMT_DECODE_MSGPACK_ALLOCATION_ERROR;
        }

        cmt_sds_cat(opts->fqname, opts->namespace, cmt_sds_len(opts->namespace));
        cmt_sds_cat(opts->fqname, "_", 1);

        if (cmt_sds_len(opts->subsystem) > 0) {
            cmt_sds_cat(opts->fqname, opts->subsystem, cmt_sds_len(opts->subsystem));
            cmt_sds_cat(opts->fqname, "_", 1);
        }
        cmt_sds_cat(opts->fqname, opts->name, cmt_sds_len(opts->name));
    }

    return result;
}

static int unpack_label_dictionary_entry(mpack_reader_t *reader,
                                         size_t index,
                                         void *context)
{
    int                   result;
    struct cmt_map_label *new_label;
    cmt_sds_t             label_name;
    struct mk_list       *target_label_list;

    if (NULL == reader  ||
        NULL == context ) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    target_label_list = (struct mk_list *) context;

    result = cmt_mpack_consume_string_tag(reader, &label_name);

    if (CMT_DECODE_MSGPACK_SUCCESS != result) {
        cmt_sds_destroy(label_name);
        return result;
    }

    new_label = calloc(1, sizeof(struct cmt_map_label));

    if (NULL == new_label) {
        cmt_sds_destroy(label_name);

        return CMT_DECODE_MSGPACK_ALLOCATION_ERROR;
    }
    else
    {
        new_label->name = label_name;

        mk_list_add(&new_label->_head, target_label_list);
    }

    return CMT_DECODE_MSGPACK_SUCCESS;
}

static int unpack_label(mpack_reader_t *reader,
                        size_t index,
                        struct mk_list *unique_label_list,
                        struct mk_list *target_label_list)
{
    int                   result;
    struct cmt_map_label *new_label;
    uint64_t              label_index;
    struct cmt_map_label *dictionary_entry;

    if (NULL == reader            ||
        NULL == unique_label_list ||
        NULL == target_label_list ) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    result = cmt_mpack_consume_uint_tag(reader, &label_index);

    if (CMT_DECODE_MSGPACK_SUCCESS != result) {
        return result;
    }

    dictionary_entry = find_label_by_index(unique_label_list, label_index);

    if (NULL == dictionary_entry) {
        return CMT_DECODE_MSGPACK_DICTIONARY_LOOKUP_ERROR;
    }

    new_label = calloc(1, sizeof(struct cmt_map_label));

    if (NULL == new_label) {
        return CMT_DECODE_MSGPACK_ALLOCATION_ERROR;
    }
    else {
        new_label->name = cmt_sds_create(dictionary_entry->name);

        if (NULL == new_label->name) {
            free(new_label);

            return CMT_DECODE_MSGPACK_ALLOCATION_ERROR;
        }

        mk_list_add(&new_label->_head, target_label_list);
    }

    return CMT_DECODE_MSGPACK_SUCCESS;
}

static int unpack_static_label(mpack_reader_t *reader,
                               size_t index,
                               struct mk_list *unique_label_list,
                               struct mk_list *target_label_list)
{
    int                   result;
    uint64_t              label_index;
    struct cmt_label     *new_static_label;
    struct cmt_label     *last_static_label;
    struct cmt_map_label *dictionary_entry;

    if (NULL == reader            ||
        NULL == unique_label_list ||
        NULL == target_label_list ) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    result = cmt_mpack_consume_uint_tag(reader, &label_index);

    if (CMT_DECODE_MSGPACK_SUCCESS != result) {
        return result;
    }

    dictionary_entry = find_label_by_index(unique_label_list, label_index);

    if (NULL == dictionary_entry) {
        return CMT_DECODE_MSGPACK_DICTIONARY_LOOKUP_ERROR;
    }

    if (0 == (index % 2)) {
        new_static_label = calloc(1, sizeof(struct cmt_label));

        if (NULL == new_static_label) {
            return CMT_DECODE_MSGPACK_ALLOCATION_ERROR;
        }
        else {
            new_static_label->key = cmt_sds_create(dictionary_entry->name);

            if (NULL == new_static_label->key) {
                free(new_static_label);

                return CMT_DECODE_MSGPACK_ALLOCATION_ERROR;
            }

            new_static_label->val = NULL;

            mk_list_add(&new_static_label->_head, target_label_list);
        }
    }
    else {
        last_static_label = mk_list_entry_last(target_label_list, struct cmt_label, _head);

        if (NULL == last_static_label) {
            return CMT_DECODE_MSGPACK_DICTIONARY_LOOKUP_ERROR; /* Not quite */
        }

        last_static_label->val = cmt_sds_create(dictionary_entry->name);

        if (NULL == last_static_label->val) {
            return CMT_DECODE_MSGPACK_ALLOCATION_ERROR;
        }
    }

    return CMT_DECODE_MSGPACK_SUCCESS;
}

static int unpack_metric_label(mpack_reader_t *reader, size_t index, void *context)
{
    struct cmt_msgpack_decode_context *decode_context;

    if (NULL == reader  ||
        NULL == context ) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    decode_context = (struct cmt_msgpack_decode_context *) context;

    return unpack_label(reader,
                        index,
                        &decode_context->unique_label_list,
                        &decode_context->metric->labels);
}

static int unpack_metric_ts(mpack_reader_t *reader, size_t index, void *context)
{
    struct cmt_msgpack_decode_context *decode_context;

    if (NULL == reader  ||
        NULL == context ) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    decode_context = (struct cmt_msgpack_decode_context *) context;

    return cmt_mpack_consume_uint_tag(reader, &decode_context->metric->timestamp);
}

static int unpack_metric_value(mpack_reader_t *reader, size_t index, void *context)
{
    double                             value;
    int                                result;
    struct cmt_msgpack_decode_context *decode_context;

    if (NULL == reader  ||
        NULL == context ) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    decode_context = (struct cmt_msgpack_decode_context *) context;

    result = cmt_mpack_consume_double_tag(reader, &value);

    if(CMT_DECODE_MSGPACK_SUCCESS == result) {
        decode_context->metric->val = cmt_math_d64_to_uint64(value);
    }

    return result;
}

static int unpack_metric_labels(mpack_reader_t *reader, size_t index, void *context)
{
    if (NULL == reader ||
        NULL == context) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cmt_mpack_unpack_array(reader,
                                  unpack_metric_label,
                                  context);
}

static int unpack_metric(mpack_reader_t *reader,
                         struct cmt_msgpack_decode_context *decode_context,
                         struct cmt_metric **out_metric)
{
    int                                   result;
    struct cmt_metric                    *metric;
    struct cmt_mpack_map_entry_callback_t callbacks[] = \
        {
            {"ts",     unpack_metric_ts},
            {"value",  unpack_metric_value},
            {"labels", unpack_metric_labels},
            {NULL,     NULL}
        };

    if (NULL == reader         ||
        NULL == decode_context ||
        NULL == out_metric) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    /* Maybe we could move this cmt_metric constructor code to its own file, add a
     * destructor and update map_metric_create and map_metric_destroy to use them right?
     */

    metric = calloc(1, sizeof(struct cmt_metric));

    if (NULL == metric) {
        return CMT_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    mk_list_init(&metric->labels);

    decode_context->metric = metric;

    result = cmt_mpack_unpack_map(reader, callbacks, (void *) decode_context);

    if (CMT_DECODE_MSGPACK_SUCCESS != result) {
        destroy_label_list(&metric->labels);

        free(metric);
    }
    else {
        *out_metric = metric;
    }

    return result;
}

static int unpack_metric_array_entry(mpack_reader_t *reader, size_t index, void *context)
{
    int                                result;
    struct cmt_metric                 *metric;
    struct cmt_msgpack_decode_context *decode_context;

    if (NULL == reader ||
        NULL == context) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    decode_context = (struct cmt_msgpack_decode_context *) context;

    metric = NULL;
    result = unpack_metric(reader, decode_context, &metric);

    if (CMT_DECODE_MSGPACK_SUCCESS == result) {
        if (0 == mk_list_size(&metric->labels)) {
            /* Should we care about finding more than one "implicitly static metric" in
             * the array?
             */

            decode_context->map->metric_static_set = 1;

            decode_context->map->metric.val = metric->val;
            decode_context->map->metric.hash = metric->hash;
            decode_context->map->metric.timestamp = metric->timestamp;

            free(metric);
        }
        else
        {
            mk_list_add(&metric->_head, &decode_context->map->metrics);
        }
    }

    return result;
}

static int unpack_meta_ver(mpack_reader_t *reader, size_t index, void *context)
{
    uint64_t                           value;
    int                                result;

    if (NULL == reader ||
        NULL == context) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    result = cmt_mpack_consume_uint_tag(reader, &value);

    if (CMT_DECODE_MSGPACK_SUCCESS == result) {
        if (MSGPACK_ENCODER_VERSION != value)  {
            result = CMT_DECODE_MSGPACK_VERSION_ERROR;
        }
    }

    return result;
}

static int unpack_meta_type(mpack_reader_t *reader, size_t index, void *context)
{
    uint64_t                           value;
    int                                result;
    struct cmt_msgpack_decode_context *decode_context;

    if (NULL == reader ||
        NULL == context) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    decode_context = (struct cmt_msgpack_decode_context *) context;

    result = cmt_mpack_consume_uint_tag(reader, &value);

    if (CMT_DECODE_MSGPACK_SUCCESS == result) {
        decode_context->map->type = value;
    }

    return result;
}

static int unpack_meta_opts(mpack_reader_t *reader, size_t index, void *context)
{
    struct cmt_msgpack_decode_context *decode_context;

    if (NULL == reader ||
        NULL == context) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    decode_context = (struct cmt_msgpack_decode_context *) context;

    return unpack_opts(reader, decode_context->map->opts);
}

static int unpack_meta_label_dictionary(mpack_reader_t *reader, size_t index, void *context)
{
    struct cmt_msgpack_decode_context *decode_context;

    if (NULL == reader ||
        NULL == context) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    decode_context = (struct cmt_msgpack_decode_context *) context;

    return cmt_mpack_unpack_array(reader, unpack_label_dictionary_entry,
                                  (void *) &decode_context->unique_label_list);
}

static int unpack_header_static_label(mpack_reader_t *reader, size_t index, void *context)
{
    struct cmt_msgpack_decode_context *decode_context;

    if (NULL == reader ||
        NULL == context) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    decode_context = (struct cmt_msgpack_decode_context *) context;

    return unpack_static_label(reader, index,
                               &decode_context->unique_label_list,
                               &decode_context->cmt->static_labels->list);
}

static int unpack_meta_label(mpack_reader_t *reader, size_t index, void *context)
{
    struct cmt_msgpack_decode_context *decode_context;

    if (NULL == reader ||
        NULL == context) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    decode_context = (struct cmt_msgpack_decode_context *) context;

    return unpack_label(reader, index,
                        &decode_context->unique_label_list,
                        &decode_context->map->label_keys);
}

static int unpack_meta_static_labels(mpack_reader_t *reader, size_t index, void *context)
{
    if (NULL == reader ||
        NULL == context) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cmt_mpack_unpack_array(reader, unpack_header_static_label, context);
}

static int unpack_meta_labels(mpack_reader_t *reader, size_t index, void *context)
{
    if (NULL == reader ||
        NULL == context) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cmt_mpack_unpack_array(reader, unpack_meta_label, context);
}

static int unpack_basic_type_meta(mpack_reader_t *reader, size_t index, void *context)
{
    int                                   result;
    struct cmt_msgpack_decode_context    *decode_context;
    struct cmt_mpack_map_entry_callback_t callbacks[] = \
        {
            {"ver",              unpack_meta_ver},
            {"type",             unpack_meta_type},
            {"opts",             unpack_meta_opts},
            {"label_dictionary", unpack_meta_label_dictionary},
            {"static_labels",    unpack_meta_static_labels},
            {"labels",           unpack_meta_labels},
            {NULL,               NULL}
        };

    if (NULL == reader ||
        NULL == context) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    decode_context = (struct cmt_msgpack_decode_context *) context;

    result = cmt_mpack_unpack_map(reader, callbacks, context);

    if (CMT_DECODE_MSGPACK_SUCCESS == result) {
        decode_context->map->label_count = mk_list_size(&decode_context->map->label_keys);
    }

    return result;
}

static int unpack_basic_type_values(mpack_reader_t *reader, size_t index, void *context)
{
    if (NULL == reader ||
        NULL == context) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cmt_mpack_unpack_array(reader,
                                  unpack_metric_array_entry,
                                  context);
}

static int unpack_basic_type(mpack_reader_t *reader, struct cmt *cmt, struct cmt_map **map)
{
    int                                   result;
    struct cmt_msgpack_decode_context     decode_context;
    struct cmt_mpack_map_entry_callback_t callbacks[] = \
        {
            {"meta",   unpack_basic_type_meta},
            {"values", unpack_basic_type_values},
            {NULL,     NULL}
        };

    if (NULL == reader ||
        NULL == map) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    *map = cmt_map_create(0, NULL, 0, NULL);

    if (NULL == *map) {
        return CMT_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    (*map)->metric_static_set = 0;
    (*map)->opts = calloc(1, sizeof(struct cmt_opts));

    if (NULL == (*map)->opts) {
        cmt_map_destroy(*map);

        return CMT_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    decode_context.cmt = cmt;
    decode_context.map = *map;

    mk_list_init(&decode_context.unique_label_list);

    result = cmt_mpack_unpack_map(reader, callbacks, (void *) &decode_context);

    if (CMT_DECODE_MSGPACK_SUCCESS != result) {
        cmt_map_destroy(*map);
        free((*map)->opts);

        *map = NULL;
    }

    destroy_label_list(&decode_context.unique_label_list);

    return result;
}

static int append_unpacked_counter_to_metrics_context(struct cmt *context,
                                                      struct cmt_map *map)
{
    struct cmt_counter *counter;

    if (NULL == context ||
        NULL == map     ) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    counter = calloc(1, sizeof(struct cmt_counter));

    if (NULL == counter) {
        return CMT_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    counter->map = map;

    memcpy(&counter->opts, map->opts, sizeof(struct cmt_opts));

    free(map->opts);

    map->opts = &counter->opts;

    mk_list_add(&counter->_head, &context->counters);

    return CMT_DECODE_MSGPACK_SUCCESS;
}

static int append_unpacked_gauge_to_metrics_context(struct cmt *context,
                                                    struct cmt_map *map)
{
    struct cmt_gauge *gauge;

    if (NULL == context ||
        NULL == map     ) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    gauge = calloc(1, sizeof(struct cmt_gauge));

    if (NULL == gauge) {
        return CMT_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    gauge->map = map;

    memcpy(&gauge->opts, map->opts, sizeof(struct cmt_opts));

    free(map->opts);

    map->opts = &gauge->opts;

    mk_list_add(&gauge->_head, &context->gauges);

    return CMT_DECODE_MSGPACK_SUCCESS;
}

static int append_unpacked_untyped_to_metrics_context(struct cmt *context,
                                                      struct cmt_map *map)
{
    struct cmt_untyped *untyped;

    if (NULL == context ||
        NULL == map     ) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    untyped = calloc(1, sizeof(struct cmt_untyped));
    if (NULL == untyped) {
        return CMT_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    untyped->map = map;

    memcpy(&untyped->opts, map->opts, sizeof(struct cmt_opts));

    free(map->opts);

    map->opts = &untyped->opts;

    mk_list_add(&untyped->_head, &context->untypeds);

    return CMT_DECODE_MSGPACK_SUCCESS;
}

static int unpack_basic_type_entry(mpack_reader_t *reader, size_t index, void *context)
{
    int             result;
    struct cmt     *cmt;
    struct cmt_map *map;

    if (NULL == reader ||
        NULL == context) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    cmt = (struct cmt *) context;

    result = unpack_basic_type(reader, cmt, &map);

    if (CMT_DECODE_MSGPACK_SUCCESS == result) {
        if (CMT_COUNTER == map->type) {
            result = append_unpacked_counter_to_metrics_context(cmt, map);
        }
        else if (CMT_GAUGE == map->type) {
            result = append_unpacked_gauge_to_metrics_context(cmt, map);
        }
        else if (CMT_HISTOGRAM == map->type) {
            // result = append_unpacked_histogram_to_metrics_context(cmt, map);
        }
        else if (CMT_UNTYPED == map->type) {
            result = append_unpacked_untyped_to_metrics_context(cmt, map);
        }
    }

    return result;
}

static int unpack_basic_type_entries(mpack_reader_t *reader, struct cmt *cmt)
{
    if (NULL == reader ||
        NULL == cmt) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cmt_mpack_unpack_array(reader,
                                  unpack_basic_type_entry,
                                  (void *) cmt);
}

/* Convert cmetrics msgpack payload and generate a CMetrics context */
int cmt_decode_msgpack_create(struct cmt **out_cmt, char *in_buf, size_t in_size,
                              size_t *offset)
{
    struct cmt     *cmt;
    mpack_reader_t  reader;
    int             result;
    size_t          remainder;

    if (NULL == out_cmt ||
        NULL == in_buf ||
        NULL == offset ||
        in_size < *offset ) {
        return CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    if (0 == in_size ||
        0 == (in_size - *offset) ) {
        return CMT_DECODE_MSGPACK_INSUFFICIENT_DATA;
    }

    cmt = cmt_create();

    if (NULL == cmt) {
        return CMT_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    in_size -= *offset;

    mpack_reader_init_data(&reader, &in_buf[*offset], in_size);

    result = unpack_basic_type_entries(&reader, cmt);

    remainder = mpack_reader_remaining(&reader, NULL);

    *offset += in_size - remainder;

    result = mpack_reader_destroy(&reader);

    if (CMT_DECODE_MSGPACK_SUCCESS != result) {
        cmt_destroy(cmt);
    }
    else {
        *out_cmt = cmt;
    }

    return result;
}

void cmt_decode_msgpack_destroy(struct cmt *cmt)
{
    if (NULL != cmt) {
        cmt_destroy(cmt);
    }
}
