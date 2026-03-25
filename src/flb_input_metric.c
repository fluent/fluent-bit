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

#include <stdint.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_input_metric.h>
#include <fluent-bit/flb_input_plugin.h>
#include <cfl/cfl.h>
#include <cfl/cfl_kvlist.h>
#include <cmetrics/cmt_cat.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_label.h>

/*
 * Copy static labels from a source cmt context to a destination cmt context.
 * This ensures each batch retains the same static labels as the original.
 */
static int copy_static_labels(struct cmt *dst, struct cmt *src)
{
    int ret;
    struct cfl_list *head;
    struct cmt_label *label;

    if (src->static_labels == NULL) {
        return 0;
    }

    cfl_list_foreach(head, &src->static_labels->list) {
        label = cfl_list_entry(head, struct cmt_label, _head);
        ret = cmt_label_add(dst, label->key, label->val);
        if (ret != 0) {
            return -1;
        }
    }

    return 0;
}

/*
 * Deep-copy a cfl_kvlist by iterating its entries and inserting copies
 * into the destination. Handles string, int64, uint64, double, and bool
 * variant types. Nested kvlists and arrays are skipped (not typically
 * used in cmetrics metadata).
 */
static int copy_kvlist(struct cfl_kvlist *dst, struct cfl_kvlist *src)
{
    int ret;
    struct cfl_list *head;
    struct cfl_kvpair *pair;

    if (src == NULL || dst == NULL) {
        return 0;
    }

    cfl_list_foreach(head, &src->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);

        switch (pair->val->type) {
        case CFL_VARIANT_STRING:
            ret = cfl_kvlist_insert_string(dst, pair->key,
                                           pair->val->data.as_string);
            break;
        case CFL_VARIANT_INT:
            ret = cfl_kvlist_insert_int64(dst, pair->key,
                                          pair->val->data.as_int64);
            break;
        case CFL_VARIANT_UINT:
            ret = cfl_kvlist_insert_uint64(dst, pair->key,
                                           pair->val->data.as_uint64);
            break;
        case CFL_VARIANT_DOUBLE:
            ret = cfl_kvlist_insert_double(dst, pair->key,
                                           pair->val->data.as_double);
            break;
        case CFL_VARIANT_BOOL:
            ret = cfl_kvlist_insert_bool(dst, pair->key,
                                         pair->val->data.as_bool);
            break;
        case CFL_VARIANT_BYTES:
            ret = cfl_kvlist_insert_bytes(dst, pair->key,
                                          pair->val->data.as_bytes,
                                          pair->val->size, CFL_FALSE);
            break;
        default:
            /* Skip unsupported types (arrays, nested kvlists, references) */
            ret = 0;
            break;
        }

        if (ret != 0) {
            return -1;
        }
    }

    return 0;
}

/*
 * Copy internal and external metadata from a source cmt context to a
 * destination cmt context. This preserves OTLP resource/scope metadata
 * across batch splits.
 */
static int copy_metadata(struct cmt *dst, struct cmt *src)
{
    int ret;

    ret = copy_kvlist(dst->internal_metadata, src->internal_metadata);
    if (ret != 0) {
        return -1;
    }

    ret = copy_kvlist(dst->external_metadata, src->external_metadata);
    if (ret != 0) {
        return -1;
    }

    return 0;
}

/*
 * Split a large cmt context into multiple smaller batches and append each
 * one individually. This is used when the encoded metrics exceed the chunk
 * size limit (FLB_INPUT_CHUNK_FS_MAX_SIZE = 2MB).
 *
 * The approach: count total metric families across all 6 metric type lists,
 * estimate how many families fit per batch, then iterate through families
 * in order, building up temporary cmt contexts and flushing them.
 *
 * Note: if a mid-batch error occurs, previously appended batches are NOT
 * rolled back. This is acceptable because metrics consumers (e.g.,
 * Prometheus, OTLP) handle partial scrapes gracefully.
 *
 * Note: internal/external metadata (kvlists) are deep-copied into each
 * batch via copy_metadata() to preserve OTLP resource/scope attributes.
 */
static int input_metrics_split_and_append(struct flb_input_instance *ins,
                                          const char *tag, size_t tag_len,
                                          struct cmt *src,
                                          size_t total_encoded_size)
{
    int ret;
    int total_families;
    int families_per_batch;
    int batch_count = 0;
    int batches_sent = 0;
    uint64_t numerator;
    char *mt_buf;
    size_t mt_size;
    struct cmt *batch = NULL;
    struct cfl_list *head;
    struct cfl_list *tmp_head;

    /* Iteration variables used by the PROCESS_METRIC_LIST macro */
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;
    struct cmt_histogram *histogram;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_summary *summary;

    /* Count total metric families across all type lists */
    total_families = cfl_list_size(&src->counters) +
                     cfl_list_size(&src->gauges) +
                     cfl_list_size(&src->untypeds) +
                     cfl_list_size(&src->histograms) +
                     cfl_list_size(&src->exp_histograms) +
                     cfl_list_size(&src->summaries);

    if (total_families == 0) {
        return 0;
    }

    /*
     * Estimate how many families fit within the chunk size limit.
     * Use 64-bit arithmetic to avoid overflow on 32-bit platforms.
     * Ensure at least 1 family per batch to guarantee forward progress.
     */
    numerator = (uint64_t) total_families * FLB_INPUT_CHUNK_FS_MAX_SIZE;
    families_per_batch = (int) (numerator / total_encoded_size);
    if (families_per_batch < 1) {
        families_per_batch = 1;
    }

    flb_plg_debug(ins,
                  "metric batch split: total_families=%d "
                  "families_per_batch=%d encoded_size=%zu limit=%zu",
                  total_families, families_per_batch,
                  total_encoded_size, (size_t) FLB_INPUT_CHUNK_FS_MAX_SIZE);

/*
 * Macro to iterate one metric type list, adding families to the current
 * batch. When the batch reaches families_per_batch, it is encoded,
 * appended, and destroyed. A new batch is created for subsequent families.
 *
 * Parameters:
 *   list      - the cfl_list head in the source cmt (e.g., src->counters)
 *   type      - the C struct type (e.g., cmt_counter)
 *   cat_func  - the cmt_cat function (e.g., cmt_cat_counter)
 *   var       - a local variable of the correct pointer type
 */
#define PROCESS_METRIC_LIST(list, type, cat_func, var)                        \
    cfl_list_foreach_safe(head, tmp_head, &(list)) {                          \
        var = cfl_list_entry(head, struct type, _head);                       \
                                                                              \
        /* Create a new batch context if needed */                            \
        if (batch == NULL) {                                                  \
            batch = cmt_create();                                             \
            if (batch == NULL) {                                              \
                flb_plg_error(ins,                                            \
                              "could not create batch cmt context");          \
                goto error;                                                   \
            }                                                                 \
            ret = copy_static_labels(batch, src);                             \
            if (ret != 0) {                                                   \
                flb_plg_error(ins,                                            \
                              "could not copy static labels to batch");       \
                goto error;                                                   \
            }                                                                 \
            ret = copy_metadata(batch, src);                                  \
            if (ret != 0) {                                                   \
                flb_plg_error(ins,                                            \
                              "could not copy metadata to batch");            \
                goto error;                                                   \
            }                                                                 \
            batch_count = 0;                                                  \
        }                                                                     \
                                                                              \
        ret = cat_func(batch, var, NULL);                                     \
        if (ret != 0) {                                                       \
            flb_plg_error(ins,                                                \
                          "could not concatenate metric family into batch");  \
            goto error;                                                       \
        }                                                                     \
        batch_count++;                                                        \
                                                                              \
        /* Flush the batch if it has reached the target size */               \
        if (batch_count >= families_per_batch) {                              \
            ret = cmt_encode_msgpack_create(batch, &mt_buf, &mt_size);        \
            cmt_destroy(batch);                                               \
            batch = NULL;                                                     \
            if (ret != 0) {                                                   \
                flb_plg_error(ins, "could not encode metric batch");          \
                goto error;                                                   \
            }                                                                 \
            if (mt_size > FLB_INPUT_CHUNK_FS_MAX_SIZE &&                      \
                families_per_batch > 1) {                                     \
                families_per_batch = (families_per_batch + 1) / 2;            \
                flb_plg_debug(ins,                                            \
                              "batch %zu bytes exceeds limit, reducing "      \
                              "families_per_batch to %d",                     \
                              mt_size, families_per_batch);                   \
            }                                                                 \
            else if (mt_size > FLB_INPUT_CHUNK_FS_MAX_SIZE) {                 \
                flb_plg_warn(ins,                                             \
                             "metric batch (%zu bytes) still exceeds "        \
                             "chunk limit; cannot split further", mt_size);   \
            }                                                                 \
            ret = flb_input_chunk_append_raw(ins, FLB_INPUT_METRICS, 0,       \
                                             tag, tag_len,                    \
                                             mt_buf, mt_size);               \
            cmt_encode_msgpack_destroy(mt_buf);                               \
            if (ret != 0) {                                                   \
                flb_plg_error(ins, "could not append metric batch");          \
                goto error;                                                   \
            }                                                                 \
            batches_sent++;                                                   \
        }                                                                     \
    }

    /* Process all 6 metric type lists in order */
    PROCESS_METRIC_LIST(src->counters, cmt_counter, cmt_cat_counter, counter);
    PROCESS_METRIC_LIST(src->gauges, cmt_gauge, cmt_cat_gauge, gauge);
    PROCESS_METRIC_LIST(src->untypeds, cmt_untyped, cmt_cat_untyped, untyped);
    PROCESS_METRIC_LIST(src->histograms, cmt_histogram,
                        cmt_cat_histogram, histogram);
    PROCESS_METRIC_LIST(src->exp_histograms, cmt_exp_histogram,
                        cmt_cat_exp_histogram, exp_histogram);
    PROCESS_METRIC_LIST(src->summaries, cmt_summary,
                        cmt_cat_summary, summary);

#undef PROCESS_METRIC_LIST

    /* Flush any remaining families in the last partial batch */
    if (batch != NULL) {
        ret = cmt_encode_msgpack_create(batch, &mt_buf, &mt_size);
        cmt_destroy(batch);
        batch = NULL;
        if (ret != 0) {
            flb_plg_error(ins, "could not encode final metric batch");
            return -1;
        }
        if (mt_size > FLB_INPUT_CHUNK_FS_MAX_SIZE) {
            flb_plg_warn(ins,
                         "metric batch (%zu bytes) still exceeds "
                         "chunk limit; cannot split further", mt_size);
        }
        ret = flb_input_chunk_append_raw(ins, FLB_INPUT_METRICS, 0,
                                         tag, tag_len, mt_buf, mt_size);
        cmt_encode_msgpack_destroy(mt_buf);
        if (ret != 0) {
            flb_plg_error(ins, "could not append final metric batch");
            return -1;
        }
        batches_sent++;
    }

    flb_plg_debug(ins, "metric batch split complete: %d batches sent",
                  batches_sent);

    return 0;

error:
    if (batch != NULL) {
        cmt_destroy(batch);
    }
    return -1;
}

static int input_metrics_append(struct flb_input_instance *ins,
                                size_t processor_starting_stage,
                                const char *tag, size_t tag_len,
                                struct cmt *cmt)
{
    int ret;
    char *mt_buf;
    size_t mt_size;
    int processor_is_active;
    struct cmt *out_context = NULL;
    struct cmt *encode_context;

    processor_is_active = flb_processor_is_active(ins->processor);
    if (processor_is_active) {
        if (!tag) {
            if (ins->tag && ins->tag_len > 0) {
                tag = ins->tag;
                tag_len = ins->tag_len;
            }
            else {
                tag = ins->name;
                tag_len = strlen(ins->name);
            }
        }

        ret = flb_processor_run(ins->processor,
                                processor_starting_stage,
                                FLB_PROCESSOR_METRICS,
                                tag,
                                tag_len,
                                (char *) cmt, 0,
                                (void **)&out_context, NULL);

        if (ret == -1) {
            return -1;
        }
    }

    if (out_context) {
        encode_context = out_context;
    }
    else {
        encode_context = cmt;
    }

    /* Drop the context if it contains no metrics */
    if (encode_context == NULL || flb_metrics_is_empty(encode_context)) {
        if (out_context && out_context != cmt) {
            cmt_destroy(out_context);
        }
        return 0;
    }

    /* Convert metrics to msgpack */
    ret = cmt_encode_msgpack_create(encode_context, &mt_buf, &mt_size);
    if (ret != 0) {
        if (out_context && out_context != cmt) {
            cmt_destroy(out_context);
        }
        flb_plg_error(ins, "could not encode metrics");
        return -1;
    }

    /* Fast path: encoded metrics fit within the chunk size limit */
    if (mt_size <= FLB_INPUT_CHUNK_FS_MAX_SIZE) {
        if (out_context && out_context != cmt) {
            cmt_destroy(out_context);
        }

        ret = flb_input_chunk_append_raw(ins, FLB_INPUT_METRICS, 0,
                                         tag, tag_len, mt_buf, mt_size);
        cmt_encode_msgpack_destroy(mt_buf);
        return ret;
    }

    /*
     * Slow path: encoded metrics exceed the chunk size limit.
     * Free the oversized buffer and split into smaller batches.
     * We need encode_context alive for iteration, so defer its cleanup.
     */
    flb_plg_debug(ins,
                  "encoded metrics size %zu exceeds chunk limit %zu, splitting",
                  mt_size, (size_t) FLB_INPUT_CHUNK_FS_MAX_SIZE);

    cmt_encode_msgpack_destroy(mt_buf);

    ret = input_metrics_split_and_append(ins, tag, tag_len,
                                         encode_context, mt_size);

    if (out_context && out_context != cmt) {
        cmt_destroy(out_context);
    }

    return ret;
}

/* Take a metric context and enqueue it as a Metric's Chunk */
int flb_input_metrics_append(struct flb_input_instance *ins,
                             const char *tag, size_t tag_len,
                             struct cmt *cmt)
{
    return input_metrics_append(ins,
                                0,
                                tag, tag_len,
                                cmt);
}

/* Take a metric context and enqueue it as a Metric's Chunk */
int flb_input_metrics_append_skip_processor_stages(
        struct flb_input_instance *ins,
        size_t processor_starting_stage,
        const char *tag, size_t tag_len,
        struct cmt *cmt)
{
    return input_metrics_append(ins,
                                processor_starting_stage,
                                tag, tag_len,
                                cmt);
}
