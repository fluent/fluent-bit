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

#include <fluent-bit/flb_mem.h>
#include <cmetrics/cmt_encode_opentelemetry.h>
#include <cmetrics/cmt_decode_opentelemetry.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_cat.h>
#include <cmetrics/cmt_otlp_metadata.h>
#include "fts_telemetry.h"
#include <stddef.h>

const struct fts_signal_adapter fts_metrics_adapter = {
    .event_type = FLB_PROCESSOR_METRICS,
    .register_helpers = fts_register_telemetry_helpers,
    .run_callback = fts_run_telemetry
};

static struct cfl_kvlist *map_at(struct cfl_kvlist *map, char *key)
{
    struct cfl_variant *value;
    struct cfl_kvlist *child;

    value = cfl_kvlist_fetch(map, key);
    if (value) {
        return value->type == CFL_VARIANT_KVLIST ? value->data.as_kvlist : NULL;
    }

    child = cfl_kvlist_create();
    if (!child || cfl_kvlist_insert_kvlist(map, key, child) != 0) {
        cfl_kvlist_destroy(child);
        return NULL;
    }

    return child;
}

static int copy_map(struct cfl_kvlist *dst, struct cfl_kvlist *src)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    struct cfl_variant *copy;

    cfl_list_foreach(head, &src->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        copy = fts_copy_value(pair->val, 0);
        if (!copy || cfl_kvlist_insert_s(dst, pair->key, cfl_sds_len(pair->key), copy) != 0) {
            cfl_variant_destroy(copy);
            return -1;
        }
    }

    return 0;
}

static int family_metadata(struct cmt *out, struct cmt *source, struct cmt_map *family,
                           const char *type, size_t resource_index)
{
    struct cfl_kvlist *metadata;

    if (!family->otlp_metadata) {
        family->otlp_metadata = cfl_kvlist_create();
    }

    if (!family->otlp_metadata) {
        return -1;
    }

    metadata = map_at(family->otlp_metadata, "routing");
    if (!metadata) {
        return -1;
    }

    cfl_kvlist_remove(metadata, "scope_flat_index");
    cfl_kvlist_remove(metadata, "resource_index");
    cfl_kvlist_remove(metadata, "scope_index");

    if (cfl_kvlist_insert_uint64(metadata, "resource_index", resource_index) != 0 ||
        cfl_kvlist_insert_uint64(metadata, "scope_index", 0) != 0) {
        return -1;
    }

    return 0;
}

/* Move complete families: concatenation would aggregate samples and lose identity. */
#define MOVE_FAMILIES(member, family_type, family, type_name)                       \
    cfl_list_foreach_safe(head, tmp, &source->member) {                            \
        family = cfl_list_entry(head, family_type, _head);                         \
        if (family_metadata(out, source, family->map, type_name, index) != 0) {    \
            goto failure;                                                          \
        }                                                                          \
        cfl_list_del(head);                                                        \
        cfl_list_add(head, &out->member);                                          \
        family->cmt = out;                                                         \
    }

static struct cmt *merge_contexts(struct cfl_list *contexts, struct cmt *input)
{
    struct cmt *out;
    struct cmt *source;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_histogram *histogram;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_summary *summary;
    struct cmt_untyped *untyped;
    struct cfl_list *context_head;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cfl_array *resources;
    struct cfl_kvlist *resource;
    struct cfl_variant *value;
    struct cfl_variant *copy;
    const char *keys[] = {"resource", "resource_metrics", "scope", "scope_metrics"};
    size_t i;
    size_t index = 0;

    out = cmt_create();
    if (!out) {
        return NULL;
    }

    if (copy_map(out->internal_metadata, input->internal_metadata) != 0 ||
        copy_map(out->external_metadata, input->external_metadata) != 0) {
        goto failure;
    }

    cfl_kvlist_remove(out->external_metadata, "resource_metrics_list");
    cfl_kvlist_remove(out->external_metadata, "otlp");

    resources = cfl_array_create(cfl_list_size(contexts));
    if (!resources ||
        cfl_kvlist_insert_array(out->external_metadata, "resource_metrics_list",
                                resources) != 0) {
        cfl_array_destroy(resources);
        goto failure;
    }

    cfl_list_foreach(context_head, contexts) {
        source = cfl_list_entry(context_head, struct cmt, _head);

        resource = cfl_kvlist_create();
        if (!resource || cfl_array_append_kvlist(resources, resource) != 0) {
            cfl_kvlist_destroy(resource);
            goto failure;
        }

        for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
            value = cfl_kvlist_fetch(source->external_metadata, (char *) keys[i]);
            if (value) {
                copy = fts_copy_value(value, 0);
                if (!copy || cfl_kvlist_insert(resource, (char *) keys[i], copy) != 0) {
                    cfl_variant_destroy(copy);
                    goto failure;
                }
            }
        }

        MOVE_FAMILIES(counters, struct cmt_counter, counter, "counter");
        MOVE_FAMILIES(gauges, struct cmt_gauge, gauge, "gauge");
        MOVE_FAMILIES(histograms, struct cmt_histogram, histogram, "histogram");
        MOVE_FAMILIES(exp_histograms, struct cmt_exp_histogram, exp_histogram, "exp_histogram");
        MOVE_FAMILIES(summaries, struct cmt_summary, summary, "summary");
        MOVE_FAMILIES(untypeds, struct cmt_untyped, untyped, "untyped");
        index++;
    }

    return out;

failure:
    cmt_destroy(out);
    return NULL;
}

/* OTLP scalars are int64 or double: uint64 values must fit int64 exactly. */
static int scalar_value_supported(struct cmt_metric *sample)
{
    if (cmt_metric_get_value_type(sample) != CMT_METRIC_VALUE_UINT64) {
        return FLB_TRUE;
    }

    return cmt_metric_get_uint64_value(sample) <= INT64_MAX;
}

static int scalar_values_supported(struct cmt_map *map)
{
    struct cfl_list *head;
    struct cmt_metric *sample;

    if (map->metric_static_set && !scalar_value_supported(&map->metric)) {
        return FLB_FALSE;
    }

    cfl_list_foreach(head, &map->metrics) {
        sample = cfl_list_entry(head, struct cmt_metric, _head);
        if (!scalar_value_supported(sample)) {
            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

struct unsupported_family {
    struct cfl_list *head;
    struct cfl_list *next;
    struct cmt_map *map;
    void *family;
    int type;
    struct cfl_kvlist *metadata;
};

/* Families are detached only while the input is encoded, then restored. */
#define DETACH_UNSUPPORTED(member, family_type, item, map_type)                     \
    cfl_list_foreach_safe(head, next, &input->member) {                            \
        item = cfl_list_entry(head, family_type, _head);                           \
        if (!scalar_values_supported(item->map)) {                                 \
            rejected[rejected_count].head = head;                                  \
            rejected[rejected_count].next = head->next;                            \
            rejected[rejected_count].map = item->map;                              \
            rejected[rejected_count].family = item;                                \
            rejected[rejected_count].type = map_type;                              \
            rejected_count++;                                                      \
            cfl_list_del(head);                                                    \
        }                                                                          \
    }

static uint64_t routing_value(struct cfl_kvlist *routing, char *key)
{
    struct cfl_variant *value;

    value = routing ? cfl_kvlist_fetch(routing, key) : NULL;
    if (value && value->type == CFL_VARIANT_UINT) {
        return value->data.as_uint64;
    }

    if (value && value->type == CFL_VARIANT_INT && value->data.as_int64 >= 0) {
        return (uint64_t) value->data.as_int64;
    }

    return 0;
}

/* Preserve the original contexts of families that cannot enter the OTLP API. */
static int prepare_rejected_families(struct cmt *out, struct cmt *input,
                                     struct unsupported_family *families, size_t count)
{
    struct cfl_variant *output_resources;
    struct cfl_variant *input_resources;
    struct cfl_variant *copy;
    struct cfl_variant *scopes;
    struct cfl_variant *flat;
    struct cfl_kvlist *resource;
    struct cfl_kvlist *routing;
    const char *keys[] = {"resource", "resource_metrics", "scope", "scope_metrics"};
    size_t offset;
    size_t index;
    size_t key_index;
    size_t resource_index;
    size_t scope_index;
    uint64_t flat_index;
    size_t scope_count;

    output_resources = cfl_kvlist_fetch(out->external_metadata, "resource_metrics_list");
    if (!output_resources || output_resources->type != CFL_VARIANT_ARRAY) {
        return -1;
    }

    cfl_array_resizable(output_resources->data.as_array, CFL_TRUE);
    offset = output_resources->data.as_array->entry_count;

    input_resources = cfl_kvlist_fetch(input->external_metadata, "resource_metrics_list");
    if (input_resources && input_resources->type == CFL_VARIANT_ARRAY &&
        input_resources->data.as_array->entry_count > 0) {
        for (index = 0; index < input_resources->data.as_array->entry_count; index++) {
            copy = fts_copy_value(input_resources->data.as_array->entries[index], 0);
            if (!copy || cfl_array_append(output_resources->data.as_array, copy) != 0) {
                cfl_variant_destroy(copy);
                return -1;
            }
        }
    }
    else {
        resource = cfl_kvlist_create();
        if (!resource || cfl_array_append_kvlist(output_resources->data.as_array, resource) != 0) {
            cfl_kvlist_destroy(resource);
            return -1;
        }

        for (key_index = 0; key_index < sizeof(keys) / sizeof(keys[0]); key_index++) {
            copy = cfl_kvlist_fetch(input->external_metadata, (char *) keys[key_index]);
            if (copy) {
                copy = fts_copy_value(copy, 0);
                if (!copy || cfl_kvlist_insert(resource, (char *) keys[key_index], copy) != 0) {
                    cfl_variant_destroy(copy);
                    return -1;
                }
            }
        }
    }

    for (index = 0; index < count; index++) {
        if (families[index].map->otlp_metadata) {
            families[index].metadata =
                cmt_otlp_metadata_clone(families[index].map->otlp_metadata);
        }
        else {
            families[index].metadata = cfl_kvlist_create();
        }

        if (!families[index].metadata) {
            return -1;
        }

        routing = map_at(families[index].metadata, "routing");
        if (!routing) {
            return -1;
        }

        resource_index = routing_value(routing, "resource_index");
        scope_index = routing_value(routing, "scope_index");

        flat = cfl_kvlist_fetch(routing, "scope_flat_index");
        if (flat && input_resources && input_resources->type == CFL_VARIANT_ARRAY) {
            flat_index = routing_value(routing, "scope_flat_index");
            for (resource_index = 0;
                 resource_index < input_resources->data.as_array->entry_count;
                 resource_index++) {
                copy = input_resources->data.as_array->entries[resource_index];
                if (copy->type == CFL_VARIANT_KVLIST) {
                    scopes = cfl_kvlist_fetch(copy->data.as_kvlist, "scope_metrics_list");
                }
                else {
                    scopes = NULL;
                }

                if (scopes && scopes->type == CFL_VARIANT_ARRAY &&
                    scopes->data.as_array->entry_count) {
                    scope_count = scopes->data.as_array->entry_count;
                }
                else {
                    scope_count = 1;
                }

                if (flat_index < scope_count) {
                    scope_index = flat_index;
                    break;
                }
                flat_index -= scope_count;
            }
        }

        if (resource_index >= output_resources->data.as_array->entry_count - offset) {
            resource_index = 0;
            scope_index = 0;
        }

        cfl_kvlist_remove(routing, "scope_flat_index");
        cfl_kvlist_remove(routing, "resource_index");
        cfl_kvlist_remove(routing, "scope_index");

        if (cfl_kvlist_insert_uint64(routing, "resource_index", offset + resource_index) != 0 ||
            cfl_kvlist_insert_uint64(routing, "scope_index", scope_index) != 0) {
            return -1;
        }
    }

    return 0;
}

/* The input context stays owned by its producer, so kept families are copied. */
static int copy_rejected_families(struct cmt *out, struct unsupported_family *families,
                                  size_t count)
{
    int ret;
    size_t index;
    struct cfl_list *list;
    struct cfl_list *head;
    struct cmt_map *map;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;

    for (index = 0; index < count; index++) {
        if (families[index].type == CMT_COUNTER) {
            ret = cmt_cat_counter(out, families[index].family, NULL);
            list = &out->counters;
        }
        else if (families[index].type == CMT_GAUGE) {
            ret = cmt_cat_gauge(out, families[index].family, NULL);
            list = &out->gauges;
        }
        else {
            ret = cmt_cat_untyped(out, families[index].family, NULL);
            list = &out->untypeds;
        }

        if (ret != 0) {
            return -1;
        }

        /* Attach the routing metadata prepared for this family to its copy. */
        map = NULL;
        cfl_list_foreach(head, list) {
            if (families[index].type == CMT_COUNTER) {
                counter = cfl_list_entry(head, struct cmt_counter, _head);
                map = counter->map;
            }
            else if (families[index].type == CMT_GAUGE) {
                gauge = cfl_list_entry(head, struct cmt_gauge, _head);
                map = gauge->map;
            }
            else {
                untyped = cfl_list_entry(head, struct cmt_untyped, _head);
                map = untyped->map;
            }

            if (strcmp(map->opts->fqname, families[index].map->opts->fqname) == 0) {
                break;
            }
            map = NULL;
        }

        if (!map) {
            return -1;
        }

        cfl_kvlist_destroy(map->otlp_metadata);
        map->otlp_metadata = families[index].metadata;
        families[index].metadata = NULL;
    }

    return 0;
}

int fts_process_metrics(struct flb_processor_instance *ins, struct cmt *input,
                        struct cmt **output, const char *tag, int tag_len)
{
    struct fts_runtime *ctx = ins->context;
    cfl_sds_t encoded;
    char *buffer = NULL;
    size_t size;
    size_t offset = 0;
    struct cfl_list contexts;
    struct cfl_list *head;
    struct cfl_list *next;
    struct unsupported_family *rejected = NULL;
    size_t rejected_count = 0;
    size_t family_count;
    size_t index;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;
    int ret;
    int handled_errors;
    const char *phase = "encode native metrics";

    *output = NULL;
    cfl_list_init(&contexts);

    family_count = cfl_list_size(&input->counters) + cfl_list_size(&input->gauges) +
                   cfl_list_size(&input->untypeds);
    if (family_count > 0) {
        rejected = flb_calloc(family_count, sizeof(*rejected));
        if (!rejected) {
            flb_errno();
            goto failure;
        }
    }

    DETACH_UNSUPPORTED(counters, struct cmt_counter, counter, CMT_COUNTER);
    DETACH_UNSUPPORTED(gauges, struct cmt_gauge, gauge, CMT_GAUGE);
    DETACH_UNSUPPORTED(untypeds, struct cmt_untyped, untyped, CMT_UNTYPED);

    encoded = cmt_encode_opentelemetry_create(input);

    /* Restore the exact input list order before invoking any policy. */
    for (index = rejected_count; index > 0; index--) {
        cfl_list_add(rejected[index - 1].head, rejected[index - 1].next);
    }

    if (!encoded) {
        goto failure;
    }

    phase = "transform metric policies";
    ret = fts_telemetry_transform(ins, encoded, cfl_sds_len(encoded), &buffer, &size,
                                  tag, tag_len);
    cmt_encode_opentelemetry_destroy(encoded);
    handled_errors = ret > 0;
    if (ret < 0) {
        goto failure;
    }

    phase = "decode transformed metrics";
    ret = size ? cmt_decode_opentelemetry_create(&contexts, buffer, size, &offset) : 0;
    flb_free(buffer);
    buffer = NULL;
    if (ret != 0) {
        goto failure;
    }

    phase = "merge native metric contexts";
    *output = merge_contexts(&contexts, input);
    cmt_decode_opentelemetry_destroy(&contexts);
    if (!*output) {
        goto failure;
    }

    if (rejected_count > 0) {
        if (strcmp(ctx->error_mode, "keep") == 0) {
            phase = "restore native uint64 family contexts";
            if (prepare_rejected_families(*output, input, rejected, rejected_count) != 0) {
                cmt_destroy(*output);
                *output = NULL;
                goto failure;
            }

            if (copy_rejected_families(*output, rejected, rejected_count) != 0) {
                cmt_destroy(*output);
                *output = NULL;
                goto failure;
            }
        }
        flb_plg_warn(ins, "FTS cannot process %zu native uint64 scalar families above "
                     "INT64_MAX; error_mode applied to these families", rejected_count);
    }

    if (handled_errors || rejected_count > 0) {
        fts_report_policy_error(ins);
    }

    flb_free(rejected);
    return FLB_PROCESSOR_SUCCESS;

failure:
    for (index = 0; index < rejected_count; index++) {
        cfl_kvlist_destroy(rejected[index].metadata);
    }
    flb_free(rejected);

    fts_report_policy_error(ins);
    flb_free(buffer);
    cmt_decode_opentelemetry_destroy(&contexts);
    flb_plg_error(ins, "cannot construct FTS metrics output (%s); edits discarded", phase);

    *output = strcmp(ctx->error_mode, "drop") == 0 ? cmt_create() : input;
    return *output ? FLB_PROCESSOR_SUCCESS : FLB_PROCESSOR_FAILURE;
}
