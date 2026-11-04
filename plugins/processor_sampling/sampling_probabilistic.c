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

#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <fluent-bit/flb_random.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_map.h>
#include <math.h>
#include <errno.h>

#include "sampling.h"

struct sampling_settings {
    flb_sds_t percentage_str;
    flb_sds_t sampling_key;
    double sampling_percentage;
    uint64_t random_state;
};

static struct flb_config_map settings_config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "sampling_percentage", "10",
        0, FLB_TRUE, offsetof(struct sampling_settings, percentage_str),
        "Percentage to retain, from 0 through 100 (fractional values supported)."
    },
    {
        FLB_CONFIG_MAP_STR, "sampling_key", "trace_id",
        0, FLB_TRUE, offsetof(struct sampling_settings, sampling_key),
        "Log body or metadata string field used for deterministic sampling."
    },
    {0}
};

/* FNV-1a over all bytes: independent of machine byte order and batch boundaries. */
static uint64_t sampling_hash(const void *data, size_t len, uint64_t hash)
{
    const unsigned char *bytes = data;
    size_t i;

    for (i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

/* Avalanche short and structured identifiers before applying a threshold. */
static int sampling_keep(struct sampling_settings *settings, uint64_t hash)
{
    hash ^= hash >> 33;
    hash *= UINT64_C(0xff51afd7ed558ccd);
    hash ^= hash >> 33;
    hash *= UINT64_C(0xc4ceb9fe1a85ec53);
    hash ^= hash >> 33;

    return (double) (hash >> 11) / 9007199254740992.0 <
           settings->sampling_percentage / 100.0;
}

static int cb_init(struct flb_config *config, struct sampling *ctx)
{
    int ret;
    char *end;
    struct sampling_settings *settings;

    settings = flb_calloc(1, sizeof(struct sampling_settings));
    if (!settings) {
        return -1;
    }
    ret = flb_config_map_set(config, &ctx->plugin_settings_properties,
                             ctx->plugin_config_map, settings);
    if (ret == -1) {
        flb_free(settings);
        return -1;
    }

    if (!settings->percentage_str || !settings->sampling_key) {
        flb_plg_error(ctx->ins, "sampling_percentage and sampling_key must be nonempty");
        flb_free(settings);
        return -1;
    }

    errno = 0;
    settings->sampling_percentage = strtod(settings->percentage_str, &end);
    if (errno || end == settings->percentage_str || *end != '\0' ||
        !isfinite(settings->sampling_percentage) || settings->sampling_percentage < 0 ||
        settings->sampling_percentage > 100 || flb_sds_len(settings->sampling_key) == 0) {
        flb_plg_error(ctx->ins, "sampling_percentage must be a finite number in [0, 100] "
                      "and sampling_key must be nonempty");
        flb_free(settings);
        return -1;
    }
    if (flb_random_bytes((unsigned char *) &settings->random_state,
                         sizeof(settings->random_state)) != 0) {
        flb_free(settings);
        return -1;
    }
    sampling_set_context(ctx, settings);
    return 0;
}

static int valid_trace_id(const unsigned char *id, size_t len)
{
    size_t i;
    unsigned char bits = 0;

    if (len != 16) {
        return FLB_FALSE;
    }
    for (i = 0; i < len; i++) {
        bits |= id[i];
    }
    return bits != 0;
}

static int cb_do_sampling(struct sampling *ctx, void *plugin_context,
                          struct ctrace *in_ctr, struct ctrace **out_ctr)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct ctrace_span *span;
    struct sampling_settings *settings = plugin_context;

    cfl_list_foreach_safe(head, tmp, &in_ctr->span_list) {
        span = cfl_list_entry(head, struct ctrace_span, _head_global);
        if (!span->trace_id ||
            !valid_trace_id((unsigned char *) span->trace_id->buf,
                            cfl_sds_len(span->trace_id->buf)) ||
            !sampling_keep(settings, sampling_hash(span->trace_id->buf, 16,
                                                    UINT64_C(14695981039346656037)))) {
            ctr_span_destroy(span);
        }
    }
    *out_ctr = in_ctr;
    return FLB_PROCESSOR_SUCCESS;
}

static struct cfl_variant *map_field(struct cfl_variant *map, const char *key)
{
    if (!map || map->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }
    return cfl_kvlist_fetch(map->data.as_kvlist, (char *) key);
}

static int hex_digit(unsigned char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

int sampling_probabilistic_logs(struct flb_processor_instance *ins, void *chunk_data,
                                 const char *tag, int tag_len)
{
    int ret;
    int record_type;
    int high;
    int low;
    int has_key;
    size_t i;
    size_t len;
    uint64_t hash;
    unsigned char trace_id[16];
    const void *data;
    struct sampling *ctx = ins->context;
    struct sampling_settings *settings = ctx->plugin_context;
    struct flb_mp_chunk_cobj *chunk = chunk_data;
    struct flb_mp_chunk_record *record;
    struct cfl_variant *value;

    while ((ret = flb_mp_chunk_cobj_record_next(chunk, &record)) == FLB_MP_CHUNK_RECORD_OK) {
        if (flb_log_event_decoder_get_record_type(&record->event, &record_type) !=
            FLB_EVENT_DECODER_SUCCESS) {
            return FLB_PROCESSOR_FAILURE;
        }
        if (record_type != FLB_LOG_EVENT_NORMAL) {
            continue;
        }
        value = map_field(map_field(record->cobj_metadata->variant, "otlp"),
                          settings->sampling_key);
        if (!value) {
            value = map_field(record->cobj_metadata->variant, settings->sampling_key);
        }
        if (!value) {
            value = map_field(record->cobj_record->variant, settings->sampling_key);
        }
        has_key = FLB_FALSE;
        if (value && value->size > 0 &&
            (value->type == CFL_VARIANT_STRING || value->type == CFL_VARIANT_BYTES)) {
            data = value->data.as_string;
            len = value->size;
            /* Normalize hex trace IDs so logs and spans make the same decision. */
            if (strcmp(settings->sampling_key, "trace_id") == 0 && len == 32) {
                for (i = 0; i < 16; i++) {
                    high = hex_digit(((const unsigned char *) data)[i * 2]);
                    low = hex_digit(((const unsigned char *) data)[i * 2 + 1]);
                    if (high < 0 || low < 0) {
                        break;
                    }
                    trace_id[i] = (high << 4) | low;
                }
                if (i == 16) {
                    data = trace_id;
                    len = 16;
                }
            }
            if (strcmp(settings->sampling_key, "trace_id") != 0 || valid_trace_id(data, len)) {
                hash = sampling_hash(data, len, UINT64_C(14695981039346656037));
                has_key = FLB_TRUE;
            }
        }
        if (!has_key) {
            /* A random seed plus an avalanched counter avoids per-record syscalls. */
            settings->random_state += UINT64_C(0x9e3779b97f4a7c15);
            hash = settings->random_state;
        }
        if (!sampling_keep(settings, hash)) {
            flb_mp_chunk_cobj_record_destroy(chunk, record);
        }
    }
    return ret == FLB_MP_CHUNK_RECORD_EOF ? FLB_PROCESSOR_SUCCESS : FLB_PROCESSOR_FAILURE;
}

static void sample_metric_map(struct sampling_settings *settings, struct cmt_map *map)
{
    uint64_t base;
    uint64_t hash;
    uint64_t pair_hash;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cfl_list *key_head;
    struct cfl_list *value_head;
    struct cmt_metric *metric;
    struct cmt_map_label *key;
    struct cmt_map_label *value;

    base = sampling_hash(map->opts->fqname, cfl_sds_len(map->opts->fqname),
                         UINT64_C(14695981039346656037));
    if (map->metric_static_set && !sampling_keep(settings, base)) {
        map->metric_static_set = 0;
    }
    cfl_list_foreach_safe(head, tmp, &map->metrics) {
        metric = cfl_list_entry(head, struct cmt_metric, _head);
        hash = base;
        key_head = map->label_keys.next;
        cfl_list_foreach(value_head, &metric->labels) {
            if (key_head == &map->label_keys) {
                break;
            }
            key = cfl_list_entry(key_head, struct cmt_map_label, _head);
            value = cfl_list_entry(value_head, struct cmt_map_label, _head);
            pair_hash = sampling_hash(key->name, cfl_sds_len(key->name),
                                      UINT64_C(14695981039346656037));
            pair_hash = sampling_hash("\0", 1, pair_hash);
            if (value->name) {
                pair_hash = sampling_hash(value->name, cfl_sds_len(value->name), pair_hash);
            }
            /* Label order must not change the series decision. */
            hash ^= pair_hash;
            key_head = key_head->next;
        }
        if (!sampling_keep(settings, hash)) {
            cmt_map_metric_destroy(metric);
        }
    }
}

#define SAMPLE_FAMILIES(list, type, destroy) \
    cfl_list_foreach_safe(head, tmp, &in_cmt->list) { \
        struct type *family = cfl_list_entry(head, struct type, _head); \
        sample_metric_map(settings, family->map); \
        if (!family->map->metric_static_set && cfl_list_is_empty(&family->map->metrics)) { \
            destroy(family); \
        } \
    }

int sampling_probabilistic_metrics(struct flb_processor_instance *ins, struct cmt *in_cmt,
                                    struct cmt **out_cmt, const char *tag, int tag_len)
{
    struct sampling *ctx = ins->context;
    struct sampling_settings *settings = ctx->plugin_context;
    struct cfl_list *head;
    struct cfl_list *tmp;

    SAMPLE_FAMILIES(counters, cmt_counter, cmt_counter_destroy);
    SAMPLE_FAMILIES(gauges, cmt_gauge, cmt_gauge_destroy);
    SAMPLE_FAMILIES(histograms, cmt_histogram, cmt_histogram_destroy);
    SAMPLE_FAMILIES(exp_histograms, cmt_exp_histogram, cmt_exp_histogram_destroy);
    SAMPLE_FAMILIES(summaries, cmt_summary, cmt_summary_destroy);
    SAMPLE_FAMILIES(untypeds, cmt_untyped, cmt_untyped_destroy);
    *out_cmt = in_cmt;
    return FLB_PROCESSOR_SUCCESS;
}

static int cb_exit(struct flb_config *config, void *data)
{
    flb_free(data);
    return 0;
}

struct sampling_plugin sampling_probabilistic_plugin = {
    .type           = SAMPLING_TYPE_PROBABILISTIC,
    .name           = "probabilistic",
    .config_map     = settings_config_map,
    .cb_init        = cb_init,
    .cb_do_sampling = cb_do_sampling,
    .cb_exit        = cb_exit,
};
