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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_hash_table.h>
#include <msgpack.h>

#include "rewrite_tag.h"

/* Create an emitter input instance */
static int emitter_create(struct flb_rewrite_tag *ctx)
{
    int ret;
    struct flb_input_instance *ins;

    ret = flb_input_name_exists(ctx->emitter_name, ctx->config);
    if (ret == FLB_TRUE) {
        flb_plg_error(ctx->ins, "emitter_name '%s' already exists",
                      ctx->emitter_name);
        return -1;
    }

    ins = flb_input_new(ctx->config, "emitter", NULL, FLB_FALSE);
    if (!ins) {
        flb_plg_error(ctx->ins, "cannot create emitter instance");
        return -1;
    }

    /* Set the alias name */
    ret = flb_input_set_property(ins, "alias", ctx->emitter_name);
    if (ret == -1) {
        flb_plg_warn(ctx->ins,
                     "cannot set emitter_name, using fallback name '%s'",
                     ins->name);
    }

    /* Set the emitter_mem_buf_limit */
    if(ctx->emitter_mem_buf_limit > 0) {
        ins->mem_buf_limit = ctx->emitter_mem_buf_limit;
    }

    /* Set the storage type */
    ret = flb_input_set_property(ins, "storage.type",
                                 ctx->emitter_storage_type);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot set storage.type");
    }

    /* Initialize emitter plugin */
    ret = flb_input_instance_init(ins, ctx->config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot initialize emitter instance '%s'",
                      ins->name);
        flb_input_instance_exit(ins, ctx->config);
        flb_input_instance_destroy(ins);
        return -1;
    }

#ifdef FLB_HAVE_METRICS
    /* Override Metrics title */
    ret = flb_metrics_title(ctx->emitter_name, ins->metrics);
    if (ret == -1) {
        flb_plg_warn(ctx->ins, "cannot set metrics title, using fallback name %s",
                     ins->name);
    }
#endif

    /* Storage context */
    ret = flb_storage_input_create(ctx->config->cio, ins);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot initialize storage for stream '%s'",
                      ctx->emitter_name);
        flb_input_instance_exit(ins, ctx->config);
        flb_input_instance_destroy(ins);
        return -1;
    }
    ctx->ins_emitter = ins;
    return 0;
}

/*
 * Validate and prepare internal contexts based on the received
 * config_map values.
 */
static int process_config(struct flb_rewrite_tag *ctx)
{
    struct mk_list *head;
    struct flb_slist_entry *entry;
    struct rewrite_rule *rule;
    struct flb_config_map_val *val;

    if (!ctx->cm_rules) {
        return -1;
    }

    mk_list_foreach(head, ctx->cm_rules) {
        /*
         * When multiple entries are allowed in a config map, this becomes
         * a list of struct flb_config_map_val. Every entry is linked in the
         * 'mult' field
         */
        val = mk_list_entry(head, struct flb_config_map_val, _head);

        /* Allocate a rule */
        rule = flb_malloc(sizeof(struct rewrite_rule));
        if (!rule) {
            flb_errno();
            return -1;
        }

        /* key */
        entry = flb_slist_entry_get(val->val.list, 0);
        if (entry == NULL) {
            flb_plg_error(ctx->ins, "failed to get entry");
            flb_free(rule);
            return -1;
        }
        rule->ra_key = flb_ra_create(entry->str, FLB_FALSE);
        if (!rule->ra_key) {
            flb_plg_error(ctx->ins, "invalid record accessor key ? '%s'",
                          entry->str);
            flb_free(rule);
            return -1;
        }

        /* regex */
        entry = flb_slist_entry_get(val->val.list, 1);
        rule->regex = flb_regex_create(entry->str);
        if (!rule->regex) {
            flb_plg_error(ctx->ins, "could not compile regex pattern '%s'",
                          entry->str);
            flb_ra_destroy(rule->ra_key);
            flb_free(rule);
            return -1;
        }

        /* tag */
        entry = flb_slist_entry_get(val->val.list, 2);
        rule->ra_tag = flb_ra_create(entry->str, FLB_FALSE);

        if (!rule->ra_tag) {
            flb_plg_error(ctx->ins, "could not compose tag: %s", entry->str);
            flb_ra_destroy(rule->ra_key);
            flb_regex_destroy(rule->regex);
            flb_free(rule);
            return -1;
        }

        /* keep record ? */
        entry = flb_slist_entry_get(val->val.list, 3);
        rule->keep_record = flb_utils_bool(entry->str);

        /* Link new rule */
        mk_list_add(&rule->_head, &ctx->rules);
    }

    if (mk_list_size(&ctx->rules) == 0) {
        flb_plg_warn(ctx->ins, "no rules have defined");
        return 0;
    }

    return 0;
}

static int is_wildcard(char* match)
{
    size_t len;
    size_t i;

    if (match == NULL) {
        return 0;
    }
    len = strlen(match);

    /* '***' should be ignored. So we check every char. */
    for (i=0; i<len; i++) {
        if (match[i] != '*') {
            return 0;
        }
    }
    return 1;
}

static int cb_rewrite_tag_init(struct flb_filter_instance *ins,
                               struct flb_config *config,
                               void *data)
{
    int ret;
    flb_sds_t tmp;
    flb_sds_t emitter_name = NULL;
    struct flb_rewrite_tag *ctx;
    struct flb_processor_unit *processor_unit;
    struct flb_processor *processor;
    (void) data;

    if (ins->parent_processor != NULL) {
        processor_unit = ins->parent_processor;
        processor = processor_unit->parent;
        if (processor->source_plugin_type != FLB_PLUGIN_INPUT) {
            flb_plg_error(ins, "rewrite_tag only supports input processors");
            return -1;
        }
    }

    /* Create context */
    ctx = flb_calloc(1, sizeof(struct flb_rewrite_tag));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    if (is_wildcard(ins->match)) {
        flb_plg_warn(ins, "'Match' may cause infinite loop.");
    }
    ctx->ins = ins;
    ctx->config = config;
    mk_list_init(&ctx->rules);

    /*
     * Emitter name: every rewrite_tag instance needs an emitter input plugin,
     * with that one is able to emit records. We use a unique instance so we
     * can use the metrics interface.
     *
     * If not set, we define an emitter name
     *
     * Validate if the emitter_name has been set before to check with the
     * config map. If is not set, do a manual set of the property, so we let the
     * config map handle the memory allocation.
     */
    tmp = (char *) flb_filter_get_property("emitter_name", ins);
    if (!tmp) {
        emitter_name = flb_sds_create_size(64);
        if (!emitter_name) {
            flb_free(ctx);
            return -1;
        }

        if (ins->parent_processor != NULL) {
            tmp = flb_sds_printf(&emitter_name, "emitter_for_%s_%s_%zu",
                                 ((struct flb_input_instance *) processor->data)->name,
                                 flb_filter_name(ins), processor_unit->stage);
        }
        else {
            tmp = flb_sds_printf(&emitter_name, "emitter_for_%s", flb_filter_name(ins));
        }
        if (!tmp) {
            flb_error("[filter rewrite_tag] cannot compose emitter_name");
            flb_sds_destroy(emitter_name);
            flb_free(ctx);
            return -1;
        }

        flb_filter_set_property(ins, "emitter_name", emitter_name);
        flb_sds_destroy(emitter_name);
    }

    /* Set config_map properties in our local context */
    ret = flb_filter_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    if (ctx->batch_size < 0 || ctx->batch_size > 4096) {
        flb_plg_error(ins, "batch_size must be between 0 and 4096");
        flb_free(ctx);
        return -1;
    }

    /*
     * Emitter Storage Type: the emitter input plugin to be created by default
     * uses memory buffer, this option allows to define a filesystem mechanism
     * for new records created (only if the main service is also filesystem
     * enabled).
     *
     * On this code we just validate the input type: 'memory' or 'filesystem'.
     */
    tmp = ctx->emitter_storage_type;
    if (strcasecmp(tmp, "memory") != 0 && strcasecmp(tmp, "filesystem") != 0) {
        flb_plg_error(ins, "invalid 'emitter_storage.type' value. Only "
                      "'memory' or 'filesystem' types are allowed");
        flb_free(ctx);
        return -1;
    }

    /* Set plugin context */
    flb_filter_set_context(ins, ctx);

    /* Process the configuration */
    ret = process_config(ctx);
    if (ret == -1) {
        return -1;
    }

    /* Create the emitter context */
    ret = emitter_create(ctx);
    if (ret == -1) {
        return -1;
    }

    /* Register a metric to count the number of emitted records */
#ifdef FLB_HAVE_METRICS
    ctx->cmt_emitted = cmt_counter_create(ins->cmt,
                                          "fluentbit", "filter", "emit_records_total",
                                          "Total number of emitted records",
                                          1, (char *[]) {"name"});

    /* OLD api */
    flb_metrics_add(FLB_RTAG_METRIC_EMITTED,
                    "emit_records", ctx->ins->metrics);
#endif

    return 0;
}

static int ingest_inline(struct flb_rewrite_tag *ctx,
                         flb_sds_t out_tag,
                         const void *buf, size_t buf_size)
{
    struct flb_input_instance *input_instance;
    struct flb_processor_unit *processor_unit;
    struct flb_processor      *processor;
    int                        result;

    if (ctx->ins->parent_processor != NULL) {
        processor_unit = (struct flb_processor_unit *) \
                            ctx->ins->parent_processor;
        processor = (struct flb_processor *) processor_unit->parent;
        input_instance = (struct flb_input_instance *) processor->data;

        if (processor->source_plugin_type == FLB_PLUGIN_INPUT) {
            result = flb_input_log_append_skip_processor_stages(
                        input_instance,
                        processor_unit->stage + 1,
                        out_tag, flb_sds_len(out_tag),
                        buf, buf_size);

            if (result == 0) {
                return FLB_TRUE;
            }
        }
    }

    return FLB_FALSE;
}


/* Find the first matching rule and expand its destination tag. */
static flb_sds_t match_record(const char *tag, int tag_len, msgpack_object map,
                              int *keep, struct flb_rewrite_tag *ctx)
{
    int ret;
    flb_sds_t out_tag;
    struct mk_list *head;
    struct rewrite_rule *rule = NULL;
    struct flb_regex_search result = {0};

    *keep = FLB_TRUE;

    mk_list_foreach(head, &ctx->rules) {
        rule = mk_list_entry(head, struct rewrite_rule, _head);
        if (rule) {
            *keep = rule->keep_record;
        }
        ret = flb_ra_regex_match(rule->ra_key, map, rule->regex, &result);
        if (ret < 0) { /* no match */
            rule = NULL;
            continue;
        }

        /* A record matched, just break and check 'rule' */
        break;
    }

    if (!rule) {
        return NULL;
    }

    /* Compose new tag */
    out_tag = flb_ra_translate(rule->ra_tag, (char *) tag, tag_len, map, &result);

    /* Release any capture info from 'results' */
    flb_regex_results_release(&result);

    if (out_tag == NULL || flb_sds_len(out_tag) == 0) {
        flb_sds_destroy(out_tag);
        *keep = FLB_TRUE;
        return NULL;
    }

    return out_tag;
}

static int process_record(const char *tag, int tag_len, msgpack_object map,
                          const void *buf, size_t buf_size, int *keep,
                          struct flb_rewrite_tag *ctx, int *matched,
                          struct flb_input_instance *i_ins)
{
    int ret;
    flb_sds_t out_tag;

    *matched = FLB_FALSE;
    out_tag = match_record(tag, tag_len, map, keep, ctx);
    if (out_tag == NULL) {
        return FLB_FALSE;
    }
    *matched = FLB_TRUE;

    ret = ingest_inline(ctx, out_tag, buf, buf_size);

    if (!ret) {
        /* Emit record with new tag */
        ret = in_emitter_add_record(out_tag, flb_sds_len(out_tag), buf, buf_size,
                                    ctx->ins_emitter, i_ins);
    }
    else {
        ret = 0;
    }

    /* Release the tag */
    flb_sds_destroy(out_tag);

    if (ret < 0) {
        *keep = FLB_TRUE;
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

/* Each emitted record must carry a complete group, independent of its tag. */
static int encode_grouped_record(struct flb_log_event_encoder *encoder,
                                 struct flb_log_event *event,
                                 const char *record, size_t length)
{
    int ret;

    flb_log_event_encoder_reset(encoder);
    ret = flb_log_event_encoder_group_init(encoder);
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_metadata_from_msgpack_object(
                encoder, event->group_metadata);
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_body_from_msgpack_object(
                encoder, event->group_attributes);
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_group_header_end(encoder);
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_emit_raw_record(encoder, record, length);
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_group_end(encoder);
    }

    return ret;
}

struct rewrite_batch {
    flb_sds_t tag;
    msgpack_sbuffer records;
    int emitted;
};

struct rewrite_batch_record {
    size_t offset;
    size_t length;
    int keep;
    struct rewrite_batch *batch;
};

/*
 * Prepare the entire callback before publishing anything. Retain every original
 * in one buffer, then compact it in place after emission; this requires no
 * allocation after side effects and preserves original order on failed appends.
 * Bound scratch space by accepting only small callbacks. Larger callbacks and
 * preparation failures use the existing record-at-a-time path.
 */
static int rewrite_tag_batch(struct flb_rewrite_tag *ctx,
                              struct flb_input_instance *input,
                              const void *data, size_t bytes,
                              const char *tag, int tag_len,
                              void **out_buf, size_t *out_bytes)
{
    int ret;
    int status = -1;
    int emitted = 0;
    int decoder_ready = FLB_FALSE;
    int encoder_ready = FLB_FALSE;
    size_t count;
    size_t index = 0;
    size_t batch_count = 0;
    size_t i;
    size_t retained = 0;
    size_t length;
    const char *record;
    flb_sds_t out_tag;
    msgpack_sbuffer originals;
    struct rewrite_batch *batches = NULL;
    struct rewrite_batch *batch;
    struct rewrite_batch_record *records = NULL;
    struct rewrite_batch_record *entry;
    struct flb_hash_table *tags = NULL;
    struct flb_log_event_decoder decoder;
    struct flb_log_event_encoder group_encoder;
    struct flb_log_event event;
#ifdef FLB_HAVE_METRICS
    uint64_t ts;
    char *name;
#endif

    if (bytes > FLB_INPUT_CHUNK_SIZE) {
        return -1;
    }
    count = flb_mp_count_log_records(data, bytes);
    if (count < 2 || count > ctx->batch_size) {
        return -1;
    }

    msgpack_sbuffer_init(&originals);
    records = flb_calloc(count, sizeof(*records));
    batches = flb_calloc(count, sizeof(*batches));
    tags = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 64, count);
    if (records == NULL || batches == NULL || tags == NULL) {
        goto cleanup;
    }
    ret = flb_log_event_decoder_init(&decoder, (char *) data, bytes);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        goto cleanup;
    }
    decoder_ready = FLB_TRUE;
    ret = flb_log_event_encoder_init(&group_encoder, FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        goto cleanup;
    }
    encoder_ready = FLB_TRUE;

    while ((ret = flb_log_event_decoder_next(&decoder, &event)) == FLB_EVENT_DECODER_SUCCESS) {
        if (index >= count) {
            goto cleanup;
        }
        record = decoder.record_base;
        length = decoder.record_length;
        if (event.group_metadata != NULL && event.group_attributes != NULL) {
            ret = encode_grouped_record(&group_encoder, &event, record, length);
            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                goto cleanup;
            }
            record = group_encoder.output_buffer;
            length = group_encoder.output_length;
        }
        /* Group expansion must not make the scratch payload unbounded. */
        if (length > FLB_INPUT_CHUNK_SIZE - originals.size) {
            goto cleanup;
        }
        entry = &records[index++];
        entry->offset = originals.size;
        entry->length = length;
        if (msgpack_sbuffer_write(&originals, record, length) != 0) {
            goto cleanup;
        }
        out_tag = match_record(tag, tag_len, *event.body, &entry->keep, ctx);
        if (out_tag == NULL) {
            continue;
        }
        batch = flb_hash_table_get_ptr(tags, out_tag, flb_sds_len(out_tag));
        if (batch == NULL) {
            batch = &batches[batch_count++];
            batch->tag = out_tag;
            msgpack_sbuffer_init(&batch->records);
            /* Avoid the default 8 KiB allocation for every distinct tag. */
            batch->records.data = flb_malloc(length);
            if (batch->records.data == NULL) {
                goto cleanup;
            }
            batch->records.alloc = length;
            ret = flb_hash_table_add(tags, out_tag, flb_sds_len(out_tag), batch, 0);
            if (ret < 0) {
                goto cleanup;
            }
        }
        else {
            flb_sds_destroy(out_tag);
        }
        entry->batch = batch;
        ret = msgpack_sbuffer_write(&batch->records,
                                    originals.data + entry->offset, length);
        if (ret != 0) {
            goto cleanup;
        }
    }
    if (ret != FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA ||
        decoder.offset != bytes || index != count) {
        goto cleanup;
    }

    flb_plg_debug(ctx->ins, "batching %zu records into %zu destination tags", count, batch_count);
    for (i = 0; i < batch_count; i++) {
        batch = &batches[i];
        batch->emitted = ingest_inline(ctx, batch->tag,
                                       batch->records.data, batch->records.size);
    }
    for (i = 0; i < count; i++) {
        entry = &records[i];
        batch = entry->batch;
        if (batch != NULL) {
            ret = 0;
            if (batch->emitted == FLB_FALSE) {
                /* Preserve the existing per-record emitter admission policy. */
                ret = in_emitter_add_record(batch->tag, flb_sds_len(batch->tag),
                                            originals.data + entry->offset, entry->length,
                                            ctx->ins_emitter, input);
            }
            if (ret < 0) {
                entry->keep = FLB_TRUE;
            }
            else {
                emitted++;
            }
        }
        if (batch == NULL || entry->keep == FLB_TRUE) {
            memmove(originals.data + retained,
                    originals.data + entry->offset, entry->length);
            retained += entry->length;
        }
    }

    status = FLB_FILTER_NOTOUCH;
    if (emitted > 0) {
#ifdef FLB_HAVE_METRICS
        ts = cfl_time_now();
        name = (char *) flb_filter_name(ctx->ins);
        cmt_counter_add(ctx->cmt_emitted, ts, emitted, 1, (char *[]) {name});
        flb_metrics_sum(FLB_RTAG_METRIC_EMITTED, emitted, ctx->ins->metrics);
#endif
        *out_buf = originals.data;
        *out_bytes = retained;
        originals.data = NULL;
        status = FLB_FILTER_MODIFIED;
    }

cleanup:
    if (decoder_ready) {
        flb_log_event_decoder_destroy(&decoder);
    }
    if (encoder_ready) {
        flb_log_event_encoder_destroy(&group_encoder);
    }
    if (tags != NULL) {
        flb_hash_table_destroy(tags);
    }
    for (i = 0; i < batch_count; i++) {
        flb_sds_destroy(batches[i].tag);
        msgpack_sbuffer_destroy(&batches[i].records);
    }
    flb_free(batches);
    flb_free(records);
    msgpack_sbuffer_destroy(&originals);
    return status;
}

static int cb_rewrite_tag_filter(const void *data, size_t bytes,
                                 const char *tag, int tag_len,
                                 void **out_buf, size_t *out_bytes,
                                 struct flb_filter_instance *f_ins,
                                 struct flb_input_instance *i_ins,
                                 void *filter_context,
                                 struct flb_config *config)
{
    int keep;
    int emitted_num = 0;
    int is_matched = FLB_FALSE;
    int is_emitted = FLB_FALSE;
    const char *record;
    size_t record_length;
#ifdef FLB_HAVE_METRICS
    uint64_t ts;
    char *name;
#endif
    msgpack_object map;
    struct flb_rewrite_tag *ctx;
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_encoder group_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int ret;

    (void) config;
    (void) i_ins;

    ctx = (struct flb_rewrite_tag *) filter_context;

    if (ctx->batch_size > 0 && f_ins->parent_processor != NULL) {
        ret = rewrite_tag_batch(ctx, i_ins, data, bytes, tag, tag_len, out_buf, out_bytes);
        if (ret != -1) {
            return ret;
        }
    }

#ifdef FLB_HAVE_METRICS
    ts = cfl_time_now();
    name = (char *) flb_filter_name(f_ins);
#endif

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return FLB_FILTER_NOTOUCH;
    }

    ret = flb_log_event_encoder_init(&log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event encoder initialization error : %d", ret);

        flb_log_event_decoder_destroy(&log_decoder);

        return FLB_FILTER_NOTOUCH;
    }

    ret = flb_log_event_encoder_init(&group_encoder, FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_decoder_destroy(&log_decoder);
        flb_log_event_encoder_destroy(&log_encoder);
        return FLB_FILTER_NOTOUCH;
    }

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        record = log_decoder.record_base;
        record_length = log_decoder.record_length;
        if (log_event.group_metadata != NULL && log_event.group_attributes != NULL) {
            ret = encode_grouped_record(&group_encoder, &log_event, record, record_length);
            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                break;
            }
            record = group_encoder.output_buffer;
            record_length = group_encoder.output_length;
        }
        keep = FLB_FALSE;
        map = *log_event.body;
        is_matched = FLB_FALSE;
        /*
         * Process the record according the defined rules. If it returns FLB_TRUE means
         * the record was emitter with a different tag.
         *
         * If a record was emitted, the variable 'keep' will define if the record must
         * be preserved or not.
         */
        is_emitted = process_record(tag, tag_len, map, record, record_length,
                                    &keep, ctx, &is_matched, i_ins);
        if (is_emitted == FLB_TRUE) {
            /* A record with the new tag was emitted */
            emitted_num++;
        }

        /*
         * Here we decide if the original record must be preserved or not:
         *
         * - record with new tag was emitted and the rule says it must be preserved
         * - record was not emitted
         */
        if (keep == FLB_TRUE || is_matched != FLB_TRUE) {
            ret = flb_log_event_encoder_emit_raw_record(
                    &log_encoder,
                    record, record_length);
            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                break;
            }
        }
    }

    flb_log_event_encoder_destroy(&group_encoder);

    if (emitted_num == 0) {
        flb_log_event_decoder_destroy(&log_decoder);
        flb_log_event_encoder_destroy(&log_encoder);

        return FLB_FILTER_NOTOUCH;
    }
#ifdef FLB_HAVE_METRICS
    else if (emitted_num > 0) {
        cmt_counter_add(ctx->cmt_emitted, ts, emitted_num,
                        1, (char *[]) {name});

        /* OLD api */
        flb_metrics_sum(FLB_RTAG_METRIC_EMITTED, emitted_num, ctx->ins->metrics);
    }
#endif

    if (ret == FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA &&
        log_decoder.offset == bytes) {
        ret = FLB_EVENT_ENCODER_SUCCESS;
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        *out_buf   = log_encoder.output_buffer;
        *out_bytes = log_encoder.output_length;

        ret = FLB_FILTER_MODIFIED;

        flb_log_event_encoder_claim_internal_buffer_ownership(&log_encoder);
    }
    else {
        flb_plg_error(ctx->ins,
                      "Log event encoder error : %d", ret);

        ret = FLB_FILTER_NOTOUCH;
    }

    flb_log_event_decoder_destroy(&log_decoder);
    flb_log_event_encoder_destroy(&log_encoder);

    return ret;
}

/* Destroy rules from context */
static void destroy_rules(struct flb_rewrite_tag *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct rewrite_rule *rule;

    mk_list_foreach_safe(head, tmp, &ctx->rules) {
        rule = mk_list_entry(head, struct rewrite_rule, _head);
        flb_regex_destroy(rule->regex);
        flb_ra_destroy(rule->ra_key);
        flb_ra_destroy(rule->ra_tag);
        mk_list_del(&rule->_head);
        flb_free(rule);
    }
}

static int cb_rewrite_tag_exit(void *data, struct flb_config *config)
{
    struct flb_rewrite_tag *ctx = (struct flb_rewrite_tag *) data;

    if (!ctx) {
        return 0;
    }

    destroy_rules(ctx);
    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_SLIST_4, "rule", NULL,
     FLB_TRUE, FLB_TRUE, offsetof(struct flb_rewrite_tag, cm_rules),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "emitter_name", NULL,
     FLB_FALSE, FLB_TRUE, offsetof(struct flb_rewrite_tag, emitter_name),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "emitter_storage.type", "memory",
     FLB_FALSE, FLB_TRUE, offsetof(struct flb_rewrite_tag, emitter_storage_type),
     NULL
    },
    {
     FLB_CONFIG_MAP_INT, "batch_size", "0",
     FLB_FALSE, FLB_TRUE, offsetof(struct flb_rewrite_tag, batch_size),
     "Experimental maximum records per batched input callback (0 disables, maximum 4096)"
    },
    {
     FLB_CONFIG_MAP_SIZE, "emitter_mem_buf_limit", FLB_RTAG_MEM_BUF_LIMIT_DEFAULT,
     FLB_FALSE, FLB_TRUE, offsetof(struct flb_rewrite_tag, emitter_mem_buf_limit),
     "set a memory buffer limit to restrict memory usage of emitter"
    },
    /* EOF */
    {0}
};

struct flb_filter_plugin filter_rewrite_tag_plugin = {
    .name         = "rewrite_tag",
    .description  = "Rewrite records tags",
    .cb_init      = cb_rewrite_tag_init,
    .cb_filter    = cb_rewrite_tag_filter,
    .cb_exit      = cb_rewrite_tag_exit,
    .config_map   = config_map,
    .flags        = 0
};
