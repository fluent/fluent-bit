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

/*
 * Adaptive telemetry for logs
 * ===========================
 * The processor learns the templates behind the log stream, measures each
 * one and keeps a share of it that shrinks as the template gets louder.
 * Records that are kept carry the number of records they stand for, so the
 * destination can still account for every record that was produced.
 *
 * Attached to an output it reduces only that route: another output can keep
 * the full stream, for example an object store used as the archive.
 */

#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_log_event_decoder.h>

#include <string.h>
#include <inttypes.h>

#include "adaptive.h"

#define NS_PER_SECOND   1000000000ULL

static const char *action_names[2][2] = {
    {"kept", "would_drop"},
    {"kept", "dropped"}
};

static struct cmt_counter *counter_get(struct cmt *cmt, const char *name,
                                       const char *help, int count, char **labels)
{
    char fqname[128];
    struct cfl_list *head;
    struct cmt_counter *counter;

    snprintf(fqname, sizeof(fqname), "fluentbit_adaptive_%s", name);

    /* several instances can share the owner context */
    cfl_list_foreach(head, &cmt->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        if (counter->opts.fqname && strcmp(counter->opts.fqname, fqname) == 0) {
            return counter;
        }
    }

    return cmt_counter_create(cmt, "fluentbit", "adaptive", (char *) name,
                              (char *) help, count, labels);
}

static struct cmt_gauge *gauge_get(struct cmt *cmt, const char *name,
                                   const char *help, int count, char **labels)
{
    char fqname[128];
    struct cfl_list *head;
    struct cmt_gauge *gauge;

    snprintf(fqname, sizeof(fqname), "fluentbit_adaptive_%s", name);

    cfl_list_foreach(head, &cmt->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        if (gauge->opts.fqname && strcmp(gauge->opts.fqname, fqname) == 0) {
            return gauge;
        }
    }

    return cmt_gauge_create(cmt, "fluentbit", "adaptive", (char *) name,
                            (char *) help, count, labels);
}

static void metrics_init(struct adaptive_ctx *ctx)
{
    struct cmt *cmt = NULL;
    struct flb_processor *proc;
    struct flb_processor_instance *ins = ctx->ins;
    char *records_labels[] = {"name", "scope", "processor", "stage", "signal",
                              "action", "reason"};
    char *bytes_labels[] = {"name", "scope", "processor", "stage", "signal", "action"};
    char *event_labels[] = {"name", "scope", "processor", "stage", "signal", "event"};
    char *status_labels[] = {"name", "scope", "processor", "stage", "signal", "status"};
    char *base_labels[] = {"name", "scope", "processor", "stage", "signal"};

    /* same label set as the processor metrics of the core */
    ctx->label_owner = (char *) flb_processor_instance_get_name(ins);
    ctx->label_scope = "unknown";
    ctx->label_processor = ins->p->name;
    ctx->label_stage[0] = '0';
    ctx->label_stage[1] = '\0';

    if (!ins->pu || !ins->pu->parent) {
        return;
    }
    ctx->label_processor = ins->pu->name;
    snprintf(ctx->label_stage, sizeof(ctx->label_stage), "%zu", ins->pu->stage);

    proc = ins->pu->parent;
    if (proc->data && proc->source_plugin_type == FLB_PLUGIN_INPUT) {
        cmt = ((struct flb_input_instance *) proc->data)->cmt;
        ctx->label_owner = (char *) flb_input_name((struct flb_input_instance *) proc->data);
        ctx->label_scope = "input";
    }
    else if (proc->data && proc->source_plugin_type == FLB_PLUGIN_OUTPUT) {
        cmt = ((struct flb_output_instance *) proc->data)->cmt;
        ctx->label_owner = (char *) flb_output_name((struct flb_output_instance *) proc->data);
        ctx->label_scope = "output";
    }
    if (!cmt) {
        return;
    }

    ctx->cmt_records = counter_get(cmt, "records_total",
                                   "Log records seen by the adaptive processor.",
                                   7, records_labels);
    ctx->cmt_bytes = counter_get(cmt, "message_bytes_total",
                                 "Bytes of the mined message of each record seen.",
                                 6, bytes_labels);
    ctx->cmt_pattern_events = counter_get(cmt, "pattern_events_total",
                                          "Pattern lifecycle events.",
                                          6, event_labels);
    ctx->cmt_policy_reloads = counter_get(cmt, "policy_reloads_total",
                                          "Policy file reload attempts.",
                                          6, status_labels);
    ctx->cmt_summaries = counter_get(cmt, "summary_records_total",
                                     "Summary records emitted, or attempts that failed.",
                                     6, status_labels);
    ctx->cmt_state = counter_get(cmt, "state_writes_total",
                                 "State snapshots written to disk, or attempts that failed.",
                                 6, status_labels);
    ctx->cmt_patterns = gauge_get(cmt, "patterns",
                                  "Patterns currently tracked.",
                                  5, base_labels);
    ctx->cmt_groups = gauge_get(cmt, "groups",
                                "Groups currently tracked.",
                                5, base_labels);
}

/* Publish what changed since the last call */
static void metrics_flush(struct adaptive_ctx *ctx, struct adaptive_totals *delta, uint64_t now)
{
    int i;
    int action;
    int reason;
    uint64_t value;
    uint64_t before[4];
    char *labels[7];
    static char *events[4] = {"created", "generalized", "evicted", "expired"};

    adaptive_labels(ctx, labels);

    if (ctx->cmt_records && delta) {
        for (action = 0; action < 2; action++) {
            for (reason = 0; reason < ADAPTIVE_REASON_COUNT; reason++) {
                value = delta->by_reason[action][reason];
                if (value == 0) {
                    continue;
                }
                labels[5] = (char *) action_names[ctx->enforce][action];
                labels[6] = (char *) adaptive_policy_reason_name(reason);
                cmt_counter_add(ctx->cmt_records, now, (double) value, 7, labels);
            }
        }
    }

    if (ctx->cmt_bytes && delta) {
        if (delta->bytes > delta->bytes_dropped) {
            labels[5] = (char *) action_names[ctx->enforce][ADAPTIVE_KEEP];
            cmt_counter_add(ctx->cmt_bytes, now,
                            (double) (delta->bytes - delta->bytes_dropped), 6, labels);
        }
        if (delta->bytes_dropped > 0) {
            labels[5] = (char *) action_names[ctx->enforce][ADAPTIVE_DROP];
            cmt_counter_add(ctx->cmt_bytes, now, (double) delta->bytes_dropped, 6, labels);
        }
    }

    memcpy(before, ctx->miner_events, sizeof(before));
    adaptive_groups_stats(ctx);

    if (ctx->cmt_pattern_events) {
        for (i = 0; i < 4; i++) {
            if (ctx->miner_events[i] > before[i]) {
                labels[5] = events[i];
                cmt_counter_add(ctx->cmt_pattern_events, now,
                                (double) (ctx->miner_events[i] - before[i]), 6, labels);
            }
        }
    }

    if (ctx->cmt_patterns) {
        cmt_gauge_set(ctx->cmt_patterns, now, (double) ctx->pattern_count, 5, labels);
    }
    if (ctx->cmt_groups) {
        cmt_gauge_set(ctx->cmt_groups, now, (double) ctx->group_count, 5, labels);
    }
}

static void policy_refresh(struct adaptive_ctx *ctx, uint64_t now, int force)
{
    int ret;
    char *labels[6];

    if (!ctx->policy_file) {
        return;
    }

    if (!force && now - ctx->last_policy_check < (uint64_t) ctx->policy_refresh * NS_PER_SECOND) {
        return;
    }
    ctx->last_policy_check = now;

    ret = adaptive_policy_load_file(ctx->policy, ctx->policy_file);
    if (ret == ADAPTIVE_POLICY_UNCHANGED) {
        return;
    }

    adaptive_labels(ctx, labels);
    if (ret == ADAPTIVE_POLICY_LOADED) {
        ctx->policy_reloads++;
        labels[5] = "ok";
        flb_plg_info(ctx->ins, "policy loaded from %s: %d pattern rules",
                     ctx->policy_file, ctx->policy->entry_count);
    }
    else {
        ctx->policy_errors++;
        labels[5] = "error";
        flb_plg_error(ctx->ins, "invalid policy file %s, keeping the previous policy",
                      ctx->policy_file);
    }

    if (ctx->cmt_policy_reloads) {
        cmt_counter_add(ctx->cmt_policy_reloads, now, 1.0, 6, labels);
    }
}

/* Work that depends on time, not on records: runs per chunk and per tick */
static void housekeeping(struct adaptive_ctx *ctx, uint64_t now)
{
    policy_refresh(ctx, now, FLB_FALSE);

    if (now - ctx->last_expire >= NS_PER_SECOND) {
        ctx->last_expire = now;
        adaptive_groups_expire(ctx, now);
    }

    if (ctx->report_file &&
        now - ctx->last_report >= (uint64_t) ctx->report_interval * NS_PER_SECOND) {
        ctx->last_report = now;
        adaptive_groups_stats(ctx);
        if (adaptive_report_write(ctx, now) != 0) {
            flb_plg_warn(ctx->ins, "could not write report file %s", ctx->report_file);
        }
    }

    /* the tick is one second long: half of it as slack keeps a 1s interval at 1s */
    if (ctx->state_fs &&
        now - ctx->last_state + NS_PER_SECOND / 2 >=
        (uint64_t) ctx->state_interval * NS_PER_SECOND) {
        if (adaptive_state_write(ctx, now) != 0) {
            flb_plg_warn(ctx->ins, "could not save state in %s", ctx->state_path);
        }
    }
}

/* Keeps windows, reports and summaries moving while no records arrive */
static void cb_tick(struct flb_config *config, void *data)
{
    uint64_t now = cfl_time_now();
    struct adaptive_ctx *ctx = data;

    (void) config;

    pthread_mutex_lock(&ctx->lock);

    if (ctx->ingress && adaptive_summary_due(ctx, now)) {
        adaptive_summary_ingress(ctx, now);
    }
    housekeeping(ctx, now);
    metrics_flush(ctx, NULL, now);

    pthread_mutex_unlock(&ctx->lock);
}

static int variant_string(struct cfl_variant *variant, const char **str, size_t *len)
{
    if (!variant || variant->type != CFL_VARIANT_STRING || !variant->data.as_string) {
        return -1;
    }

    *str = variant->data.as_string;
    *len = cfl_variant_size_get(variant);
    if (*len == 0 && !variant->referenced) {
        *len = cfl_sds_len(variant->data.as_string);
    }

    return 0;
}

int adaptive_level_is_protected(struct adaptive_ctx *ctx, const char *str, size_t len)
{
    struct mk_list *head;
    struct flb_slist_entry *entry;

    mk_list_foreach(head, ctx->protect_levels) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);
        if (flb_sds_len(entry->str) == len && strncasecmp(entry->str, str, len) == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

/* OTLP severity numbers come in ranges of four per level */
const char *adaptive_otlp_severity_name(int64_t number)
{
    if (number >= 21 && number <= 24) {
        return "fatal";
    }
    else if (number >= 17) {
        return "error";
    }
    else if (number >= 13) {
        return "warn";
    }
    else if (number >= 9) {
        return "info";
    }
    else if (number >= 5) {
        return "debug";
    }
    else if (number >= 1) {
        return "trace";
    }

    return NULL;
}

/* OTLP logs carry their severity in the record metadata, not in the body */
static int otlp_is_protected(struct adaptive_ctx *ctx, struct flb_mp_chunk_record *record)
{
    size_t len;
    const char *str;
    struct cfl_variant *otlp;
    struct cfl_variant *variant;

    if (!record->cobj_metadata || !record->cobj_metadata->variant ||
        record->cobj_metadata->variant->type != CFL_VARIANT_KVLIST) {
        return FLB_FALSE;
    }

    otlp = cfl_kvlist_fetch_s(record->cobj_metadata->variant->data.as_kvlist, "otlp", 4);
    if (!otlp || otlp->type != CFL_VARIANT_KVLIST) {
        return FLB_FALSE;
    }

    variant = cfl_kvlist_fetch_s(otlp->data.as_kvlist, "severity_text", 13);
    if (variant_string(variant, &str, &len) == 0 && adaptive_level_is_protected(ctx, str, len)) {
        return FLB_TRUE;
    }

    variant = cfl_kvlist_fetch_s(otlp->data.as_kvlist, "severity_number", 15);
    if (variant && (variant->type == CFL_VARIANT_INT || variant->type == CFL_VARIANT_UINT)) {
        str = adaptive_otlp_severity_name(variant->type == CFL_VARIANT_INT ?
                                 variant->data.as_int64 :
                                 (int64_t) variant->data.as_uint64);
        if (str && adaptive_level_is_protected(ctx, str, strlen(str))) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static int record_is_protected(struct adaptive_ctx *ctx, struct flb_mp_chunk_record *record,
                               struct cfl_kvlist *kvlist, struct adaptive_source *source)
{
    size_t len;
    const char *str;
    struct cfl_variant *variant;

    if (ctx->protect_levels) {
        /* the severity found next to a nested or JSON message comes first */
        if (source->level && adaptive_level_is_protected(ctx, source->level, source->level_len)) {
            return FLB_TRUE;
        }

        if (ctx->level_key) {
            variant = cfl_kvlist_fetch_s(kvlist, ctx->level_key, cfl_sds_len(ctx->level_key));
            if (variant_string(variant, &str, &len) == 0 &&
                adaptive_level_is_protected(ctx, str, len)) {
                return FLB_TRUE;
            }
        }

        if (otlp_is_protected(ctx, record)) {
            return FLB_TRUE;
        }
    }

    if (ctx->protect_regex &&
        flb_regex_match(ctx->protect_regex, (unsigned char *) source->str, source->len) > 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

/* Attach the pattern and the accounting of what it stands for */
static void record_annotate(struct adaptive_ctx *ctx, struct flb_mp_chunk_record *record,
                            struct cfl_kvlist *kvlist, struct adaptive_pattern *pattern,
                            struct adaptive_decision *decision)
{
    int ret = 0;
    char id[17];
    struct cfl_kvlist *info;

    if (!adaptive_annotation_needed(ctx, decision)) {
        return;
    }

    info = cfl_kvlist_create_like(kvlist);
    if (!info) {
        return;
    }

    if (ctx->annotate_pattern_id) {
        snprintf(id, sizeof(id), "%016" PRIx64, pattern->id);
        ret = cfl_kvlist_insert_string_s(info, "pattern_id", 10, id, 16, CFL_FALSE);
    }

    if (ret == 0 && decision->action == ADAPTIVE_DROP) {
        ret = cfl_kvlist_insert_string_s(info, "decision", 8, "drop", 4, CFL_FALSE);
    }
    if (ret == 0 && decision->suppressed > 0) {
        ret = cfl_kvlist_insert_int64_s(info, "suppressed", 10, (int64_t) decision->suppressed);
    }
    if (ret == 0 && decision->sample_rate > 1) {
        ret = cfl_kvlist_insert_int64_s(info, "sample_rate", 11, (int64_t) decision->sample_rate);
    }
    if (ret == 0 && ctx->annotate_template) {
        ret = cfl_kvlist_insert_string_s(info, "template", 8, pattern->template_str,
                                         cfl_sds_len(pattern->template_str), CFL_FALSE);
    }

    if (ret != 0) {
        cfl_kvlist_destroy(info);
        return;
    }

    cfl_kvlist_remove(kvlist, ctx->annotate_key);
    ret = cfl_kvlist_insert_kvlist_s(kvlist, ctx->annotate_key,
                                     cfl_sds_len(ctx->annotate_key), info);
    if (ret != 0) {
        cfl_kvlist_destroy(info);
        return;
    }

    record->modified = FLB_TRUE;
}

/* What every chunk ends with, whichever way its records were read */
static void chunk_done(struct adaptive_ctx *ctx, struct adaptive_totals *delta, uint64_t now)
{
    ctx->totals.records += delta->records;
    ctx->totals.bytes += delta->bytes;
    ctx->totals.kept += delta->kept;
    ctx->totals.dropped += delta->dropped;
    ctx->totals.bytes_dropped += delta->bytes_dropped;
    ctx->totals.unmatched += delta->unmatched;

    housekeeping(ctx, now);
    metrics_flush(ctx, delta, now);
}

/*
 * Fast path: the chunk is read as MessagePack and the records that are kept
 * as they came are copied as bytes, nothing is decoded into objects.
 */
static int cb_process_logs_raw(struct flb_processor_instance **instances, size_t count,
                               const void *data, size_t bytes,
                               void **out_buf, size_t *out_size,
                               const char *tag, int tag_len)
{
    int ret;
    uint64_t now;
    struct adaptive_ctx *ctx;
    struct adaptive_totals delta;

    /* FLB_PROCESSOR_FLAG_LOGS_RAW_FILTER: one unit per call */
    if (count != 1 || !instances[0]->context) {
        return FLB_PROCESSOR_RAW_UNSUPPORTED;
    }
    ctx = instances[0]->context;

    memset(&delta, 0, sizeof(delta));
    now = cfl_time_now();

    pthread_mutex_lock(&ctx->lock);

    policy_refresh(ctx, now, FLB_FALSE);
    ret = adaptive_raw_process(ctx, data, bytes, out_buf, out_size, tag, tag_len, now, &delta);
    chunk_done(ctx, &delta, now);

    pthread_mutex_unlock(&ctx->lock);

    return ret;
}

static int cb_process_logs(struct flb_processor_instance *ins,
                           void *chunk_data, const char *tag, int tag_len)
{
    int ret;
    int is_new;
    int changed;
    int record_type;
    int is_protected;
    uint64_t now;
    struct adaptive_ctx *ctx = ins->context;
    struct adaptive_totals delta;
    struct adaptive_decision decision;
    struct adaptive_source source;
    struct adaptive_group *group;
    struct adaptive_pattern *pattern;
    struct cfl_kvlist *kvlist;
    struct flb_mp_chunk_record *record;
    struct flb_mp_chunk_cobj *chunk_cobj = (struct flb_mp_chunk_cobj *) chunk_data;

    memset(&delta, 0, sizeof(delta));
    now = cfl_time_now();

    /* output processors can be entered from several flush workers */
    pthread_mutex_lock(&ctx->lock);

    policy_refresh(ctx, now, FLB_FALSE);

    while (flb_mp_chunk_cobj_record_next(chunk_cobj, &record) == FLB_MP_CHUNK_RECORD_OK) {
        ret = flb_log_event_decoder_get_record_type(&record->event, &record_type);
        if (ret != FLB_EVENT_DECODER_SUCCESS) {
            pthread_mutex_unlock(&ctx->lock);
            return FLB_PROCESSOR_FAILURE;
        }

        /* group envelopes describe the records that follow, never drop them */
        if (record_type != FLB_LOG_EVENT_NORMAL) {
            continue;
        }

        delta.records++;

        if (!record->cobj_record || !record->cobj_record->variant ||
            record->cobj_record->variant->type != CFL_VARIANT_KVLIST) {
            delta.unmatched++;
            delta.by_reason[ADAPTIVE_KEEP][ADAPTIVE_REASON_UNMATCHED]++;
            continue;
        }
        kvlist = record->cobj_record->variant->data.as_kvlist;

        /* a summary written by an earlier instance is not a log line */
        if (adaptive_summary_is_record(ctx, kvlist) ||
            adaptive_source_resolve(ctx, kvlist, &source) == ADAPTIVE_SOURCE_NONE) {
            delta.unmatched++;
            delta.by_reason[ADAPTIVE_KEEP][ADAPTIVE_REASON_UNMATCHED]++;
            continue;
        }

        group = adaptive_group_resolve(ctx, record, kvlist, tag, tag_len, now);
        if (!group) {
            delta.unmatched++;
            delta.by_reason[ADAPTIVE_KEEP][ADAPTIVE_REASON_UNMATCHED]++;
            continue;
        }

        pattern = adaptive_miner_process(group->miner, source.str, source.len, now,
                                         &is_new, &changed);
        if (!pattern) {
            delta.unmatched++;
            delta.by_reason[ADAPTIVE_KEEP][ADAPTIVE_REASON_UNMATCHED]++;
            continue;
        }

        if (is_new && ctx->report_exemplars) {
            pattern->exemplar = cfl_sds_create_len(source.str,
                                                   source.len > ADAPTIVE_EXEMPLAR_MAX ?
                                                   ADAPTIVE_EXEMPLAR_MAX : source.len);
        }

        is_protected = record_is_protected(ctx, record, kvlist, &source);
        adaptive_policy_decide(ctx->policy, pattern, source.len, now, is_protected, &decision);

        delta.bytes += source.len;
        delta.by_reason[decision.action][decision.reason]++;

        if (decision.action == ADAPTIVE_DROP) {
            delta.dropped++;
            delta.bytes_dropped += source.len;
            if (ctx->enforce) {
                flb_mp_chunk_cobj_record_destroy(chunk_cobj, record);
                continue;
            }
        }
        else {
            delta.kept++;
        }

        if (ctx->annotate) {
            record_annotate(ctx, record, kvlist, pattern, &decision);
        }
    }

    /* without a way into the input, summaries ride on the chunk at hand */
    if (!ctx->ingress && adaptive_summary_due(ctx, now)) {
        adaptive_summary_append(ctx, chunk_cobj, now);
    }

    chunk_done(ctx, &delta, now);

    pthread_mutex_unlock(&ctx->lock);

    return FLB_PROCESSOR_SUCCESS;
}

static void adaptive_destroy(struct adaptive_ctx *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->protect_regex) {
        flb_regex_destroy(ctx->protect_regex);
    }
    adaptive_state_close(ctx);
    adaptive_groups_destroy(ctx);
    adaptive_selectors_destroy(ctx);
    adaptive_policy_destroy(ctx->policy);
    if (ctx->line) {
        cfl_sds_destroy(ctx->line);
    }
    if (ctx->lock_ready) {
        pthread_mutex_destroy(&ctx->lock);
    }
    flb_free(ctx);
}

/* Summaries and idle housekeeping need a timer, and summaries a way in */
static void timer_start(struct adaptive_ctx *ctx)
{
    int ret;
    struct flb_sched *sched;
    struct flb_processor *proc = NULL;

    if (ctx->ins->pu) {
        proc = ctx->ins->pu->parent;
    }

    if (ctx->summary && ctx->enforce && proc && proc->data &&
        proc->source_plugin_type == FLB_PLUGIN_INPUT) {
        ctx->input = proc->data;
        if (flb_input_ingress_enable(ctx->input) == 0) {
            ctx->ingress = FLB_TRUE;
        }
        else {
            flb_plg_warn(ctx->ins, "summaries cannot be injected into this input, "
                         "they will travel with the next records");
        }
    }

    sched = flb_sched_ctx_get();
    if (sched) {
        ret = flb_sched_timer_cb_create(sched, FLB_SCHED_TIMER_CB_PERM, 1000,
                                        cb_tick, ctx, &ctx->timer);
        if (ret != 0) {
            ctx->timer = NULL;
        }
    }

    if (!ctx->timer) {
        /* still correct, but nothing happens while no records arrive */
        ctx->ingress = FLB_FALSE;
        flb_plg_debug(ctx->ins, "no scheduler available, running on record arrival only");
    }
}

static void timer_stop(struct adaptive_ctx *ctx)
{
    pthread_mutex_lock(&ctx->lock);
    if (ctx->timer) {
        flb_sched_timer_invalidate(ctx->timer);
        ctx->timer = NULL;
    }
    ctx->ingress = FLB_FALSE;
    pthread_mutex_unlock(&ctx->lock);
}

static int cb_init(struct flb_processor_instance *ins, void *source_plugin_instance,
                   int source_plugin_type, struct flb_config *config)
{
    int i;
    int ret;
    int sample_mode;
    struct adaptive_ctx *ctx;
    struct adaptive_miner *probe;

    (void) source_plugin_instance;
    (void) source_plugin_type;
    (void) config;

    ctx = flb_calloc(1, sizeof(struct adaptive_ctx));
    if (!ctx) {
        flb_errno();
        return FLB_PROCESSOR_FAILURE;
    }
    ctx->ins = ins;
    cfl_list_init(&ctx->selectors);
    cfl_list_init(&ctx->groups);
    for (i = 0; i < ADAPTIVE_GROUP_BUCKETS; i++) {
        cfl_list_init(&ctx->buckets[i]);
    }

    ret = flb_processor_instance_config_map_set(ins, ctx);
    if (ret == -1) {
        flb_free(ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    if (strcasecmp(ctx->mode_str, "enforce") == 0) {
        ctx->enforce = FLB_TRUE;
    }
    else if (strcasecmp(ctx->mode_str, "observe") == 0) {
        ctx->enforce = FLB_FALSE;
    }
    else {
        flb_plg_error(ins, "invalid mode '%s', expected 'enforce' or 'observe'", ctx->mode_str);
        adaptive_destroy(ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    sample_mode = adaptive_policy_sample_mode(ctx->sample_mode_str);
    if (sample_mode < 0) {
        flb_plg_error(ins, "invalid sample_mode '%s', expected log, sqrt, suppress or off",
                      ctx->sample_mode_str);
        adaptive_destroy(ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    if (!ctx->keys || mk_list_is_empty(ctx->keys) == 0 ||
        !ctx->annotate_key || cfl_sds_len(ctx->annotate_key) == 0) {
        flb_plg_error(ins, "'key' and 'annotate_key' cannot be empty");
        adaptive_destroy(ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    if (ctx->policy_refresh < 1 || ctx->report_interval < 1 || ctx->state_interval < 1 ||
        ctx->pattern_ttl < 0) {
        flb_plg_error(ins, "policy_refresh, report_interval and state_interval must be "
                      "at least 1 second");
        adaptive_destroy(ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    if (ctx->max_groups < 1) {
        flb_plg_error(ins, "max_groups must be at least 1");
        adaptive_destroy(ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    if (adaptive_selectors_create(ctx) != 0) {
        adaptive_destroy(ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    /* groups create their miner on demand: check the settings once here */
    probe = adaptive_miner_create(ctx->similarity, ctx->depth, ctx->max_children,
                                  ctx->max_tokens, ctx->max_patterns);
    if (!probe) {
        flb_plg_error(ins, "invalid pattern settings: similarity_threshold 0..1, "
                      "tree_depth %d..%d, max_tokens %d..%d, max_children and "
                      "max_patterns above 0",
                      ADAPTIVE_DEPTH_MIN, ADAPTIVE_DEPTH_MAX,
                      ADAPTIVE_TOKENS_MIN, ADAPTIVE_TOKENS_MAX);
        adaptive_destroy(ctx);
        return FLB_PROCESSOR_FAILURE;
    }
    adaptive_miner_destroy(probe);

    ctx->policy = adaptive_policy_create(ctx->window, ctx->allow, ctx->min_events,
                                         sample_mode, ctx->max_sample_rate,
                                         ctx->budget_bytes);
    if (!ctx->policy) {
        flb_plg_error(ins, "invalid decision settings: window and max_sample_rate "
                      "must be at least 1, allow_per_window and min_events cannot "
                      "be negative");
        adaptive_destroy(ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    if (ctx->protect_regex_str) {
        ctx->protect_regex = flb_regex_create(ctx->protect_regex_str);
        if (!ctx->protect_regex) {
            flb_plg_error(ins, "invalid protect_regex '%s'", ctx->protect_regex_str);
            adaptive_destroy(ctx);
            return FLB_PROCESSOR_FAILURE;
        }
    }

    ctx->line = cfl_sds_create_size(512);
    if (!ctx->line) {
        adaptive_destroy(ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    if (pthread_mutex_init(&ctx->lock, NULL) != 0) {
        flb_errno();
        adaptive_destroy(ctx);
        return FLB_PROCESSOR_FAILURE;
    }
    ctx->lock_ready = FLB_TRUE;

    ctx->started = cfl_time_now();
    ctx->last_report = ctx->started;
    ctx->last_expire = ctx->started;
    ctx->summary_window = ctx->started / ctx->policy->window_ns;

    metrics_init(ctx);

    /* the directory is named after the owner, known once metrics are set */
    if (adaptive_state_open(ctx, ctx->started) != 0) {
        adaptive_destroy(ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    policy_refresh(ctx, ctx->started, FLB_TRUE);
    timer_start(ctx);

    flb_processor_instance_set_context(ins, ctx);
    ins->logs_raw_enabled = ctx->fast_path;

    return FLB_PROCESSOR_SUCCESS;
}

/* Runs on the input thread while its scheduler is still alive */
static int cb_input_stop(struct flb_processor_instance *ins, void *data)
{
    (void) ins;

    if (data) {
        timer_stop(data);
    }

    return 0;
}

static int cb_exit(struct flb_processor_instance *ins, void *data)
{
    struct adaptive_ctx *ctx = (struct adaptive_ctx *) data;

    if (!ctx) {
        return FLB_PROCESSOR_SUCCESS;
    }

    /* on an input the timer is already gone, see cb_input_stop */
    timer_stop(ctx);

    /* leave a final snapshot so short lived runs still report */
    adaptive_groups_stats(ctx);
    if (ctx->report_file && adaptive_report_write(ctx, cfl_time_now()) != 0) {
        flb_plg_warn(ins, "could not write report file %s", ctx->report_file);
    }

    /*
     * What was not summarized yet is sent by the next run. The metrics of the
     * owner are already released at this point, so this save is not counted.
     */
    ctx->cmt_state = NULL;
    if (ctx->state_fs && adaptive_state_write(ctx, cfl_time_now()) != 0) {
        flb_plg_warn(ins, "could not save state in %s", ctx->state_path);
    }

    adaptive_destroy(ctx);

    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_CLIST, "key", "log,message,msg",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, keys),
        "Record keys that can hold the log message used to learn patterns, the "
        "first one present wins."
    },
    {
        FLB_CONFIG_MAP_BOOL, "structured", "true",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, structured),
        "Look inside JSON and map messages, and learn patterns from the fields "
        "of records that have no message."
    },
    {
        FLB_CONFIG_MAP_CLIST, "group_by", NULL,
        0, FLB_TRUE, offsetof(struct adaptive_ctx, group_by),
        "Learn and sample separately per value of these selectors: 'tag', "
        "'resource:<attribute>' for OTLP resources, or a record key such as "
        "$kubernetes['namespace_name']."
    },
    {
        FLB_CONFIG_MAP_INT, "max_groups", "100",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, max_groups),
        "Groups kept in memory, later keys share the '_other' group."
    },
    {
        FLB_CONFIG_MAP_STR, "mode", "enforce",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, mode_str),
        "'enforce' drops records, 'observe' keeps every record and marks the "
        "ones that would be dropped."
    },
    {
        FLB_CONFIG_MAP_STR, "level_key", "level",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, level_key),
        "Record key that holds the severity used by 'protect_levels'."
    },
    {
        FLB_CONFIG_MAP_CLIST, "protect_levels",
        "error,err,fatal,critical,crit,panic,emergency,emerg,alert",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, protect_levels),
        "Severities that are never dropped, compared without case. OTLP records "
        "are checked through their severity text and number."
    },
    {
        FLB_CONFIG_MAP_STR, "protect_regex", NULL,
        0, FLB_TRUE, offsetof(struct adaptive_ctx, protect_regex_str),
        "Messages matching this regular expression are never dropped."
    },
    {
        FLB_CONFIG_MAP_TIME, "window", "30s",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, window),
        "Length of the decision window."
    },
    {
        FLB_CONFIG_MAP_INT, "allow_per_window", "10",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, allow),
        "Records of each pattern that always pass in a window."
    },
    {
        FLB_CONFIG_MAP_INT, "min_events", "30",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, min_events),
        "Patterns below this volume per window are not sampled."
    },
    {
        FLB_CONFIG_MAP_STR, "sample_mode", "log",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, sample_mode_str),
        "How the 1 in N rate grows with pattern volume: 'log', 'sqrt', "
        "'suppress' (drop everything past the allowance) or 'off'."
    },
    {
        FLB_CONFIG_MAP_INT, "max_sample_rate", "100",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, max_sample_rate),
        "Upper bound for the automatic 1 in N rate."
    },
    {
        FLB_CONFIG_MAP_SIZE, "budget_bytes", "0",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, budget_bytes),
        "Message bytes that may pass per window, 0 disables the budget."
    },
    {
        FLB_CONFIG_MAP_DOUBLE, "similarity_threshold", "0.5",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, similarity),
        "Share of equal tokens needed to join an existing pattern."
    },
    {
        FLB_CONFIG_MAP_INT, "tree_depth", "4",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, depth),
        "Depth of the pattern tree, depth minus two leading tokens route a line."
    },
    {
        FLB_CONFIG_MAP_INT, "max_children", "100",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, max_children),
        "Branches per tree node before new tokens share the wildcard branch."
    },
    {
        FLB_CONFIG_MAP_INT, "max_tokens", "64",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, max_tokens),
        "Tokens of a message used to learn patterns."
    },
    {
        FLB_CONFIG_MAP_INT, "max_patterns", "2000",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, max_patterns),
        "Patterns kept in memory per group, the least recently seen is evicted "
        "first."
    },
    {
        FLB_CONFIG_MAP_TIME, "pattern_ttl", "10m",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, pattern_ttl),
        "Forget patterns not seen for this long, 0 disables expiration."
    },
    {
        FLB_CONFIG_MAP_BOOL, "annotate", "true",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, annotate),
        "Add the suppressed count and sample rate to the kept records that "
        "stand for dropped ones."
    },
    {
        FLB_CONFIG_MAP_BOOL, "annotate_pattern_id", "false",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, annotate_pattern_id),
        "Add the pattern id to every kept record."
    },
    {
        FLB_CONFIG_MAP_STR, "annotate_key", "adaptive",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, annotate_key),
        "Record key that receives the annotation map."
    },
    {
        FLB_CONFIG_MAP_BOOL, "annotate_template", "false",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, annotate_template),
        "Add the pattern template text to every kept record."
    },
    {
        FLB_CONFIG_MAP_BOOL, "summary", "false",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, summary),
        "Emit one record per window for each pattern that lost records, with "
        "the template and the counts of seen, kept and dropped."
    },
    {
        FLB_CONFIG_MAP_STR, "policy_file", NULL,
        0, FLB_TRUE, offsetof(struct adaptive_ctx, policy_file),
        "JSON file with per pattern drop rates, reloaded when it changes."
    },
    {
        FLB_CONFIG_MAP_TIME, "policy_refresh", "10s",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, policy_refresh),
        "How often the policy file is checked for changes."
    },
    {
        FLB_CONFIG_MAP_STR, "report_file", NULL,
        0, FLB_TRUE, offsetof(struct adaptive_ctx, report_file),
        "JSON file that receives the pattern report."
    },
    {
        FLB_CONFIG_MAP_TIME, "report_interval", "60s",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, report_interval),
        "How often the pattern report is written."
    },
    {
        FLB_CONFIG_MAP_BOOL, "report_exemplars", "false",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, report_exemplars),
        "Store one raw sample line per pattern in the report."
    },
    {
        FLB_CONFIG_MAP_BOOL, "fast_path", "true",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, fast_path),
        "Read chunks as MessagePack and copy kept records as bytes when this is "
        "the first processor of the list. Off: always decode records into objects."
    },
    {
        FLB_CONFIG_MAP_STR, "state_path", NULL,
        0, FLB_TRUE, offsetof(struct adaptive_ctx, state_path),
        "Directory where patterns and their counters are saved, so a restart "
        "continues from what was learned. Not set: state lives in memory only."
    },
    {
        FLB_CONFIG_MAP_TIME, "state_interval", "60s",
        0, FLB_TRUE, offsetof(struct adaptive_ctx, state_interval),
        "How often the state is saved. It is also saved on a clean exit."
    },

    /* EOF */
    {0}
};

struct flb_processor_plugin processor_adaptive_plugin = {
    .name               = "adaptive",
    .description        = "Adaptive telemetry: pattern aware log reduction",
    .cb_init            = cb_init,
    .cb_process_logs    = cb_process_logs,
    .cb_process_logs_raw = cb_process_logs_raw,
    .cb_process_metrics = NULL,
    .cb_process_traces  = NULL,
    .cb_exit            = cb_exit,
    .cb_input_stop      = cb_input_stop,
    .config_map         = config_map,
    .flags              = FLB_PROCESSOR_FLAG_INPUT_STOP | FLB_PROCESSOR_FLAG_LOGS_RAW_FILTER
};
