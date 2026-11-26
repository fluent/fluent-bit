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

#ifndef FLB_PROCESSOR_ADAPTIVE_H
#define FLB_PROCESSOR_ADAPTIVE_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_pthread.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_fstore.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>

#include "adaptive_miner.h"
#include "adaptive_policy.h"

#define ADAPTIVE_GROUP_OTHER         "_other"
#define ADAPTIVE_GROUP_KEY_MAX       256
#define ADAPTIVE_GROUP_BUCKETS       64
#define ADAPTIVE_SELECTOR_PARTS      8

/* Where a 'group_by' value is read from */
#define ADAPTIVE_SELECT_TAG          0
#define ADAPTIVE_SELECT_RESOURCE     1   /* OTLP resource attribute        */
#define ADAPTIVE_SELECT_RECORD       2   /* path inside the record body    */

/* What a record offers to the miner */
#define ADAPTIVE_SOURCE_NONE         0
#define ADAPTIVE_SOURCE_TEXT         1   /* the message string             */
#define ADAPTIVE_SOURCE_FIELDS       2   /* a line derived from its fields */

struct adaptive_totals {
    uint64_t records;
    uint64_t bytes;
    uint64_t kept;
    uint64_t dropped;
    uint64_t bytes_dropped;
    uint64_t unmatched;
    uint64_t by_reason[2][ADAPTIVE_REASON_COUNT];
};

struct adaptive_selector {
    int type;
    int part_count;
    cfl_sds_t parts[ADAPTIVE_SELECTOR_PARTS];
    struct cfl_list _head;
};

/*
 * A group is one partition of the stream, for example a namespace or a
 * service. Each group learns its own patterns, so the volume of one group
 * never sets the rate of another.
 */
struct adaptive_group {
    cfl_sds_t key;
    uint64_t hash;
    struct adaptive_miner *miner;
    cfl_sds_t tag;              /* last tag seen, used to emit summaries */
    uint64_t last_seen;

    /* removed patterns whose records are not in a summary yet */
    uint64_t lost_count;
    uint64_t lost_kept;
    uint64_t lost_dropped;
    uint64_t lost_bytes_dropped;

    struct cfl_list _head;
    struct cfl_list _bucket;
};

/* The text a record is mined by, plus the severity found on the way */
struct adaptive_source {
    int type;
    const char *str;
    size_t len;
    const char *level;
    size_t level_len;
};

struct adaptive_ctx {
    /* configuration */
    struct mk_list *keys;
    cfl_sds_t level_key;
    struct mk_list *protect_levels;
    cfl_sds_t protect_regex_str;
    cfl_sds_t mode_str;
    struct mk_list *group_by;
    int max_groups;
    int structured;
    int window;
    int allow;
    int min_events;
    cfl_sds_t sample_mode_str;
    int max_sample_rate;
    size_t budget_bytes;
    double similarity;
    int depth;
    int max_children;
    int max_tokens;
    int max_patterns;
    int pattern_ttl;
    int annotate;
    int annotate_pattern_id;
    cfl_sds_t annotate_key;
    int annotate_template;
    int summary;
    int fast_path;
    cfl_sds_t policy_file;
    int policy_refresh;
    cfl_sds_t report_file;
    int report_interval;
    int report_exemplars;
    cfl_sds_t state_path;
    int state_interval;

    /* state */
    int enforce;
    struct flb_regex *protect_regex;
    struct adaptive_policy *policy;
    struct adaptive_totals totals;
    uint64_t started;
    uint64_t last_policy_check;
    uint64_t last_expire;
    uint64_t last_report;
    uint64_t policy_reloads;
    uint64_t policy_errors;
    pthread_mutex_t lock;
    int lock_ready;

    /* groups */
    struct cfl_list selectors;
    struct cfl_list groups;
    struct cfl_list buckets[ADAPTIVE_GROUP_BUCKETS];
    int group_count;
    int pattern_count;
    struct adaptive_group *last_group;
    uint64_t miner_events[4];   /* created, generalized, evicted, expired */
    uint64_t miner_retired[4];  /* same, from groups already removed      */
    uint64_t groups_overflowed;
    char group_buf[ADAPTIVE_GROUP_KEY_MAX];

    /* structured records are turned into a line here */
    cfl_sds_t line;

    /* timer and summaries */
    struct flb_sched_timer *timer;
    struct flb_input_instance *input;
    int ingress;
    uint64_t summary_window;
    uint64_t summary_records;
    uint64_t summary_failures;

    /* state kept on disk across restarts */
    struct flb_fstore *state_fs;
    struct flb_fstore_stream *state_stream;
    struct flb_fstore_file *state_file;     /* snapshot currently on disk */
    uint64_t state_sequence;
    uint64_t last_state;
    uint64_t state_writes;
    uint64_t state_errors;
    uint64_t state_bytes;
    int state_restored_groups;
    int state_restored_patterns;

    /* metrics, registered in the owner plugin context */
    char *label_owner;
    char *label_scope;
    char *label_processor;
    char label_stage[24];
    struct cmt_counter *cmt_records;
    struct cmt_counter *cmt_bytes;
    struct cmt_counter *cmt_pattern_events;
    struct cmt_counter *cmt_policy_reloads;
    struct cmt_counter *cmt_summaries;
    struct cmt_counter *cmt_state;
    struct cmt_gauge *cmt_patterns;
    struct cmt_gauge *cmt_groups;

    struct flb_processor_instance *ins;
};

/* The labels every metric of this processor starts with */
static inline void adaptive_labels(struct adaptive_ctx *ctx, char **labels)
{
    labels[0] = ctx->label_owner;
    labels[1] = ctx->label_scope;
    labels[2] = ctx->label_processor;
    labels[3] = ctx->label_stage;
    labels[4] = "logs";
}

/* A record that only stands for itself is left as it came */
static inline int adaptive_annotation_needed(struct adaptive_ctx *ctx,
                                             struct adaptive_decision *decision)
{
    return ctx->annotate_pattern_id || ctx->annotate_template ||
           decision->action != ADAPTIVE_KEEP ||
           decision->suppressed != 0 || decision->sample_rate > 1;
}

/* adaptive_group.c */
int adaptive_selectors_create(struct adaptive_ctx *ctx);
void adaptive_selectors_destroy(struct adaptive_ctx *ctx);
struct adaptive_group *adaptive_group_resolve(struct adaptive_ctx *ctx,
                                              struct flb_mp_chunk_record *record,
                                              struct cfl_kvlist *body,
                                              const char *tag, int tag_len,
                                              uint64_t now);
struct adaptive_group *adaptive_group_restore(struct adaptive_ctx *ctx,
                                              const char *key, size_t len);
size_t adaptive_group_key_append(char *buf, size_t used, const char *str, size_t len);
struct adaptive_group *adaptive_group_by_key(struct adaptive_ctx *ctx, size_t key_len,
                                             const char *tag, int tag_len, uint64_t now);
void adaptive_groups_expire(struct adaptive_ctx *ctx, uint64_t now);
void adaptive_groups_stats(struct adaptive_ctx *ctx);
void adaptive_groups_destroy(struct adaptive_ctx *ctx);

/* adaptive_structured.c */
int adaptive_source_resolve(struct adaptive_ctx *ctx, struct cfl_kvlist *body,
                            struct adaptive_source *source);
int adaptive_source_from_text(struct adaptive_ctx *ctx, const char *str, size_t len,
                              struct adaptive_source *source);

/* adaptive_summary.c */
int adaptive_summary_due(struct adaptive_ctx *ctx, uint64_t now);
int adaptive_summary_append(struct adaptive_ctx *ctx,
                            struct flb_mp_chunk_cobj *chunk_cobj, uint64_t now);
int adaptive_summary_ingress(struct adaptive_ctx *ctx, uint64_t now);
int adaptive_summary_encode(struct adaptive_ctx *ctx, struct flb_log_event_encoder *encoder,
                            uint64_t now);
int adaptive_summary_is_record(struct adaptive_ctx *ctx, struct cfl_kvlist *body);

/* adaptive.c */
int adaptive_level_is_protected(struct adaptive_ctx *ctx, const char *str, size_t len);
const char *adaptive_otlp_severity_name(int64_t number);

/* adaptive_raw.c */
int adaptive_raw_process(struct adaptive_ctx *ctx, const void *data, size_t bytes,
                         void **out_buf, size_t *out_size, const char *tag, int tag_len,
                         uint64_t now, struct adaptive_totals *delta);

/* adaptive_state.c */
int adaptive_state_open(struct adaptive_ctx *ctx, uint64_t now);
int adaptive_state_write(struct adaptive_ctx *ctx, uint64_t now);
void adaptive_state_close(struct adaptive_ctx *ctx);

/* adaptive_report.c */
int adaptive_report_write(struct adaptive_ctx *ctx, uint64_t now);

#endif
