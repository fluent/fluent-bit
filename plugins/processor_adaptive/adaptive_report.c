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
 * Pattern report
 * ==============
 * The report is the outbound half of the feedback loop: a JSON snapshot of
 * every live pattern with its volume and what happened to it. A controller
 * reads it, decides which patterns are worth keeping and writes the policy
 * file that the processor reloads.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "adaptive.h"

/* Length of the well formed UTF-8 sequence at 's', 0 when it is not one */
static int utf8_sequence(const unsigned char *s, size_t left)
{
    int i;
    int len;

    if (s[0] >= 0xC2 && s[0] <= 0xDF) {
        len = 2;
    }
    else if (s[0] >= 0xE0 && s[0] <= 0xEF) {
        len = 3;
    }
    else if (s[0] >= 0xF0 && s[0] <= 0xF4) {
        len = 4;
    }
    else {
        return 0;
    }

    if ((size_t) len > left) {
        return 0;
    }

    for (i = 1; i < len; i++) {
        if ((s[i] & 0xC0) != 0x80) {
            return 0;
        }
    }

    return len;
}

static void json_string(cfl_sds_t *buf, const char *str, size_t len)
{
    int seq;
    size_t i = 0;
    char tmp[8];
    unsigned char c;

    cfl_sds_cat_safe(buf, "\"", 1);

    while (i < len) {
        c = (unsigned char) str[i];

        if (c == '"' || c == '\\') {
            tmp[0] = '\\';
            tmp[1] = c;
            cfl_sds_cat_safe(buf, tmp, 2);
            i++;
        }
        else if (c < 0x20 || c == 0x7F) {
            snprintf(tmp, sizeof(tmp), "\\u%04x", c);
            cfl_sds_cat_safe(buf, tmp, 6);
            i++;
        }
        else if (c < 0x80) {
            cfl_sds_cat_safe(buf, str + i, 1);
            i++;
        }
        else {
            seq = utf8_sequence((const unsigned char *) str + i, len - i);
            if (seq == 0) {
                cfl_sds_cat_safe(buf, "?", 1);
                i++;
            }
            else {
                cfl_sds_cat_safe(buf, str + i, seq);
                i += seq;
            }
        }
    }

    cfl_sds_cat_safe(buf, "\"", 1);
}

static int compare_bytes(const void *a, const void *b)
{
    const struct adaptive_pattern *pa = *(const struct adaptive_pattern **) a;
    const struct adaptive_pattern *pb = *(const struct adaptive_pattern **) b;

    if (pa->bytes != pb->bytes) {
        return pa->bytes < pb->bytes ? 1 : -1;
    }
    if (pa->serial != pb->serial) {
        return pa->serial < pb->serial ? -1 : 1;
    }

    return 0;
}

static void pattern_json(struct adaptive_ctx *ctx, cfl_sds_t *buf,
                         struct adaptive_pattern *pattern)
{
    cfl_sds_printf(buf, "{\"id\":\"%016" PRIx64 "\",\"group\":", pattern->id);
    json_string(buf, pattern->group ? pattern->group : "",
                pattern->group ? strlen(pattern->group) : 0);
    cfl_sds_cat_safe(buf, ",\"template\":", 12);
    json_string(buf, pattern->template_str, cfl_sds_len(pattern->template_str));
    cfl_sds_printf(buf,
                   ",\"count\":%" PRIu64 ",\"bytes\":%" PRIu64
                   ",\"kept\":%" PRIu64 ",\"dropped\":%" PRIu64
                   ",\"bytes_dropped\":%" PRIu64 ",\"protected\":%" PRIu64
                   ",\"first_seen\":%" PRIu64 ",\"last_seen\":%" PRIu64,
                   pattern->count, pattern->bytes,
                   pattern->kept, pattern->dropped,
                   pattern->bytes_dropped, pattern->protected_count,
                   pattern->first_seen / 1000000000ULL,
                   pattern->last_seen / 1000000000ULL);

    /* the binding is only meaningful while it matches the current policy */
    if (pattern->policy && pattern->policy_generation == ctx->policy->generation) {
        cfl_sds_printf(buf, ",\"policy_drop_rate\":%.6f", pattern->policy->drop_rate);
    }
    else {
        cfl_sds_cat_safe(buf, ",\"policy_drop_rate\":null", 24);
    }

    if (pattern->exemplar) {
        cfl_sds_cat_safe(buf, ",\"exemplar\":", 12);
        json_string(buf, pattern->exemplar, cfl_sds_len(pattern->exemplar));
    }

    cfl_sds_cat_safe(buf, "}", 1);
}

/* Write the snapshot to a temporary file and rename it over the target */
int adaptive_report_write(struct adaptive_ctx *ctx, uint64_t now)
{
    int i = 0;
    int count;
    int ret = -1;
    size_t len;
    cfl_sds_t buf;
    cfl_sds_t tmp_path = NULL;
    FILE *fp;
    struct cfl_list *head;
    struct cfl_list *ghead;
    struct adaptive_group *group;
    struct adaptive_pattern **patterns = NULL;
    struct adaptive_totals *totals = &ctx->totals;

    if (!ctx->report_file) {
        return 0;
    }

    buf = cfl_sds_create_size(4096);
    if (!buf) {
        return -1;
    }

    count = ctx->pattern_count;
    if (count > 0) {
        patterns = flb_calloc(count, sizeof(struct adaptive_pattern *));
        if (!patterns) {
            flb_errno();
            cfl_sds_destroy(buf);
            return -1;
        }
        cfl_list_foreach(ghead, &ctx->groups) {
            group = cfl_list_entry(ghead, struct adaptive_group, _head);
            cfl_list_foreach(head, &group->miner->lru) {
                if (i < count) {
                    patterns[i++] = cfl_list_entry(head, struct adaptive_pattern, _lru);
                }
            }
        }
        count = i;
        qsort(patterns, count, sizeof(struct adaptive_pattern *), compare_bytes);
    }

    cfl_sds_printf(&buf,
                   "{\"version\":1,\"generated_at\":%" PRIu64
                   ",\"uptime_seconds\":%" PRIu64 ",\"mode\":\"%s\"",
                   now / 1000000000ULL,
                   (now - ctx->started) / 1000000000ULL,
                   ctx->enforce ? "enforce" : "observe");

    cfl_sds_printf(&buf,
                   ",\"totals\":{\"records\":%" PRIu64 ",\"bytes\":%" PRIu64
                   ",\"kept\":%" PRIu64 ",\"dropped\":%" PRIu64
                   ",\"bytes_dropped\":%" PRIu64 ",\"unmatched\":%" PRIu64 "}",
                   totals->records, totals->bytes, totals->kept,
                   totals->dropped, totals->bytes_dropped, totals->unmatched);

    cfl_sds_printf(&buf,
                   ",\"miner\":{\"groups\":%d,\"groups_overflowed\":%" PRIu64
                   ",\"patterns\":%d,\"created\":%" PRIu64
                   ",\"merged\":%" PRIu64 ",\"evicted\":%" PRIu64
                   ",\"expired\":%" PRIu64 "}",
                   ctx->group_count, ctx->groups_overflowed, ctx->pattern_count,
                   ctx->miner_events[0], ctx->miner_events[1],
                   ctx->miner_events[2], ctx->miner_events[3]);

    cfl_sds_printf(&buf,
                   ",\"policy\":{\"entries\":%d,\"reloads\":%" PRIu64
                   ",\"errors\":%" PRIu64 "}",
                   ctx->policy->entry_count, ctx->policy_reloads, ctx->policy_errors);

    cfl_sds_printf(&buf,
                   ",\"summaries\":{\"records\":%" PRIu64 ",\"failures\":%" PRIu64
                   "},\"patterns\":[",
                   ctx->summary_records, ctx->summary_failures);

    for (i = 0; i < count; i++) {
        if (i > 0) {
            cfl_sds_cat_safe(&buf, ",", 1);
        }
        cfl_sds_cat_safe(&buf, "\n", 1);
        pattern_json(ctx, &buf, patterns[i]);
    }
    cfl_sds_cat_safe(&buf, "\n]}\n", 4);
    flb_free(patterns);

    tmp_path = cfl_sds_create_size(cfl_sds_len(ctx->report_file) + 8);
    if (!tmp_path) {
        cfl_sds_destroy(buf);
        return -1;
    }
    cfl_sds_printf(&tmp_path, "%s.tmp", ctx->report_file);

    fp = fopen(tmp_path, "w");
    if (!fp) {
        flb_errno();
        goto done;
    }

    len = cfl_sds_len(buf);
    if (fwrite(buf, 1, len, fp) != len) {
        flb_errno();
        fclose(fp);
        remove(tmp_path);
        goto done;
    }

    if (fclose(fp) != 0) {
        flb_errno();
        remove(tmp_path);
        goto done;
    }

#ifdef FLB_SYSTEM_WINDOWS
    /* rename does not replace an existing file on Windows */
    remove(ctx->report_file);
#endif

    if (rename(tmp_path, ctx->report_file) != 0) {
        flb_errno();
        remove(tmp_path);
        goto done;
    }
    ret = 0;

done:
    cfl_sds_destroy(tmp_path);
    cfl_sds_destroy(buf);

    return ret;
}
