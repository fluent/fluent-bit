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

#include <fluent-bit/flb_input_log.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_gcp_auth.h>
#include <fluent-bit/flb_regex.h>

#include <inttypes.h>
#include <stdlib.h>

#include "gcs.h"

/* Integers above this value are epoch milliseconds in the 'auto' time format */
#define GCS_EPOCH_MS_THRESHOLD 100000000000LL

/* Parse exactly 'count' decimal digits */
static int gcs_digits(const char *p, const char *end, int count, int *out)
{
    int i;
    int value = 0;

    if (end - p < count) {
        return -1;
    }
    for (i = 0; i < count; i++) {
        if (p[i] < '0' || p[i] > '9') {
            return -1;
        }
        value = (value * 10) + (p[i] - '0');
    }
    *out = value;
    return 0;
}

static int gcs_days_in_month(int year, int mon)
{
    static const int days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    if (mon == 2 && ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0)) {
        return 29;
    }
    return days[mon - 1];
}

/*
 * ISO8601 'YYYY-MM-DDTHH:MM:SS[.frac][Z|+HH:MM|-HH:MM]' or the java sql timestamp
 * 'YYYY-MM-DD HH:MM:SS[.frac]' (always UTC). A date without zone is treated as UTC.
 */
int in_gcs_time_parse_string(int format, const char *str, size_t len, struct flb_time *out)
{
    int year;
    int mon;
    int day;
    int hour;
    int min;
    int sec;
    int zh;
    int zm;
    int ndigits;
    int sign;
    int is_sql;
    int has_colon;
    long nsec = 0;
    long zone = 0;
    time_t epoch;
    const char *p = str;
    const char *end = str + len;

    if (format != FLB_GCS_TIME_AUTO && format != FLB_GCS_TIME_ISO8601 &&
        format != FLB_GCS_TIME_JAVA_SQL) {
        return -1;
    }

    if (gcs_digits(p, end, 4, &year) != 0 || end - p < 19 || p[4] != '-' ||
        gcs_digits(p + 5, end, 2, &mon) != 0 || p[7] != '-' ||
        gcs_digits(p + 8, end, 2, &day) != 0) {
        return -1;
    }

    if (p[10] == 'T' || p[10] == 't') {
        is_sql = FLB_FALSE;
    }
    else if (p[10] == ' ') {
        is_sql = FLB_TRUE;
    }
    else {
        return -1;
    }
    if ((is_sql == FLB_TRUE && format == FLB_GCS_TIME_ISO8601) ||
        (is_sql == FLB_FALSE && format == FLB_GCS_TIME_JAVA_SQL)) {
        return -1;
    }

    if (gcs_digits(p + 11, end, 2, &hour) != 0 || p[13] != ':' ||
        gcs_digits(p + 14, end, 2, &min) != 0 || p[16] != ':' ||
        gcs_digits(p + 17, end, 2, &sec) != 0) {
        return -1;
    }
    p += 19;

    if (mon < 1 || mon > 12 || day < 1 || day > gcs_days_in_month(year, mon) || hour > 23 ||
        min > 59 || sec > 60) {
        return -1;
    }

    /* fraction of second, up to nanoseconds */
    if (p < end && *p == '.') {
        p++;
        ndigits = 0;
        while (p < end && *p >= '0' && *p <= '9') {
            if (ndigits < 9) {
                nsec = (nsec * 10) + (*p - '0');
                ndigits++;
            }
            p++;
        }
        if (ndigits == 0) {
            return -1;
        }
        while (ndigits < 9) {
            nsec *= 10;
            ndigits++;
        }
    }

    /* time zone, ISO8601 only */
    if (p < end) {
        if (is_sql == FLB_TRUE) {
            return -1;
        }
        if (*p == 'Z' || *p == 'z') {
            p++;
        }
        else if (*p == '+' || *p == '-') {
            sign = (*p == '-') ? -1 : 1;
            p++;
            if (gcs_digits(p, end, 2, &zh) != 0) {
                return -1;
            }
            p += 2;
            zm = 0;
            has_colon = FLB_FALSE;
            if (p < end && *p == ':') {
                has_colon = FLB_TRUE;
                p++;
            }
            /* minutes are optional ('+01'), but a colon must be followed by them */
            if (p < end || has_colon == FLB_TRUE) {
                if (gcs_digits(p, end, 2, &zm) != 0) {
                    return -1;
                }
                p += 2;
            }
            if (zh > 23 || zm > 59) {
                return -1;
            }
            zone = sign * ((zh * 3600L) + (zm * 60L));
        }
        else {
            return -1;
        }
        if (p != end) {
            return -1;
        }
    }

    epoch = flb_gcp_utc_to_epoch(year, mon, day, hour, min, sec);
    flb_time_set(out, epoch - zone, nsec);
    return 0;
}

/* Timestamps given as JSON numbers */
int in_gcs_time_parse_number(int format, const msgpack_object *obj, struct flb_time *out)
{
    int64_t v;
    double d;

    if (format == FLB_GCS_TIME_ISO8601 || format == FLB_GCS_TIME_JAVA_SQL) {
        return -1;
    }

    if (obj->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        if (obj->via.u64 > (uint64_t) INT64_MAX) {
            return -1;
        }
        v = (int64_t) obj->via.u64;
    }
    else if (obj->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        return -1;
    }
    else if (obj->type == MSGPACK_OBJECT_FLOAT32 || obj->type == MSGPACK_OBJECT_FLOAT64) {
        d = obj->via.f64;
        if (d < 0 || d > 1e15) {
            return -1;
        }
        if (format == FLB_GCS_TIME_EPOCH_MS ||
            (format == FLB_GCS_TIME_AUTO && d > (double) GCS_EPOCH_MS_THRESHOLD)) {
            d /= 1000.0;
        }
        flb_time_from_double(out, d);
        return 0;
    }
    else {
        return -1;
    }

    if (format == FLB_GCS_TIME_EPOCH_MS ||
        (format == FLB_GCS_TIME_AUTO && v > GCS_EPOCH_MS_THRESHOLD)) {
        flb_time_set(out, (time_t) (v / 1000), (long) (v % 1000) * 1000000L);
    }
    else {
        flb_time_set(out, (time_t) v, 0);
    }
    return 0;
}

/* The first capture group of 'tag_regex' applied to the object name, or NULL */
flb_sds_t in_gcs_tag_from_name(struct flb_in_gcs *ctx, const char *name, size_t len)
{
    int ret;
    ptrdiff_t start;
    ptrdiff_t end;
    flb_sds_t tag = NULL;
    struct flb_regex_search result;

    if (!ctx->tag_regex) {
        return NULL;
    }

    memset(&result, 0, sizeof(result));
    ret = flb_regex_do(ctx->tag_regex, name, len, &result);
    if (ret <= 0) {
        flb_plg_debug(ctx->ins, "'tag_regex' does not match '%s', using the input tag", name);
        return NULL;
    }

    ret = flb_regex_results_get(&result, 1, &start, &end);
    if (ret == 0 && start >= 0 && end > start) {
        tag = flb_sds_create_len(name + start, end - start);
    }
    flb_regex_results_release(&result);

    return tag;
}

static int gcs_key_equals(const msgpack_object *key, const char *name)
{
    size_t len;

    if (!name || key->type != MSGPACK_OBJECT_STR) {
        return FLB_FALSE;
    }
    len = strlen(name);
    return key->via.str.size == len && strncmp(key->via.str.ptr, name, len) == 0;
}

/* Pack {"log": <line>} */
static int gcs_pack_log_record(const char *line, size_t len, char **out_buf, size_t *out_size)
{
    int ret;
    msgpack_sbuffer sbuf;
    msgpack_packer pk;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
    ret = msgpack_pack_map(&pk, 1);
    ret |= msgpack_pack_str(&pk, 3);
    ret |= msgpack_pack_str_body(&pk, "log", 3);
    ret |= msgpack_pack_str(&pk, len);
    ret |= msgpack_pack_str_body(&pk, line, len);
    if (ret != 0) {
        msgpack_sbuffer_destroy(&sbuf);
        return -1;
    }

    *out_buf = sbuf.data;
    *out_size = sbuf.size;
    return 0;
}

static int gcs_only_blanks(const char *p, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (p[i] != ' ' && p[i] != '\t' && p[i] != '\r' && p[i] != '\n') {
            return FLB_FALSE;
        }
    }
    return FLB_TRUE;
}

/*
 * Convert a line into a msgpack map (owned by the caller, flb_free). 'ts' and 'has_ts'
 * are only set when a parser provided a timestamp.
 */
static int gcs_line_to_msgpack(struct flb_in_gcs *ctx, const char *line, size_t len,
                               char **out_buf, size_t *out_size,
                               struct flb_time *ts, int *has_ts)
{
    int ret;
    int root_type;
    size_t consumed = 0;
    size_t off;
    msgpack_unpacked result;
    char *buf = NULL;
    size_t size = 0;

    *has_ts = FLB_FALSE;

    if (ctx->parser) {
        flb_time_zero(ts);
        ret = flb_parser_do(ctx->parser, line, len, (void **) &buf, &size, ts);
        if (ret >= 0) {
            off = 0;
            msgpack_unpacked_init(&result);
            ret = msgpack_unpack_next(&result, buf, size, &off);
            if (ret == MSGPACK_UNPACK_SUCCESS && result.data.type == MSGPACK_OBJECT_MAP) {
                msgpack_unpacked_destroy(&result);
                *has_ts = (ts->tm.tv_sec != 0 || ts->tm.tv_nsec != 0);
                *out_buf = buf;
                *out_size = size;
                return 0;
            }
            msgpack_unpacked_destroy(&result);
            flb_free(buf);
        }
        flb_plg_debug(ctx->ins, "parser '%s' could not process a line, using it as raw log",
                      ctx->parser_name);
        return gcs_pack_log_record(line, len, out_buf, out_size);
    }

    ret = flb_pack_json(line, len, &buf, &size, &root_type, &consumed);
    if (ret == 0) {
        off = 0;
        msgpack_unpacked_init(&result);
        ret = msgpack_unpack_next(&result, buf, size, &off);
        if (ret == MSGPACK_UNPACK_SUCCESS && result.data.type == MSGPACK_OBJECT_MAP &&
            gcs_only_blanks(line + consumed, len - consumed) == FLB_TRUE) {
            msgpack_unpacked_destroy(&result);
            *out_buf = buf;
            *out_size = size;
            return 0;
        }
        msgpack_unpacked_destroy(&result);
        flb_free(buf);
    }

    return gcs_pack_log_record(line, len, out_buf, out_size);
}

/* Look for the time key and parse its value; returns 0 if a timestamp was found */
static int gcs_extract_time(struct flb_in_gcs *ctx, const msgpack_object *map,
                            struct flb_time *ts, uint32_t *key_index)
{
    uint32_t i;
    int ret;
    const msgpack_object_kv *kv;

    for (i = 0; i < map->via.map.size; i++) {
        kv = &map->via.map.ptr[i];
        if (gcs_key_equals(&kv->key, ctx->time_key) == FLB_FALSE) {
            continue;
        }

        if (kv->val.type == MSGPACK_OBJECT_STR) {
            ret = in_gcs_time_parse_string(ctx->time_format, kv->val.via.str.ptr,
                                           kv->val.via.str.size, ts);
        }
        else {
            ret = in_gcs_time_parse_number(ctx->time_format, &kv->val, ts);
        }
        /* a time that the event encoder cannot represent is treated as unparseable */
        if (ret == 0 && flb_time_is_valid_eventtime(ts) == FLB_TRUE) {
            *key_index = i;
            return 0;
        }
        return -1;
    }

    return -1;
}

/*
 * Test seam, only active with FLB_IN_GCS_PLUGIN_UNDER_TEST=true: a line that starts with the
 * marker fails to encode, forever or, with a ':<n>' suffix, for the first <n> attempts.
 */
#define GCS_TEST_ENCODE_FAILURE "__flb_in_gcs_test_encode_failure__"

static int gcs_test_encode_failure(struct flb_in_gcs *ctx, const char *line, size_t len)
{
    size_t marker_len = sizeof(GCS_TEST_ENCODE_FAILURE) - 1;

    if (ctx->under_test == FLB_FALSE || len < marker_len ||
        strncmp(line, GCS_TEST_ENCODE_FAILURE, marker_len) != 0) {
        return FLB_FALSE;
    }
    if (len > marker_len + 1 && line[marker_len] == ':') {
        return ctx->encode_failures < atoi(line + marker_len + 1) ? FLB_TRUE : FLB_FALSE;
    }
    return FLB_TRUE;
}

/* the pair at 'index' is not copied to the rebuilt record */
static int gcs_pair_skipped(struct flb_in_gcs *ctx, const msgpack_object *map,
                            uint32_t index, int time_found, uint32_t time_index)
{
    if (time_found == FLB_TRUE && ctx->time_keep == FLB_FALSE && index == time_index) {
        return FLB_TRUE;
    }
    if (ctx->object_key &&
        gcs_key_equals(&map->via.map.ptr[index].key, ctx->object_key) == FLB_TRUE) {
        return FLB_TRUE;
    }
    return FLB_FALSE;
}

/* Build one record from a line and add it to the encoder */
static int gcs_encode_line(struct flb_in_gcs *ctx, const char *line, size_t len)
{
    int ret;
    int has_ts;
    int time_found = FLB_FALSE;
    uint32_t i;
    uint32_t time_index = 0;
    uint32_t entries = 0;
    size_t off = 0;
    char *mp_buf = NULL;
    size_t mp_size = 0;
    struct flb_time ts;
    msgpack_unpacked result;
    msgpack_sbuffer sbuf;
    msgpack_packer pk;
    const msgpack_object *map;
    const msgpack_object_kv *kv;

    if (gcs_test_encode_failure(ctx, line, len) == FLB_TRUE) {
        return -1;
    }

    ret = gcs_line_to_msgpack(ctx, line, len, &mp_buf, &mp_size, &ts, &has_ts);
    if (ret != 0) {
        return -1;
    }

    /* a parser timestamp that the event encoder cannot represent is not used */
    if (has_ts == FLB_TRUE && flb_time_is_valid_eventtime(&ts) != FLB_TRUE) {
        has_ts = FLB_FALSE;
    }

    msgpack_unpacked_init(&result);
    if (msgpack_unpack_next(&result, mp_buf, mp_size, &off) != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&result);
        flb_free(mp_buf);
        return -1;
    }
    map = &result.data;

    if (!ctx->parser && ctx->time_key_enabled == FLB_TRUE) {
        if (gcs_extract_time(ctx, map, &ts, &time_index) == 0) {
            time_found = FLB_TRUE;
            has_ts = FLB_TRUE;
        }
    }
    if (has_ts == FLB_FALSE) {
        flb_time_get(&ts);
    }

    /* rebuild the map: drop the used time key, replace the object name key */
    for (i = 0; i < map->via.map.size; i++) {
        if (gcs_pair_skipped(ctx, map, i, time_found, time_index) == FLB_FALSE) {
            entries++;
        }
    }
    if (ctx->object_key) {
        entries++;
    }

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

    ret = msgpack_pack_map(&pk, entries);
    for (i = 0; i < map->via.map.size; i++) {
        if (gcs_pair_skipped(ctx, map, i, time_found, time_index) == FLB_TRUE) {
            continue;
        }
        kv = &map->via.map.ptr[i];
        ret |= msgpack_pack_object(&pk, kv->key);
        ret |= msgpack_pack_object(&pk, kv->val);
    }
    if (ctx->object_key) {
        ret |= msgpack_pack_str(&pk, flb_sds_len(ctx->object_key));
        ret |= msgpack_pack_str_body(&pk, ctx->object_key, flb_sds_len(ctx->object_key));
        ret |= msgpack_pack_str(&pk, flb_sds_len(ctx->current.name));
        ret |= msgpack_pack_str_body(&pk, ctx->current.name, flb_sds_len(ctx->current.name));
    }

    msgpack_unpacked_destroy(&result);
    flb_free(mp_buf);

    if (ret != 0) {
        msgpack_sbuffer_destroy(&sbuf);
        return -1;
    }

    ret = flb_log_event_encoder_begin_record(ctx->encoder);
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_timestamp(ctx->encoder, &ts);
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_body_from_raw_msgpack(ctx->encoder, sbuf.data,
                                                              sbuf.size);
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(ctx->encoder);
    }
    else {
        flb_log_event_encoder_rollback_record(ctx->encoder);
    }
    msgpack_sbuffer_destroy(&sbuf);

    return ret == FLB_EVENT_ENCODER_SUCCESS ? 0 : -1;
}

/*
 * Emit up to 'batch_size' records of the current object, resuming from 'buf_off'.
 * Lines are split on '\n', a trailing '\r' is removed and empty lines are skipped.
 * Returns FLB_GCS_EMIT_OK, or a failure after which the same batch is tried again.
 */
int in_gcs_emit_batch(struct flb_in_gcs *ctx)
{
    int ret;
    int emitted = 0;
    size_t start_off = ctx->buf_off;
    size_t line_len;
    const char *start;
    const char *nl;
    const char *tag = NULL;
    size_t tag_len = 0;

    while (emitted < ctx->batch_size && ctx->buf_off < ctx->buf_len) {
        start = ctx->buf + ctx->buf_off;
        nl = memchr(start, '\n', ctx->buf_len - ctx->buf_off);
        if (nl) {
            line_len = nl - start;
            ctx->buf_off += line_len + 1;
        }
        else {
            line_len = ctx->buf_len - ctx->buf_off;
            ctx->buf_off = ctx->buf_len;
        }

        if (line_len > 0 && start[line_len - 1] == '\r') {
            line_len--;
        }
        if (line_len == 0) {
            continue;
        }

        ret = gcs_encode_line(ctx, start, line_len);
        if (ret != 0) {
            /* drop the partial batch: the whole batch is encoded again later */
            flb_plg_warn(ctx->ins, "could not encode a record of '%s'", ctx->current.name);
            flb_log_event_encoder_reset(ctx->encoder);
            ctx->buf_off = start_off;
            return FLB_GCS_EMIT_ENCODE_FAILED;
        }
        emitted++;
    }

    if (emitted == 0) {
        return FLB_GCS_EMIT_OK;
    }

    if (ctx->tag) {
        tag = ctx->tag;
        tag_len = flb_sds_len(ctx->tag);
    }

    ret = flb_input_log_append(ctx->ins, tag, tag_len, ctx->encoder->output_buffer,
                               ctx->encoder->output_length);
    flb_log_event_encoder_reset(ctx->encoder);
    if (ret != 0) {
        /* nothing was ingested (e.g. backpressure): resume from the same line later */
        flb_plg_warn(ctx->ins, "could not append %d records of '%s', will retry", emitted,
                     ctx->current.name);
        ctx->buf_off = start_off;
        return FLB_GCS_EMIT_APPEND_FAILED;
    }
    ctx->records_emitted += emitted;

    return FLB_GCS_EMIT_OK;
}
