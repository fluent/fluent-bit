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

#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define _GNU_SOURCE
#include <time.h>

#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_parser_decoder.h>
#include <msgpack.h>

/*
 * CSV field parser, implementing (most of) RFC 4180: double-quoted fields,
 * "" as an escaped double quote, and comma as the sole delimiter. Since
 * flb_parser_do() always receives a single, already delimited record with
 * no guaranteed trailing line terminator (callers usually strip it before
 * invoking the parser), embedded newlines inside quoted fields are not
 * supported here - that would require access to the raw, un-split stream,
 * which flb_csv.c (used for streaming/record splitting) already handles.
 *
 * This is a single left-to-right pass over the input buffer: it never
 * copies or rescans bytes to find field boundaries, it only records
 * (offset, length) pairs into the caller's buffer. A second, position-only
 * pass fills the msgpack map once the total field count (and therefore the
 * map header) is known. Unescaping ("" -> ") is only performed for the
 * (uncommon) fields that actually contain an embedded quote, and reuses a
 * small stack buffer unless the field is unusually large.
 */

/* Fields are tracked on the stack up to this count before falling back to
 * a heap allocated (and geometrically grown) buffer, avoiding both a fixed
 * hard limit and unnecessary allocations for typical CSV records.
 */
#define FLB_PARSER_CSV_STATIC_FIELDS 128

/* Fields are unescaped on the stack up to this size before falling back to
 * a one-off heap allocation.
 */
#define FLB_PARSER_CSV_STATIC_UNESCAPE 256

struct csv_field {
    size_t pos;
    size_t len;
    bool has_dquote;
};

struct csv_field_buf {
    struct csv_field *fields;
    size_t cap;
    bool heap;
};

static int csv_field_buf_grow(struct csv_field_buf *fb)
{
    size_t new_cap;
    struct csv_field *new_fields;

    new_cap = fb->cap * 2;

    if (fb->heap) {
        new_fields = flb_realloc(fb->fields, new_cap * sizeof(struct csv_field));
        if (!new_fields) {
            flb_errno();
            return -1;
        }
    }
    else {
        new_fields = flb_malloc(new_cap * sizeof(struct csv_field));
        if (!new_fields) {
            flb_errno();
            return -1;
        }
        memcpy(new_fields, fb->fields, fb->cap * sizeof(struct csv_field));
        fb->heap = true;
    }

    fb->fields = new_fields;
    fb->cap = new_cap;
    return 0;
}

/*
 * Split a single CSV record into (offset, length) fields. Returns the
 * number of fields found, or (size_t) -1 on allocation failure while
 * growing the field buffer.
 */
static size_t csv_split_record(const char *buf, size_t len,
                               struct csv_field_buf *fb)
{
    size_t pos = 0;
    size_t count = 0;
    struct csv_field *f;

    for (;;) {
        if (count >= fb->cap) {
            if (csv_field_buf_grow(fb) == -1) {
                return (size_t) -1;
            }
        }
        f = &fb->fields[count];
        f->has_dquote = false;

        if (pos < len && buf[pos] == '"') {
            /* quoted field */
            pos++;
            f->pos = pos;
            while (pos < len) {
                if (buf[pos] == '"') {
                    if (pos + 1 < len && buf[pos + 1] == '"') {
                        f->has_dquote = true;
                        pos += 2;
                        continue;
                    }
                    break;
                }
                pos++;
            }
            f->len = pos - f->pos;
            if (pos < len) {
                /* skip closing quote */
                pos++;
            }
            count++;
            if (pos < len && buf[pos] == ',') {
                pos++;
                continue;
            }
            break;
        }
        else {
            f->pos = pos;
            while (pos < len && buf[pos] != ',') {
                pos++;
            }
            f->len = pos - f->pos;
            count++;
            if (pos < len) {
                /* skip comma; a trailing comma implies one more (empty)
                 * field, handled by the next loop iteration */
                pos++;
                continue;
            }
            break;
        }
    }

    return count;
}

/* Collapse a "" escaped quote pair into a single ", mirroring flb_csv.c */
static size_t csv_unescape(const char *src, size_t len, char *dst)
{
    size_t in = 0;
    size_t out = 0;

    while (in < len) {
        if (src[in] == '"') {
            in++;
        }
        dst[out++] = src[in++];
    }
    return out;
}

static int csv_pack_value(msgpack_packer *pck, const char *buf,
                          struct csv_field *f)
{
    char stack_buf[FLB_PARSER_CSV_STATIC_UNESCAPE];
    char *out_buf;
    size_t out_len;
    bool heap = false;

    if (!f->has_dquote) {
        msgpack_pack_str(pck, f->len);
        msgpack_pack_str_body(pck, buf + f->pos, f->len);
        return 0;
    }

    if (f->len <= sizeof(stack_buf)) {
        out_buf = stack_buf;
    }
    else {
        out_buf = flb_malloc(f->len);
        if (!out_buf) {
            flb_errno();
            return -1;
        }
        heap = true;
    }

    out_len = csv_unescape(buf + f->pos, f->len, out_buf);
    msgpack_pack_str(pck, out_len);
    msgpack_pack_str_body(pck, out_buf, out_len);

    if (heap) {
        flb_free(out_buf);
    }
    return 0;
}

void flb_parser_csv_resolve_time_field(struct flb_parser *parser)
{
    int i;
    char *end;
    long idx;

    parser->csv_time_field_index = -1;

    if (!parser->time_key) {
        return;
    }

    if (parser->csv_field_names) {
        for (i = 0; i < parser->csv_field_names_len; i++) {
            if (strcmp(parser->csv_field_names[i], parser->time_key) == 0) {
                parser->csv_time_field_index = i;
                return;
            }
        }
        return;
    }

    /* No named fields: 'time_key' must be a 0-based field index */
    errno = 0;
    idx = strtol(parser->time_key, &end, 10);
    if (end != parser->time_key && *end == '\0' && errno == 0 && idx >= 0) {
        parser->csv_time_field_index = (int) idx;
    }
}

int flb_parser_csv_set_fields(struct flb_parser *parser,
                              char **fields, int fields_len)
{
    int i;
    char **names;

    if (fields_len <= 0) {
        return -1;
    }

    names = flb_calloc(fields_len, sizeof(char *));
    if (!names) {
        flb_errno();
        return -1;
    }

    for (i = 0; i < fields_len; i++) {
        names[i] = flb_strdup(fields[i]);
        if (!names[i]) {
            flb_errno();
            while (i > 0) {
                flb_free(names[--i]);
            }
            flb_free(names);
            return -1;
        }
    }

    if (parser->csv_field_names) {
        for (i = 0; i < parser->csv_field_names_len; i++) {
            flb_free(parser->csv_field_names[i]);
        }
        flb_free(parser->csv_field_names);
    }

    parser->csv_field_names = names;
    parser->csv_field_names_len = fields_len;

    flb_parser_csv_resolve_time_field(parser);
    return 0;
}

int flb_parser_csv_do(struct flb_parser *parser,
                      const char *in_buf, size_t in_size,
                      void **out_buf, size_t *out_size,
                      struct flb_time *out_time)
{
    int ret;
    int time_idx;
    size_t i;
    size_t field_count;
    size_t map_size;
    bool have_time = false;
    bool exclude_time_field;
    double tmfrac = 0;
    struct flb_tm tm = {0};
    struct csv_field static_fields[FLB_PARSER_CSV_STATIC_FIELDS];
    struct csv_field_buf fb;
    struct csv_field *f;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    char key_buf[32];
    const char *key;
    int key_len;
    char *dec_out_buf;
    size_t dec_out_size;

    fb.fields = static_fields;
    fb.cap = FLB_PARSER_CSV_STATIC_FIELDS;
    fb.heap = false;

    field_count = csv_split_record(in_buf, in_size, &fb);
    if (field_count == (size_t) -1) {
        return -1;
    }

    time_idx = parser->csv_time_field_index;
    if (time_idx >= 0 && (size_t) time_idx < field_count && parser->time_fmt) {
        f = &fb.fields[time_idx];
        ret = flb_parser_time_lookup(in_buf + f->pos, f->len, 0, parser, &tm, &tmfrac);
        if (ret == -1) {
            flb_warn("[parser:%s] invalid time format %s",
                     parser->name, parser->time_fmt_full);
        }
        else {
            have_time = true;
        }
    }

    out_time->tm.tv_sec = 0;
    out_time->tm.tv_nsec = 0;
    if (have_time) {
        out_time->tm.tv_sec = flb_parser_tm2time_parser(&tm, parser);
        out_time->tm.tv_nsec = (tmfrac * 1000000000);
    }

    exclude_time_field = have_time && !parser->time_keep;
    map_size = field_count - (exclude_time_field ? 1 : 0);

    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&tmp_pck, map_size);

    for (i = 0; i < field_count; i++) {
        if (exclude_time_field && i == (size_t) time_idx) {
            continue;
        }

        f = &fb.fields[i];

        if (parser->csv_field_names && i < (size_t) parser->csv_field_names_len) {
            key = parser->csv_field_names[i];
            key_len = strlen(key);
        }
        else {
            key_len = snprintf(key_buf, sizeof(key_buf), "%zu", i);
            key = key_buf;
        }

        if (parser->types_len != 0) {
            char val_stack[FLB_PARSER_CSV_STATIC_UNESCAPE];
            char *val_buf;
            size_t val_len;
            bool val_heap = false;

            if (!f->has_dquote) {
                flb_parser_typecast(key, key_len, in_buf + f->pos, f->len,
                                    &tmp_pck, parser->types, parser->types_len);
            }
            else {
                if (f->len <= sizeof(val_stack)) {
                    val_buf = val_stack;
                }
                else {
                    val_buf = flb_malloc(f->len);
                    if (!val_buf) {
                        flb_errno();
                        msgpack_sbuffer_destroy(&tmp_sbuf);
                        if (fb.heap) {
                            flb_free(fb.fields);
                        }
                        return -1;
                    }
                    val_heap = true;
                }
                val_len = csv_unescape(in_buf + f->pos, f->len, val_buf);
                flb_parser_typecast(key, key_len, val_buf, val_len,
                                    &tmp_pck, parser->types, parser->types_len);
                if (val_heap) {
                    flb_free(val_buf);
                }
            }
        }
        else {
            msgpack_pack_str(&tmp_pck, key_len);
            msgpack_pack_str_body(&tmp_pck, key, key_len);

            ret = csv_pack_value(&tmp_pck, in_buf, f);
            if (ret == -1) {
                msgpack_sbuffer_destroy(&tmp_sbuf);
                if (fb.heap) {
                    flb_free(fb.fields);
                }
                return -1;
            }
        }
    }

    if (fb.heap) {
        flb_free(fb.fields);
    }

    *out_buf = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;

    /* Check if some decoder was specified */
    if (parser->decoders) {
        ret = flb_parser_decoder_do(parser->decoders,
                                    tmp_sbuf.data, tmp_sbuf.size,
                                    &dec_out_buf, &dec_out_size);
        if (ret == 0) {
            *out_buf = dec_out_buf;
            *out_size = dec_out_size;
            msgpack_sbuffer_destroy(&tmp_sbuf);
        }
    }

    return (int) in_size;
}
