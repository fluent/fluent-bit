/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include "fluent-bit/flb_log.h"
#include "fluent-bit/flb_sds.h"
#include "fluent-bit/flb_str.h"
#include "mpack/mpack.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define _GNU_SOURCE
#include <time.h>

#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_parser_decoder.h>



#define MAX_FIELD_COUNT 1024

struct csv_field {
    int pos;
    int len;
    bool has_dquote;
};

struct output_buffer {
    char *buf;
    size_t size;
};


/* Implementation of https://datatracker.ietf.org/doc/html/rfc4180 minus support
 * for newline characters in quoted fields */

static void mpack_buffer_flush(mpack_writer_t* writer, const char* buffer, size_t count)
{
    struct output_buffer *outbuf = writer->context;
    if (outbuf->buf == NULL) {
        /* first allocation */
        outbuf->buf = flb_malloc(count);
        outbuf->size = 0;
    } else {
        outbuf->buf = flb_realloc(outbuf->buf, count + outbuf->size);
        outbuf->size += count;
    }

    memcpy(outbuf->buf + outbuf->size, buffer, count);
    outbuf->size += count;
}

static int parse_simple(
        struct csv_field *fields, 
        size_t *field_count,
        const char *in_buf, size_t in_size, size_t *in_pos)
{
    bool remove_last;
    struct csv_field *current = fields + *field_count;
    current->pos = *in_pos;

    while (*in_pos < in_size) {
        if (in_buf[(*in_pos)++] == ',') {
            /* end of field */
            break;
        }
    }

    remove_last = *in_pos < in_size;
    (*field_count)++;
    current->len = *in_pos - current->pos - (remove_last ? 1 : 0);
    return 1;
}

static int parse_quoted(
        struct csv_field *fields, 
        size_t *field_count,
        const char *in_buf, size_t in_size, size_t *in_pos)
{
    struct csv_field *current = fields + *field_count;
    /* advance past opening quote */
    (*in_pos)++;
    current->pos = *in_pos;

    while (*in_pos < in_size) {
        if (in_buf[(*in_pos)++] == '"') {
            if (in_buf[*in_pos] != '"') {
                break;
            } else {
                current->has_dquote = true;
                (*in_pos)++;
            }
        }
    }

    /* end of field */
    (*field_count)++;
    current->len = *in_pos - current->pos - 1;
    /* advance past the comma */
    *in_pos += 1;
    return 1;
}

static int parse_csv_field(
        struct csv_field *fields, 
        size_t *field_count,
        const char *in_buf, size_t in_size, size_t *in_pos)
{
    if (*in_pos >= in_size) {
        return 0;
    }
    (fields + *field_count)->has_dquote = false;
    if (in_buf[*in_pos] == '"') {
        return parse_quoted(fields, field_count, in_buf, in_size, in_pos);
    }
    else {
        return parse_simple(fields, field_count, in_buf, in_size, in_pos);
    }
}

static size_t parse_csv_record(
        struct csv_field *fields,
        const char *in_buf, size_t in_size)
{
    size_t in_pos = 0;
    size_t field_count = 0;
    int parsed;

    do {
        parsed = parse_csv_field(fields, &field_count, in_buf, in_size, &in_pos);
    } while (parsed);

    return field_count;
}

char **flb_parser_csv_parse_line(const char *in_buf, size_t in_size)
{
    struct csv_field fields[MAX_FIELD_COUNT];
    size_t field_count;
    size_t i = 0;
    size_t j;
    char **result = NULL;

    field_count = parse_csv_record(fields, in_buf, in_size);
    result = flb_calloc(field_count + 1, sizeof *result);
    if (!result) {
        flb_error("failed to allocate memory");
        goto error;
    }

    for (i = 0; i < field_count; i++) {
        size_t pos = fields[i].pos;
        size_t len = fields[i].len;
        result[i] = flb_strndup(in_buf + pos, len);
        if (!result[i]) {
            flb_error("failed to allocate memory");
            goto error;
        }
    }
    result[i] = NULL;  /* sentinel to signal end of array */

    return result;
error:
    /* free array items that were successfully allocated */
    for (j = 0; j < i; j++) {
        flb_free(result[j]);
    }
    /* free array */
    if (result) {
        flb_free(result);
    }
    return NULL;
}

static int search_time_field(struct flb_parser *parser, size_t field_count)
{
    size_t i;

    if (!parser->time_key || !parser->time_fmt) {
        return 0;
    }

    if (!parser->csv_context.header) {
        /* no header was defined, but it is possible to specify a field index
         * as the time key */
        return parser->csv_context.time_field_index >= 0 &&
            parser->csv_context.time_field_index < field_count;
    }

    for (i = 0; i < parser->csv_context.header_count; i++) {
        if (parser->csv_context.header[i] &&
                !strcmp(parser->csv_context.header[i], parser->time_key)) {
            /* found */
            return 1;
        }
    }

    return 0;
}

static int parse_time_field(
        struct flb_parser *parser,
        const char *in_buf,
        struct csv_field *fields, size_t i,
        struct flb_time *out_time)
{
    int ret;
    double tmfrac;
    struct tm tm = {0};
    time_t time_lookup;
    size_t pos = fields[i].pos;
    size_t len = fields[i].len;

    if (!parser->time_key || !parser->time_fmt) {
        return 0;
    }

    ret = flb_parser_time_lookup(in_buf + pos, len, 0, parser, &tm, &tmfrac);
    if (ret) {
        char tmp[256];
        if (len > sizeof(tmp) - 1) {
            len = sizeof(tmp) - 1;
        }
        memcpy(tmp, in_buf + pos, len);
        tmp[len] = 0;
        flb_warn("[parser:%s] invalid time format %s for '%s'",
                 parser->name, parser->time_fmt_full, tmp);
        return 0;
    } else {
        time_lookup = flb_parser_tm2time(&tm);
        (*out_time).tm.tv_sec = time_lookup;
        (*out_time).tm.tv_nsec = (tmfrac * 1000000000);
        return 1;
    }
}

static struct flb_parser_csv_state *get_state(struct flb_parser *parser)
{
    /* TODO: we need to associate one state per input instance */
    return &parser->csv_context.state;
}

static int pack_escaped_field(
        struct flb_parser *parser,
        mpack_writer_t *writer,
        struct csv_field *field,
        const char *inbuf)
{
    size_t in_pos = field->pos;
    size_t in_end = in_pos + field->len;
    size_t out_pos = 0;
    size_t buffer_size = field->len + 1;

    if (!parser->csv_context.escape_buf) {
        /* Allocate a buffer in the context to perform the escaping.
         * We store in the context to reuse between calls and avoid allocating
         * whenever we need to escape a field */
        parser->csv_context.escape_buf_size = buffer_size;
        parser->csv_context.escape_buf = flb_malloc(buffer_size);
        if (!parser->csv_context.escape_buf) {
            goto oom;
        }
    } else if (buffer_size > parser->csv_context.escape_buf_size)  {
        /* Buffer size not enough, need to reallocate */
        parser->csv_context.escape_buf = flb_realloc(
                parser->csv_context.escape_buf, buffer_size);
        if (!parser->csv_context.escape_buf) {
            goto oom;
        }
        parser->csv_context.escape_buf_size = buffer_size;
    }

    while (in_pos < in_end) {
        if (inbuf[in_pos] == '"') {
            /* every double quote inside the field must have been escaped,
             * so we simply skip the first one */
            in_pos++;
        }
        parser->csv_context.escape_buf[out_pos++] = inbuf[in_pos++];
    }
    mpack_write_str(writer, parser->csv_context.escape_buf, out_pos);
    return 1;

oom:
    flb_error("failed to allocate memory");
    return 0;
}

static int pack_field(struct flb_parser *parser,
                     mpack_writer_t *writer,
                     const char *in_buf, size_t in_size,
                     struct csv_field *fields, size_t i,
                     struct flb_time *out_time)
{
    if (parser->csv_context.header && i < parser->csv_context.header_count) {
        if (!strcmp(parser->time_key, parser->csv_context.header[i]) &&
                parse_time_field(parser, in_buf, fields, i, out_time)) {
            /* found and parsed */
            return 0;
        } else {
            mpack_write_cstr(writer, parser->csv_context.header[i]);
        }
    } else {
        if (parser->csv_context.time_field_index == i &&
                parse_time_field(parser, in_buf, fields, i, out_time)) {
            return 0;
        }
    }
    if (fields[i].has_dquote) {
        /* Since the field has double quotes, we must use a temporary buffer
         * to escape. `pack_escaped_field` function will handle everything */
        return pack_escaped_field(parser, writer, fields + i, in_buf);
    } else {
        mpack_write_str(writer, in_buf + fields[i].pos, fields[i].len);
        return 1;
    }
}

int flb_parser_csv_do(struct flb_parser *parser,
                      const char *in_buf, size_t in_size,
                      void **out_buf, size_t *out_size,
                      struct flb_time *out_time)
{
    char writebuf[1024];
    struct output_buffer outbuf;
    mpack_writer_t writer;
    struct csv_field fields[MAX_FIELD_COUNT];
    size_t field_count;
    size_t i;
    int time_field_found;
    size_t msgpack_count;


    field_count = parse_csv_record(fields, in_buf, in_size);
    if (!field_count) {
        field_count = 1;
        fields[0].pos = 0;
        fields[0].len = in_size;
    }
    time_field_found = search_time_field(parser, field_count);
    msgpack_count = time_field_found ? field_count - 1 : field_count;

    memset(&outbuf, 0, sizeof outbuf);
    mpack_writer_init(&writer, writebuf, sizeof(writebuf));
    mpack_writer_set_context(&writer, &outbuf);
    mpack_writer_set_flush(&writer, mpack_buffer_flush);

    if (parser->csv_context.header) {
        mpack_write_tag(&writer, mpack_tag_map(msgpack_count));
    } else {
        mpack_write_tag(&writer, mpack_tag_map(1));
        mpack_write_cstr(&writer, "values");
        mpack_write_tag(&writer, mpack_tag_array(msgpack_count));
    }
    for (i = 0; i < field_count; i++) {
        pack_field(parser, &writer, in_buf, in_size, fields, i, out_time);
    }

    mpack_writer_flush_message(&writer);
    mpack_writer_destroy(&writer);

    *out_buf = outbuf.buf;
    *out_size = outbuf.size;

    return outbuf.size;
}
