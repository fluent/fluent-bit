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
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#define _GNU_SOURCE
#include <time.h>

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_str.h>

#include <fluent-bit/flb_csv.h>


enum {
    FLB_CSV_STATE_INITIAL = 0,
    FLB_CSV_STATE_STARTED_SIMPLE,
    FLB_CSV_STATE_STARTED_DQUOTE,
    FLB_CSV_STATE_FOUND_DQUOTE,
    FLB_CSV_STATE_FOUND_CR
};

static void reset_state(struct flb_csv_state *state)
{
    state->start = 0;
    state->length = 0;
    state->has_dquote = false;
    state->field_parsed = false;
    state->state = FLB_CSV_STATE_INITIAL;
    flb_sds_len_set(state->escape_buffer, 0);
    flb_sds_len_set(state->buffered_data, 0);
    state->offset = 0;
}

static int invoke_field_callback(struct flb_csv_state *state, const char *buf, size_t bufsize)
{
    size_t escpos;
    size_t bufpos;
    size_t bufend;

    if (!state->has_dquote) {
        /* simple case, since there's no double quotes, no escaping needs
         * to be done */
        state->field_callback(state->data, buf + state->start, state->length);
        return 0;
    }
    /* ensure there's enough space in the escape buffer */
    if (flb_sds_alloc(state->escape_buffer) < state->length) {
        state->escape_buffer = flb_sds_increase(
                state->escape_buffer, state->length);
        if (!state->escape_buffer) {
            return FLB_CSV_ALLOC_FAILED;
        }
    }

    escpos = 0;
    bufpos = state->start;
    bufend = bufpos + state->length;
    while (bufpos < bufend) {
        if (buf[bufpos] == '"') {
            /* escape double quote */
            bufpos++;
        }
        state->escape_buffer[escpos++] = buf[bufpos++];
    }
    state->escape_buffer[escpos] = 0;
    flb_sds_len_set(state->escape_buffer, escpos);
    state->field_callback(state->data, state->escape_buffer, escpos);
    return 0;
}

static int parse_simple(struct flb_csv_state *state, const char *buf, size_t bufsize)
{
    char c;

    for (;;) {
        if (state->offset >= bufsize) {
            return FLB_CSV_EOF;
        }
        c = buf[state->offset];
        if (c == ',' || c == '\n' || c == '\r') {
            /* end of field */
            break;
        }
        state->offset++;
    }

    state->length = state->offset - state->start;
    return 0;
}

static int parse_quoted(struct flb_csv_state *state, const char *buf, size_t bufsize)
{
    char c;

    for (;;) {
        if (state->offset >= bufsize) {
            return FLB_CSV_EOF;
        }
        c = buf[state->offset];
        if (state->state == FLB_CSV_STATE_FOUND_DQUOTE) {
            state->state = FLB_CSV_STATE_STARTED_DQUOTE;
            if (c == '"') {
                /* dquote inside field, skip but set flag so we can properly escape later */
                state->has_dquote = true;
            }
            else {
                /* end of field */
                break;
            }
        }
        else if (c == '"') {
            state->state = FLB_CSV_STATE_FOUND_DQUOTE;
        }
        state->offset++;
    }

    /* subtract 1 to remove ending double quote */
    state->length = state->offset - state->start - 1;
    return 0;
}

static int parse_csv_field(struct flb_csv_state *state, const char *data, size_t len)
{
    int ret;
    const char *buf;
    size_t bufsize;
    bool buffered = false;

    buf = data;
    bufsize = len;

    if (state->state == FLB_CSV_STATE_INITIAL) {
        if (data[state->offset] == '"') {
            /* advance past opening quote */
            state->offset++;
            state->state = FLB_CSV_STATE_STARTED_DQUOTE;
        }
        else {
            state->state = FLB_CSV_STATE_STARTED_SIMPLE;
        }
        state->start = state->offset;
    }
    else if (state->field_callback) {
        state->buffered_data = flb_sds_cat(state->buffered_data, data, len);
        if (!state->buffered_data) {
            return FLB_CSV_ALLOC_FAILED;
        }
        buf = state->buffered_data;
        bufsize = flb_sds_len(state->buffered_data);
        buffered = true;
    }

    switch (state->state) {
        case FLB_CSV_STATE_STARTED_SIMPLE:
            ret = parse_simple(state, buf, bufsize);
            break;
        case FLB_CSV_STATE_STARTED_DQUOTE:
        case FLB_CSV_STATE_FOUND_DQUOTE:
            ret = parse_quoted(state, buf, bufsize);
            break;
        default:
            return FLB_CSV_INVALID_STATE;
    }

    if (ret) {
        if (!buffered && ret == FLB_CSV_EOF) {
            /* not finished, we need to save data in the buffer */
            state->buffered_data = flb_sds_cat(state->buffered_data, data, len);
            if (!state->buffered_data) {
                return FLB_CSV_ALLOC_FAILED;
            }
        }
        return ret;
    }

    if (state->field_callback) {
        ret = invoke_field_callback(state, buf, bufsize);
        if (ret) {
            return ret;
        }
    }

    return ret;
}

void flb_csv_init(struct flb_csv_state *state,
                  flb_csv_field_parsed_callback field_callback,
                  void *data)
{
    state->buffered_data = flb_sds_create("");
    state->escape_buffer = flb_sds_create("");
    state->field_callback = field_callback;
    state->data = data;
    state->field_count = 0;
    reset_state(state);
}

int flb_csv_parse_record(struct flb_csv_state *state,
                         char **bufptr,
                         size_t *buflen,
                         size_t *field_count)
{
    char c;
    int ret;
    size_t initial_offset;
    size_t advanced;

    for (;;) {
        if (!(*buflen)) {
            return FLB_CSV_EOF;
        }
        c = **bufptr;
        if (state->state == FLB_CSV_STATE_INITIAL) {
            if (c == '\r') {
                state->state = FLB_CSV_STATE_FOUND_CR;
                (*bufptr)++;
                (*buflen)--;
                continue;
            }
            else if (c == '\n') {
                /* accept single linefeed as record terminator, even
                 * though the spec says to look for \r\n */
                (*bufptr)++;
                (*buflen)--;
                break;
            }
            else if (c == ',') {
                (*bufptr)++;
                (*buflen)--;
                if (!state->field_parsed) {
                    state->field_count++;
                    if (state->field_callback) {
                        /* empty field, but we need to invoke the callback anyway */
                        state->field_callback(state->data, "", 0);
                    }
                }
                state->field_parsed = false;
                continue;
            }
        }
        else if (state->state == FLB_CSV_STATE_FOUND_CR) {
            state->state = FLB_CSV_STATE_INITIAL;
            if (c == '\n') {
                /* if the character following \r is \n, consume it */
                (*bufptr)++;
                (*buflen)--;
            }
            /* in any case, accept lone \r as record separator */
            break;
        }

        initial_offset = state->offset;

        ret = parse_csv_field(state, *bufptr, *buflen);

        advanced = state->offset - initial_offset;
        *bufptr += advanced;
        *buflen -= advanced;

        if (ret) {
            if (!state->field_callback) {
                /* when no field callback is set, we shouldn't keep
                 * offset state between calls since no data will be buffered */
                state->offset = 0;
            }
            return ret;
        }

        /* when a field is fully parsed, we can reset state */
        reset_state(state);
        /* set this flag so we can properly handle empty fields at the start
         * of the loop */
        state->field_parsed = true;
        state->field_count++;
    }

    if (!state->field_parsed) {
        state->field_count++;
        if (state->field_callback) {
            /* empty field, but we need to invoke the callback anyway */
            state->field_callback(state->data, "", 0);
        }
    }
    state->field_parsed = false;
    *field_count = state->field_count;
    state->field_count = 0;
    return FLB_CSV_SUCCESS;
}

void flb_csv_destroy(struct flb_csv_state *state)
{
    flb_sds_destroy(state->buffered_data);
    flb_sds_destroy(state->escape_buffer);
}
