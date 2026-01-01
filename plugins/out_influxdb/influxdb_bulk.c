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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <fluent-bit.h>
#include "influxdb.h"
#include "influxdb_bulk.h"

static const uint64_t ONE_BILLION = 1000000000;

static int influxdb_escape(char *out, const char *str, int size, bool quote) {
    int out_size = 0;
    int i;
    for (i = 0; i < size; ++i) {
        char ch = str[i];
        if (quote ? (ch == '"' || ch == '\\') : (isspace(ch) || ch == ',' || ch == '=')) {
            out[out_size++] = '\\';
        } else if (ch == '\\') {
            out[out_size++] = '\\';
        }
        out[out_size++] = ch;
    }
    return out_size;
}

static int influxdb_bulk_buffer(struct influxdb_bulk *bulk, int required)
{
    int new_size;
    int available;
    char *ptr;

    available = (bulk->size - bulk->len);
    if (available < required) {
        new_size = bulk->size + available + required + INFLUXDB_BULK_CHUNK;
        ptr = flb_realloc(bulk->ptr, new_size);
        if (!ptr) {
            flb_errno();
            return -1;
        }
        bulk->ptr  = ptr;
        bulk->size = new_size;
    }

    return 0;
}

struct influxdb_bulk *influxdb_bulk_create()
{
    struct influxdb_bulk *b;

    b = flb_malloc(sizeof(struct influxdb_bulk));
    if (!b) {
        perror("calloc");
        return NULL;
    }

    b->ptr = flb_malloc(INFLUXDB_BULK_CHUNK);
    if (!b->ptr) {
        perror("malloc");
        flb_free(b);
        return NULL;
    }

    b->size = INFLUXDB_BULK_CHUNK;
    b->len  = 0;

    return b;
}

void influxdb_bulk_destroy(struct influxdb_bulk *bulk)
{
    if (bulk->size > 0) {
        flb_free(bulk->ptr);
    }
    flb_free(bulk);
}

int influxdb_bulk_append_header(struct influxdb_bulk *bulk,
                                const char *tag, int tag_len,
                                uint64_t seq_n, const char *seq, int seq_len)
{
    int ret;
    int required;

    required = tag_len + 1 + seq_len + 1 + 32;

    /* Make sure we have enough space */
    ret = influxdb_bulk_buffer(bulk, required);
    if (ret != 0) {
        return -1;
    }

    /* Tag, sequence and final space */
    memcpy(bulk->ptr + bulk->len, tag, tag_len);
    bulk->len += tag_len;

    if (seq_len != 0) {
        bulk->ptr[bulk->len] = ',';
        bulk->len++;

        /* Sequence number */
        memcpy(bulk->ptr + bulk->len, seq, seq_len);
        bulk->len += seq_len;

        bulk->ptr[bulk->len] = '=';
        bulk->len++;

        ret = snprintf(bulk->ptr + bulk->len, 32, "%" PRIu64, seq_n);
        bulk->len += ret;
    }

    /* Add a NULL byte for debugging purposes */
    bulk->ptr[bulk->len] = '\0';

    return 0;
}

int influxdb_bulk_append_kv(struct influxdb_bulk *bulk,
                            const char *key, int k_len,
                            const char *val, int v_len,
                            int quote)
{
    int ret;
    int required;

    /* Reserve double space for keys and values in case of escaping */
    required = k_len * 2 + 1 + v_len * 2 + 1 + 1;
    if (quote) {
        required += 2;
    }

    /* Make sure we have enough space */
    ret = influxdb_bulk_buffer(bulk, required);
    if (ret != 0) {
        return -1;
    }

    if (bulk->len > 0) {
        bulk->ptr[bulk->len] = ',';
        bulk->len++;
    }

    /* key */
    bulk->len += influxdb_escape(bulk->ptr + bulk->len, key, k_len, false);

    /* separator */
    bulk->ptr[bulk->len] = '=';
    bulk->len++;

    /* value */
    if (quote) {
        bulk->ptr[bulk->len] = '"';
        bulk->len++;
    }
    bulk->len += influxdb_escape(bulk->ptr + bulk->len, val, v_len, quote);
    if (quote) {
        bulk->ptr[bulk->len] = '"';
        bulk->len++;
    }

    /* Add a NULL byte for debugging purposes */
    bulk->ptr[bulk->len] = '\0';

    return 0;
};

int influxdb_bulk_append_timestamp(struct influxdb_bulk *bulk,
                                   struct flb_time *t)
{
    int ret;
    int len;
    uint64_t timestamp;

    /* Make sure we have enough space */
    ret = influxdb_bulk_buffer(bulk, 128);
    if (ret != 0) {
        return -1;
    }

    /* Timestamp is in Nanoseconds */
    timestamp = (t->tm.tv_sec * ONE_BILLION) + t->tm.tv_nsec;
    len = snprintf(bulk->ptr + bulk->len, 127, " %" PRIu64, timestamp);
    if (len == -1) {
        return -1;
    }
    bulk->len += len;
    bulk->ptr[bulk->len] = '\0';

    return 0;
};

int influxdb_bulk_append_bulk(struct influxdb_bulk *bulk_to,
                              struct influxdb_bulk *bulk_from,
                              char separator)
{
    if (influxdb_bulk_buffer(bulk_to, bulk_from->len + 2) != 0) {
        return -1;
    }

    if (bulk_to->len > 0) {
        bulk_to->ptr[bulk_to->len] = separator;
        bulk_to->len += 1;
    }

    memcpy(bulk_to->ptr + bulk_to->len,
           bulk_from->ptr, bulk_from->len * sizeof(char));
    bulk_to->len += bulk_from->len;

    /* Add a NULL byte for always terminating with NULL */
    bulk_to->ptr[bulk_to->len] = '\0';

    return 0;
};
