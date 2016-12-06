/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#include <fluent-bit.h>
#include "influxdb_bulk.h"

static int influxdb_bulk_buffer(struct influxdb_bulk *bulk, int required)
{
    int new_size;
    int available;
    char *ptr;

    available = (bulk->size - bulk->len);
    if (available < required) {
        new_size = bulk->size + (((available + required) / INFLUXDB_BULK_CHUNK) + INFLUXDB_BULK_CHUNK);
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
                                char *db, int db_len,
                                char *tag, int tag_len)
{
    int ret;
    int required;

    required = 4 + db_len + 1 + tag_len + 2;

    /* Make sure we have enough space */
    ret = influxdb_bulk_buffer(bulk, required);
    if (ret != 0) {
        return -1;
    }

    /* Prefix message with database name */
    memcpy(bulk->ptr + bulk->len, db, db_len);
    bulk->len += db_len;

    /* Separator */
    bulk->ptr[bulk->len] = ',';
    bulk->len++;

    /* Tag and final space */
    memcpy(bulk->ptr + bulk->len, "tag=", 4);
    bulk->len += 4;
    memcpy(bulk->ptr + bulk->len, tag, tag_len);
    bulk->len += tag_len;

    bulk->ptr[bulk->len] = ' ';
    bulk->len++;

    /* Add a NULL byte for debugging purposes */
    bulk->ptr[bulk->len] = '\0';

    return 0;
}

int influxdb_bulk_append_kv(struct influxdb_bulk *bulk,
                            char *key, int k_len,
                            char *val, int v_len,
                            int more, int quote)
{
    int ret;
    int required;

    required = k_len + 1 + v_len + 1 + 1;
    if (quote) {
        required += 2;
    }

    /* Make sure we have enough space */
    ret = influxdb_bulk_buffer(bulk, required);
    if (ret != 0) {
        return -1;
    }

    if (more) {
        bulk->ptr[bulk->len] = ',';
        bulk->len++;
    }

    /* key */
    memcpy(bulk->ptr + bulk->len, key, k_len);
    bulk->len += k_len;

    /* separator */
    bulk->ptr[bulk->len] = '=';
    bulk->len++;

    /* value */
    if (quote) {
        bulk->ptr[bulk->len] = '"';
        bulk->len++;
    }
    memcpy(bulk->ptr + bulk->len, val, v_len);
    bulk->len += v_len;
    if (quote) {
        bulk->ptr[bulk->len] = '"';
        bulk->len++;
    }

    /* Add a NULL byte for debugging purposes */
    bulk->ptr[bulk->len] = '\0';

    return 0;
};

int influxdb_bulk_append_eol(struct influxdb_bulk *bulk)
{
    int ret;

    /* Make sure we have enough space */
    ret = influxdb_bulk_buffer(bulk, 2);
    if (ret != 0) {
        return -1;
    }

    /* Break line */
    bulk->ptr[bulk->len] = '\n';
    bulk->len++;

    /* Add a NULL byte for debugging purposes */
    bulk->ptr[bulk->len] = '\0';

    return 0;
};

int influxdb_bulk_append_timestamp(struct influxdb_bulk *bulk, time_t t)
{
    int ret;
    int len;

    /* Make sure we have enough space */
    ret = influxdb_bulk_buffer(bulk, 128);
    if (ret != 0) {
        return -1;
    }

    len = snprintf(bulk->ptr + bulk->len, 127, " %ld\n", (long) t);
    if (len == -1) {
        return -1;
    }
    bulk->len += len;
    bulk->ptr[bulk->len] = '\0';

    return 0;
};
