 /* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#ifndef FLB_INFLUXDB_BULK_H
#define FLB_INFLUXDB_BULK_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_time.h>
#include <inttypes.h>

#define INFLUXDB_BULK_CHUNK  4096  /* 4KB of buffer chunks    */

struct influxdb_bulk {
    char *ptr;
    uint32_t len;
    uint32_t size;
};

struct influxdb_bulk *influxdb_bulk_create();

int influxdb_bulk_append_header(struct influxdb_bulk *bulk,
                                const char *tag, int tag_len,
                                uint64_t seq_n, const char *seq, int seq_len);

int influxdb_bulk_append_kv(struct influxdb_bulk *bulk,
                            const char *key, int k_len,
                            const char *val, int v_len,
                            int quote);

int influxdb_bulk_append_bulk(struct influxdb_bulk *bulk_to,
                              struct influxdb_bulk *bulk_from,
                              char separator);

void influxdb_bulk_destroy(struct influxdb_bulk *bulk);
int influxdb_bulk_append_timestamp(struct influxdb_bulk *bulk,
                                   struct flb_time *t);

#endif
