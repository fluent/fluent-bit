/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#ifndef FLB_OUT_INFLUXDB_H
#define FLB_OUT_INFLUXDB_H

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_time.h>

#define FLB_INFLUXDB_HOST "127.0.0.1"
#define FLB_INFLUXDB_PORT 8086

struct flb_influxdb {
    uint64_t seq;

    char uri[2048];

    /* v1 */
    /* database */
    flb_sds_t database;

    /* HTTP Auth */
    flb_sds_t http_user;
    flb_sds_t http_passwd;

    // v2
    /* bucket */
    flb_sds_t bucket;

    /* organization */
    flb_sds_t organization;

    /* custom HTTP URI */
    flb_sds_t custom_uri;

    /* HTTP Token */
    flb_sds_t http_token;

    /* sequence tag */
    char *seq_name;
    int seq_len;

    /* prefix */
    char *prefix;
    int prefix_len;

    /* auto_tags: on/off */
    int auto_tags;

    /* tag_keys: space separated list of key */
    struct mk_list *tag_keys;

    /* Arbitrary HTTP headers */
    struct mk_list *headers;

    /* Use line protocol's integer type */
    int use_influxdb_integer;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;

    /* used for incrementing identical timestamps */
    struct flb_time ts_dupe;
    struct flb_time ts_last;

    struct flb_output_instance *ins;
};

#endif
