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

#ifndef FLB_OUT_INFLUXDB_H
#define FLB_OUT_INFLUXDB_H

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_time.h>

#define FLB_INFLUXDB_HOST "127.0.0.1"
#define FLB_INFLUXDB_PORT 8086

struct flb_influxdb {
    uint64_t seq;

    char uri[256];

    /* database */
    char *db_name;
    int  db_len;

    /* HTTP Auth */
    char *http_user;
    char *http_passwd;

    /* sequence tag */
    char *seq_name;
    int seq_len;

    /* auto_tags: on/off */
    int auto_tags;

    /* tag_keys: space separated list of key */
    struct mk_list *tag_keys;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;

    /* used for incrementing identical timestamps */
    struct flb_time ts_dupe;
    struct flb_time ts_last;

    struct flb_output_instance *ins;
};

#endif
