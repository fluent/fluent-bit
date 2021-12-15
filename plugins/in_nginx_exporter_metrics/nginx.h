/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#ifndef FLB_IN_NGINX_H
#define FLB_IN_NGINX_H

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_network.h>

#define DEFAULT_STATUS_URL          "/status"

struct nginx_ctx
{
    int coll_id;                    /* collector id */
    flb_sds_t status_url;
    struct flb_parser *parser;
    struct flb_input_instance *ins; /* Input plugin instace */
    struct flb_upstream *upstream;
    struct cmt *cmt;
    struct cmt_counter *connections_accepted;
    struct cmt_counter *connections_handled;
    struct cmt_counter *connections_total;
    struct cmt_gauge *connection_active;
    struct cmt_gauge *connections_active;
    struct cmt_gauge *connections_reading;
    struct cmt_gauge *connections_writing;
    struct cmt_gauge *connections_waiting;
    struct cmt_gauge *connection_up;
    bool is_up;
};

struct nginx_status
{
    uint64_t active;
    uint64_t reading;
    uint64_t writing;
    uint64_t waiting;
    uint64_t accepts;
    uint64_t handled;
    uint64_t requests;
};

#endif
